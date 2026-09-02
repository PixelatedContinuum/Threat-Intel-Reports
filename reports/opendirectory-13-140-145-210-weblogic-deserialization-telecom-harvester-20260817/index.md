---
title: "Carrier Credential Harvesting Through a Customer's Router"
date: '2026-08-18'
layout: post
permalink: /reports/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/
thumbnail: /assets/images/cards/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817.png
hide: true
category: "Telecom Intrusion Campaign"
description: "An operator reached an Ecuadorian carrier's AAA and provisioning secrets through one small business customer's carrier-managed Cisco router, making the device upload 424,946,514 bytes of its own firmware, crash dumps and configuration files."
detection_page: /hunting-detections/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-detections/
ioc_feed: /ioc-feeds/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/
stix_bundle: /stix/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817.json
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
  - value: "13.140.145[.]210"
    note: "Operator VPS, Contabo AS51167, France"
  - value: "95.214.114[.]37"
    note: "Operator VPN egress seen in the victim log"
  - value: "radius-sync[.]com"
    note: "Operator domain impersonating telecom AAA"
  - value: "72c6383477bbcb93811fd837a9e4721cfddea0cd238eebe3012acc0e6a31c40e"
    note: "exfil_nvram.sh, the WSMA fileCopy exfil script"
  - value: "5f2efa79f548b648a318e6c6f3512581574002b79fab97cfec10b77feba177b8"
    note: "serve_http.log, receipt of the 100 uploads"
figure_nav:
  - image: instrument-versus-objective.svg
    parts:
      - label: "Instrument vs objective"
        anchor: "#41-objectives-versus-instruments"
      - label: "What was taken"
        anchor: "#61-what-was-taken"
      - label: "Inside the carrier"
        anchor: "#71-inside-the-carrier-a-confirmed-foothold"
  - image: crash-harvest-loop.svg
    parts:
      - label: "The parser crash"
        anchor: "#63-the-exploitation-mechanics-in-full"
      - label: "The loop itself"
        anchor: "#62-the-loop-that-manufactures-its-own-loot"
      - label: "What it yielded"
        anchor: "#61-what-was-taken"
  - image: wsma-filecopy-self-exfiltration.svg
    parts:
      - label: "The double-encoded path"
        anchor: "#63-the-exploitation-mechanics-in-full"
      - label: "What left the device"
        anchor: "#61-what-was-taken"
      - label: "The network signature"
        anchor: "#132-the-highest-value-network-signatures"
      - label: "Where the data went"
        anchor: "#83-where-the-data-went-is-unknown-and-that-is-a-real-finding"
---

**Campaign Identifier:** WebLogicDeserialization-TelecomHarvester-13.140.145.210<br>
**Last Updated:** September 1, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary
{: .hl-tier-1}

An operator reached a national carrier's credential and provisioning material by taking over the internet-facing web management interface of one ordinary business customer's carrier-managed router, then instructing that router to upload its own firmware image, crash dumps and configuration files outbound, and finally mining the stolen configs for the carrier's authentication secrets. The customer was a 96-person printing and office-supplies firm. Nothing of that company's own business data was taken, and there was no lateral movement into its office LAN, even though the operator held an arbitrary-file-read primitive on a device sitting behind the company firewall. What they took was the device's own material, and their post-processing says why. The stolen configs were grepped for `tacacs`, `radius`, `acs`, `cwmp`, `tr069`, SNMP community strings and Cisco `key 7` and `key 5` encrypted passwords in a single pass.

That is the whole point of this case. The printing company was the route. The carrier's credential and provisioning plane was the objective.

The anchor is a receipt, not an inference. On 2026-07-24 the victim router uploaded **424,946,514 bytes across 100 HTTP PUTs**, and it was the router itself making those requests, with `User-Agent: cisco-IOS` on every one. That total breaks down as the full 355,970,456-byte IOS-XE firmware image, 65 unique nginx core dumps, 3 ad-hoc core pulls and 19 configuration pulls including `cwmp_inventory`, the device's TR-069 provisioning record. All of it landed in the operator's own listener log, which two independent captures of the operator's exposed working directory later recovered. I claim compromise here because the evidence is victim-side, not because a script would have printed success if it worked.

The rest of the campaign is broader than that one router. I recovered **169 unique operator files**, SHA256-verified, from a directory-listing web server the operator left open on the public internet at `13.140.145[.]210:8888`. Inside sit a hand-written Oracle WebLogic T3 and JNDI exploitation suite, a from-scratch four-mode LDAP exploitation server, a Cisco-shaped multi-port capture rig, tunnelling and post-exploitation scripts, three bespoke credential wordlists totalling roughly 2.7 MB, a userland rootkit's originals-backup, and the operator's own run logs. Beyond the router, a host inside Ecuador's state telecom reached out and pulled the operator's tunnelling client from their staging server, which is a confirmed internal foothold in a national carrier. A WebLogic attack against a municipal government application failed outright. A monitoring-server credential harvest, a Windows post-exploitation chain and the rootkit install are all built, targeted and staged, with no captured victim-side outcome.

I rate the campaign **HIGH**, on an overall risk score of **7.9/10** derived in Section 3. It is not CRITICAL because nothing in the 169 files encrypts, wipes, defaces or denies service, because the WebLogic leg against its named target failed with three independent confirmations, and because the credential-cracking step against the stolen crash dumps failed outright with 21 candidate passwords all rejected and zero authentication tokens recovered. Those failures matter to the rating and I state them as findings rather than burying them.

I am publishing this because of a specific gap. Public reporting on the Cisco IOS-XE web management vulnerability class is extensive, the double-decode path bypass that reaches the internal WSMA endpoint included, and this operator invented none of it.

What I could not find documented anywhere are the two choices they made on top of it. The first is the exfiltration primitive, where they reached WSMA's **filesystem** sub-service rather than its command-execution one, so the victim device pushes its own material out and the operator never takes a shell. The second is the crash loop, where their own malformed authorization headers break the router's Lua authentication parser and every crash writes a core dump holding live credential material for them to steal and mine. I carry both at MODERATE-HIGH, as negative-search results rather than proven firsts. Section 6.3 carries the searches behind both and why that label straddles.

I cannot attribute this to a named threat actor, and I hold that at INSUFFICIENT confidence, around 15 percent. I am tracking the activity as **UTA-2026-023** *(an internal tracking label used by The Hunters Ledger, see Section 12)*. Every artifact the operator authored themselves is Spanish, from code comments and status strings to the wordlist seeds. The only Chinese-language material in the corpus is documentation shipped with two downloaded public exploit tools, which tells you where those tools were written and nothing at all about where the operator sits. Six infrastructure-expansion pivots across five platforms came back empty, and no catalogued threat actor or malware family shares a single indicator with this one.

The activity is espionage-shaped and the operator is unattributed, and those two statements belong in the same sentence so nobody separates them. What tips it is where their reconnaissance points. It scoped the carrier's signalling plane, the machinery that routes calls and tracks where subscribers are, and that is a collection objective rather than inventory a broker could sell on. So I lean espionage-flavoured collection over access-brokering at roughly 60/40, at LOW confidence, and a lean is all it is, because two artifacts in the corpus pull the other way and I never saw where the collected access went. Section 12.4 carries the discriminator in full, the counterweights, and the hypothesis testing behind that 60/40.

The part that should worry a defender most is not the operator at all. Two of the three victim sites remain observably exposed, established entirely from third-party passive data without touching anything. The compromised router had its management plane on the public internet **continuously since October 2022**, had not rebooted in roughly 310 days as of 2026-08-15, and served the vulnerable web interface throughout the period this campaign was active. Nobody was watching that device for four years, and it is the reason the carrier's AAA and provisioning material for that device is now in somebody else's hands.

That router has since stopped answering. As of 2026-09-01 it responds on none of the five ports it previously exposed, nor to ICMP. From outside I cannot separate a decommissioning from a readdressing from a device that is simply switched off, and the distinction carries real weight, because the implant class used against it is memory-resident and does not survive a reboot. A device that genuinely restarted has most likely shed whatever was placed on it in July. The exposure that allowed all of this is untouched by any of those readings.

---

## 2. Key Takeaways
{: .hl-tier-1}

Stop assuming the interesting victims are the big ones. The unremarkable business customer's carrier-managed router is how somebody gets at the carrier. That single sentence is what I would want a network operator to take away from this case, and everything below is support for it.

- The victim device does the exfiltration itself. Because the operator drove Cisco's WSMA `fileCopy` capability rather than its command-execution one, the router opened outbound HTTP connections and PUT its own firmware, crash dumps and configs to an external server. There is no attacker-initiated download to catch, and the traffic carries `User-Agent: cisco-IOS`, which is the highest-fidelity signal in the entire case precisely because the operator cannot suppress something the victim device generates.
- Carrier-managed customer premises equipment holds the carrier's secrets, not the customer's. A device provisioned and managed by the carrier carries TACACS, RADIUS, SNMP and TR-069 material for the management relationship. Compromising it is a route into the carrier's management plane, so the blast radius of a small customer's router is a national estate rather than one site.
- Hunting for leftover operator files will mostly fail here by design. Four independent anti-forensic mechanisms run through this campaign, with webshells dropped and deleted every session, stolen registry hives wiped at both ends, staging files removed, and a modified script backdated to 2010-10-07. The durable signals are the ones on the wire and in device telemetry, not on the victim's disk.
- Monitoring servers are the shortest path to a whole fleet's credentials. A script in this corpus is built to pull every stored Windows, Linux and SNMP credential out of a carrier's monitoring platform in a handful of API calls, including the root-group credentials that apply estate-wide. That step is staged rather than confirmed executed, but the design intent is not ambiguous.
- Exploitation can manufacture its own loot. Each malformed authorization header the operator sent crashed the router's Lua authentication handler, and each crash wrote a core dump holding live credentials in memory. Treat core dumps on network devices as sensitive material rather than as debris.
- Capability is not attribution. This operator builds real tooling and understands telecom infrastructure genuinely, and none of that tells you who pays them.

Three signals are worth hunting before anything else in this campaign. The router uploading its own files outbound. The double-encoded request path that reaches its internal management endpoint. And a reverse tunnel from an internal host followed by a local SOCKS listener. Section 9.3 gives each one in the form you would hunt on, and all three are covered by rules in the [companion detection file](/hunting-detections/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-detections/).

---

## 3. Risk Assessment
{: .hl-tier-1}

I score this campaign **7.9/10, HIGH**. The score is driven by a confirmed large-volume theft of carrier-relevant credential material and a confirmed foothold inside a national telecom, and it is held below CRITICAL by three genuine failures and by the complete absence of any destructive capability.

<table>
<colgroup>
<col style="width: 24%;">
<col style="width: 14%;">
<col style="width: 62%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>9/10</td><td>424,946,514 bytes confirmed out of one device in a single day, with the device as the transport. The operator held an arbitrary-file-read primitive on that router and used it to take the complete firmware image, 65 crash dumps and the TR-069 provisioning inventory, then mined the results for carrier AAA secrets. Not a 10 because the credential-recovery step against the stolen dumps failed and no subscriber or business data was taken.</td></tr>
<tr><td>System Compromise</td><td>8/10</td><td>Privilege-15 equivalent control of a production edge router, confirmed. A confirmed internal foothold inside the state telecom, where victim hosts pulled the operator's tunnelling client and connected back. A claimed root session on the carrier's RADIUS server, held at MODERATE because that claim rests on operator-side artifacts only.</td></tr>
<tr><td>Persistence Difficulty</td><td>7/10</td><td>The IOS-XE implant class is memory-resident and clears on reboot, which sounds easy until you notice the victim device had not rebooted in roughly 310 days. On the Linux side, the operator rewrote an AAA watchdog into a self-healing loop and backdated it, and staged a userland rootkit whose backup set covers the seven binaries an administrator would use to find it.</td></tr>
<tr><td>Evasion Capability</td><td>8/10</td><td>A double-encoded request path that slips the router's own route filter, attack traffic from a rented in-country VPN exit while loot went to a different country, four separate anti-forensic mechanisms on victims, and a domain named to read as legitimate AAA infrastructure. Held at 8 rather than higher because the operator's own infrastructure hygiene is poor enough that this entire case exists.</td></tr>
<tr><td>Lateral Movement</td><td>8/10</td><td>A chain built end to end from external exploit through reverse SOCKS tunnel and SSH jump host to internal web application and credential spray, confirmed as far as the jump host and unproven beyond it. The stated objective is reachability into the carrier's 172.x internal networks. The score is about what that chain gives the operator, not about a completed intrusion path. They move inward on credentials rather than exploits, and hold an SSH private key and monitoring-platform credentials acquired by a step that never appears in the evidence.</td></tr>
<tr><td>Detection Challenge</td><td>7/10</td><td>Deliberate victim-side anti-forensics defeats file-based hunting across three of the capability clusters, and the tooling is bespoke enough that no commodity family signature applies. Pulled down from higher by the one thing the operator cannot control, which is a router announcing itself as <code>cisco-IOS</code> while uploading 356 MB of firmware to the internet.</td></tr>
</tbody>
</table>

Those weight out to **7.9/10**, which is HIGH. Data exfiltration and system compromise carry 20 percent each, and persistence, evasion, lateral movement and detection challenge carry 15 percent each.

### 3.1 What is actually at risk

The data at risk is not the compromised company's data. That distinction is the most useful thing in this report for anyone assessing their own exposure, because it changes who needs to care. A carrier-managed edge device holds the carrier's authentication credentials and its provisioning relationship, so an organisation reading this should not ask whether their business files are safe on their router. They should ask what the carrier put on that device and who else that material unlocks.

Three further dimensions follow from the rest of the corpus. The monitoring-plane script concentrates an entire estate's credentials into one authenticated foothold, with no per-device exploitation needed. The signalling-plane reconnaissance, the activity on a carrier AAA server, the AAA-impersonating domain and the back-office platform name seeded into the wordlists all point at subscriber-facing carrier systems, meaning who the subscribers are, how they authenticate and how their traffic is signalled. And the full firmware image plus a 65-dump crash corpus plus the carved authentication-handler source is the complete input set for offline analysis of that exact router build, whether or not the operator ever used it that way.

### 3.2 What this campaign does not do

Nothing in 169 files encrypts, wipes, defaces, denies service or manipulates data. There is no ransomware, no stealer, no miner, no loader and no botnet component. The single modification observed on a victim system makes that victim's daemon **more** resilient rather than less, because the operator wanted the logging pipeline they were collecting from to keep running. That absence is a finding in its own right and it bounds the rating. Any framing of this campaign that implies destructive intent would be unsupported by the evidence.

---

## 4. Campaign Scope and the Victims Still Exposed
{: .hl-tier-2}

Every resolved target in this campaign is critical infrastructure or government, with one instrument and one foreign outlier. The operator worked Ecuador's state telecom by name, a second carrier's customer edge, one municipal cadastre, the application estate of a second municipality, a national education portal, and a Mexican bank's password-reset endpoint. One further government body appears in the table without being a target at all, because the carrier monitoring platform the operator built a harvest script against also monitors a metropolitan fire service. That is the scope, and it is what makes this a briefing for a national regulator rather than an incident report for one company.

| Target | Sector | What happened | Evidence class |
|---|---|---|---|
| A printing company's carrier-managed edge (Cisco ISR 1100 + Sophos XG, on the managing carrier's AS) | Carrier-managed customer edge | **Compromised.** 424,946,514 bytes exfiltrated 2026-07-24, device as HTTP client | Victim-side, DEFINITE |
| Two state-telecom internal hosts | Communications, state telecom | **Internal foothold.** Both pulled operator tooling from the staging server; one became an SSH jump host | Victim-side, HIGH |
| The state telecom's `radius01` AAA server | Communications, carrier AAA | Reachability confirmed; a root session is claimed by operator tooling only | Mixed, MODERATE on root |
| The state telecom's PRTG monitoring server | Communications, monitoring plane | Credential-harvest script built with working API credentials; no captured outcome | Operator-side, HIGH capability |
| A metropolitan fire service, surfaced by a TLS certificate on the carrier's monitoring server | Government, emergency services | **Collateral only.** No operator action against it anywhere in the corpus; the platform staged for harvest happens to monitor the fire department, which is how it enters the picture | Certificate-derived, LOW |
| A municipal government's application host | Government, municipal | **Attack failed.** WebLogic RCE returned 401 and 404 with no callback on any listener | Victim-side, DEFINITE negative |
| `CATASTRO` at internal `192.168.10.12`, a municipal cadastre host | Government, municipal cadastre | Two webshells and a credential-spray chain built against it; no captured outcome. The municipality is named from a municipality-derived string in the operator's own spray list, withheld here because it is a plausible working credential, together with captured internal reconnaissance, not from anything victim-side | Operator-side, HIGH capability; municipality named at MODERATE |
| A national education ministry portal | Government, education | Landing page captured under the operator's own probe-oriented filename | Operator-side, targeted |
| A Mexican retail bank's online-banking host | Financial, Mexico | Password-reset endpoint iterated over real nine-digit customer-ID ranges | Operator-side, intent MODERATE |

### 4.1 Objectives versus instruments

The printing company is an instrument, not an objective, and separating the two is what makes the rest of this case parse. A 96-person office-supplies business founded in 1950 is not a strategic target. Its carrier-managed router is, because that router's own telnet banner identifies it as carrier-managed equipment and its configuration files carry the carrier's provisioning relationship.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/instrument-versus-objective.svg" | relative_url }}" alt="Three-card vertical diagram separating the instrument from the objective. Card one, orange, labelled THE INSTRUMENT: one ordinary business customer, a 96-person printing and office-supplies company in Quito founded in 1950, whose carrier-managed edge router has had its management plane facing the internet since 2022, and which was pre-selected by name rather than found by chance. Card two, red, labelled WHAT WAS TAKEN: only the device's own material, namely the firmware image, the crash dumps, the configuration files and cwmp_inventory, with no business data, no documents and no lateral movement into the company network, despite the operator holding an arbitrary file-read primitive. Card three, deep red, labelled THE OBJECTIVE: the carrier's credential plane, with the stolen configuration files mined in a single pass for tacacs, radius, acs, cwmp, tr069, community, key 7 and key 5, covering device AAA secrets, SNMP communities, stored passwords and TR-069 provisioning data. The footer states that the interesting victim is not always the big one, and that an unremarkable customer's managed router is a route into the carrier that manages it.">
  <figcaption><em>Figure 1: The instrument-versus-objective split that governs the rest of this case. The printing company was the route; the carrier's credential and provisioning material was what the operator actually came for, which is why nothing of the customer's own business data was touched.</em></figcaption>
</figure>

Two artifacts settle that reading from opposite directions. The operator deliberately exfiltrated `cwmp_inventory`, which is the device's TR-069 record of its relationship with the carrier's auto-configuration server, alongside the running and startup configs. Then they mined everything they took for `tacacs`, `radius`, `acs`, `cwmp`, `tr069`, community strings and Cisco type-5 and type-7 encrypted passwords. Nobody greps a printing company's router for `acs` and `tr069` out of curiosity about printing.

The operator's own wordlists say the same thing from the opposite direction, and Section 10.5 carries the counts, the seeds and the methodological caution that goes with them. What matters at this level is the conclusion those files support. They were built to crack this one router rather than this one company, they seed a telecom back-office vendor's name that only somebody reading the carrier's systems would think to include, and they contain nothing at all about any other victim in this campaign.

Two things follow. The customer-edge operation was pre-selected rather than swept up opportunistically. And the entire carrier side of this campaign ran with no credential-guessing component whatsoever, which means one campaign carried two completely different access approaches, each saying something different about how the operator sized up the target in front of them.

### 4.2 Two of the three sites are still exposed, and I established that without touching anything

This is the part that matters to somebody, and all of it comes from third-party passive scan history rather than from any probe of my own.

The compromised router's management plane has been on the public internet **continuously since October 2022**. It still served the IOS-XE web interface redirect on port 80 as of 2026-08-15, its SNMP engine time indicated no reboot in roughly 310 days, and the implant class used against it is memory-resident and does not survive a reboot. Read those two facts together and the conclusion was uncomfortable. Anything the operator placed in July 2026 was, on the evidence available then, still resident on that device.

That reading no longer holds, and it is worth saying so plainly rather than letting it stand. As of 2026-09-01 the router answers nothing, on any of the five ports it previously exposed or on ICMP, and the adjacent host in the same address block answers normally, so this is the device rather than the path to it. I cannot establish from outside which of decommissioning, readdressing or a power cycle explains it. Any of the three most likely takes the memory-resident implant with it, which makes this the second piece of good news in the case. What I will not do is keep asserting the implant is resident, because the fact that supported that claim has gone.

The Sophos firewall standing beside it had its administrative console exposed for fifteen months, and still presents its administration portal.

The third site is a municipal government environment, identified from a hypervisor cluster certificate rather than from anything the operator wrote down. It presents three internet-facing Java and Oracle application servers, a hypervisor management API and MikroTik Winbox, eleven open ports in total on the most recent passive data. Of the three sites, this is the one where the exposure is unchanged, and it is the best-supported still-exposed claim in this report as of 2026-09-01.

The WebLogic attempt against that environment failed, and it is the only confirmed successful defence anywhere in this case. I want that on the record, because negative results get dropped and this one is genuinely good news. It also reframes rather than closes the risk. Had the attack landed, the hop from a WebLogic virtual machine to the Proxmox API on the same subnet is short, and Proxmox is not one server in that environment, it is the environment. That is a near miss against a municipal government, not a footnote.

The router was also contested, which changes how any future forensic work on it has to be scoped. Crash traces preserved in the stolen dumps show five other clients hitting the same device between 2026-05-12 and 2026-07-24, all using the generic public exploitation URI rather than this operator's distinctive path. They are separate actors, they are explicitly not folded into this operator's infrastructure, and their existence means nobody should assume a single intruder when they go looking.

---

## 5. Technical Classification
{: .hl-tier-2}

There is no malware family here, and treating this as one would misread the case. What was recovered is a single operator's complete working directory, left listing on the public internet. That distinction has practical consequences for anyone building coverage, because there is no family name to pivot on, no import-hash cluster, and no command-and-control protocol signature in the conventional sense.

| Field | Assessment |
|---|---|
| Type | Operator intrusion toolkit. Not self-propagating, not a packaged family |
| Family | None. DEFINITE that this matches no known family, INSUFFICIENT for any named-family association |
| Public tools present | ysoserial (50 stock gadget blobs across 5 regenerated sets), `JNDIExploit.jar` (welk1n), chisel v1.23.1, PuTTY `plink.exe`, the public CVE-2023-21839 Go exploit, the public "Dirty Frag" Linux LPE, a public CVE-2020-2555 WebLogic tool |
| Sophistication | Intermediate to advanced, with an unusual shape. Builds its own operational tooling, runs downloaded heavy exploits byte-for-byte unmodified. No evidence of original vulnerability research |
| Campaign complexity | Multi-vector, single operator. Nine capability clusters across at least five external victim environments plus internal pivots |
| Operator language | Spanish throughout every operator-authored artifact |
| Impact tactic | None mapped. Nothing encrypts, wipes, defaces or denies service |

### 5.1 What the operator builds, and what they buy

The split is clean and it is byte-confirmed in both directions, which is rare enough to be worth stating precisely.

They build the operations. The WebLogic T3 and JNDI suite is 22 hand-written Java files with no license headers and no upstream provenance markers, including a T3 credential tester that prints `AUTHENTICATED!` on success, which is the tool you write when you expect to hold credentials and need to validate them. The four-mode LDAP exploitation server implements BER encoding primitives from scratch. The capture rig binds Cisco device-callback ports specifically rather than a generic port range. The multi-session command console on `127.0.0.1:19999` matches no stock framework on either its port or its banner.

They buy the exploits, and they do not even modify them. Two Go binaries in the corpus are exactly 3,008,878 bytes each with different hashes, which looks like a pristine-versus-customised pair until you diff them. **106 bytes differ** out of 3,008,878, and every one is build metadata. No new hard-coded address, no new callback, no logic change. The operator built the same public tool twice, once from a clean checkout and once from a tree that was dirty for reasons that never reached the binary. The Linux kernel privilege-escalation exploit tells the same story from a different angle, with 102 of the 142 string literals from its public source present in the compiled binary and `127.0.0.1` as the only embedded address.

So the profile is a competent integrator who invests effort exactly where it differentiates them and buys the rest. That is not a criticism. It is the most efficient way to run an operation, and it is also why hash-based detection of the heavy exploits in this case detects the public tool rather than this operator.

### 5.2 Two captures, three weeks apart, two different operations

The corpus is **169 unique files** carrying 171 operator-assigned filenames, because the operator saved two captured pages under two names apiece and content-hash deduplication collapsed each pair. The figure to cite is 169.

Those 169 files are the union of two independent captures of the same host, taken three weeks apart, and neither one alone yields the campaign. The July capture holds the WebLogic exploitation build-out, the payload classes, the JSP webshell, the gadget arsenal, the tunnels and the proxy chains. The August capture holds the credential-harvesting phase, meaning the router exfiltration script, the bespoke wordlists, the core-dump mining and the capture-rig logs. 88 files appear in both, 64 in the July capture only, and 17 in the August capture only.

That is a collection lesson worth carrying past this case. Trusting either source alone would have produced half an operation with no indication that the other half existed.

---

## 6. The Confirmed Compromise: 424 MB Out of a Customer's Router
{: .hl-tier-2}

The victim is a single Cisco 1100-series integrated services router running IOS-XE 16.6.4, a 2018 build that was never patched for the 2023 web-interface vulnerability. Its hostname embeds the customer's own company name and its head-office site, which the crash-dump filename convention reveals without the operator ever writing it down. Its management address and its egress address are adjacent addresses in the same carrier-assigned block, and the internal web backend that its nginx front end proxies to sits at `192.168.1.6:80`.

The sequence reconstructs cleanly from three sources that agree, the operator's own listener logs, an independent raw capture of the same traffic, and the victim device's own error log recovered from the crash dumps the operator stole.

| Time (UTC) | What happened | Where the evidence comes from |
|---|---|---|
| 2026-07-24 01:59:05 | First attempt using a single-encoded path fails and crashes the router's Lua authentication parser, source `95.214.114[.]37` | Victim's own nginx error log, carved from a stolen core dump |
| 2026-07-24 02:02:12 | Double-encoded path succeeds, request proxied upstream to the internal web backend, same source address | Same log, three minutes later |
| Same session | Two small test files retrieved to prove the file-copy primitive works before running it in anger | Operator's listener log |
| 2026-07-24, across the day | **100 HTTP PUTs totalling 424,946,514 bytes** arrive from the customer-edge egress address | Operator's listener log, corroborated by an independent raw capture carrying `User-Agent: cisco-IOS` |
| 2026-07-24 12:50:23 | Operator generates a self-signed TLS certificate for their own listeners, same day as the theft | Certificate material in the corpus |

The three-minute gap between the failure and the success is the whole technique in miniature. The first request used the encoding form that public proof-of-concept code uses. It crashed the parser and got nothing. The second used a form with two separately double-encoded characters and different casing, and it went straight through.

### 6.1 What was taken

| Content | PUT events | Bytes |
|---|---|---|
| IOS-XE firmware image `c1100-16.06.04.SPA.bin` | 1 | 355,970,456 |
| nginx core dumps (65 unique files) | 77 | 66,205,853 |
| Ad-hoc core pulls | 3 | 2,589,708 |
| Configuration files including `cwmp_inventory` | 19 | 180,497 |
| **Total** | **100** | **424,946,514** |

The firmware image is 84 percent of everything taken, and nobody exfiltrates a full firmware image to harvest passwords. Read alongside the 65-dump crash corpus and a script that carves the web interface's own source code out of those dumps, the operator assembled the complete raw material for offline analysis of that exact router build.

I hold two honest counterweights against reading that as a research programme. The image is a signed 2018 package Cisco distributes and that is widely mirrored, so taking it from the victim buys the exact running image without needing a vendor account, which argues for engineering against that specific box rather than against the build in general. And the batch log shows the operator grinding every dump for `admin:` hashes and authentication tokens, so "more dumps, more chances at a live token" explains the crash corpus with no research intent whatsoever. The firmware pull is the strong leg of the argument. The crash corpus is the weak one.

The timeline needs stating precisely, because it is easy to get wrong. The 424 MB transfer was a **single day**. The February-to-July span visible on the core dumps is the age of those dumps as they sat on the victim device, a pre-existing cache grabbed in one pass. This is not five months of operator dwell time and should not be read as such.

One declared pull is unaccounted for. The operator's script pre-declares exact byte sizes for four files, which means the device's non-volatile memory was enumerated before that run ever started, and one of the four never appears in the listener log. Whether that single copy failed is unresolved.

### 6.2 The loop that manufactures its own loot

This is the mechanism I would most want a network operator to understand, because it inverts the usual relationship between exploitation and evidence.

The operator's malformed authorization header crashes the router's web interface authentication handler with an arithmetic-on-nil error at a specific line of a specific Lua file. Every crash writes a core dump. That core dump is a memory image of the process that had just been handling credential checks, and the operator knows it, which is why their post-processing greps the stolen dumps for authentication tokens. Exploitation manufactures the artifact that exploitation then harvests.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/crash-harvest-loop.svg" | relative_url }}" alt="Four-card vertical diagram with a dashed loop-back arrow, showing exploitation that manufactures its own loot. Card one, orange: the operator sends an Authorization header the parser cannot handle, with no scheme prefix. Card two, red: the Lua parser dies with an arithmetic-on-nil error in smgmt_parse_auth_hdr at smgmt2.lua line 336, killing the authentication handler mid-request. Card three, yellow: the device writes a core dump, saving process memory that holds live credential material, in core archives named after the device hostname. Card four, deep red: the operator steals the dumps using the same fileCopy primitive and mines them for credentials, though here all 21 candidates were rejected and no tokens were recovered. A dashed orange arrow loops from the final card back to the first, captioned that every retry restocks the shelf it is about to empty. The footer notes 65 dumps were taken spanning February to July 2026, so most predate this operator, with one directly attributable and the other 64 unresolved.">
  <figcaption><em>Figure 2: The loop that feeds the credential theft. Each failed authentication attempt crashes the parser and writes a fresh core dump holding live credentials, so the exploitation manufactures the very artifact it then harvests. The mechanism is confirmed; the credential recovery it was aimed at failed.</em></figcaption>
</figure>

The credential recovery failed, and that is a confirmed negative rather than an unknown. The batch log covers 5 of the 65 dumps. Each records a successful exfiltration, then a candidate-checking pass in Spanish, then **21 candidate passwords** across the batch, every single one rejected. The token-extraction section is empty in all five. So the data theft succeeded and the password cracking failed, and both halves belong in the record.

The practical takeaway is uncomfortable for anyone running edge routers. Core dumps on a network device are not debris. They are memory images that can hold live credential material, and on this device the attacker was generating them on demand.

### 6.3 The exploitation mechanics, in full

The access-bypass class is publicly documented and this operator did not invent it, so what carries the value is the set of implementation choices that make their traffic distinguishable from the five other actors who hit the same device. Those choices are also what a defender needs at byte level to reproduce the detection logic, or to recognise a variant where one constant has changed.

<details markdown="1" class="hl-teardown">
<summary>The double-encoded path, the forged token, and why the filesystem sub-service was the clever choice</summary>

#### The forged authorization token

The operator sends `0123456789abcdefab` as a bare `Authorization` header value, with no authentication scheme prefix. That works because the affected web interface validates this header only against the pattern `[a-f0-9]{18}` and never binds it to an actual session, so any 18-character hexadecimal string does the job.

The literal itself is a class artifact rather than an operator fingerprint, and Cisco's own advisory settles that. The vendor's documented implant check posts a request and treats a returned hexadecimal string as implant-present, and the worked example Cisco publishes in that advisory is `0123456789abcdef01`. This operator's `0123456789abcdefab` is the same sequential-hex shape with the last two characters changed, which is what somebody produces after reading the advisory rather than a choice that identifies them. Nobody should treat the literal as an attribution signal, and the detection file and the IOC feed both handle it that way already.

What that leaves is a shape and a path. Detection built on the shape, meaning 18 hexadecimal characters with no scheme, covers the whole public exploitation class including the five unrelated intruders on this device, and it is the request path rather than the token that separates this operator from them.

#### The path bypass, character by character

The request goes to `POST /%2577eb%2575i_%2577sma_Http`. Decoding once yields `/%77ebui_%77sma_Http`. Decoding twice yields `/webui_wsma_Http`, which is the internal web services management endpoint the front-end proxy is supposed to protect.

The bypass works because nginx and the IOS daemon behind it each decode the path independently. nginx sees the once-decoded form, which does not match the protected internal route, so it falls through to a less restrictive handler and proxies the request onward. The IOS daemon then decodes again and receives the real endpoint name.

That general double-decode class is documented publicly by OPSWAT, VulnCheck and the Knownsec 404 team, and their write-ups describe the same mechanical principle. What differs here is the construction. The public walkthroughs double-encode exactly one character, the leading `w` of `webui`. This operator double-encodes **two** separate characters, the `w` of `web` and the `u` of `ui`, as two independent `%25xx` sequences, and targets an endpoint name ending `_Http` with a capital H rather than the lowercase `_https` the public write-ups use.

That is why the string is a fingerprint rather than a generic signature. The identical byte sequence appears in the operator's own script and in the victim's own error log, arriving from the operator's VPN exit, so it is corroborated from both ends of the connection. No public proof-of-concept found in two research passes uses this exact two-character encoding pattern or this endpoint-name casing.

#### The exfiltration primitive, and the choice that made it

Once inside the web services management endpoint, the obvious thing to do, and what every public write-up describes, is inject configuration commands. That is the exec-oriented use of the service, and it is how the implant gets written in the mass-exploitation case.

This operator did something else. They sent a SOAP body scoped to `urn:cisco:wsma-filesystem`, invoking `fileCopy` with `srcURL=nvram:/<file>` and `dstURL=http://<operator-host>/<file>`.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/wsma-filecopy-self-exfiltration.svg" | relative_url }}" alt="Four-card vertical diagram showing how the victim router exfiltrates itself. Card one, orange: a double-encoded path, POST slash percent-2577-e-b percent-2575-i underscore percent-2577-sma underscore Http, slips the route filter because nginx and IOSd each decode once, a spelling distinct from the single-encoded lowercase form used by public proofs of concept. Card two, red: the operator sends a SOAP body scoped to urn:cisco:wsma-filesystem invoking fileCopy with a source URL of nvram and a destination URL pointing at the operator's host, choosing the filesystem service rather than the exec service that every public write-up describes. Card three, yellow: the direction of travel inverts, as the router opens its own outbound HTTP connection and pushes rather than being pulled from, so the traffic originates inside the trusted network. Card four, deep red: 424,946,514 bytes leave across 100 uploads on 2026-07-24, every request carrying User-Agent cisco-IOS, comprising the 356 MB firmware image, 65 nginx core dumps and 19 configuration files including cwmp_inventory.">
  <figcaption><em>Figure 3: Why this compromise left a receipt rather than an inference. Driving Cisco's WSMA fileCopy capability instead of its command-execution one made the victim device the HTTP client, so the exfiltration is recorded from both ends and survives the anti-forensics the operator applied elsewhere.</em></figcaption>
</figure>

`fileCopy` is legitimate, officially documented Cisco functionality. The vendor's own configuration guide describes the filesystem service as copying and validating files between local and remote file systems, moving data using whatever protocol the source and destination URLs specify. The operator read that schema, saw that the filesystem sub-service is a separate capability from the exec one, and picked the one that moves data out without ever needing a shell.

The consequence is the inversion that makes this case distinctive. Because the copy runs from the device's own process, the router becomes the HTTP client. The loot arrives at the operator's listener as an **inbound PUT from the victim**, carrying `User-Agent: cisco-IOS`, and the operator pulls nothing. There is no attacker-initiated download in the traffic at all.

Three search passes looked specifically for prior public documentation connecting the double-decode bypass to the filesystem sub-service, or to outbound self-exfiltration, and located none. Every public exploitation write-up reviewed describes the exec-oriented use, and the one prior vendor advisory concerning WSMA information disclosure covers a different product line and a different vulnerability entirely.

The last pass widened the search past the exploitation literature. A large public malware corpus returned zero objects. A corpus of captured attacker directories returned 333 hits for `wsma`, every one of them wordlist noise apart from a single penetration-test report that merely enumerates `/webui/wsma` endpoints. Two fresh targeted searches returned Cisco's own configuration guide describing the legitimate functionality and the 2023 mass-exploitation corpus describing the implant, with no source connecting the two.

I hold that at MODERATE-HIGH. The label straddles deliberately, because the breadth of the search now justifies more than MODERATE while an unprovable negative can never justify HIGH. It stays a negative-search result rather than a proven first, since the absence of a located report is not proof that no report exists.

#### The source-carving script

The tool that carves the web interface's Lua source out of a stolen core dump scans for printable runs of 60 or more bytes containing a newline and at least one of a keyword list covering Lua constructs, the nginx Lua module namespace, and the specific handler names. Its comments are Spanish.

What it recovered includes the credential-check handler itself, which decodes a JSON request body and passes the authentication material through an internal subrequest to a password-check endpoint. Live credentials transit that path in memory, which is exactly why the operator greps the dumps for authentication tokens, and it also confirms that the nginx generating those crashes is the router's own web interface front end rather than a separate appliance. The internal file path preserved in the carved source proves it outright, because it sits under the router operating system's own read-only mount.

#### What the stolen configs were mined for

The post-processing grep across every recovered configuration file reaches for `secret`, `password`, `enable`, `username`, `key 7`, `key 5`, `community`, `tacacs`, `radius`, `auth`, `priv`, `cisco`, `admin`, `acs`, `cwmp`, `tr069`, `url` and `http` in one pass.

Read that list as a statement of intent. `key 7` and `key 5` are Cisco's stored-password encoding types. `tacacs` and `radius` are the carrier's authentication protocols. `acs`, `cwmp` and `tr069` are the carrier's remote-provisioning relationship with the device. None of it is about the printing company.

</details>

---

## 7. The Rest of the Campaign: What Landed, What Failed, What Was Only Built
{: .hl-tier-2}

The router is the one compromise I can prove from the victim's side. Everything else in this campaign sorts into three buckets, and keeping them apart is the discipline that makes the rest of this report worth reading. A confirmed foothold inside the carrier. A confirmed failure against a municipal government. And a set of capabilities that are fully built, aimed at named targets, with working credentials already in hand, but with no captured outcome at all.

A script that would print `SUCCESS` if it worked is not evidence that it worked. I apply that rule uniformly below, and it costs me several claims I would otherwise like to make.

### 7.1 Inside the carrier: a confirmed foothold

On 2026-07-13 two hosts belonging to Ecuador's state telecom reached out to the operator's staging server and pulled tunnelling tools. That is victim-side evidence, logged on the operator's own server, and it is why I rate the internal foothold HIGH.

| Time (UTC) | Event |
|---|---|
| 14:01:40 | Operator brings up a tunnelling server on port 443 in reverse mode |
| 14:02:06 | A reverse SOCKS session is established to a local listener on port 1080 |
| 19:50:30 | Operator fetches the Windows tunnelling client from their own staging server, a smoke test against themselves |
| 19:51:21 | Carrier host A requests the staging directory index |
| 19:51:42 | Carrier host A downloads the Windows tunnelling client |
| 19:55:35 | Carrier host B requests the SSH client, which is not staged yet and returns 404 |
| 19:59:44 | Carrier host B downloads the SSH client, now present |
| 20:03:51 | A second tunnelling server comes up on port 80, with SOCKS twenty seconds later |
| 20:11:23 | A third server on port 80 carries two concurrent SOCKS sessions |

One host took the tunnelling client, the other took the SSH client. The operator then reached the first over SSH as root, using a private key they already held, routed through the reverse SOCKS tunnel that the client on that same host had just created.

I want to be as careful with that session as I am with the AAA server in the next subsection, because the two rest on different classes of evidence and it would be easy to let the stronger one carry the weaker. The foothold is victim-side. The carrier's own hosts fetched the tooling, and the SOCKS sessions that followed arrived inbound at the operator's listeners.

The root level of that SSH session is not victim-side. It rests on the operator's own proxy-chain configuration files, which point at the local SOCKS listener and chain onward from there, and on what their scripts assume about the account they are running as. So the foothold is HIGH and root on the jump host is MODERATE, on exactly the reasoning I apply to the RADIUS server below.

Where that key came from is not in the evidence, and neither is where the monitoring-platform credentials came from. Both were sourced by a step that never appears in these 169 files, which means credential acquisition is happening outside everything I can see.

What they did from inside is the part that changes how you read this operator. The internal reconnaissance output is unmodified port-scanner results, 474 scan-report lines with microsecond response times to internal Docker addresses, which means it ran from a host with genuine local network access rather than through any blind timing channel. It sweeps six internal ranges. And the operator's own section headers through that file use correct carrier terminology throughout, sorting results under mobile switching centre, RADIUS, broadband network gateway, voice gateway, backbone and Docker network headings.

The reverse DNS captured in that scan reads as a carrier core-network map, with voice gateway media servers, a corporate monitoring host, an inter-ministerial government monitoring host on the carrier's ISP brand, and a monitoring platform host. Somebody who did not know the shape of a telecom network before they went in does not label a scan that way.

### 7.2 The AAA server, and a repair that was not a repair

The single most prioritised target in the entire corpus is the carrier's RADIUS server. It appears across three unrelated tool families, as the only named single host in the internal scan while every other target gets a range sweep, hard-coded with labelled per-port probes in three separate Java scanners, and as a claimed root session driven from the operator's own console.

What the operator did there sounds almost helpful until you look at it properly. They killed every duplicate copy of the statistics daemon except one, then rewrote the watchdog script so that the daemon self-heals, wrapping the original polling loop in a background loop that restarts the daemon every 30 seconds if it dies. Then they backdated the modified file to 2010-10-07.

There are three readings and I want to be honest about which one I hold. The watchdog they installed is genuinely better than what was there, because it checks before restarting and so cannot recreate the duplicate-process condition it was written to clean up, which rules out carelessness. It could be collection maintenance, since the daemon and its log are the subscriber-authentication data itself and a dead daemon stops the collection. It could be persistence disguised as maintenance, though keeping an arbitrary surviving process rather than a specific one argues against that. Or it could be pure cleanup after instability they caused.

The timestomp does not discriminate between them, and I originally thought it did. This operator backdates, deletes and hides as standard practice across unrelated operations, and a behaviour applied to everything they touch tells you nothing about the purpose of any single instance. What does discriminate is that the fix is forward-looking. Cleaning up after yourself is backward-looking, and killing the duplicates alone would have achieved it. Writing a self-healing loop is extra work that only pays off if you need that daemon running later. That favours collection maintenance at **MODERATE**, resting on one inference about why they did more work than cleanup required.

The root access itself is **MODERATE, not HIGH**, and the distinction is load-bearing. Reachability to that server is confirmed from the internal scan, which is victim-side. Root is not. The script merely assumes a root session already exists on the operator's console, the console server itself was never archived, and no captured shell output exists anywhere. The filesystem knowledge in the script is post-access knowledge, since you cannot write those paths without having been on the box, but knowing the paths is not the same as proving the session. This must not be weighted at the same level as the router compromise.

### 7.3 The attempt that failed

The operator fired a WebLogic remote-code-execution chain at the municipal application host on port 7001 and it did not work. Three independent confirmations, all victim-side, put that beyond doubt. The exploit's own output shows the callback cycled across LDAP, RMI and HTTP on six different ports with every listener reporting no connection. The captured server responses are a genuine Oracle WebLogic 401 and a genuine WebLogic 404. And the callback listener log records the listener starting and nothing ever arriving.

The captured bytes settle an earlier reading I had to withdraw. Those error pages are authentic Oracle WebLogic output, down to the HTML 4.0 draft doctype and a verbatim protocol block, and other application servers render differently. There really was a WebLogic on that port, and it refused them. Earlier suggestions that the target ran something else, or that the operator had made a fingerprinting error, are wrong and are retracted here.

That address sits in the state telecom's address space with a hosting customer as the ISP of record, and the environment behind it belongs to a municipal government. It is the only confirmed successful defence in this case.

### 7.4 Built, aimed, and unproven

Each capability below is HIGH on the tooling, the named targets and the credentials held, all read directly from source, and **unproven on outcome**. The scripts print their results. Nothing saved those prints.

The monitoring-plane harvest is the one with the largest potential blast radius. A seven-stage script runs against the carrier's monitoring platform using working administrative API credentials, and its shape is instructive. It enumerates up to 500 monitored devices with their addresses and groups in a single call, then pulls stored Windows, Linux and SNMP credentials for specific device identifiers, then reaches for the **root-group inherited credentials**, which in that platform frequently hold the fleet-wide master credentials. That third call is the highest-value single request in the file. The script then enumerates notification methods and abuses the notification-program feature for code execution, which works on any version of that platform once you hold administrative access, and finishes by enumerating users and deleting its own staging file.

You do not brute-force a carrier's device fleet. You compromise the box that already holds the fleet's passwords. That is not a novel idea in the abstract, but it is the mark of somebody who thinks about where credentials actually live rather than just running exploits.

The Windows post-exploitation chain runs against an internal host the operator labels `CATASTRO`, a cadastre server on a WAMP stack with a mapping server exposed. The full chain is below.

<details markdown="1" class="hl-teardown">
<summary>The internal Windows chain, the ephemeral webshell, and the credential store attack</summary>

#### The path in

```
operator VPS
  tunnelling server -> local SOCKS listener on 127.0.0.1:1080
    ssh -i <operator key> root@<carrier host A>   (jump host, confirmed foothold; root operator-side)
      recon -> carrier host C, operator label "SYS-GAD"                  (no captured outcome)
      192.168.10.12, operator label "CATASTRO" (WAMP stack, mapping server on :8080)
        code execution: unauthenticated OGC-filter RCE                   (no captured outcome)
        webshells written to the web root:                               (no captured outcome)
            h.php  (persistent, dispatches on an X-CMD request header)
            x.php  (written per command, fetched once, then deleted)
        lateral -> 192.168.10.1 (remote-management primary, admin-share fallback)
          objective: route print filtered for the carrier's 172.x supernet  (no captured outcome)
```

#### The ephemeral webshell, and why it changed my read

The mapping-server vulnerability is an unauthenticated remote-code-execution flaw in a library that evaluates property names as expressions, reachable through several ordinary request types by sending a malicious value reference. The operator tests it first with a `whoami` payload against the product's own default demo layer, which tells you they read the documentation rather than copying a payload wholesale.

The way they wrote it to be used is genuinely disciplined. Every command is delivered by writing a fresh single-purpose PHP file into the web root through the RCE, fetching that file over HTTP to collect the output, and deleting it. Every session, from scratch, is how the script is built to work.

That design is what moved my read on this operator most, and I want to be precise that it is the design I am reading rather than a captured session. A smash-and-grab intruder does not build it that way. Writing it costs effort once, routing every command through it costs effort every time, and the only reason to accept that cost is to leave nothing behind for whoever looks later. On the target side they were not planning to be sloppy.

#### The credential theft leg

Through the persistent webshell, the script is written to export the SAM and SYSTEM registry hives into the web root under dot-prefixed filenames so that they are retrievable over HTTP, pull them back to the jump host, base64-encode them onward, and then **delete both server-side files and the local temporaries**. Same discipline, applied to the loot rather than to the tool. Whether any of it ran is not in the evidence, because nothing captured the output at either end, so the hive return stays unproven.

#### The credential spray

The lateral-movement script sprays remote-management sessions against `192.168.10[.]1` with six credential pairs, crossing two usernames against four passwords, and falls back to an administrative-share connection over five passwords when that fails. Two of those passwords, withheld from publication as in Section 4, name an Ecuadorian municipal government and a biometrics system outright, which is targeting knowledge rather than a generic list. Success is matched on both the Spanish and the English form of the confirmation string, which is one of the small tells that the operator's working language is Spanish.

On success the script runs host identification, a full network configuration dump, and `route print` filtered for `172`, which is the carrier's internal supernet. The objective of the whole Windows chain is stated right there in a filter argument.

#### The attack on the mapping server's own credential store

A separate script attacks the mapping product's encrypted credential store rather than any Cisco material. It assumes the product's default master password and works against two stored datastore passwords, trying two encryption schemes across five iteration counts and four initialisation-vector derivations. One of the two target credential names combines a database engine with an Ecuadorian canton, which is exactly the software stack an Ecuadorian municipal cadastre runs on and matches the operator's own label for the box. No output survives, so whether the master password was left at its default is unknown.

</details>

The third staged capability is the one I find hardest to write about with the confidence I would like. The corpus contains a gzip tar archive holding pristine copies of exactly seven Linux system binaries, with the directory layout preserved for a clean overwrite. Those seven are the process lister, the process monitor, the process tree, the network state tool, the open-files tool, the file finder and the package manager. That is the canonical userland rootkit target set, covering process listing, network state, filesystem and package integrity in one archive, and their 2007-to-2010 timestamps place the host as a Red Hat 5-era system.

You back up originals when you are overwriting them. That is the whole argument, and it substantially undercuts any benign reading, though it does not logically exclude an operator staging a clean restore set. Intent and staging are **HIGH**. Install on a victim is **MODERATE** and capped there, because the trojanised replacements themselves were never exposed in the open directory and cannot be obtained from either capture. The finding cannot be raised without them, and no amount of further analysis of what I do have will produce them.

The most likely host is the carrier's AAA server, where the operator was already managing daemons and a log collector. Hiding your collector's processes and connections on the box you collect from is the coherent pairing. That specific placement is MODERATE.

### 7.5 The reconnaissance that scoped the signalling plane

One script does the target selection, and it is scoped entirely to the state telecom, by organisation name and by network block. It carries 57 queries covering 36 distinct products, each annotated with the relevant vulnerability identifiers in the operator's own comments. 54 of those queries name a product and only 3 are broad network-block sweeps, so the reconnaissance was built around known-vulnerable software rather than around scanning address space and seeing what answered.

Buried in it is a dedicated telecom block scanning for RADIUS, SIP, SMPP, Diameter, GTP and SS7 signalling ports. Those are correct, non-obvious mobile-core port numbers, chosen before the operation started, and they are the strongest independently checkable evidence for genuine telecom domain knowledge anywhere in this case. Getting into a national carrier's signalling plane is subscriber location, message interception and roaming visibility. It is not a quick-money move.

That same script carries a live third-party API key hard-coded at line 7. I come back to it in Section 12, because it is the only artifact in 169 files that is actionable against the actor rather than merely descriptive of them.

### 7.6 The Mexican outlier

Three near-identical scripts POST to a Mexican bank's password-reset endpoint, iterating customer identifiers over six distinct nine-digit ranges at escalating concurrency from 20 up to 500 parallel requests. That a real bank's password-reset endpoint was probed with real customer-identifier ranges is HIGH.

Intent is **MODERATE**, and I am deliberately not resolving it. The scripts discard every response body, carry no validity check and no branching logic, and self-label as a benchmark, which makes them as consistent with a capacity and rate-limit probe as with a customer-enumeration oracle. What they do settle is that any Ecuador-only framing of this campaign is wrong. What they refuse to settle is motive, and that refusal is genuine rather than diplomatic. A clean single-purpose intelligence tasking does not usually pause to rate-test a foreign bank.

---

## 8. Operator Infrastructure and Tradecraft
{: .hl-tier-2}

The operator's external footprint is one virtual server, one domain and one rented VPN exit. That is the entire estate, and the emptiness is a finding rather than a gap, because I went looking hard for more.

Six expansion techniques across five platforms all came back negative. No sibling domains, no subdomains, no SSH host-key reuse, no certificate reuse anywhere else, no registrant identity, and no overlap with any catalogued threat actor or malware family. Three separate passes, re-verified independently after the fact. When six different pivots return nothing, the absence starts carrying information of its own.

| Asset | Detail |
|---|---|
| Virtual server | `13.140.145[.]210`, Contabo GmbH, AS51167, France. Reverse DNS resolves to a standard provider-assigned hostname. No detections on any reputation platform |
| Domain | `radius-sync[.]com`, created 2026-07-11 at 07:53:50 UTC (registrar-authoritative; an earlier saved lookup reading 2026-07-10 is a timezone display artifact and is retracted), Cloudflare-fronted, paid out to 2029 |
| Attack-source egress | `95.214.114[.]37`, PacketHub S.A., AS136787, geolocated Ecuador, a rented commercial VPN exit rather than owned infrastructure |
| TLS material | Self-signed certificate, subject and issuer both naming the server's own address, generated 2026-07-24 at 12:50 UTC, the same day as the router theft |
| Tunnel fingerprints | Four distinct server key fingerprints captured across the tunnelling logs |

### 8.1 Sixteen minutes, and a three-year registration

Two behavioural details cut against each other in a way I find more informative than either alone.

The provisioning was fast and practised. The domain was registered at 07:53:50 UTC, resolved to the operator's own server by 07:56, and had Cloudflare nameservers and A records in front of it by 07:59. The full sequence, including two intermediate TLS certificate issuances, completed at 08:09:58. Sixteen minutes from purchase to a fully proxied domain pointing at their box, with WHOIS privacy already applied roughly four minutes after creation, captured inside that window across 19 change records with no registrant field ever recorded. There was never a leak interval to catch.

But they paid for three years. A burner domain gets the one-year minimum. Registration out to 2029 says the name was meant to be kept, and it sits alongside the fact that when the open directory closed on 2026-08-04 the operator did not abandon the server. It was still answering on SSH twelve days later, and a new listener appeared on port 53 on 2026-08-10, six days after the directory closed. That port's purpose is undetermined by any source I consulted, and it is most consistent with a DNS-based callback channel.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/operator-vps-port-history.png" | relative_url }}" alt="Third-party scan history table for the operator server, listing five services with first-seen and last-seen dates: SSH on port 22 running OpenSSH 9.6p1 on Ubuntu, a tcpwrapped listener on port 53, an HTTP service on port 80 running BaseHTTP 0.6 on Python 3.12.3 returning 404, a Python 3.12 websockets service on port 443 returning 426 Upgrade Required, and the open directory on port 8888 running SimpleHTTP 0.6 returning 200.">
  <figcaption><em>Figure 4: Third-party scan history for the operator's server, showing the open directory on port 8888 going dark after 2026-08-04 while SSH kept answering, and a new listener appearing on port 53 afterwards. The websockets service on port 443 post-dates both captures of the directory, which is why none of its tooling appears in the 169 files. The platform's interface renders first-seen dates in local time, so port 53 displays as 08/09 where the underlying record is 2026-08-10 02:32 UTC; the dates in the text above are the UTC values.</em></figcaption>
</figure>

Neither hosting provider shows any bulletproof-hosting indicator. The infrastructure investment is entirely commodity, which cuts against a well-resourced programme without ruling one out. What is notable is not the hosting tier but the behaviour layered on top of it.

The domain name is the point. A network engineer at a telecom who sees egress to something called `radius-sync[.]com` reads it as authentication infrastructure and moves on. Paired with the operator's activity on the carrier's actual RADIUS server, that is deliberate blending rather than a coincidence of naming.

### 8.2 Anti-forensics is a trait here, not a set of one-offs

Four independent mechanisms across three unrelated capability clusters, all applied victim-side, all deliberate.

| Mechanism | Where |
|---|---|
| Webshell dropped, used once, deleted, re-dropped fresh next session | The internal cadastre host |
| Stolen credential material deleted at both source and destination after transfer | The registry hive theft |
| Modified file backdated by roughly sixteen years | The carrier AAA server watchdog |
| Staging file removed immediately after use | The monitoring harvest, and the LDAP server's own cleanup |

Sourcing attack traffic from an in-country VPN exit while the loot went to a different country is ordinary operational security and I count it separately, not as anti-forensics.

The consequence for defenders is the important part and it is not intuitive. Hunting for leftover operator files on victim hosts will mostly fail here **by design**. The durable signals are the ones the operator cannot reach because they never sat on the victim's disk in the first place, meaning the outbound device-generated PUT, the double-encoded path in network logs, the crash traces in device telemetry, and modification-time-versus-change-time skew on files the operator backdated.

That discipline sits in a sharp asymmetry with their own infrastructure hygiene, which is poor enough that this entire case exists. The whole operation, tools, run logs, keys, wordlists and stolen data, sat in a directory-listing web server on the public internet. Careful in, careless at home.

I do not read that as a paradox. Offensive operators are not systems administrators, the skills genuinely do not overlap, and at the solo-to-small-team tier a throwaway box that turns out to be useful gets kept rather than replaced properly. It does not lower my read of their on-keyboard skill at all. It is just where they got caught.

### 8.3 Where the data went is unknown, and that is a real finding

Everything converges inbound on the one server. The 424 MB of router material, the reverse SOCKS sessions, the callbacks. Nothing in the corpus shows a second hop outward. No cloud upload, no email, no paste site, no transfer to another operator host, no check-in anywhere else.

I have to be careful about what that means. An open directory caught mid-operation shows what came in, not what the operator later did over an SSH session I cannot see. So the absence is consistent with the collection method rather than proof of anything, and it leaves the sharpest motive discriminator I have, meaning where the collected access actually goes, unresolved rather than answered. That single gap is why Section 12 holds motive as a lean rather than a conclusion.

---

## 9. Detection and Response Guidance
{: .hl-tier-2}

Detection content for this campaign lives in the companion file. Thirty rules ship there across three languages, twenty-three of them Detection-tier and seven Hunting-tier, organised by capability cluster rather than by family because there is no family to organise by, plus five atomic indicators routed to the machine-readable feed instead of being forced into rules that would detect nothing without their hard-coded literal.

**[Detection rules: YARA, Sigma, Suricata, and coverage gaps](/hunting-detections/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-detections/)**
**[Machine-readable IOC feed](/ioc-feeds/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-iocs.json)**

| Rule type | Detection tier | Hunting tier |
|---|---|---|
| YARA | 6 | 2 |
| Sigma | 7 | 3 |
| Suricata | 10 | 2 |

Detection-tier rules are high-fidelity and evasion-resilient, meaning they are safe to alert on. Hunting-tier rules are broader, built for scoping, and will return hits that need review.

### 9.1 Weight the signals the operator cannot reach

The single highest-priority rule in the set is the network signature for an outbound HTTP `PUT` carrying `User-Agent: cisco-IOS` to a non-management destination. It earns that position for a structural reason rather than a stylistic one. The victim device generates that traffic itself while uploading its own firmware and configuration, so the operator cannot suppress it, cannot clean it afterwards, and cannot change it without abandoning the technique entirely. Legitimate IOS does not PUT its own configs or firmware to the internet.

Two rules in the same cluster are deliberately broader than this operator. The generic exploitation URI and the bare 18-hex forged-token shape cover the whole public exploitation class, which matters here because at least five other unrelated intruders were hitting the same victim router with exactly that generic pattern. Those rules are labelled as generic throughout the detection file so nobody mistakes a hit on one of them for this operator specifically. The two operator-specific signatures, meaning the double-encoded path and the file-copy exfiltration primitive, will not fire on the other five.

### 9.2 What has no rule, and why

Five artifacts are simply absent from the corpus and no rule is possible for them. The custom command console was never archived, so only its client-side verbs are known and nothing at all is known about its wire format. The trojanised rootkit replacement binaries were never exposed, so the detection has to target the originals-backup archive shape instead, which is the closest observable proxy. A carrier-targeting script is known only by name and a single error line. An out-of-band data-exfiltration template is missing entirely. And no packet capture exists for this campaign, so every network detail is reconstructed from the operator's own logs and captured responses, which is why the tunnel-handshake signature ships as a broad hunting heuristic rather than a protocol-specific detection.

Five more techniques have no viable rule-language mapping rather than no evidence. The router's crash trace has no standard log-source definition that would survive validation, so network-layer coverage targets the request that causes the crash instead. The monitoring-platform notification trigger is visible only in that platform's own audit log. The kernel exploit's distinctive syscall sequence would need auditd field names that are not confirmed to exist, and shipping a rule built on an unconfirmed field risks publishing something that silently never matches. Modification-time skew needs a scheduled filesystem sweep rather than an event stream, so it belongs in a hunt query rather than a portable rule. And the SNMP engine-time reading that tells a responder a months-old memory-resident implant would still be sitting there is analytic guidance rather than an event, so it cannot be expressed as a rule at all.

I would rather say all of that plainly than ship coverage that looks complete and is not.

### 9.3 Response orientation

Targets only. Detailed procedures are out of scope for a third-party intelligence product, and anyone with an active incident should be working from their own playbook rather than this section.

Detect first, in this order. Outbound HTTP `PUT` from any network device carrying `User-Agent: cisco-IOS` to a destination outside the management range. Inbound request URIs containing `%2577eb%2575i`, alongside `Authorization` headers matching `^[a-f0-9]{18}$` with no auth scheme, against any IOS-XE web management interface. A reverse connection from an internal host to an external host on 80, 443 or 8443 followed immediately by a local SOCKS listener, especially where a tunnelling or SSH client was fetched from an external HTTP server first.

Then look for these artifacts by name. A self-healing watchdog script under `/usr/local/bin/` whose modification time predates its change time by years, on any AAA or RADIUS host. Batch modification across the seven-binary Linux inspection toolset, or any archive containing exactly that member set. A persistent PHP webshell dispatching on a non-standard request header, and transient single-purpose PHP files in a web root.

Registry hive exports written into a web-served directory. A JSP command webshell on Linux WebLogic deployments. Memory-resident IOS-XE implants, which clear only on reboot. And core-dump files on edge routers, which should be treated as sensitive credential-bearing material rather than as debris.

Containment falls into six categories.

- Isolate internet-facing network-device management interfaces.
- Rotate carrier-side AAA, TACACS+, RADIUS, SNMP and TR-069 credentials reachable from any compromised customer-premises configuration.
- Rotate every credential stored in monitoring platforms, including root-group inherited credentials.
- Reboot compromised IOS-XE devices to clear memory-resident implants, after preserving evidence.
- Block and monitor the operator infrastructure listed in the IOC feed.
- Treat any device showing multiple independent intruders, as this router did, as requiring full forensic scoping rather than single-actor eradication.

---

## 10. Technical Teardown
{: .hl-tier-3}

The operator's own code settles the capability question that their file names only pose. They are a competent adapter rather than a vulnerability researcher. The differentiated technique they implement is public, they implement it once and stamp it into seven parameterised wrappers, and their genuinely original work is simpler than the impressive-looking work. That is a normal and effective way to build an offensive capability, and it is not what a first read of the directory listing suggests.

Getting there cost me two corrections that leaned the same optimistic way, which is why I state it flatly. From here on the scaffolding is off and the writing assumes a reader who does not need JNDI, page-cache writes or BER encoding explained.

### 10.1 The WebLogic T3 and JNDI suite

Twenty-two Java files, all clean, all purpose-built, no license headers and no upstream provenance markers anywhere. The suite splits into three functions, meaning client-side T3 tooling, server-side JNDI resolution abuse, and payload construction, and the authorship signal differs sharply between them.

<details markdown="1" class="hl-teardown">
<summary>Twenty-two Java files, one copy-pasted reflection block, and the tool that gives the operator away</summary>

#### Client-side T3 tooling, which is their own work

`WLExploit.java` is a straightforward T3 client built on `weblogic.jndi.WLInitialContextFactory` with three actions, `enum`, `bind <ldap_url>` and `lookup`. The `bind` action rebinds a `Reference("ExploitClass", ..., ldapURL)` and then looks it up, which is the CVE-2023-21839 trigger in its simplest form. The code shows no duplication anywhere and reads as the operator's own straightforward implementation.

`WLAuth.java` matters more than its size suggests, and it is the file I would point at if somebody asked me what this operator is actually for. It is a **T3 credential tester**. It sets `SECURITY_PRINCIPAL` and `SECURITY_CREDENTIALS`, prints `AUTHENTICATED!` on success, and then lists the JNDI tree. Nobody writes that tool speculatively. You write it when you expect to hold WebLogic credentials and need somewhere to validate them, which fits a campaign whose whole shape is credential acquisition.

`JNDIBind.java` uses the classic `javax.el.ELProcessor` local-factory reference. `T3Exploit.java` is a JNDI driver carrying the eventual victim address and port as its hard-coded example. `JNDIEnum.java` and `T3Blind.java` walk the tree.

#### The server-side primitive, and the adapt-once-and-stamp signature

`CVE_2024_21182.java`, `exploit21182.java` and the whole `x*` family construct an `AggregatableOpaqueReference`, reflect its private `referent` field to a `weblogic.application.naming.MessageDestinationReference` whose type string is spoofed and whose lookup name is an attacker-controlled URL, then `bind` and `lookup` so the WebLogic server itself resolves that URL through the `ForeignOpaqueReference` path. Transport is `iiop://`.

That is a real patch bypass. Oracle's fix for CVE-2023-21839 blocked the direct `ForeignOpaqueReference` route, and this reaches the same JNDI-injection primitive through a different class whose private field can be reflectively set. It is also entirely public, documented down to the exact class names in a vulnerability database and a public reproduction repository.

Here is the tell. The roughly twenty-line reflection block that carries the primitive is **byte-identical** across seven files. Not seven independent implementations with a shared idea, seven copies of the same block wrapped in different parameter handling. That is adapt-once-and-stamp, and it is why I walked back an earlier read of this suite as the operator's most capable original work. It is a competent integration of a published technique, well wired into a working harness. That is a real skill and it is not the same skill as finding the bug.

Weaponised, the same primitive becomes a blind internal scanner. `xprobe`, `xreach` and `xscan` are reachability and latency probes with `xscan` threaded and timeout-bounded, while `xenum`, `xmgmt`, `xmulti` and `xdiag` are enumeration variants. The `Ssrf*` trio hard-codes the WebLogic victim and sweeps a loopback service list covering admin ports, database ports, SSH and a cache, plus, and this is the part worth noticing, three explicitly labelled probes against the carrier's RADIUS server by name.

That labelling is the same tell as the internal scan headers. The operator does not sweep and sort afterwards. They know what they are looking for before they look.

#### Database credential extraction

`xds.java` is the quietest interesting file in the suite. It walks the JNDI tree, looks up three Oracle Fusion Middleware data sources including the one that stores identity and credential data, calls `getConnection()`, prints the database URL, username, product and driver, then runs a context query returning the database user, name, server host and address.

It never exploits a database vulnerability. It abuses the application server's own configured connections to reach the Oracle backends behind it, using credentials the server already holds. That is the same structural move as the monitoring-platform harvest and the same move as the carrier-managed router, meaning go to the thing that already holds the credentials rather than attacking each target separately.

The operator's Python environment ships both an Oracle driver and a SQL Server driver, which corroborates the intent from a completely different direction.

#### Payload construction

`GenBypass.java` reads a CommonsCollections6 payload and re-wraps it four ways, as a `SignedObject`, a `TextMessageImpl`, an `ObjectMessageImpl` and an `ObjectMessage` carrying the chain, with placeholder injection. Those JMS message-wrapper gadgets are a known route past WebLogic's deserialization blocklist, and the output is four gadget blobs sitting in the corpus.

The two payload classes are blunt by comparison. One is an interactive reverse shell to the operator's server on port 4445 via a bash device redirect. The other is a proof-of-execution beacon that requests a URL containing the result of `whoami`, which is how you confirm code ran when you do not yet want a shell.

Fifty stock gadget blobs sit across five separate directories, regenerated once per callback method. That regeneration-per-method pattern is the operator fingerprinting which egress path works against a given target, and they kept every set.

One correction I owe the record. The error files sitting beside those gadget sets do **not** show which chains worked against a victim, and I read them that way at first. They are local generation output, a logging banner, classpath warnings, and one number-format exception from the operator fat-fingering their own arguments. What they actually show is the operator fumbling their own payload build, which is a fine tell and a completely different one.

</details>

### 10.2 The four-mode LDAP exploitation server

This is the single strongest builder artifact in the corpus, and it is a shell script, which is not where I expected to find it.

It is not a wrapper around a downloaded tool. The operator implemented BER encoding primitives from scratch, meaning length, sequence, string and integer encoders, and built a Python LDAP server on top of them that cycles four distinct JNDI-injection modes selected by the target's Java version.

<details markdown="1" class="hl-teardown">
<summary>Four JNDI modes, a JDK-version decision tree, and a 22-byte plumbing test</summary>

| Mode | Mechanism | When it applies |
|---|---|---|
| `reference` | Classic `javaNamingReference` with a remote `javaCodeBase` pointing at the operator's staging port | JDK below 8u191, before remote codebase loading was disabled |
| `beanfactory` | Tomcat's `org.apache.naming.factory.BeanFactory` driving `javax.el.ELProcessor` expression evaluation | JDK 8u191 and above, the standard post-mitigation route |
| `serialized` | `javaSerializedData` carrying a gadget generated live at request time, across CommonsCollections 5, 6 and 7, CommonsBeanutils1, Jdk7u21 and ROME | Whenever a usable gadget exists on the target classpath |
| `resourceref` | `javax.sql.DataSource` plus `com.sun.rowset.JdbcRowSetImpl` | The WebLogic-specific data-source trick |

Knowing which JNDI bypass survives which JDK mitigation, and implementing all four rather than picking one and hoping, is genuine domain depth. There is also a JRMP listener fallback and an exhaustive matrix of gadget-by-command-encoding permutations covering shell field-separator tricks, brace expansion and direct shell invocation, which is what you build when you have been bitten by a payload that failed on quoting rather than on the vulnerability.

The 22-byte file sitting beside it is my favourite artifact in the case for what it says about method. It is a Java-serialized `String` reading `hello_from_ldap`, and its whole purpose is to confirm the LDAP and JNDI callback path is live before sending a real gadget down it. That is a plumbing test. Somebody who has debugged enough failed deserialization chains to separate "my callback path is broken" from "my gadget is wrong" builds that, and it also happens to be a clean, near-zero-false-positive byte string for detection.

The build environment carries one honest deflation. The operator compiles the patch-bypass technique inside a public vulnerable-WebLogic container with host networking, which I initially flagged as a neat trick for obtaining a real classpath they did not otherwise have. Public documentation for the same technique recommends exactly that, because the officially vulnerable versions require vendor licensing and cannot be redistributed, so testers substitute the older redistributable image that shares the same code paths. It is standard practice among anyone reproducing this, not operator ingenuity, and it should not be weighted as evidence of anything.

</details>

### 10.3 The Linux kernel privilege-escalation exploit

The operator holds a compiled kernel exploit and its full source, and both are the public tool run unmodified. What the source is worth reading for is not the operator's skill, since they contributed a wrapper and nothing else, but the structure of the exploit itself, which tells you exactly what to hunt for.

<details markdown="1" class="hl-teardown">
<summary>Two page-cache write primitives, a dispatcher, and the seam that proves it was assembled from two proofs of concept</summary>

The strongest origin evidence in the file is structural. There are **three separate `#define _GNU_SOURCE` and include blocks**, at lines 1, 364 and 1660 of a 1,951-line file. You do not write one program that way. You concatenate two independent proofs of concept and bolt a dispatcher on top.

| Lines | Component | Entry point | Target |
|---|---|---|---|
| 1 to 359 | IPsec ESP transform page-cache write | `su_lpe_main()` | Overwrites the page cache of `/usr/bin/su` |
| 360 to 1659 | RxRPC/rxkad page-cache write | `rxrpc_lpe_main()` | Rewrites line 1 of `/etc/passwd` into a uid-0 entry |
| 1660 to 1951 | Dispatcher | `main()` | ESP first, RxRPC as fallback, then drop a root pty |

The two halves are two different bugs and the pairing blurs easily, so it is worth being exact. Both are shared-page-fragment flaws, which is why they were disclosed together, but they sit in different kernel subsystems. CVE-2026-43284 is the xfrm/esp bug, and it is the one that matches the ESP half above, meaning the security-association burst over netlink and the splice into a kernel crypto socket. CVE-2026-43500 is the rxrpc bug, and it is the fallback half only. Anywhere the two are treated as interchangeable, the mechanism this exploit leads with is being credited to the wrong identifier.

**The ESP path** is a page-cache write driven through the IPsec transform layer. It calls `unshare` with the user and network namespace flags to obtain raw-socket capability inside a fresh namespace without holding real privilege, then installs 40 security associations over netlink with sequential signature-value indices, smuggling one four-byte word of payload per association in a header field. For each word it splices a crafted header into a pipe, splices sixteen bytes of the target file's page into the same pipe, and splices the pipe into a crypto socket with the page-splicing flag set. The payload is a 192-byte minimal root-shell ELF written from file offset zero, with entry shellcode at offset `0x78`, and the exploit reads that offset back expecting a specific two-byte instruction to confirm the patch landed.

**The RxRPC fallback** builds an authentication token with an attacker-chosen session key through the kernel keyring and an RxRPC socket, then uses the kernel crypto API with the cipher `pcbc(fcrypt)` to mirror the kernel's own crypto and compute the checksum. That cipher choice is the single most distinctive artifact in the whole binary, because essentially nothing else on a normal Linux host reaches for it. The source cites kernel function names and a specific line number outright, which is the signature of code written against kernel source rather than reverse-engineered from a patch. It brute-forces session keys until the decrypted user-ID field yields the right prefix, and picks splice byte positions so the rewritten passwd line still resolves to a valid six-field uid-0 entry whose shell passes validation.

Surviving proof-of-concept environment knobs are all over it, covering namespace toggles, target-file override, iteration caps, a seed, auto-verification, a corrupt-only mode and a verbosity flag. Those are hallmarks of lifted research code, not operational tooling.

The operator's own contribution is the try-both-with-fallback wrapper, a retry loop of up to three attempts on the fallback path, two already-patched checks so a rerun does not corrupt a system it already owns, and the root pty drop. That is careful glue, and it is all of it.

The exploit is staged, not confirmed executed against any victim, and that posture matches the public record precisely. Microsoft's own reporting on in-the-wild use of this exploit describes it as a post-compromise privilege-escalation tool requiring prior SSH access, staged and executed after a foothold exists. Which is exactly what this operator has, in the form of a confirmed carrier foothold reached over a reverse tunnel.

One identifier note, because it is easy to get wrong. This is the ESP and RxRPC pair published in May 2026. The mechanically similar sibling in the kernel crypto authenticated-encryption template, which is the one that reached the federal known-exploited catalogue, is a different primitive and is **not** what this sample carries. The cipher choice and the code paths both settle it.

The severity scores for the pair need stating carefully, because the public numbers disagree and the disagreement has a cause. The rxrpc half carries a primary NVD score of 7.8 HIGH on the vector `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. The xfrm/esp half carries no primary NVD score at all, and three separate numbering authorities scored it independently, one at 8.8 and two at 7.8 on differing vectors. So the honest form for that one is a range of 7.8 to 8.8 with the disagreement said out loud, not a single figure lifted from whichever aggregator surfaced first.

Neither of the two appears in the federal known-exploited catalogue, whose current release I read directly. There is no government evidence of active exploitation for the escalation this operator staged and never ran, which is worth knowing before anyone treats the staging as urgent for reasons other than the foothold that precedes it.

</details>

### 10.4 The compiled binaries

Eight compiled artifacts, and their value is almost entirely in what they rule out. Two are the same public exploit built twice, one is a public kernel exploit compiled unmodified, three are stock tunnelling and SSH utilities, one is a public JNDI attack server, and one is the rootkit originals archive.

<details markdown="1" class="hl-teardown">
<summary>Two binaries, identical size, different hashes, and 106 bytes of nothing</summary>

Two Go binaries in the corpus are each exactly 3,008,878 bytes with different hashes. That pattern normally means a pristine copy and a customised copy, and it is the kind of thing that justifies a decompilation session.

It did not need one. The two differ by **106 bytes** out of 3,008,878, which is 0.0035 percent, across six regions, and every region is build metadata. The build-ID note section, two copies of the build-info structure plus its read-only mirror carrying a version-control-dirty flag flipping from `false` to `true`, and single-byte padding adjustments in the data and symbol-table sections. The string differences amount to the build ID and that one flag.

No new hard-coded address, no new callback, no new target, no logic change. Both carry the same upstream revision hash from February 2023 and the same build paths. A byte comparison is exhaustive by definition, so there is no difference hiding somewhere a deeper analysis would find. On this tool the operator is a straight consumer and not even a modifier, and I would rather say that plainly than dress up a null result.

The compiled kernel exploit corroborates the same pattern from the other side. 102 of the 142 string literals in its public source are present in the binary, the only embedded address is loopback, and the strings reproduce the public mechanics verbatim including the distinctive cipher name, the namespace and capability handling, and the stage messages. No operator infrastructure and no custom target are baked in anywhere.

Build environments are consistent across the corpus and worth carrying as profiling detail. Go 1.22.2 tooling built from a fixed temporary path, and the native binary built with GCC 13.3.0 on Ubuntu 24.04. One modern Linux development box of virtual-server class, used throughout, which is one of the several small things that argue for a single operator rather than a team.

The rootkit originals archive is 284,896 bytes holding seven binaries with their directory layout preserved for a clean overwrite, and their 2007-to-2010 timestamps place the target host as Red Hat 5-era. A package-name list elsewhere in the corpus names the specific packages that provide four of those seven, which is consistent placement rather than a coincidence.

</details>

### 10.5 The wordlists

Three files totalling roughly 2.7 MB, and they are the sharpest targeting evidence in the case. They also carry a methodological trap I want to flag for anyone re-running this kind of analysis.

<details markdown="1" class="hl-teardown">
<summary>52,027 lines built to crack one router, and two seeds nobody could guess</summary>

The three files run to 52,027, 55,576 and 77,360 lines. Whole-file case-insensitive counts put the customer's own company name as the top two seeds across all three, ahead of the managing carrier's three brand names.

The variant set encodes precise prior knowledge rather than a scrape. The registered legal name appears in full. So does a compound of the company name, the city by its three-letter airport code, and the Spanish word for head office. There are 7,310 instances of the city code and 5,286 of the head-office token. Systematic single-letter prefix mutations around the company name show generation rather than a copied list.

The list was built to crack a router, not a company. It carries `cisco` 1,184 times, and `enable` and `secret` 1,152 times each, which together are the two words of the IOS command that sets the privileged-mode password. The third file carries the platform name and `router` 405 times each.

Two seeds are neither generic nor guessable, and this is the part I did not expect. `netcraker` and a variant appear 2,304 times each, naming a real telecom back-office vendor whose platform the managing carrier publicly runs in this market. A second acronym appears 3,473 times combined, decorated with the same punctuation prefix as the rest, and I could not resolve what it expands to against Ecuadorian telecom sources. I am not going to guess it. Carrier back-office system names sitting inside a list built to crack one customer's router is the single detail in this corpus that most clearly says the customer was never the point.

The negative result is equally strong and easier to miss. These three router-cracking wordlists, a separate artifact from the lateral-movement script's hard-coded spray pairs in Section 7.4, contain **zero** occurrences of the state telecom, its ISP brand, either municipality, the cadastre label, the education portal, the mapping server, the monitoring platform, RADIUS, WebLogic or the fire department. Every other victim in this campaign is absent. These were built for one operation and no other, which also means the entire carrier side of the campaign ran with no credential-guessing component whatsoever. Two completely different access approaches in one campaign.

One caution for anyone re-deriving this. Leet-normalisation produces artifacts that show up in token counts and return zero on a direct search, and I hit two of them. Verify tokens by direct search before treating them as seeds. In the same vein, one European carrier name sits at exactly the generic-seed baseline alongside `access`, `backbone` and `fibra`, has no Ecuadorian operation, and is telecom filler vocabulary rather than a target.

</details>

### 10.6 The capture rig

The listener side is the least glamorous part of this toolkit and the one that most clearly shows the operator planning ahead. Their capture rig binds TFTP over UDP plus fifteen TCP ports, and two of those choices give the game away. Port 2000 and the 6970 to 6974 range are Cisco device-callback ports. The rig was shaped for Cisco gear specifically, before the Cisco operation ran, rather than assembled generically and pointed at whatever turned up.

The full listener set on the operator's server reads as a purpose-built range. Port 8888 served the open directory and doubled as the remote-codebase staging URL for JNDI reference payloads. Port 80 took the exfiltration, staged the tunnelling tools and hosted a tunnel server. Port 443 carried a tunnel server and an HTTPS capture listener behind the operator's own self-signed certificate.

Port 1389 ran the LDAP and RMI callback. Port 4445 took reverse shells and beacons. Ports 8080 and 8443 held additional callbacks and tunnels. Port 19999, bound to loopback only, ran the multi-session console. Port 53 appeared six days after the directory closed and remains unexplained.

---

## 11. MITRE ATT&CK Mapping
{: .hl-tier-2}

Thirteen of the fourteen ATT&CK Enterprise tactics are represented. The one that is empty is Impact, and its emptiness is a finding rather than a gap, because nothing in 169 files encrypts, wipes, defaces, denies service or manipulates data. The only modification observed on a victim system makes that victim's daemon more resilient. Any reading of this campaign as destructive would be unsupported.

The capability-versus-execution split runs through the whole mapping, and it dominates it. Most of this campaign is tooling that is fully built, aimed at a named target and holding working credentials, with no captured evidence that it ever ran. Twenty-eight of the fifty-nine rows below carry a `(MODERATE)` marker for exactly that reason. The rootkit row states its split inline instead, because staging and install sit at different levels, and the rows confirmed from victim-side evidence carry `(DEFINITE)`. Anyone lifting this table wholesale should carry the markers with it, since the table is otherwise the one place where a built capability could be mistaken for a completed one.

Two mapping decisions are worth stating rather than leaving for someone to query. Network service discovery is credited to port scanning run from the confirmed internal foothold, not to the WebLogic scanner suite, because that suite produced no output artifact anywhere and its hard-coded ranges are disjoint from the scan results that do exist. And the core-dump credential mining is mapped to the parent credential-dumping technique rather than a sub-technique, because ATT&CK's leaves under it cover Windows and directory credential stores, and mining a network appliance's crash dumps for in-memory web-authentication tokens has no matching leaf.

<details markdown="1" class="hl-teardown">
<summary>The full technique table, 13 tactics, 59 rows, one evidence citation each</summary>

> **Confidence note:** every row below is HIGH confidence unless explicitly marked `(MODERATE)` or `(DEFINITE)`. Section 14 organises the findings by confidence level for the higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Reconnaissance / T1595.002 | Vulnerability Scanning | 57 queries, all scoped to the state telecom, covering 36 distinct products |
| Reconnaissance / T1596.005 | Scan Databases | Live third-party scan-service API key hard-coded at line 7 |
| Reconnaissance / T1590.005 | IP Addresses | Two carrier netblocks scoped by name in the recon script |
| Reconnaissance / T1592.004 | Client Configurations | Captured SSL-VPN portal and education-portal landing pages |
| Reconnaissance / T1589.001 | Credentials | Wordlists seeded on the target's legal name, city and site role |
| Reconnaissance / T1589 | Gather Victim Identity Information | Bank customer-ID iteration, response bodies discarded (MODERATE) |
| Resource Development / T1583.003 | Virtual Private Server | `13.140.145.210`, Contabo AS51167 (DEFINITE) |
| Resource Development / T1583.001 | Domains | `radius-sync.com`, Cloudflare-fronted, paid to 2029 |
| Resource Development / T1587.001 | Malware | Own T3/JNDI suite, 4-mode LDAP server, C2 console, capture rig |
| Resource Development / T1587.003 | Digital Certificates | Self-signed cert generated the day of the router theft |
| Resource Development / T1588.002 | Tool | chisel v1.23.1, `plink.exe`, ysoserial, `JNDIExploit.jar` |
| Resource Development / T1588.005 | Exploits | Public CVE-2023-21839 Go tool and Dirty Frag LPE, both unmodified |
| Resource Development / T1608.001 | Upload Malware | Tunnelling and SSH clients staged on the operator's port 80 |
| Initial Access / T1190 | Exploit Public-Facing Application | CVE-2023-20198 + CVE-2023-20273 double-encode chain, succeeded (DEFINITE) |
| Initial Access / T1190 | Exploit Public-Facing Application | CVE-2024-36401 `valueReference=exec(...)` built; CVE-2023-21839 / CVE-2024-21182 over T3, that leg failed (MODERATE) |
| Initial Access / T1078 | Valid Accounts | SSH key and monitoring API credentials, both sourced upstream (MODERATE) |
| Initial Access / T1199 | Trusted Relationship | Carrier-managed CPE mined for the carrier's AAA and TR-069 material (MODERATE) |
| Execution / T1059.001 | PowerShell | `X-CMD` webshell dispatch, `Set-Content` writing the ephemeral shell (MODERATE) |
| Execution / T1059.004 | Unix Shell | `cmd.jsp` to `/bin/bash -c`; reverse shell via bash device redirect (MODERATE) |
| Execution / T1059.003 | Windows Command Shell | Batch recon drop, output redirected to a text file (MODERATE) |
| Persistence / T1505.003 | Web Shell | `h.php` dispatcher, `x.php` ephemeral, `cmd.jsp` on WebLogic, none observed deployed (MODERATE) |
| Persistence / T1543 | Create or Modify System Process | AAA watchdog rewritten as a self-healing daemon loop (MODERATE) |
| Persistence / T1554 | Compromise Host Software Binary | Originals-backup of the seven-binary inspection toolset, install unproven (MODERATE) |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | CVE-2026-43284 + CVE-2026-43500 staged, unexecuted, including `unshare` with user and network namespaces for raw-socket capability (MODERATE) |
| Privilege Escalation / T1098 | Account Manipulation | RxRPC path rewrites `/etc/passwd` line 1 to a uid-0 entry (MODERATE) |
| Defense Evasion / T1014 | Rootkit | Userland trojanisation of the inspection toolset. Staging HIGH, install MODERATE |
| Defense Evasion / T1070.006 | Timestomp | Watchdog script backdated to 2010-10-07, read from the operator's own script (MODERATE) |
| Defense Evasion / T1070.004 | File Deletion | Per-session webshell deletion; hives wiped both ends; staging files removed (MODERATE) |
| Defense Evasion / T1027 | Obfuscated Files or Information | `SignedObject` / JMS message-wrapper gadget re-wrapping |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | Watchdog in `/usr/local/bin`; domain posing as AAA infrastructure |
| Defense Evasion / T1548.001 | Setuid and Setgid | `/usr/bin/su` page-cache patch with a root-shell payload (MODERATE) |
| Defense Evasion / T1090.002 | External Proxy | Attack traffic from a rented Ecuador VPN exit, loot to France |
| Credential Access / T1003 | OS Credential Dumping | 65 router core dumps mined for auth tokens. Recovery FAILED, 21 candidates rejected |
| Credential Access / T1003.002 | Security Account Manager | `reg save` of SAM and SYSTEM into a web-served directory, hive return unproven (MODERATE) |
| Credential Access / T1555 | Credentials from Password Stores | Monitoring-platform stored device credentials, root group included, harvest unproven (MODERATE) |
| Credential Access / T1552.001 | Credentials In Files | Stolen configs grepped for `tacacs`, `radius`, `acs`, `cwmp`, `key 7`, `key 5` |
| Credential Access / T1552.004 | Private Keys | Operator-held SSH private key for the carrier jump host |
| Credential Access / T1110.003 | Password Spraying | 6 remote-management and 5 admin-share pairs; 52k-line `enable secret` list, no captured outcome (MODERATE) |
| Credential Access / T1212 | Exploitation for Credential Access | Application-server data-source `getConnection()` extraction (MODERATE) |
| Discovery / T1046 | Network Service Discovery | Port scanning from the internal foothold across six ranges |
| Discovery / T1018 | Remote System Discovery | `nbtstat`, `net view`, `Test-WSMan` scripted against the lateral target (MODERATE) |
| Discovery / T1016 | System Network Configuration Discovery | `ipconfig /all`; `route print` filtered for the carrier supernet, scripted (MODERATE) |
| Discovery / T1049 | System Network Connections Discovery | `netstat -an` filtered for listening sockets, scripted (MODERATE) |
| Discovery / T1082 | System Information Discovery | `whoami`, `hostname`; 19-path and 20-port probe of an internal host (MODERATE) |
| Discovery / T1087 | Account Discovery | `net user`; monitoring-platform user enumeration, both scripted (MODERATE) |
| Lateral Movement / T1021.004 | SSH | Key-based SSH to the carrier jump host through the local SOCKS listener, root level operator-side |
| Lateral Movement / T1021.006 | Windows Remote Management | `New-PSSession` spray built against the internal lateral target, no captured outcome (MODERATE) |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | Administrative-share fallback with five passwords, built, no captured outcome (MODERATE) |
| Lateral Movement / T1210 | Exploitation of Remote Services | Mapping-server RCE built internally, outcome unproven; T3/IIOP against the municipal host failed (MODERATE) |
| Collection / T1005 | Data from Local System | 356 MB firmware, 65 core dumps, 19 configs incl. `cwmp_inventory` (DEFINITE) |
| Collection / T1074.001 | Local Data Staging | Registry hives written to the web root; monitoring output to `/tmp`, both scripted (MODERATE) |
| Command and Control / T1071.001 | Web Protocols | HTTP collection listener on port 80; execution-proof beacon (DEFINITE) |
| Command and Control / T1105 | Ingress Tool Transfer | Carrier hosts GET the tunnelling and SSH clients from port 80 (DEFINITE) |
| Command and Control / T1572 | Protocol Tunneling | chisel reverse tunnel, four server key fingerprints captured |
| Command and Control / T1090.001 | Internal Proxy | SOCKS on `127.0.0.1:1080` plus two proxy-chain configs |
| Command and Control / T1571 | Non-Standard Port | 4445 reverse shell, 1389 LDAP callback, 8888 codebase, 19999 console |
| Command and Control / T1132.001 | Standard Encoding | `hello_from_ldap` serialized-String callback validation |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | 424,946,514 bytes over 100 PUTs, victim as HTTP client (DEFINITE) |
| Exfiltration / T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | WSMA `fileCopy` with an external `dstURL` pushes the files out |

</details>

---

## 12. Threat Actor Assessment
{: .hl-tier-2}

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-023 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports, it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

I cannot attribute this activity to a named threat actor, and the evidence does not support trying. I hold that at INSUFFICIENT confidence, around 15 percent that a currently catalogued named actor is responsible.

That rests on a negative I measured rather than assumed, which is a distinction worth making because the two look identical in a report and are not remotely the same thing. Zero infrastructure overlaps with any catalogued actor, established across three independent passes and five query types spanning two platforms. Zero code similarity, and here the reason matters. Three of the operator's own tools have never been submitted to the largest public malware corpus by anyone at all, which means there is nothing on the other side of the comparison to run. And zero external attribution, because no Tier-1, Tier-2 or Tier-3 source has published on this infrastructure at all.

What is missing is any of the four things that would open a route. There is no infrastructure or handler link to a tracked cluster, no operator-authored language artifact pointing anywhere other than Spanish, no code lineage to compare against, and no independent vendor reporting to weigh.

### 12.1 What I can say

The operator writes in Spanish across every artifact they authored themselves, works Ecuador-focused targets with one Mexican outlier, and operates as a solo effort or a very small one.

I assess an independent Spanish-speaking operator or very small team at MODERATE confidence, around 72 percent. Every comment, status string, error label and wordlist seed they wrote is Spanish, from `verificando contra hash` through to the credential-spray script matching success on both the Spanish and English confirmation words. Underneath that sits a single-VPS single-domain estate that six pivots failed to expand, and the complete absence of any group-scale infrastructure or tooling signature. What is missing is the ability to distinguish an independent operator from a hired one, because the evidence tells me who typed the commands and not who tasked them, and a contractor produces artifacts identical to a freelancer's. That one limitation is why this is 72 percent and not higher.

Team size sits at MODERATE, around 70 percent, and the picture is coherent rather than decisive. One server, one domain, one rented exit. A single consistent build environment across every observed service, matching the compiler toolchain used for the one native binary. One console design, one operational rhythm, no handoff conventions and no divergent coding styles between artifacts. But everything there is equally consistent with two or three people sharing a box and a style, and I have no artifact that separates those. A second operator working from different infrastructure would leave no trace in this corpus at all.

Regional base is the weakest of the three, and I hold it at LOW, around 65 percent for Latin America with Ecuador-proximate as the best available narrowing. The strongest leg is the uniform Spanish. Supporting it are the exclusive focus on Ecuadorian infrastructure, verified knowledge of a specific carrier back-office platform in that market, and an attack-source exit that terminates in Ecuador. None of those legs is what it looks like at first glance, though. Language identifies the working language and Spanish spans two continents, target geography identifies the target and not the operator, and the Ecuadorian exit is a commercial VPN anybody can rent, which is exactly what a competent operator elsewhere would use to appear local. The hosting jurisdiction is France and carries no information about the operator whatsoever, only about a rental decision.

### 12.2 The trap in this case, and it is a teaching-grade one

Two of the public tools in this corpus ship Chinese-language documentation. The behavioural shape of the campaign, meaning critical infrastructure and telecom, implant, persist, collect and pre-position, resembles documented Chinese state-aligned telecom activity. Put those two together and you have a story. It would be wrong.

Tool-documentation language is a property of the downloaded tool, **never of the operator**. Public Chinese vulnerability proofs of concept are used by everyone on earth, and the author of one of these tools maintains a set of public WebLogic exploit repositories that security researchers worldwide pull from. Leaning on that README is the single most common misattribution error with public offensive tooling, and here the operator's own authored artifacts cut against it hard, because every one of them is Spanish. Operator-authored language is materially stronger origin evidence than a downloaded tool's docs, and it is not close.

I went looking for the strongest possible version of the opposing case rather than waiting for someone else to raise it. The closest documented analogue anyone has surfaced is a China-nexus intrusion cluster that Cisco Talos documents targeting telecommunications providers in South America, which is the first China-nexus telecom cluster with a documented Latin American footprint. It fails every concrete test.

None of its documented implants appear anywhere in these 169 files. Ecuador is not among its victim countries. Its most recent published indicator predates this activity window by four months. And the operator language runs the opposite way.

On infrastructure I have to be more careful than I am on those four, because the primary indicator comparison never ran. The endpoint returned a query failure, and the substitute route I used instead returned zero overlap. What I can honestly say is that no overlap surfaced on the route that did work, not that the comparison came back clean. I record that as NOT CHECKED rather than as a negative, because a check that did not run is not a result, and quietly filing it as one is how a gap turns into a false reassurance.

I raised it specifically to try to break my own negative finding, and it strengthened it instead.

Two catalogue hazards are worth recording for anyone repeating this work. One threat-actor catalogue asserts that a China-nexus telecom actor is another name for a much larger group, while the vendor that originated the designation tracks them as distinct, so do not inherit that equivalence. And an alias chain runs from the South America cluster through a second group name to a synonym of a sanctioned telecom-targeting programme. Chained naively, that manufactures a story about that programme operating in South America. The catalogue's own text says the groups are not publicly established as identical. Alias-chaining across vendor clusters is not evidence.

Salt Typhoon, Volt Typhoon and Liminal Panda appear here as illustrative threat-class comparisons and nothing else. They are Tier-1 government-documented clusters, they demonstrate what sustained telecom and critical-infrastructure collection tradecraft looks like at the highest confidence available, and that context helps a reader calibrate what they are looking at here. None of their publicly documented targeting extends to Latin America in any source I located, and this operator shares zero infrastructure, zero tooling and zero indicators with any of them.

### 12.3 Capability is not attribution

I want to state this plainly once, because the findings in Section 10 pull hard in the wrong direction if it is left implicit.

The capability floor in this case is genuinely high. Building a four-mode LDAP exploitation harness with hand-written BER primitives, an own T3 client and credential tester, a persistent collection platform on a carrier's authentication server, and a custom multi-session console is not an unskilled operator's work. That raises the floor decisively and it selects between nothing. A skilled criminal access broker, a mid-tier contractor and a state programme's own personnel all produce artifacts that look like this, and a broker selling durable national-telecom access produces artifacts identical to a state operator's, because the access is the same access.

So sophistication is not sponsorship, and the question is answered by infrastructure and tasking links rather than by more reverse engineering. No such link exists today. More analysis of these samples will make the skill case stronger and will not move the sponsorship question a single point, and I am setting that expectation deliberately.

I cannot establish state sponsorship or direction, and I hold that at INSUFFICIENT, around 20 percent. The 20 is not zero, and I want the reason on the record. The activity really is espionage-shaped, and "state-aligned or state-contracted espionage-style operation" is a legitimate leading hypothesis for the **activity** even while the **operator** stays unattributed. Those two clauses belong in one sentence so nobody separates them. What keeps it at 20 is the total absence of a link plus three items of positive friction, since the WebLogic leg failed despite substantial effort, the own-infrastructure hygiene is poor enough that this whole case exists because of it, and the heavy exploits are downloaded public tools run byte-for-byte unmodified. I hold those three as friction rather than as a verdict, because contractors fail, disposable infrastructure is a real deniability posture, and public exploits are used across the entire tier range.

### 12.4 Motive

I assess espionage-flavoured intelligence collection as the stronger reading over access-brokering, at LOW confidence, roughly 60/40 rather than a settled call.

The discriminator doing the work is the signalling plane. Precisely scoped reconnaissance against SS7, SIGTRAN, Diameter, GTP and SMPP on a national carrier is an intelligence objective, giving interception, subscriber location and roaming visibility, and it is not a commodity an access broker packages and resells. Public reporting supports treating that depth as intelligence tradecraft independently and across several sources rather than one, including documented commercial surveillance campaigns built on exactly those protocol interactions. Around it sit a deep-and-narrow investment in one carrier's authentication plane rather than breadth across many victims, and the absence of any mass-credential or victim-count-maximisation play.

What is missing is the only thing that would settle it. The destination of the collected access was never observed, because the trail terminates at the operator's server, and an open directory caught mid-operation would not show a transfer made over an untraced session anyway. The bank probe also remains genuinely unexplained, for the reason I give in Section 7.6. I carry one honest counterweight too, which is that the monitoring-platform harvest was staged for fleet-wide stored-credential extraction, and that is a breadth play that fits a broker perfectly well.

Formal hypothesis testing on motive comes out close rather than clean, and the closeness belongs on the page. Espionage-flavoured collection carries one inconsistency against the broker hypothesis at three, with the two remaining hypotheses at five and four. That gap is thinner than the counts make it look, because two of the rows I added under stress-testing lean on absence of evidence in a corpus that is only an open-directory snapshot caught mid-operation, and the counterweight above it, the fleet-wide monitoring-platform harvest, I scored as discriminating nothing at all rather than quietly left out.

The lean survives on the quality of the evidence rather than on the count. The single inconsistency against espionage is the retail-bank probe, one concrete but ambiguous data point that reads as easily as a capacity test as an enumeration oracle. The inconsistencies against brokering rest on a pattern repeated across several independent sources rather than on any single artifact. One ambiguous data point against a repeated multi-source pattern is not a tie, and it is not a settled call either, which is why the confidence sits where it does.

The actor-type matrix is a separate question with a separate result, and I am not going to borrow its cleanliness for this one. There the independent Spanish-speaking operator hypothesis carries zero inconsistencies against a field of four, the nearest competitor carries three, and the Chinese-state-via-contractor hypothesis accumulates the most at five, which makes it unsupported rather than refuted. Every evidence row I added on that pass either supported the winner or damaged a competitor, which is precisely what did not happen on motive.

What would raise the motive confidence is a captured protocol-level interaction on the signalling plane rather than port scanning, something like a subscriber-information or interrogation request, which would tip intent-to-use over intent-to-prove-sellable. A marketplace listing referencing this victim set would tip it the other way, and I would welcome that equally, because either one resolves the question.

### 12.5 One thing can actually be done to this actor

The operator hard-coded a live third-party scanning-service API key into their own reconnaissance script. It is the only artifact in 169 files that is actionable against the actor rather than merely descriptive of them.

Every branch of reporting it is a win. Best case, the issuing vendor identifies the account holder, which is an attribution surface no analyst can reach and which survived the WHOIS privacy dead end. Worst case, the operator's reconnaissance capability is burned. And the third branch matters most for a reason that forced me to correct my own framing. I had written it up as the operator's own credential, which was an assumption. It may be stolen from a legitimate customer, in which case there is a third victim in this case who does not know their account is being used to scan Ecuadorian telecom infrastructure.

So the key is published only in truncated form, it must not be used by anyone reading this, and the disclosure describes it as a key observed in use by an actor conducting unauthorised scanning, leaving the vendor to determine whose it is. The vendor also holds the full query history behind that key, which would show targets that never appear in the scripted queries at all.

When an actor leaves a third-party API key in their tooling, that is not just an indicator. It is a lever, and the vendor is the one who can pull it.

---

## 13. Indicators of Compromise
{: .hl-tier-2}

The complete, validated, machine-readable indicator set lives in the companion feed, un-defanged and ready for ingestion.

**[Download the IOC feed](/ioc-feeds/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-iocs.json)**

It carries operator infrastructure, the full SHA256 set for the corpus, host-based artifacts across Linux and Windows, credential material observed in use, and network signatures, with per-indicator confidence and context. Indicators in the prose below are defanged. Indicators in the feed are not, because a parser needs the real value.

### 13.1 Operator infrastructure

| Type | Indicator | Confidence | Note |
|---|---|---|---|
| IPv4 | `13.140.145[.]210` | DEFINITE | Operator server, Contabo AS51167. Open directory closed 2026-08-04, host still answering on SSH 2026-08-16 |
| IPv4 | `95.214.114[.]37` | HIGH | Attack-source VPN exit, PacketHub AS136787. Attribution rests on the double-encoded path appearing byte-identically in the victim's own log |
| Domain | `radius-sync[.]com` | HIGH | Operator-registered 2026-07-11, Cloudflare-fronted, origin unmasked from the operator's own capture log, paid to 2029 |
| Port set | 22, 53, 80, 443, 1389, 4445, 8080, 8443, 8888 on the operator server | DEFINITE | Port 53 first seen 2026-08-10, purpose undetermined |
| Loopback service | `127.0.0.1:19999` | HIGH | Custom multi-session console, server side never archived |
| TLS certificate | Self-signed, subject and issuer naming the server's own address | DEFINITE | Generated 2026-07-24 12:50:23 UTC. Full SHA-256, SHA-1, serial and public-key hash in the feed |
| Tunnel keys | Four distinct server key fingerprints | DEFINITE | Pivot material rather than rule content, since they are not visible on the wire without interception |
| API key | Truncated to `H3yv3vx…bAvs` | DEFINITE present, MODERATE ownership | Live third-party scanning-service key. Do not use it. Report it |

### 13.2 The highest-value network signatures

The full set is in the [detection file](/hunting-detections/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-detections/). These four carry the case.

- An outbound HTTP `PUT` from a network device carrying `User-Agent: cisco-IOS` to a destination outside the management range. DEFINITE, and the operator cannot suppress it.
- A request path containing `%2577eb%2575i` or the full `%2577eb%2575i_%2577sma_Http`. DEFINITE, and the highest-specificity indicator in the case.
- A SOAP body carrying `urn:cisco:wsma-filesystem` with a `dstURL` whose scheme is `http://` and whose host sits outside the management range. HIGH, and it is the exfiltration primitive itself.
- An `Authorization` header matching `^[a-f0-9]{18}$` with no auth scheme against an IOS-XE web interface. HIGH, and deliberately generic across the whole public exploitation class rather than specific to this operator.

There is no conventional beacon in this campaign, which is worth knowing before anyone builds a sleep-interval or jitter profile and finds nothing. The reverse shell is interactive, the execution-proof beacon is a single request, and the tunnel is a persistent WebSocket rather than a polling implant. No domain-generation algorithm and no fronting beyond ordinary proxying of the operator's own domain.

### 13.3 What is deliberately not in the indicator set

This matters as much as what is, because three categories of address in this case will look like operator infrastructure to anyone who does not read the context.

Five addresses are explicitly not this operator. Crash traces on the victim router preserve activity from `140.99.223[.]46`, `147.124.203[.]51`, `62.133.46[.]18`, `146.70.52[.]222` and `47.130.108[.]237` between May and July 2026. All five used the generic public exploitation URI rather than this operator's distinctive double-encoded path. They are independent actors on the same victim device, they must not be folded into operator infrastructure, and their real evidentiary value runs the other way, since any future forensics on that router cannot assume a single intruder.

One address is retracted outright. The operator's domain pointed at `2.57.91[.]91` for roughly fifteen seconds at registration before being repointed. That is shared parking infrastructure at a large consumer registrar holding millions of domains, and its reputation score is mass-hosting noise. It is not an operator address and it should not be carried by anyone.

Two addresses must not be blocked. The current proxy addresses for the operator's domain are shared edge infrastructure. They are useful for resolution context and blocking them would take out unrelated traffic.

And victim addresses are victims. The router and firewall pair, the two carrier foothold hosts, the carrier AAA and monitoring servers, the municipal application host and the internal cadastre addresses all appear in the feed flagged as victim infrastructure specifically so nobody blocks or reports them as hostile.

---

## 14. Confidence, Gaps, and Calibration
{: .hl-tier-2}

### 14.1 Confidence Summary, findings organized by confidence level

| Level | Findings |
|---|---|
| **DEFINITE** | The router compromise and the 424,946,514-byte exfiltration on 2026-07-24 with the victim device as HTTP client. The double-encoded path and the forged 18-hex token as operator constants. The failure of the WebLogic leg, on three independent victim-side confirmations. The failure of the core-dump credential cracking, 21 candidates all rejected. The two Go binaries being the same unmodified public tool built twice. The rootkit originals-archive contents. The operator's TLS material and the four tunnel fingerprints |
| **HIGH** | The VPN exit as the operator's attack source. The domain as operator-owned. The internal carrier foothold. Rootkit intent and staging. Genuine telecom domain knowledge, on the signalling-plane port selection, the correct carrier terminology in the internal scan, and the back-office platform seeded in the wordlists. Deliberate pre-selection of the router victim. The monitoring-plane, mapping-server, hive-theft and credential-spray tooling as capability with named targets |
| **MODERATE** | Root access on the carrier AAA server, and root on the carrier jump host, since in both the reach is victim-side while the root session itself is operator-side inference. Rootkit install on a victim, capped because the replacements are unrecoverable. The specific host the rootkit targeted. Bank-probe intent. The collection-maintenance reading of the watchdog rewrite. The absence of prior public documentation for the file-copy exfiltration technique, held at MODERATE-HIGH as a negative-search result |
| **LOW to INSUFFICIENT** | Any named-actor attribution. Any state-sponsorship claim. Whether the credential-store attack succeeded. Whether the monitoring harvest ran. What happened to the collected data after it reached the operator's server |

### 14.2 Where I was wrong, and what changed

I would rather publish this than have somebody find it. Three red-team passes plus a fourth on the infrastructure phase ran against this investigation, and the corrections below are the ones that changed a claim rather than a wording.

The credential theft did not succeed, and I initially wrote that it had. My first read of the exfiltration log said it "literally lists which admin passwords they recovered." Wrong. The exfiltration succeeded, the cracking failed, 21 candidates all rejected and no token recovered. Data theft succeeded and password cracking failed, and both halves are the finding.

The error files do not show which gadget chains worked either. I called them a nice touch that told me which chains landed on the victim. They are local generation output, and whether any gadget reached the target is unproven from them.

Both of my errors leaned the same way, reading the operator's own artifacts as proof their attacks landed. That is the single-point-of-view trap, and the rule that came out of it now runs through the whole report. Separate "they ran this" from "it worked," and claim success only on victim-side results.

Nobody spent five months on that router. The 424 MB transfer was one day. The February-to-July span is the age of the stolen crash dumps as they sat on the device, a pre-existing cache grabbed in a single pass. That was a wording error rather than a judgment error, and it would have inflated the operator badly.

Root on the AAA server came down from HIGH to MODERATE once I separated victim-side reachability from an operator-side session claim.

The WebLogic target really was running WebLogic. Earlier readings that it ran a different application server, or that the operator had made a fingerprinting error, are withdrawn. The captured error pages are authentic vendor output and the target simply refused them, which makes it a defensive success rather than an operator mistake.

The WebLogic suite is adapted, not authored. I called it the operator's most capable original work, which repeated my own earlier mistake in a different place. The core technique is public and the same reflection block is copy-pasted byte-identically across seven files. Their genuinely original piece is the simpler T3 client.

The internal network map came from port scanning on a foothold, not from the WebLogic scanner suite. That is actually a stronger "they got inside" signal than the one I credited, arriving by a different mechanism, and the scanner suite's execution stays unproven.

The operator's sophistication did not grow over this campaign. My assessment grew as I read more of it. Everything in the corpus is contemporaneous July 2026 with no early-versus-late skill gradient anywhere, so there is no trajectory to point at. Writing it the other way invents a story the files do not carry, and I nearly did.

The corpus is 169 files, not 171. A filename-level pass read two duplicate captures as distinct until the hashes settled it.

The scanning API key may not be the operator's. I wrote it up as their own credential, which was an assumption rather than a finding, and correcting it turned a pure indicator into a possible third victim.

And the compromised customer is a printing company, not a telecom vendor. The lead that the best-evidenced victim might be a carrier contractor is dead, and killing it is what forced the objectives-versus-instruments framing that now carries this whole report.

One further claim failed against time rather than against evidence, and it belongs in a different category from everything above. I wrote that anything the operator placed on the router in July was, on the balance of the evidence, still resident on it, resting that on the device not having rebooted in roughly 310 days. The router has since stopped answering altogether, and every explanation for that which involves it restarting also clears a memory-resident implant. The claim was sound when written and is not sound now. The rule it leaves behind is to date any present-tense claim to its observation window when the claim depends on a state that can change without anybody telling me, which is exactly what a device uptime is.

### 14.3 What is missing

Some of these are recoverable and some are not, and the difference matters for anyone deciding whether to pull on a thread.

Five artifacts are simply absent. The command console's server side was never archived. The trojanised rootkit replacements were never exposed in the directory and are unrecoverable from both captures. A carrier-targeting script survives only as a name and one error line. An out-of-band exfiltration template is missing. And no packet capture exists, so everything network-side is reconstructed from the operator's own logs and captured responses.

Several questions stayed open without blocking anything. Where the operator's SSH private key and monitoring-platform credentials came from, since both were sourced by a step that never appears in the corpus. Whether the credential-store attack succeeded. Whether one declared file transfer failed.

What the unresolved wordlist acronym expands to, which a direct search against Ecuadorian telecom sources did not settle and which I will not guess. Who owns the captured SSL-VPN portal. Whether the 64 dumps not directly attributable to the operator trace to the other five intruders or to ordinary faults. And what the port 53 listener is for.

Four checks are recorded as NOT CHECKED rather than as negatives, because the distinction is the whole point of recording them. The primary indicator comparison against the disambiguation candidate in Section 12.2 never ran, and the substitute route that did run returned zero rather than confirming a clean negative. Tunnel-fingerprint reuse could not be searched, since no available platform accepts a chisel fingerprint as a search key. No live blocklist-feed check was run against either hosting network, so the not-bulletproof verdict rests on the absence of other positive indicators rather than on a clean feed result. And a version-string identification test on the captured VPN portal is blocked on paid-tier access this project does not hold.

Three ceilings are permanent and no further work removes them. The destination of the collected access was never observed, because the trail terminates at the operator's server, and that is what keeps motive at a lean rather than a conclusion. The corpus is a snapshot rather than an estate, and a service that appeared on the operator's server in early August, after both capture windows closed, is nowhere in these 169 files, so absence from the archive is not absence from the operation. And the missing artifacts above cap how far several capability claims can be taken, none of which changes a conclusion but each of which bounds one.

### 14.4 Disclosure

Affected parties, hosting providers and the vendor whose API key appears in the operator's tooling were notified on 2026-08-17, and the hosting provider carrying the collection server on 2026-08-29. A reply is victim-side evidence and outranks any inference in this report, so anything that comes back will be reflected here rather than argued with. Nothing has come back so far.

The infrastructure did change. Between 2026-08-30 and 2026-09-01 the collection server stopped answering on every port it had ever used and on ICMP, while the network path to it stayed clean all the way to the hosting provider's own edge, which is the shape of a machine that has been stopped rather than a route that has been withdrawn. The operator's VPN egress address stopped being routed at all in the same period. The registered domain that fronted the collection server now returns a gateway timeout from its own content-delivery layer, the response that layer gives when it cannot reach the origin behind it, though the registration itself is intact and has not lapsed.

I put it at HIGH that the provider notification is what took the collection server down, and I read this as a disrupted operation rather than a relocated one. Three things carry that. The provider is the one notified party with direct control over the machine. The host had been continuously observable for 83 days, from 2026-06-08 through 2026-08-30, which makes a coincidental disappearance inside the three days after the report an expensive thing to believe. And the operator was still actively developing on that host as late as 2026-08-22, staging a fresh set of payloads on it, which is not how somebody behaves days before walking away from a machine by choice.

The shape of the outage points the same way. The address stayed routed cleanly all the way to the provider's own network edge while the machine behind it stopped answering anything at all, including ICMP. That is what provider intervention looks like from outside, and it is not what an operator relocating their own infrastructure usually leaves behind, since they tend to keep the host and change what runs on it.

What keeps this below the top of the scale is that the provider has not replied and nobody has confirmed an action, so it rests on timing and shape rather than on a documented takedown. Timing alone never establishes cause. I am comfortable saying the reporting disrupted this operation and not comfortable calling it a confirmed suspension, and those are different claims.

---

## 15. References
{: .hl-tier-2}

Each source below carries the tier rating I assigned it while researching this case. Where a rating came out split, the entry sits at the lower of the two and says so. Several primary pages could not be retrieved directly, and those entries say that too rather than implying a clean primary read.

### 15.1 Tier 1, government advisories and vendor product documentation

- Cisco, Security Advisory `cisco-sa-iosxe-webui-privesc-j22SaA4z`, covering CVE-2023-20198 and CVE-2023-20273. Retrieved directly, and the primary description of the privilege-escalation and command-injection pair, at CVSS Base 10.0 on the vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, CWE-420 and CWE-78, Cisco bug ID CSCwh87343, advisory version 2.6 Final, first published 2023-10-16 and last updated 2023-11-01. It carries the implant-detection check that POSTs to `/webui/logoutconfirm.html?logon_hash=1` and looks for an 18-character hexadecimal string in the response, and its worked-example token `0123456789abcdef01` is what grounds the class-artifact reading of this operator's own literal in Section 6.3. The earlier HTTP 403 on this page was user-agent filtering rather than a paywall or a removal.
- Cisco, Web Services Management Agent Configuration Guide, IOS releases 12.4T through 15SY. The vendor documentation establishing the filesystem service and its `fileCopy` operation as legitimate, officially documented functionality, which is what the exfiltration-primitive finding in Section 6.3 rests on.
- Cisco, security advisory `cisco-sa-20190717-wsma-info.html`. The only prior WSMA information-disclosure advisory I found, covering a different product line and a different vulnerability. This one returned HTTP 403 and was not re-fetched, so it is the single Cisco entry here that is not a direct primary read.
- CISA, Known Exploited Vulnerabilities catalog, release 2026.08.17, 1,666 entries, pulled directly as `known_exploited_vulnerabilities.json`. Every exploitation vulnerability in this campaign is listed in it, with CVE-2023-20198 added 2023-10-16, CVE-2023-20273 added 2023-10-23, CVE-2023-21839 added 2023-05-01, CVE-2020-14882 added 2021-11-03, CVE-2024-36401 added 2024-07-15, and CVE-2024-21182 added 2026-06-01 with a federal remediation deadline of 2026-06-04. Neither Dirty Frag vulnerability appears in that release, which is the negative Section 10.3 rests on.
- CISA, Known Exploited Vulnerabilities catalog, CVE-2026-31431 ("Copy Fail") added 2026-05-01 with a deadline of 2026-05-15. This is the sibling Linux kernel flaw, and Section 10.3 cites it to establish that it is not the pair this operator staged. Its dates are carried through secondary reporting that quotes the catalog rather than from my own read of that entry.
- NIST National Vulnerability Database, queried directly through the NVD REST API. CVE-2026-43500 carries a primary NVD score of 7.8 HIGH on the vector `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, published 2026-05-11, in the rxrpc subsystem. CVE-2026-43284 carries no primary NVD score at all, published 2026-05-08, in the xfrm/esp subsystem, with three numbering authorities scoring it separately at 8.8 and twice at 7.8 on differing vectors. This record resolves the scoring discrepancy reported in Section 10.3, and it is also what establishes that only the xfrm/esp half matches the mechanism this operator's exploit leads with.
- CISA, Alert AA25-266A, documenting the United States federal agency intrusion that began through CVE-2024-36401 on 2024-07-11.
- CISA, NSA and FBI, Joint Cybersecurity Advisory AA24-038A on Volt Typhoon pre-positioning against United States critical infrastructure. I cite this in Section 12.2 as an illustrative threat-class comparison and nothing more.
- United States Department of the Treasury, Office of Foreign Assets Control, January 2025 designation of Sichuan Juxinhe Network Technology, connecting Salt Typhoon infrastructure to China's Ministry of State Security. Also an illustrative comparison only, and reached through secondary reporting of the sanctions action rather than through the primary notice.

### 15.2 Tier 2, vendor research and named technical reporting

- OPSWAT, "CVE-2023-20198 & CVE-2023-20273: From Unauthenticated Web Request to Root on IOS XE". The technical walkthrough of double-URL-encoding a request path to reach the internal `webui_wsma_https` endpoint, and the closest public analogue to the bypass in Section 6.3. OPSWAT also corroborates the GeoServer advisory below.
- VulnCheck, corroborated by the Knownsec 404 team. Independent confirmation that nginx and IOSd decode the request path separately, which is the mechanical basis of the whole bypass class. VulnCheck's implant-scanner documentation and Fox-IT's `cisco-ios-xe-implant-detection` repository are the two public scanners built around the generic implant URI.
- Cisco Talos, "UAT-9244 targets South American telecommunication providers with three new malware implants", https://blog.talosintelligence.com/uat-9244/ (March 2026). The China-nexus cluster used in Section 12.2 as the strongest opposing hypothesis, with the TernDoor, PeerTime and BruteEntry implants and the South American telecommunications victimology. Cited as a threat-class comparison only, never as attribution.
- Cisco Talos, "Active exploitation of Cisco IOS XE Software". Three evolving implant variants between October and November 2023, each adding an evasion check, all sharing the same underlying command-execution logic.
- Oracle, corroborated by Qualys ThreatPROTECT and CVE Details. CVE-2023-21839, the `ForeignOpaqueReference.getReferent()` JNDI injection reachable over T3 and IIOP. I rated this Tier 1/2 and list it here at the lower of the two.
- SentinelOne vulnerability database. Its CVE-2024-21182 entry documents the `AggregatableOpaqueReference` patch bypass down to the class names I read out of the operator's own reflection block in Section 10.1. SentinelOne also carries the CVE-2020-14882 and CVE-2024-36401 entries drawn on here.
- `4ra1n/CVE-2023-21839` and `houqe/POC_CVE-2023-21839` on GitHub, corroborated by SentinelOne and AttackerKB. The two public proofs of concept in circulation, one of which the operator's compiled Go binary runs unmodified. GreyNoise Labs separately built emulation tooling for the same vulnerability.
- The GeoServer project's vulnerability advisory for CVE-2024-36401, the `commons-jxpath` XPath evaluation flaw affecting every default install prior to 2.22.6, 2.23.6, 2.24.4 and 2.25.2. Corroborated by OPSWAT, Keysight and SentinelOne. I rated this Tier 1/2 and list it here at the lower of the two.
- Fortinet FortiGuard Labs. Exploitation telemetry for CVE-2024-36401 against IT service providers in India, technology companies in the United States, government entities in Belgium, and telecommunications companies in Thailand and Brazil.
- Wiz, corroborated by Tenable, Sysdig, Red Hat (RHSB-2026-003), AlmaLinux, Ubuntu and CloudLinux. The "Dirty Frag" analysis establishing the CVE-2026-43284 and CVE-2026-43500 split, the 2026-05-07/08 disclosure, the attribution to researcher Hyunwoo Kim, and the public proof of concept at `github.com/V4bel/dirtyfrag`. It is the subsystem split rather than the scores that this entry carries, since the two are separate bugs in xfrm/esp and rxrpc respectively.
- Tenable, Dirty Frag FAQ. It states CVSS 7.8 for CVE-2026-43284 with CVE-2026-43500 undocumented at the time it was written, while a separate aggregation suggested 8.8 and 7.8. The NVD record listed above resolves that disagreement, so Section 10.3 now carries the resolved form rather than declining to publish a figure.
- Microsoft, "Active attack: Dirty Frag Linux vulnerability expands post-compromise risk", published 2026-05-08 and updated 2026-05-14. The documented in-the-wild sequence of SSH access, a staged ELF binary, then escalation through `su`, which is the pattern behind the staging comparison in Section 10.3. Sysdig, SafeBreach and Help Net Security corroborate the separate Copy Fail catalog action.
- CrowdStrike, "Unveiling LIMINAL PANDA". I cite this in Section 12.2 as an illustrative threat-class comparison only. CrowdStrike scopes the actor's targeting to Asia and Africa, and no source I found places it in Latin America.
- The Citizen Lab, University of Toronto, "Bad Connection". Two commercial surveillance campaigns combining SS7 location queries, Diameter manipulation and a SIMjacker-style zero-click SMS technique, which is the public basis for treating signalling-plane access as an intelligence objective rather than a routine compromise outcome. Rated Tier 2/3.
- CloudSEK, "Operation Escaneo". A financially motivated Latin American campaign with secondary Ecuador activity, sharing no infrastructure, hash or hosting overlap with this operator. I cite it only to establish that the same regional footprint draws criminal activity as well as potential state-aligned activity. Rated Tier 2/3.

### 15.3 Tier 3, trade press, security journalism and public repositories

- SEC Consult, "TR-069: IoT Before It Was Cool!". The provisioning-protocol exposure history behind the carrier-managed customer-premises argument in Section 4.1, corroborated by independent technical summaries of the protocol and by retrospectives on the November 2016 Deutsche Telekom incident.
- Netcracker Technology press release of 2025-03-26, corroborated by BusinessWire, SDxCentral and Developing Telecoms, on the extension of its full-stack BSS partnership with the carrier in this market. That partnership is what makes the `netcraker` wordlist seed in Section 10.5 genuine carrier knowledge rather than a guess. Developing Telecoms is also the June 2025 source for that carrier's pending divestment of its Ecuadorian mobile unit, which had not closed as of the most recent reporting I found. The sources name the parties; this report does not, since the carrier and its customer are victims here and naming them adds nothing a defender can act on.
- The Hacker News, June 2026, reporting the CVE-2024-21182 catalog addition and noting that no public reports describe how the vulnerability is being exploited and that no threat actor is named in connection with it. The `dinosn/CVE-2024-21182` repository documentation is the source for the vulhub 12.2.1.3 container being the standard, publicly recommended build workaround rather than operator ingenuity.

### 15.4 What could not be retrieved

Two retrieval limits are worth stating rather than papering over, because each one changes how much weight a claim above can carry. A third closed on a later verification pass, and that is worth recording too, since it moved several figures in this report from secondary to primary.

The closed one covers the Cisco advisory, the CISA catalog and the NVD scoring records, all three retrieved directly on 2026-08-18. The CVSS figures, the CWE identifiers, the Cisco bug ID, the catalog dates, the subsystem split across the Dirty Frag pair and the worked-example token are now primary reads rather than quotations of somebody else's read. The earlier HTTP 403 on the Cisco page turned out to be user-agent filtering rather than a paywall or a removal. The 2019 WSMA advisory was not re-fetched and stays the one Cisco entry here carried through secondary reporting.

The GSMA T-ISAC blog on the SS7 threat landscape returned HTTP 403 and could not be read at all. Nothing in this report rests on it, and its content is not represented here beyond what other sources independently corroborate.

A public statement by a CISA official on SS7 and Diameter abuse, a December 2024 United States Senate disclosure naming states exploiting SS7, and reporting on an APT28 campaign that names Ecuadorian military entities are all carried through secondary aggregation. I did not independently retrieve the underlying primary statements, which is why none of them carries weight above landscape context in Section 12.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
