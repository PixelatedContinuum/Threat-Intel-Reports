---
title: "A Prepared Intruder Inside a Pakistani University, With an ESXi Path Staged"
date: '2026-11-17'
layout: post
permalink: /reports/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116/
hide: true
unlisted: true
sitemap: false
preview_cover_label: "AD Intrusion"   # preview only: header cover while the catalog entry is parked; drop at go-live
preview_severity: high
category: "Active Directory Intrusion"
description: "An operator ran Sliver and Metasploit sessions on four servers of a Pakistani university, read its whole directory through one valid account, held 328,942 rows of the university's records and staged a public VMware ESXi exploit with scanners aimed at the university's own range."
detection_page: /hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
ioc_feed: /ioc-feeds/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "169[.]58[.]165[.]63"
    note: "Operator server on Contabo: Sliver C2 on 31337 and 8000, Meterpreter callbacks, open-directory toolkit"
  - value: "cytomate[.]xyz"
    note: "Front domain registered 2026-09-12; its Cloudflare Origin Certificate sits on the operator server"
  - value: "59eb3f044d9d2811c2664e9cd86bc7d1d39042978125bf043394647c7d343539"
    note: "Sliver mTLS CA certificate shared by five of the eight builds (SHA-256)"
  - value: "bd1a14378f3b067f36808098b4571bede03e40545e4eb237f9cfdef345a5b01d"
    note: "sp.exe, plain Sliver build named spweb1, mTLS to port 31337 (SHA-256)"
  - value: "0d65479e7522efaa1ee8c83b87e86298f70305b0ae10d5f3865f1366ef683be6"
    note: "esxi_implant, garbled Linux Sliver build, HTTPS to port 8000 (SHA-256)"
figure_nav:
  - image: opendirectory-169-58-165-63-university-intrusion-chain.svg
    parts:
      - label: "Operator server prepared"
        anchor: "#10-infrastructure"
      - label: "Four Windows footholds"
        anchor: "#5-the-attack-chain"
      - label: "Credentials collected"
        anchor: "#93-credential-and-directory-tooling"
      - label: "Directory read through one account"
        anchor: "#93-credential-and-directory-tooling"
      - label: "University records, held"
        anchor: "#3-victims-who-was-hit-and-how-far-the-operator-got"
      - label: "Tool staging, internal association"
        anchor: "#7-working-from-inside-the-perimeter"
      - label: "ESXi path"
        anchor: "#6-the-esxi-path-staged-and-aimed-not-shown-used"
---

**Campaign Identifier:** OpenDirectory-Sliver-AD-Intrusion-169[.]58[.]165[.]63<br>
**Last Updated:** November 17, 2026<br>
**Threat Level:** HIGH

> **Risk vs. Campaign Threat Level:** The toolkit itself scores MEDIUM, 6.1 out of 10, because almost all of it is public tooling that existing detections already see (Section 2). The campaign is HIGH because of where it sat: authenticated access inside a university's network, its whole directory read, 328,942 rows of the university's records on the operator's server, and an ESXi attack path staged against the university's own address range while the server was still running on 16 November 2026.

---

## 1. Executive Summary
{: .hl-tier-1}
{: .hl-tab-overview}

An operator I cannot name worked inside a Pakistani university's Windows estate in early November 2026, and the way it did so is the lesson. It ran commands on four of the university's servers through Metasploit sessions (Metasploit is an attack framework security testers also use), captured a local administrator's network logon responses as they crossed the wire, saved registry hives, read the university's entire Active Directory through one valid account, and then staged its next move against the virtualisation layer: a public exploit for VMware ESXi and scanners set to the university's own address range. What lets a defender find this operator is the shape of the work, and a server identity that the builds and stagers point back to: one certificate authority (the signing root that vouches for a server's identity) inside its Sliver implants (Sliver is an open-source command-and-control framework), a front domain (a public-facing name that stands in front of the real server) that borrows a security vendor's name, and a single address. I found no prior public reporting on this host, front or campaign in the search forms I could verify.

- This was a prepared intrusion. Three of the eight Sliver implants carry names the operator chose for the hosts they were meant for, the scanners shipped already pointed at the university's range, and the tools were staged in order over three days. My read is that the operator arrived ready to do a specific job and was doing it.
- The operator worked from inside the perimeter. Tools were requested from the operator's server by an address registered to the university's own research network, and one implant was built to call a parent inside the university rather than the internet. Most monitoring watches the edge for outside threats, and this operator was positioned not to look like one.
- The university's records were in the operator's hands. The server held 328,942 rows from five university tables (rows, not people), covering admissions, alumni, degrees and staff records. When and by what route those rows reached the server is not shown.
- The virtualisation layer looks like the next target. The operator staged a public exploit for an ESXi flaw from 2021, with scanners aimed at the university's range, but nothing I hold shows it fired at any host. My own read, set out with what leaves it open in Section 14, is that this has the shape of the extortion operations hitting universities this year.
- The operator's side was still running at the latest observation, on 16 November 2026: new listeners opened, new files were served the day before, and a poller kept writing its log.
- The first move for any organisation is to look inside the network: for internal hosts that reached the operator's server, for one ordinary account reading the whole directory, and for hypervisors whose SLP service is reachable from the internal network.

From here I grade how far the operator got on each part of the university's estate, walk the attack chain, take the toolkit apart, and give the indicators and 23 detection rules a defender can use now. No named actor is tied to this operator, and I hold no victim-side telemetry, so everything here comes from the operator's own files and server.

## 2. Business Risk Assessment
{: .hl-tier-1}
{: .hl-tab-overview}

For an organisation outside this case, the risk sits less in this operator's tools than in where it chose to stand.

An intruder inside the perimeter is harder to see than one outside it. Controls tuned to catch connections from unfamiliar hosting providers do not see an internal address fetching tools as foreign, which is the position this operator took (Section 7).

One ordinary account opened the whole directory. A single domain account with no privileged membership shown was enough to read the user, group and computer objects, 14,038 user rows in all. A directory read of that size is the map an intruder uses to pick the next target, and it needed no administrator rights at all.

Personal records on an outside server are leverage whoever holds them. The operator's server held 328,942 rows of the university's admissions, alumni, degree and staff records. I cannot show when or how those rows were collected, so I do not treat this as a breach of record in this intrusion. For the people in those tables the exposure exists either way.

The virtualisation layer is a single point of failure. The operator staged a public exploit for an ESXi flaw that has been fixed since 2021, with scanners that look for the port it attacks across the university's range. An attack that lands on a hypervisor can reach the virtual servers running on it at once. Nothing I hold shows the exploit fired, so this is a staged capability.

The scores below rate the toolkit's technical risk to a defender.

| Risk dimension | Score | Rationale |
|---|---|---|
| Data exposure | 7/10 | 328,942 rows of the university's records and 4,739 application login pairs held on the operator server; how they got there is not shown |
| System compromise | 7/10 | Commands run on four servers through Metasploit sessions and the whole directory read through one account; no domain-admin session shown |
| Persistence difficulty | 4/10 | No persistence shown on any host; a pivot implant and two PowerShell command loops staged |
| Evasion capability | 6/10 | Five garble-obfuscated Sliver builds, encoded PowerShell, a front domain and an implant that only talks inside the network |
| Lateral movement | 7/10 | Chisel tunnels, a Sliver TCP pivot build, pass-the-hash tooling, ARP-spoofing launchers and the ESXi exploit staged; none shown used |
| Detection challenge | 5/10 | Public tools with public signatures, offset by garbled builds that hide their strings and an inside address that does not look foreign |

Weighted 20, 20, 15, 15, 15 and 15 percent, I score the toolkit's overall technical risk at 6.1 out of 10, MEDIUM. The campaign is HIGH for what it reached and what it was preparing. I hold no victim-side telemetry, so none of these scores is confirmed from the university's own logs.

## 3. Victims: Who Was Hit and How Far the Operator Got
{: .hl-tier-2}
{: .hl-tab-victims}

There is one victim organisation in this case, a Pakistani university I call V-01 and do not name. As an organisation it is graded ACCESS SHOWN. The table below breaks it into the parts of its estate the operator's files touch, one row per part, so a defender can see where the evidence is strong and where it is thin. Where two grades fit a row I record the lower one, and nothing is upgraded on inference.

The four grades mean different things. ACCESS SHOWN means host-side evidence: output of a command the operator ran on the victim's own system. COMPROMISED means the operator holds material that only working access returns, but the route that produced it is not in any file I hold. REACHED means the operator touched the system and got a response without access beyond that. LISTED means the system is named in the operator's tooling and nothing more.

Of the 7 rows, the grades are 1 ACCESS SHOWN, 3 COMPROMISED, 1 REACHED and 2 LISTED.

| Organisation | Grade | What the operator's files show | Latest dated evidence |
|---|---|---|---|
| V-01, four of its application and web servers, none of them a directory computer | ACCESS SHOWN | Output of the same encoded user, session and saved-credential survey from all four within 8 minutes; registry hives saved from three; six NTLMv2 logon captures from one server's local Administrator; a further session whose host is not identified returned a failed directory query | 2026-11-05, host output (16:01:32 on the last host's own clock) |
| V-01, its domain controller | COMPROMISED | An authenticated LDAP bind returned 14,038 user rows, 59 groups and 4 computer accounts; no command output from the controller itself, no controller hive and no domain database | No dated evidence held |
| V-01, one domain account | COMPROMISED | Its bind returned the whole directory; no privileged membership shown, delegated rights not checked; the same credential sits among 4,739 application login pairs the operator holds | No dated evidence held |
| V-01, the systems holding its admissions, alumni, degree and staff tables (not identified) | COMPROMISED, route not shown | Five table files of 328,942 rows on the operator server; when, from where and by what route they were collected is not shown | Present at the 2026-11-14 recapture of the operator server |
| V-01, directory accounts touched by the spray and the AS-REP probe | REACHED | 3,804 distinct names marked accepted by a one-password spray, of which one is validated and six match directory accounts exactly; 110 AS-REP probes, none roastable; the built-in Administrator answered by the KDC with no password result held | No dated evidence held |
| V-01, internal hosts and sessions named in the tooling with no reply held | LISTED | 22 distinct internal addresses across the bettercap launchers (20 of them in the looping launcher's fixed list), the scanners' default range, the pivot implant's parent address, two sessions with no output, five database login tuples | No dated evidence held |
| V-01, ESXi or vCenter hosts the VMware tooling targets | LISTED | Exploit and scanners staged; no host named, no scan output, no reply | Exploit first served 2026-11-07 (operator server clock) |

The spray row needs care, because the operator's own output overstates it. Its spray log marks 3,805 lines as successes, and an operator file calls them valid credentials. They are not 3,805 accounts. Only 6 of the 3,804 distinct names match an account in the directory the operator itself dumped, and only one credential is shown to work, by its LDAP bind output.

The controller's Guest account is enabled with no password required. I read the acceptances as a guest-session mapping at MODERATE, which is an explanation rather than an observed mechanism. A university resetting 3,804 accounts on the strength of that log would be acting on the operator's mistake.

Whether access continues is unknown. The latest host output is from 2026-11-05. The latest event tied to the university's network is the run of tool requests on 2026-11-07 and 11-08 from the address registered to its research network (Section 7), which shows delivery to that address and not execution. The operator's server was still running on 2026-11-16, and nothing I hold says whether any implant was beaconing from inside V-01 then.

A second directory on the same server, on port 8091, listed 157 further file names in October whose bytes were never obtainable. A few of those names hint at other organisations. Their relation to V-01, to this operator and to any other victim is unresolved, and I hold that reading at LOW, so there is no second victim row.

## 4. Technical Classification: A Sliver and Metasploit Toolkit Built From Public Parts
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's capability is a Sliver command-and-control setup with Metasploit stagers beside it, wrapped around public credential and directory tooling and driven by short operator-written scripts. There is no new malware family here. What the operator brought was assembly: eight Sliver implants built from one server configuration, six Meterpreter-style stagers (small first-stage programs that fetch the real payload), three stock Chisel tunnel builds, two PowerShell command loops, Impacket-based directory and spray tools, Inveigh and bettercap for the local network, and a public VMware ESXi exploit. A NimPlant server banner appeared on the same host on 16 November, though no NimPlant implant is in the corpus.

The case corpus is the operator's own open directory, captured on 14 and 16 November 2026. It lists 393 file entries across its port roots. I hold and triaged 211 of them, which resolve to 195 distinct files. Another 165 were listed with a hash but no bytes could be obtained, and 17 are known by name only. Everything below comes from the 195 held files and the listings, read statically; nothing was executed.

The Sliver call is DEFINITE for the three plain builds, whose Sliver protobuf packages sit in the clear, and HIGH for the five garble-obfuscated builds (garble is a Go obfuscator that renames code and encrypts its strings). Those five hide their package names and strings, so the call rests on protobuf accessor names garble cannot rename, the mTLS and yamux transport keywords, and the same certificate authority and signing key recovered from inside them. The garbled builds show the operator went one step past Sliver's defaults. The rest of the configuration did not: the plain builds carry Sliver's stock module-root rewrite, and three of the five garbled builds carry Sliver's own random default names.

| Component | Count | Role in this case |
|---|---|---|
| Sliver implants | 8 (7 Windows, 1 Linux; 5 garbled) | Seven dial the operator server directly; one is a pivot that dials a parent inside the university |
| Meterpreter-style stagers | 6 | All six call back to the operator server, on five ports |
| Chisel | 3 stock upstream builds | Tunnelling, staged; no server address embedded |
| PowerShell loops | 2 | An HTTP tasking poll and a raw TCP shell, both hard-coded to the operator server |
| Credential and directory tools | Impacket scripts, Inveigh, bettercap, Invoke-SMBExec | Directory reads, a spray, LAN capture and staged pass-the-hash |
| VMware tooling | 1 exploit, 6 scanners | A port of the public CVE-2021-21974 exploit and scanners aimed at the university's range |

## 5. The Attack Chain
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's work runs as one chain from a prepared server to a foothold, through credential collection and a full directory read, and on to staging tools for a wider spread and the virtualisation layer. The chain is built from the university's own servers and the operator's server logs. What it cannot show is how the first session came to exist: initial access is not identified, because no web, VPN or authentication log of the university's is in the corpus.

| Stage | What the operator did | Where it is shown |
|---|---|---|
| 1. Prepare the server | Ran SSH on the server from 13 August and a Sliver listener from 19 August 2026; registered the `cytomate[.]xyz` front on 12 September and put its Cloudflare Origin Certificate on the server; Linux Sliver builds dialling the front and the server appear in public sandboxes from 29 September; an Inveigh capture poller started on the server on 5 November | Domain registration, certificate transparency and the certificate served by the host; public sandbox submissions; the poller's own log |
| 2. Hold a foothold | Ran Metasploit sessions on four of the university's servers by 5 November; one session script removes an earlier operator file from a web application's public images folder, which hints at an earlier placement (MODERATE) | The session resource scripts and their returned output |
| 3. Survey the hosts | Ran one encoded survey of users, sessions, saved credentials and Remote Desktop history on all four servers inside 8 minutes; hunted configuration files for secrets and dumped scheduled tasks on two | The four returned survey outputs; the hunt scripts, whose outputs are not held |
| 4. Collect credentials | Ran Inveigh on one server and captured six NTLMv2 responses from another server's local Administrator in 1 h 33 m 54 s; saved SAM, SYSTEM and SECURITY hives from three servers and downloaded one full set | The capture file and poll log; the six hive files held |
| 5. Read and test the directory | Bound to the directory as one valid account and read 14,038 user rows, 59 groups and 4 computers; ran an AS-REP probe (0 roastable), a Kerberoast query (no service accounts), a one-password spray and an administrative-share test (0 of 3,805 pairs) | The directory exports and the operator's logs of each run |
| 6. Stage the spread | From 7 November served scanners, bettercap launchers and a packet-capture driver set, which an address registered to the university's research network requested; then Sliver builds, Chisel and the pivot implant (8 and 9 November), pass-the-hash tooling (13 November) and two more stagers (15 November) | The operator server's HTTP log and first-served times |
| 7. Aim at the virtualisation layer | Staged a port of the public CVE-2021-21974 ESXi exploit, scanners defaulting to the university's address range and a Linux Sliver build; no scan output, exploit reply or ESXi session is held | The exploit and scanner scripts and their first-served times |

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116/opendirectory-169-58-165-63-university-intrusion-chain.svg" | relative_url }}" alt="Vertical seven-step chain on a dark background titled Operator Server to University Chain, with the caveat that initial access is not identified and no victim-side telemetry is held. Step 1, orange, SHOWN: the operator server at 169[.]58[.]165[.]63 on Contabo, SSH from 13 August and Sliver from 19 August, Sliver on ports 31337 and 8000, stager ports 4444, 4446, 4447 and 5555, eight Sliver builds, six stagers and a front domain behind Cloudflare. Step 2, red, SHOWN: Metasploit sessions on four servers by 5 November, the same encoded survey on all four inside 8 minutes, initial access not identified. Step 3, red, SHOWN: six NTLMv2 responses captured in 1 h 33 m 54 s, SAM, SYSTEM and SECURITY hives from three servers, no domain-admin credential held. Step 4, red, SHOWN: one valid account read 14,038 user rows, 59 groups and 4 computer accounts; AS-REP probe 0 roastable, Kerberoast no entries, share test 0 of 3,805 pairs. Step 5, yellow, off the chain with no arrow: 328,942 rows from five university tables held on the operator's server, when and how taken not shown. Step 6, yellow, dashed border, STAGED: 105 requests (103 answered) for 41 distinct files from an address in a block registered to the university's research network, a network association only, plus a pivot build configured to dial an internal parent on TCP 9898 with no listener shown. Step 7, deep red, dashed border, STAGED, NOT SHOWN USED: a port of the public CVE-2021-21974 exploit, six scanners and a Linux Sliver build, with no scan output, exploit reply or ESXi session held. A footer lists three hunt starting points.">
  <figcaption><em>Figure 1: The chain from the operator's server to the university, drawn so that solid borders mark what the operator's own output shows and dashed borders mark what was only staged. The university's records sit beside the chain with no arrow, because this report does not show when or how they reached the server.</em></figcaption>
</figure>

Read top to bottom, this is a competent, ordered intrusion that leaned on what Active Directory gives any authenticated user. Every step beyond stage 5 is staged rather than shown run: the spread tooling was delivered, the ESXi path was prepared, and the corpus holds no output from either. That is the line between what this operator did and what it was getting ready to do, and I keep to it through the rest of the report.

## 6. The ESXi Path: Staged and Aimed, Not Shown Used
{: .hl-tier-2}
{: .hl-tab-chain}

This is the part of the case that struck me most. Attacks on VMware ESXi have been around for years, and I think they still get far less attention as a risk than they deserve, and here is an operator inside a university with a full set of tooling for the hypervisor layer, aimed and staged. The evidence supports something narrower than a purpose-built hypervisor weapon, and I want to be exact about it: the weapon is public, the aim is tailored, and nothing I hold shows it fired.

The exploit, `cve.py`, is a port of the public exploit for CVE-2021-21974, a heap overflow in the OpenSLP service of ESXi 6.7, with offsets for one ESXi build. It takes its target on the command line, and its payload turns the ESXi firewall off and opens a listener. The flaw dates from 2021 and its exploit is public. In February 2023 it was reported as a likely vector of the ESXiArgs ransomware wave: an updated CERT-FR advisory, as TechTarget reported it, said the attackers appeared to have targeted ESXi's SLP service through flaws including this one, which was never presented as confirmed. That history fits an operator with a destructive or extortion end state, and it proves no link to this operator.

What is tailored is the aim. The operator's VMware scanners default to the university's own address range: one looks for the SLP port the exploit attacks, one for vCenter's ports, and one labels any host with that SLP port open as ESXi. The Linux implant the operator named `esxi_implant` is a garbled Sliver build that calls the operator server over HTTPS on port 8000. Nothing in its bytes names ESXi or VMware, so it is a generic Linux implant whose file name suggests the target (MODERATE).

The timing shows intent rather than use. The operator's own first fetch of `cve.py` is the first line of its server log, at 18:26:36 on 7 November (server clock, about UTC+1). Eighteen seconds later the address registered to the university's research network requested `cve.py`, a Python runtime and the two VMware scanners (Section 7). `esxi_implant` was first served at 04:51:42 on 9 November. The corpus holds no scan output, no host name, no exploit reply and no ESXi session, so scanning, exploitation and contact with an actual ESXi or vCenter host are all NOT CHECKED rather than attempts shown.

For a defender the point stands without the attempt. An operator who has read the directory and holds Windows footholds, and then stages a hypervisor exploit with scanners set to the local range, is preparing the one move that takes the virtual servers on a host down together. ESXi hosts with the SLP service reachable from the internal network are the exposure this case points at.

## 7. Working From Inside the Perimeter
{: .hl-tier-2}
{: .hl-tab-chain}

The second thing that stood out to me is where the operator positioned itself. Two separate facts sit under it, and I keep them separate because neither alone shows a persistent internal foothold.

The first is the tool requests. Between 18:26:54 on 7 November and 19:59:07 on 8 November (server clock), one client made 105 requests to the operator's file server, 103 of them answered, for 41 distinct files: the VMware scanners and exploit, the bettercap launchers and the packet-capture driver set. Its address sits in a block the regional internet registry records as registered to the university's research network. Its first request came 18 seconds after the operator's own loopback fetch of the exploit.

Which device sent those requests, and who operated it, is not shown: a compromised university machine, an insider, an authorised tester and a shared network exit all fit. The requests show delivery to that address, not execution. In the log I hold, that client fetched no Sliver build, Chisel build or stager, though one port of the server has no access log at all.

The second is the pivot implant. `spadc1.exe` is a plain Sliver build of the pivot type. It does not call the operator server at all. It dials a parent implant on an internal university address on TCP port 9898, the port Sliver's own documentation uses in its pivot example, and only works where an upstream implant of the same server is listening there. No such listener is shown, so the parent address is LISTED.

My read is that both fit an operator trying to look like part of the inside. I have seen this pattern a fair amount in my own cases: an intruder gets in and then works from an internal host, and most security teams and tools are watching the perimeter for outside threats, and an internal machine fetching tools or an internal port relaying implant traffic does not look like one. It is a good way to hide and to confuse an investigation. What I cannot show here is that the operator held a lasting internal position. For a defender the hunt is concrete: internal hosts that reached `169[.]58[.]165[.]63` on ports 8444 or 9002, and internal hosts listening on TCP 9898.

## 8. Timeline
{: .hl-tier-2}
{: .hl-tab-timeline}

The operator ran Sliver on its server for about eleven weeks before the university activity of early November, and the hands-on window that followed is short. What the server was used for before November is not shown. The university-side commands all date to 5 November 2026; the tool staging runs from 7 to 15 November; and the server was still changing on 16 November.

Three clocks are in play. Times from the operator server's own logs are on its clock, about UTC+1 (measured once, on 16 November). Capture times are on the capture host's clock, about UTC+5. Times marked UTC come from registries, certificates and public scanners. First-served times are the earliest a file is shown on the server, not when it was created or uploaded.

| Date | Observation |
|---|---|
| 2026-08-13 | A commercial internet-scanning platform first sees SSH on the operator server |
| 2026-08-19 | The same platform first sees a TLS listener on port 31337 that it labels Sliver |
| 2026-08-29 | HTTP on port 80 is first seen |
| 2026-09-12 | `cytomate[.]xyz` is registered at 18:09:17 UTC behind a privacy service; a public certificate for it is issued 40 minutes later, and its Cloudflare Origin Certificate dates from the same day |
| 2026-09-14 | The operator server starts serving the front domain's Cloudflare Origin Certificate on port 443, which it does until 27 October, and the platform first sees Sliver on TLS port 8888 |
| 2026-09-28 | A second public certificate is issued for the front domain |
| 2026-09-29 | A public sandbox first sees a Linux Sliver build calling the operator server on port 8888, and Cloudflare-fronted variants calling `breach[.]cytomate[.]xyz` |
| 2026-09-30 | A public scanner first records a URL on the operator server's port 31337 |
| 2026-10-03 | An open-directory monitor first indexes the host and a 157-name listing on port 8091, last checked on 8 October |
| 2026-10-04 | The decoy page "Cytomate Cloud - Maintenance" is first seen on port 443 |
| 2026-10-20 | Port 8443 starts serving a page titled "canary", which it serves until 16 November; its purpose is unknown |
| 2026-10-27 | The last date the Cloudflare Origin Certificate is seen on port 443 |
| 2026-10-30 | Port 8082 answers HTTP 404, its only sighting |
| 2026-11-02 | A full-port sweep sees port 31337 open |
| 2026-11-05 08:10:17 | An Inveigh capture poller starts on the operator server, logging every 2 minutes (server clock) |
| 2026-11-05 12:34:02 | The poller's capture count reaches its final total of 19 lines and logs no new capture for the next 11 days (server clock) |
| 2026-11-05 14:58:10 | The first of six NTLMv2 captures from one university server's local Administrator; the last is at 16:32:04 (capture host clock) |
| 2026-11-05 15:53:44 | The same encoded host survey starts on the first of four university servers and reaches the fourth at 16:01:32 (each host's own clock) |
| 2026-11-07 18:26:36 | The operator server's HTTP log begins with the operator's own loopback fetch of the ESXi exploit (server clock) |
| 2026-11-07 18:26:54 | An address registered to the university's research network starts requesting files: 105 requests for 41 files, ending 19:59:07 on 8 November (server clock) |
| 2026-11-08 21:42:21 | `sp.exe` and `chisel.exe` are first served (server clock) |
| 2026-11-08 23:49:35 | `chisel6.exe` and, 3 seconds later, the pivot implant `spadc1.exe` are first served (server clock) |
| 2026-11-09 | Public reporting surfaces an extortion attack on a US university by the BYOD group; nothing links it to this operator, and it shows only that university extortion was active that week |
| 2026-11-09 04:51:42 | `esxi_implant` and the Linux Chisel build are first served (server clock) |
| 2026-11-09 08:38:31 | `vmupd.exe` is first served (server clock) |
| 2026-11-12 | Port 9000 starts serving a 6,753-byte page titled "VPN Portal" (Last-Modified 2 November), which it serves until 16 November; the page body was never captured and its purpose is unknown |
| 2026-11-13 15:58:57 | `Invoke-SMBExec.ps1` is first served (server clock) |
| 2026-11-14 | A full-port sweep finds 30 ports open, including both Sliver listeners; the five university table files are on the server's file directory |
| 2026-11-15 08:49:41 | `meter64.exe` and `meter86.exe` are first served, the last new files seen (server clock) |
| 2026-11-16 08:15:38 UTC | A public scanner records a NimPlant C2 server banner on port 8445 |
| 2026-11-16 18:42:02 UTC | The poller's log is last modified, at 404,334 bytes |
| 2026-11-16 20:58:45 UTC | A full-port sweep finds 35 ports open, six of them new since 14 November (including 4446, 8091 and 8445); port 8091 no longer serves its old listing |

## 9. Technical Teardown: The Operator's Toolkit
{: .hl-tier-3}
{: .hl-tab-chain}

The toolkit is public software assembled with care, and the teardown below is organised by what each part does. Each block opens on its finding, and the per-file detail sits behind the toggle.

### 9.1 Eight Sliver builds from one server configuration

Seven of the eight Sliver builds dial the operator server directly, five over mTLS on port 31337 and two over HTTPS on port 8000, and the eighth is the pivot implant (Section 7). The five builds that carry an mTLS certificate authority carry the same one, a self-signed P-384 CA with SHA-256 `59eb3f044d9d2811c2664e9cd86bc7d1d39042978125bf043394647c7d343539`. That gives them a common Sliver server configuration and trust lineage, at HIGH. It does not establish one physical server or one administrator, because a CA can be copied with server state.

<details markdown="1" class="hl-teardown">
<summary>Per-build configuration, names and the garble recovery</summary>

The SHA-256 of every build is in the IOC feed (Section 12).

| Build | Platform, form | C2 as recovered | Implant name |
|---|---|---|---|
| `sp.exe` | Windows x64, plain | mTLS to port 31337 | `spweb1` |
| `vmupd.exe` | Windows x64, plain | HTTPS to port 8000 | not recovered |
| `spadc1.exe` | Windows x64, plain, pivot | TCP pivot to an internal parent on port 9898 | `spadc1` |
| `sliver.exe` | Windows x64, garbled | mTLS to port 31337 | a name built from the university's abbreviation (withheld) |
| `u131.exe` | Windows x64, garbled | mTLS to port 31337 | `FOOLISH_NICHE` (Sliver default) |
| `u237.exe` | Windows x64, garbled | mTLS to port 31337 | `HAPPY_WEDGE` (Sliver default) |
| `u218.exe` | Windows x64, garbled | mTLS to port 31337 | `CRUDE_MINT` (Sliver default) |
| `esxi_implant` | Linux x86-64, garbled | HTTPS to port 8000 | not recovered |

The C2 string sits in plaintext in the two plain builds, and I hold those as DEFINITE that the string is in the file and HIGH that it is the live configuration, since the configuration constructor was not disassembled. The garbled builds hide every literal, so their C2 strings were recovered by emulating garble's literal decryptor. That method recovered 256 of 256 literals on a control program built with the same Go and garble versions, and the CA and signing key it pulled from the garbled builds are byte-identical to the plaintext copies in `sp.exe`. The garbled builds therefore stay at HIGH rather than DEFINITE, because no second method has re-run the recovery.

The builds are garble 0.15-style, which is why the older public ungarbling tools fail on them. Three of them, `u131`, `u218` and `u237`, have identical per-package function counts across all 262 packages with every name different: three garble runs of one implant source, each presumably with its own configuration (MODERATE). `sliver.exe` was built with the WireGuard transport compiled in, though no WireGuard address or key was among its recovered literals.

The same minisign key (key id `20F1D34CD5D8E2ED`) sits in the CA-carrying builds and in the plain `vmupd.exe` and `spadc1.exe`. `esxi_implant` carries neither the CA nor that key among its recovered literals, so its tie to the same lineage rests on calling the same HTTPS address as `vmupd.exe` and on sharing the garbled builds' package shape (MODERATE to HIGH).

The plain builds place Sliver's code under the module path `github.com/google/gvisor/runc/cgroup`. That looks like a disguise and is not one: Sliver's own build code rewrites the module root that way for every non-debug build. It marks plain Sliver builds family-wide and says nothing about this operator.

None of the builds carries a usable build date. All eight have zeroed PE or ELF timestamps and no version-control data, and Sliver backdates each certificate's start date by a random 0 to 364 days, so the certificates only bound the CA's creation to some point between 11 October 2025 and 10 October 2026. Beacon interval, jitter and proxy settings were not recovered for any build. None of the eight hashes was on VirusTotal when I checked, which makes them first-seen samples, not clean ones.

</details>

### 9.2 Six stagers and two command loops

All six Meterpreter-style stagers call back to the operator server. Five are small x64 or x86 reverse-TCP stagers built from one template, and the sixth is a stageless loader around an embedded DLL. Beside them sit two PowerShell loops with the server's address hard-coded. None has a held run record, so no session from any of them is shown.

<details markdown="1" class="hl-teardown">
<summary>Stager callbacks, the stageless configuration and the loops</summary>

The SHA-256 of every stager and loop is in the IOC feed (Section 12).

| File | Type | Calls back to port |
|---|---|---|
| `meter4444.exe` | x64 reverse-TCP stager | 4444 |
| `meter4446.exe` | x64 reverse-TCP stager | 4446 |
| `meter64.exe` | x64 reverse-TCP stager | 4446 |
| `meter86.exe` | x86 reverse-TCP stager | 4447 |
| `met183.exe` | x64 reverse-TCP stager | 8444 |
| `meter5555_183.exe` | x64 stageless loader, embedded 256,000-byte DLL | 5555 |

The address and port of the five small stagers are HIGH; the extractor returned four different ports, and `meter4446.exe`'s port matches the operator's handler script for 4446. That they carry Meterpreter rather than a plain shell is MODERATE, because a stager's bytes serve any stage; the file names and the handler script, which loads `windows/x64/meterpreter/reverse_tcp`, point to Meterpreter. Four share one 7,680-byte template with the same compile stamp of 14 April 2026, which is the template's stamp, so it dates nothing the operator did. The file names do not encode the port reliably (`meter64` uses 4446, `met183` uses 8444).

The stageless loader's configuration sits in a 512-byte overlay XORed with the repeating key `a15cb566`. Decoded, it gives `tcp://169[.]58[.]165[.]63:5555`, a 300-second comms timeout, a 3,600-second retry window and a session expiry of 604,800 seconds, with payload UUID `3ae7126587cf73f3cef0cff2a41a799c`. That UUID is operator-generated and is a pivot if it turns up elsewhere. The handler log the operator kept for port 4446 records the handler starting and "no session was created" at that run.

Port 4446 was closed in the 14 November sweep and open in the 16 November sweep, which fits a handler started on demand (MODERATE); it does not show a session. Two further files of the same size, `meter5555.exe` and `meter_tcp.exe`, were listed but not obtainable.

One stager does not fit the server as observed. `met183.exe` is built to call back on port 8444, but on every date I hold, 8444 answered as the toolkit's HTTP file server, and no handler script for that port exists. A stager calling 8444 then would have reached the file server, so either the port's role changed at some point I did not observe or that stager was never used against it; neither is shown.

The two loops are generic. `loop.ps1` polls `hxxp://169[.]58[.]165[.]63/t/cmd` every 5 seconds, runs any text other than "none" with `Invoke-Expression`, and posts the base64 output to `/o/out`. `r.ps1` is a raw TCP reverse shell to port 9001 that runs what it receives and returns a `PS` prompt.

</details>

### 9.3 Credential and directory tooling

The operator's credential work ran through three channels: Metasploit sessions on the four servers, Impacket-based tools run from the operator server against the domain controller, and a capture on the local network. The results it holds are one working domain account, six registry hive files from three servers, six captured NTLMv2 exchanges and a full directory read. It holds no domain-admin credential, and several of its attacks returned nothing.

<details markdown="1" class="hl-teardown">
<summary>What each credential tool returned</summary>

Inveigh ran on one server, inferred from the log path `C:\Users\Public\inveigh\Microsoft-Log.txt` (MODERATE to HIGH), and captured six NTLMv2 responses over SMB from another server's local Administrator between 14:58:10 and 16:32:04 on 5 November. A short script then read that log back and printed only the NTLMv2, Basic, cleartext and SMB lines, which is the operator checking what the capture caught. Cracking is not shown. A separate poller on the operator server kept counting the captures every 2 minutes until 16 November, and the count stayed at 19 lines from 5 November on.

The hive work used two methods on one server. A first script ran `reg save` of SAM, SYSTEM and SECURITY into `C:\Users\Public\hives`; a second copied the same three hives with `esentutl /y /vss`; a third listed the folder; and a fourth downloaded the hives to the operator console. The corpus holds the full set from that server, and a SYSTEM and SAM hive from a second server and a SAM from a third (the last by file name, MODERATE). Together they hold 11 local-account entries. Acquiring the SECURITY hive is shown; extracting LSA secrets from it is not, and whether its cached-logon slots hold domain logons is NOT CHECKED.

The directory read is the strongest result. Three Impacket LDAP scripts with one hard-coded account returned 14,038 user rows, 59 groups with 1,969 member lines and 4 computer accounts. The only user in Domain Admins, Enterprise Admins and Schema Admins is the built-in Administrator, and `adminCount=1` covers exactly Administrator and krbtgt. A separate enumeration from one session failed with "The directory service is unavailable".

The attacks on that directory mostly came back empty. An AS-REP probe of 110 names found 0 roastable accounts. A Kerberoast query returned "No entries found!". An administrative-share test of 3,805 credential pairs reached C$ on the domain controller 0 times. A brute force of the Administrator account against 7,174 candidates left no result file, so its outcome is NOT CHECKED, as are two Zerologon test scripts and an Oracle login probe, all without output.

The operator also held 4,739 application login pairs, one of them reused on the directory as the working account. Where that list came from is not shown. Its wordlists were seeded with the university's own names, year strings and administrator patterns.

</details>

### 9.4 Local-network interception and the packet-capture driver

The operator prepared to sit on the university's network as a man in the middle. It staged bettercap with eight launcher scripts that step up from a version check to a 60-second ARP-spoofing smoke test, a two-hour full-duplex spoof with a transparent HTTP and HTTPS proxy, and an endless loop against a fixed list of 20 internal hosts. None of the output files is held, so what the capture saw, and whether any launcher ran on a university host, is not shown.

<details markdown="1" class="hl-teardown">
<summary>How the operator installs a capture driver from its own server</summary>

bettercap on Windows needs a packet-capture driver, and the operator built a delivery path for one. `npcap_install.bat` fetches the Npcap driver files from `hxxp://169[.]58[.]165[.]63:8444/npcap131/` with `certutil -urlcache` and installs them with `pnputil -i -a`. `npcap_cert.bat` then downloads two certificate files named `Insecure-EV` from the same path, adds them to the TrustedPublisher store with `certutil -addstore`, and retries the install. I read those two certificate files as the Npcap vendor's own signing certificates from their names alone, which is NOT verified, so they are not offered as indicators.

The address registered to the university's research network fetched this whole set between 21:00 and 22:59 on 7 November (server clock). The install's result files are not held, so installation is not shown. The three kernel drivers held in the corpus are genuine Npcap and WinPcap packet-capture drivers, not operator code.

</details>

### 9.5 Drivers and AV killers known only by name and hash

The operator's directory listed six kernel drivers and six user-mode programs with names like `killav.exe`, `kclean.exe` and `killloop.exe`, and none of them could be obtained. Four of the six drivers match LOLDrivers by hash, and three of those are process killers. Together the names suggest a step that uses a driver to stop security software, but no held script loads any of them, so no such step is shown.

<details markdown="1" class="hl-teardown">
<summary>The listed drivers and what LOLDrivers says about them</summary>

The listed SHA-256 of each driver is in the feed's hunt-only bucket (Section 12).

| File | LOLDrivers |
|---|---|
| `GoFly64.sys` | Match: process-terminating network filter driver |
| `MonProcessEX.sys` | Match: process-terminating driver |
| `xkpsm.sys` | Match: process-terminating driver |
| `p152.sys` | Match: the signed Sysinternals Process Explorer driver, renamed |
| `HNOs2Ec.sys` | No match (not listed, not benign) |
| `MonProcess.sys` | No match (not listed, not benign) |

Three of the four matched entries were added to LOLDrivers between April and July 2026, so a blocklist built from LOLDrivers before then would miss them (MODERATE; no blocklist was tested). The hashes come from the directory listing, not from bytes, so they are MODERATE evidence that the named files existed. A control driver held in the corpus returned no match, as expected, while four real candidates matched, so the lookup can hit. Searching the 57 held script files for the twelve names found no reference, against a control pattern that did find the two Npcap install scripts.

</details>

## 10. Infrastructure
{: .hl-tier-2}
{: .hl-tab-timeline}

Everything in this case points back to one server, `169[.]58[.]165[.]63`, on AS51167 (Contabo GmbH, per VirusTotal), geolocated to Lauterbourg, France. It ran the Sliver listeners, the stager and Meterpreter callbacks, the PowerShell loops, a decoy web page and the open directories the toolkit was served from. That the operator could control it is HIGH: the host serves its own origin certificate, decoy page and toolkit. Whether it was rented for the purpose or was a third party's server first is INSUFFICIENT, and so is any claim that the provider is a bulletproof host.

Two full-port sweeps, on 14 and 16 November, found 36 distinct ports open between them, and a commercial internet-scanning platform's history adds one more, 8082 (HTTP 404, seen on 30 October only), for 37 distinct ports across sources. Sixteen are tied to an artefact in the corpus and two more serve titled pages of unknown purpose; the rest have no artefact, and I give them no role. An open port shows only that something is listening, so the service names below come from the implant configurations and the operator's scripts.

| Port | What answers there | Confidence |
|---|---|---|
| 31337 | Sliver mTLS listener of five builds; open in both sweeps and on 2 November | HIGH |
| 8000 | Sliver HTTPS listener of `vmupd.exe` and `esxi_implant`; open in both sweeps | HIGH |
| 5555 | Meterpreter listener named by the stageless loader's configuration | MODERATE |
| 4444, 4446, 4447 | Stager callback ports; 4446 opened between the two sweeps | MODERATE |
| 80 | `loop.ps1` tasking and output paths | HIGH |
| 9001 | `r.ps1` raw TCP shell target | MODERATE |
| 443 | Decoy page "Cytomate Cloud - Maintenance" | HIGH |
| 8080, 8444, 9002, 18081 | Python open-directory roots serving the toolkit; `met183.exe` is also built to call back on 8444, which answered as the file server on every date held (Section 9.2) | HIGH |
| 8091 | Open-directory root that listed 157 names in October; by 16 November it answered 404 and the listing was gone | HIGH |
| 8445 | NimPlant C2 server banner, first recorded 16 November; closed in the 14 November sweep | HIGH for the banner; not shown to be the same operator |
| 8888 | Sliver on TLS from 14 September per the platform's history; public-sandbox Sliver builds dial it | MODERATE |
| 9000 | A page titled "VPN Portal" from 12 to 16 November, body never captured | Observed; purpose unknown |
| 8443 | A page titled "canary" from 20 October to 16 November | Observed; purpose unknown |

### The front domain borrowing a vendor's name

The server fronts a domain, `cytomate[.]xyz`, with one subdomain, `breach[.]cytomate[.]xyz`. The domain was registered on 12 September 2026 at Namecheap behind a privacy service, sits behind Cloudflare name servers, and gained an apex-and-wildcard public certificate 40 minutes after registration and a second on 28 September. The operator server itself presented the domain's Cloudflare Origin Certificate (SHA-256 `8c7500fae71e868abbb1c9d545419535b4ad6b4c1c9b7d20ab32ac270a89f047`) on port 443 from 14 September to 27 October 2026. An origin certificate is installed by whoever controls the origin, so together with the decoy page on the same host it makes the domain operator-controlled infrastructure, at HIGH.

The name matches a real offensive-security vendor based in Qatar, whose publicly associated domain is a different one, `cytomate[.]net`, registered in 2020. I hold at HIGH that the .xyz domain is a same-label name distinct from that domain: the age, registrar, mail setup and history all differ. Who owns the .xyz name is not established. Whether the vendor has any role in it I could not establish, and that judgment is INSUFFICIENT. Nothing collected separates impersonation by the operator, a secondary or demonstration domain of the vendor's, or borrowed branding by an independent team.

The domain's own history names no one. Its WHOIS record has been privacy-withheld without a break since creation, one record in all, and the masked registrant email sits on about one domain, so it pivots nowhere; no registrant or person can be named. In DNS it sat on the registrar's parking for about an hour on 12 September, then on Cloudflare alone through 16 November, and passive DNS never shows an origin address. The scanning platform's certificate history is therefore the only source that places the origin certificate on the operator server. `breach[.]cytomate[.]xyz` resolved to Cloudflare 28 times between 30 September and 2 November.

The .xyz domain also shares no registration or DNS account artifact with the vendor's domain: a different registrar, a different privacy service and a different Cloudflare name-server pair. A different name-server pair usually means a different Cloudflare account, which leans against the vendor holding the .xyz, but one organisation can hold several accounts and registrars, so the vendor's role stays INSUFFICIENT. Source: my domain-history lookups, reviewed 17 November 2026.

Four Linux Sliver samples in public sandboxes, first submitted from 29 September, call the front or the server: three call `breach[.]cytomate[.]xyz` and one calls the server on port 8888. None of them is in the corpus, and I hold their tie to this operator at MODERATE. The builds I hold call the server's address, not the front. Two Cloudflare addresses sit in front of the domain; they are shared by unrelated sites and must never be blocked, so a defender blocks the names and the SNI instead.

### Liveness on 16 November

The operator's side of the server was still current on 16 November 2026. Its Inveigh poller was still writing its log, which had grown from 6,811 lines on 14 November to 8,105 lines on 16 November and was last modified at 18:42:02 UTC, at 404,334 bytes. The day before, two new stagers had been served. Between the two sweeps six ports opened (1086, 4446, 8081, 8091, 8445 and 8446) and one closed (9443). A running poller and changing listeners show a live server, not a person at the keyboard or a live channel into the university. No traffic was sent to any C2 port, so whether any implant was beaconing then is NOT CHECKED.

### What the pivots found, and what is not checked

The certificate pivots lead to no second server. In a commercial internet-scanning platform's records, a search for the Sliver CA's key identifier over the last 45 days hit only this host, and so did a search for the host's SSH keys since 18 October. A search for the front domain's origin certificate returned no other host. These are bounded negatives, HIGH for that platform's scans in those windows: they do not exclude a server it did not scan, a port it does not probe, or anything older than the window. The host's TLS fingerprint (JARM `3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5`) belongs to a common TLS stack; a search on it returned too many hosts to use, so it is context only and never a pivot.

The other addresses add little. Three hosts in a large open-directory corpus, `192[.]3[.]16[.]96`, `107[.]173[.]130[.]24` and `5[.]34[.]176[.]171`, served the same `chisel.exe` as the operator (`ca5f8e52...`). That build is public: VirusTotal holds it from 32 unique sources since 29 August 2026, so a shared copy links nothing.

Nothing else distinctive is shared: no JARM, certificate, SSH key or operator build in common, and no hash of the operator's own files appears on them. I hold at INSUFFICIENT that any of the three is connected to this operator, and I list them as context only, not as indicators to block.

Of the two outside clients that polled the directory on a fixed schedule, one is a broad open-directory crawler that fetched files from many unrelated hosts, so it is neither an operator client nor a victim channel (HIGH); the other's history is empty (INSUFFICIENT).

Two items are still NOT CHECKED: a search for other look-alike domains registered around 12 September 2026, and the vendor domain's history older than the domain-history export reaches. Neither is a negative. Source for this section's platform results: my lookups on a commercial scanning platform, reviewed 17 November 2026.

## 11. MITRE ATT&CK Mapping
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's behaviour maps to 44 procedure rows, each a distinct technique ID, in 10 tactics of ATT&CK Enterprise v20.0, every ID live. The Status column uses three values. OBSERVED means I hold an operator-side result for the procedure, which includes a retained attempt that failed where the attempt is itself the procedure. INFERRED means the operator's tooling is built or configured to do it but no execution result is held. NOT SHOWN marks a boundary and claims no impact.

The counts are 21 OBSERVED, 22 INFERRED and 1 NOT SHOWN, and row confidence is HIGH on 21 and MODERATE on 23. The NOT SHOWN row is the ESXi exploit: staged, with no target contact. Three OBSERVED rows are attempts that came back empty, the Kerberoast query, the AS-REP probe and the administrative-share test. OBSERVED never means a victim log here, because I hold none; it is always the operator's own record of a result. The Exfiltration row covers the downloaded hive set only, not the university's tables, whose route is not shown.

No technique is mapped for initial access, which is not identified, for persistence, which nothing shows on a university host, or for impact, since no encryption, wiping or ransom artefact is held. Pass-the-hash is left out at LOW: the tooling is staged with no target or credential set. The attack chain above follows these rows stage by stage, and the full table is in the collapse below.

<details markdown="1" class="hl-teardown">
<summary>All 44 procedure rows, with status, confidence and evidence</summary>

| Tactic / Technique | Name | Status | Conf. | Evidence |
|---|---|---|---|---|
| Resource Development / T1608.002 | Upload Tool | OBSERVED | HIGH | Toolkit served from ports 8080, 8444 and 9002 |
| Resource Development / T1588.002 | Tool | OBSERVED | HIGH | Stock Chisel, Inveigh, bettercap, Metasploit |
| Execution / T1059.001 | PowerShell | OBSERVED | HIGH | Encoded survey output from four servers |
| Execution / T1059.003 | Windows Command Shell | INFERRED | MODERATE | `cmd /c` instructions; no output held |
| Stealth / T1027 | Obfuscated Files or Information | OBSERVED | HIGH | Five garbled Sliver builds |
| Stealth / T1027.010 | Command Obfuscation | OBSERVED | HIGH | `-EncodedCommand` in session scripts |
| Stealth / T1078.002 | Domain Accounts | OBSERVED | HIGH | One account's bind returned the directory |
| Stealth / T1070.004 | File Deletion | INFERRED | MODERATE | `Remove-Item` of an earlier file; no output |
| Stealth / T1620 | Reflective Code Loading | INFERRED | MODERATE | Stageless loader with an embedded DLL |
| Defense Impairment / T1553 | Subvert Trust Controls | INFERRED | MODERATE | `certutil -addstore` TrustedPublisher; no result |
| Credential Access / T1003.002 | Security Account Manager | OBSERVED | HIGH | SAM hives from three servers |
| Credential Access / T1003.004 | LSA Secrets | INFERRED | MODERATE | SECURITY hive held; extraction not shown |
| Credential Access / T1557.001 | Name Resolution Poisoning and SMB Relay | OBSERVED | HIGH | Inveigh: six NTLMv2 captures |
| Credential Access / T1557.002 | ARP Cache Poisoning | INFERRED | MODERATE | bettercap `arp.spoof` launchers; no output |
| Credential Access / T1040 | Network Sniffing | INFERRED | MODERATE | bettercap `net.sniff`; Npcap set staged |
| Credential Access / T1555.004 | Windows Credential Manager | OBSERVED | HIGH | `cmdkey /list` output from four servers |
| Credential Access / T1552.001 | Credentials In Files | INFERRED | MODERATE | Config-secret hunts; results not held |
| Credential Access / T1552.002 | Credentials in Registry | INFERRED | MODERATE | Winlogon, WinSCP, PuTTY keys queried |
| Credential Access / T1552.003 | Shell History | INFERRED | MODERATE | PowerShell history read per user |
| Credential Access / T1110.003 | Password Spraying | OBSERVED | HIGH | 3,804 names accepted; 1 validated |
| Credential Access / T1110.001 | Password Guessing | INFERRED | MODERATE | Administrator vs 7,174 candidates; no result |
| Credential Access / T1558.004 | AS-REP Roasting | OBSERVED | HIGH | 110 probes, 0 roastable |
| Credential Access / T1558.003 | Kerberoasting | OBSERVED | MODERATE | Query returned "No entries found!" |
| Discovery / T1087.002 | Domain Account | OBSERVED | HIGH | 14,038 user rows over LDAP |
| Discovery / T1069.002 | Domain Groups | OBSERVED | HIGH | 59 groups, 1,969 member lines |
| Discovery / T1069.001 | Local Groups | INFERRED | MODERATE | Local Administrators query in a host survey |
| Discovery / T1018 | Remote System Discovery | OBSERVED | HIGH | 4 computer accounts over LDAP |
| Discovery / T1033 | System Owner/User Discovery | OBSERVED | HIGH | `quser`, `qwinsta` output from four servers |
| Discovery / T1049 | System Network Connections Discovery | OBSERVED | MODERATE | `net use` output from four servers |
| Discovery / T1046 | Network Service Discovery | INFERRED | MODERATE | SLP, vCenter and port scanners; no output |
| Discovery / T1083 | File and Directory Discovery | INFERRED | MODERATE | Data-volume listings; no output |
| Discovery / T1057 | Process Discovery | INFERRED | MODERATE | Process paths in host surveys |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | OBSERVED | MODERATE | C$ test: 0 of 3,805 pairs |
| Lateral Movement / T1210 | Exploitation of Remote Services | NOT SHOWN | MODERATE | CVE-2021-21974 port staged; no target contact |
| Collection / T1074.001 | Local Data Staging | OBSERVED | HIGH | `C:\Users\Public\hives` filled on one server |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | OBSERVED | HIGH | Hive set downloaded over Meterpreter only |
| Command and Control / T1105 | Ingress Tool Transfer | OBSERVED | HIGH | 105 requests from the university's block |
| Command and Control / T1573.002 | Asymmetric Cryptography | INFERRED | HIGH | Five builds, mTLS to port 31337; transport string in the file, no run result |
| Command and Control / T1071.001 | Web Protocols | INFERRED | HIGH | HTTPS to 8000; `loop.ps1` HTTP poll; configured in the file, no run result |
| Command and Control / T1095 | Non-Application Layer Protocol | INFERRED | HIGH | Six stagers; `r.ps1` on TCP 9001 |
| Command and Control / T1090.001 | Internal Proxy | INFERRED | MODERATE | `spadc1.exe` TCP pivot on 9898 |
| Command and Control / T1090 | Proxy | INFERRED | MODERATE | `proxychains` configured; launch failed |
| Command and Control / T1132.001 | Standard Encoding | INFERRED | MODERATE | `loop.ps1` base64 output |
| Command and Control / T1572 | Protocol Tunneling | INFERRED | MODERATE | Three stock Chisel builds staged |

</details>

## 12. Indicators of Compromise
{: .hl-tier-2}
{: .hl-tab-indicators}

The indicators for this case are operator-side only: the operator's server and front, the files it built or staged, and the certificates and keys inside its builds. No university value is in the feed, since I name no victim. The full machine-readable set is the IOC feed, [`opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-iocs.json`](/ioc-feeds/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-iocs.json). It carries 59 operator-side indicator entries: 28 SHA-256 file hashes, 1 IPv4 address, 2 domains, 6 URLs, 13 host-and-port endpoints and 9 certificate values.

Nine of the 28 hashes are files the directory listed but no one could obtain, so those hashes come from the listing and are marked LOW. A separate hunt-only bucket in the feed holds 22 values that must never be blocked or that only make sense as hunting keys: the two shared Cloudflare addresses, the host's TLS fingerprint, the Sliver signing and age keys, the Meterpreter payload UUID and XOR key, the six listed driver hashes and the operator's working folders on victim hosts. The stock Chisel builds are left out of the block set, because their hashes match anyone using the public tool. A short set worth acting on first:

| Indicator | What it is | Confidence | Action |
|---|---|---|---|
| `169[.]58[.]165[.]63` | Operator server: Sliver C2 on 31337 and 8000, stager and Meterpreter callbacks, toolkit directories | DEFINITE | Block the single address, not the provider's range |
| `cytomate[.]xyz` | Front domain whose origin certificate sits on the operator server | HIGH | Block the name and SNI, never the Cloudflare addresses behind it |
| `breach[.]cytomate[.]xyz` | Subdomain that public-sandbox Sliver samples call | MODERATE | Block |
| `59eb3f044d9d2811c2664e9cd86bc7d1d39042978125bf043394647c7d343539` | Sliver mTLS CA certificate in five builds | HIGH | Hunt in TLS and certificate data |
| `8c7500fae71e868abbb1c9d545419535b4ad6b4c1c9b7d20ab32ac270a89f047` | Cloudflare Origin Certificate the server presents | HIGH | Hunt in TLS and certificate data |
| `bd1a14378f3b067f36808098b4571bede03e40545e4eb237f9cfdef345a5b01d` | `sp.exe`, plain Sliver build `spweb1` | DEFINITE | Block |
| `fbb340af03b610156ae37db33ee4596749c2f1df943a6546edb0df52fdcefbdd` | `spadc1.exe`, Sliver pivot implant | DEFINITE | Block |
| `0d65479e7522efaa1ee8c83b87e86298f70305b0ae10d5f3865f1366ef683be6` | `esxi_implant`, garbled Linux Sliver build | HIGH | Block |
| `a5111c366fad5fdbbc7407419427bf3eacdaedebcaeb590eb79412e3605a304f` | `meter5555_183.exe`, stageless Meterpreter loader | HIGH | Block |
| `3ae7126587cf73f3cef0cff2a41a799c` | Payload UUID in the stageless loader's configuration | HIGH | Hunt |
| `20F1D34CD5D8E2ED` | Sliver minisign key id in seven of the eight builds | HIGH | Hunt |
| `C:\Users\Public\hives\`, `C:\Users\Public\inveigh\`, `C:\Users\Public\npcap131\` | Operator working folders on university hosts | HIGH | Hunt |
| Internal listener on TCP 9898 | Where the pivot implant expects its parent | MODERATE | Hunt inside the network |

## 13. Detection and Hunting Guidance
{: .hl-tier-2}
{: .hl-tab-indicators}

The [detection file](/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/) for this case carries 23 rules: 5 YARA (1 detection, 4 hunting), 12 Sigma (3 detection, 9 hunting) and 6 Suricata (1 detection, 5 hunting). The 5 Detection-tier rules are high-fidelity and safe to alert on; the 18 Hunting-tier rules key on the operator's own script and folder names, which a renamed script escapes, so their hits need review. Each YARA rule fires on the sample it was written from, and the Sliver and stager rules fire on nothing in a clean Windows system folder set. No Sigma or Suricata rule has been confirmed against university or sensor telemetry, because the case holds none.

The five Detection-tier rules cover the parts of this toolkit that are hardest to change. One YARA rule matches all eight Sliver builds, garbled or plain, on the protobuf accessor names garble leaves in the clear. Three Sigma rules catch a certificate added to the TrustedPublisher store from a user-writable path, bettercap started with its man-in-the-middle modules, and a PowerShell script block that opens a raw TCP stream and runs what it receives. One Suricata rule matches the NimPlant server banner in an HTTP response.

What the case gives a hunter, in order of durability:

- Directory reads at volume by one ordinary account. An LDAP bind that pulls every user, group and computer object in one pass is the step this operator relied on most, and it needs no administrator rights.
- Registry hives written to `C:\Users\Public\hives`, and the `reg save` and `esentutl /y /vss` command lines against SAM, SYSTEM and SECURITY. SigmaHQ already has rules for both command lines, so the case's own rule watches the folder.
- A packet-capture driver installed with `pnputil` from a user-writable folder, after `certutil -urlcache` fetched it from an outside address.
- Internal clients fetching files from `169[.]58[.]165[.]63` on 8444 or 9002, and any internal host listening on TCP 9898.
- Hosts that answer on the SLP port 427 inside the network, which is where the staged ESXi exploit would land.

Three gaps limit what I could write. The case holds no capture of the operator's Sliver traffic, so there is no TLS-fingerprint or HTTP-profile rule for the implants. It holds no domain-controller log, so the spray, the AS-REP probe and the directory read have no rule with a measured threshold. And no ESXi exploit traffic exists to derive a network rule for CVE-2021-21974 from; whether upstream rulesets already cover it is NOT CHECKED.

## 14. Threat Actor Assessment
{: .hl-tier-2}
{: .hl-tab-attribution}

I cannot attribute this operator to a named actor, and I am not creating a tracking designation for it; where a label is needed it is the operator of this case. Named-actor attribution is INSUFFICIENT. Every operator-side artefact I could grade is either stock tooling or has no measured base rate yet. The one comparison against my other cases (13 case inventories, 50 indicator feeds and two script collections, with 45 cases not covered) found no operator-specific link; the overlaps it did find are public tools any operator uses. This is the first coverage of this operator I know of, and I found no prior public reporting on the host, the front or the campaign in the search forms whose controls passed.

### Authorised or not

My working judgment is that this was an unauthorised intrusion, and I hold it at MODERATE. I have been part of purple-team exercises watching red teams work directly, and this does not move like one. Nothing collected separates it, though, from an authorised red team, a breach-and-attack simulation, a teaching exercise, or an authorised deployment that was later misused. The front borrowing a security vendor's name does not settle it either way. The record that would decide it is the university's own: a written statement that no engagement existed, covering internal teams and subcontractors, would raise this; an engagement document naming the host, the dates and the data classes would lower it.

### My read: an extortion-type operation, possibly caught early

This section is my own assessment, and I label it that way because it is not a finding. Since 1 August 2026 I count 24 higher-education intrusions in public reporting, and that reporting usually ends in extortion. My read is that this is either another of those attacks or someone following the same pattern. From the incident reports I read for the comparison below (Section 17), my read is that crews who bring ESXi tooling use it for destructive action at the end of an intrusion rather than for more access: they get into the virtual machines, collect data, and then encrypt everything. The tooling here points at ESXi as the objective, and my read is that this operator may have been caught before it reached its execution phase.

What leaves that open is real. No ransom note, leak-site listing, sale or buyer contact is anywhere in the corpus. My comparison searched public reporting from 1 August to 17 November 2026 with 30 queries, in English and one in Urdu, and found 24 higher-education intrusions plus one Pakistani education-sector company; four incident reports and one quarterly roundup were read in full (Section 17). Nothing fits better than chance. The reporting names no C2 framework, tunnelling tool, lateral-movement tool or way in, so there is nothing to match against, which is a gap in what is reported rather than a mismatch.

I found no reported intrusion at a Pakistani university in that window, though local-language news and national advisories are NOT CHECKED. University extortion was active that same week, with the BYOD group's attack on a US university surfacing on 9 November, and nothing links that to this operator.

The ESXi path matches how extortion crews end intrusions, and that is as far as the evidence takes the read. The motive is undetermined: financial gain leads at LOW, collection for a state or another sponsor is a live hypothesis at LOW, and an access broker working for someone else is INSUFFICIENT. A ransom demand, a leak listing or a sale tied to the university's tables would move my read up; a scope-matched engagement record from the university would end it.

### How capable

My read is that this operator is knowledgeable and came prepared. It arrived with what it needed and a plan, and it was executing that plan; this was calculated targeting and execution. The evidence behind that is the per-target builds, the scanners shipped already set to the university's range, the pivot build aimed inside, and three days of staging in order. That is also all it shows. The kit is almost entirely public, Sliver's defaults are left in several builds, and several of its attacks on the directory came back empty.

| Hypothesis | Inconsistencies | Where it stands |
|---|---|---|
| A financially motivated criminal intrusion | None in the files held; no sale, listing or demand is held | Leads, LOW; the working basis |
| An extortion-type operation like the 2026 university wave, stopped short of its objective | None in the files held; public reporting on the wave names no tradecraft to match | My assessment, not a finding |
| Collection for a state or other sponsor | None in the files held; identity and staff records fit both this and money | Survives, LOW |
| An access broker or contractor working for another beneficiary | None in the files held; no buyer or message is held | Survives, INSUFFICIENT |
| A vendor-run authorised red team or simulation | Three weak ones, none decisive; the university's authorisation is not held | Lowered, not eliminated |
| An independent authorised red team using a borrowed name | Two weak ones; the university's authorisation is not held | Lowered, not eliminated |
| An insider, student or contractor | One weak one; the tool requests from the university's block fit a compromised host equally | Lowered, not eliminated |
| A research or teaching lab with legitimate data | One weak one; no approval or dataset provenance is held | Lowered, not eliminated |
| Several unrelated operators sharing the server | None; it rests on the 157 port-8091 names, which are name-only | Survives, LOW |

| Call | What would change it |
|---|---|
| No named actor, INSUFFICIENT | The Sliver CA, the origin certificate or a build key found on another operator's server at low prevalence, or a vendor or government report naming this host |
| Unauthorised intrusion, MODERATE | The university's written statement that no engagement existed would raise it; an engagement document naming the host, dates and data classes would lower it |
| Motive undetermined, financial leading at LOW | A ransom demand, leak listing or sale tied to the university's tables; or a tasking record for a sponsor |
| No link to any reported university campaign, INSUFFICIENT | An incident-response report on a university extortion intrusion naming garbled Sliver, Chisel or Invoke-TheHash, or a front domain borrowing a security vendor's name |
| The front's tie to the vendor, INSUFFICIENT | The vendor's own statement, or the registrar's account records for `cytomate[.]xyz` |

## 15. Recommendations
{: .hl-tier-1}
{: .hl-tab-indicators}

Each of these follows from something this operator did or relied on in this case.

- Watch for one account reading the whole directory. An ordinary account with no privileged membership shown pulled the user, group and computer objects here, and that read is what the rest of the intrusion was built on.
- Find hypervisors whose SLP service is reachable from the internal network. The operator staged a public exploit for CVE-2021-21974 with scanners set to look for that port across the local range. No ESXi host is identified in this case, so I cannot say which hosts were exposed; any reachable SLP service is the exposure the staged exploit targets.
- Turn off LLMNR and NBT-NS where nothing depends on them. The operator ran Inveigh, a capture tool built on answering those lookups, and collected six NTLMv2 responses from a server's local Administrator in 1 h 33 m 54 s.
- Disable the Guest account on domain controllers. It was enabled here with no password required, and a guest-session mapping is my best explanation, at MODERATE, for 3,804 spray names coming back marked accepted. The mechanism is probable rather than proven, and the control is cheap to apply.
- Alert on `certutil -urlcache` fetching from an outside address followed by `pnputil` installing a driver from a user-writable folder, and on certificates added to the TrustedPublisher store from such a folder. That is how this operator delivered its packet-capture driver.
- Hunt for internal hosts that reached `169[.]58[.]165[.]63`, for internal listeners on TCP 9898, and for the folders `C:\Users\Public\hives`, `C:\Users\Public\inveigh` and `C:\Users\Public\npcap131`.
- Block the operator server and the `cytomate[.]xyz` names, never the shared Cloudflare addresses in front of the domain.

## 16. Confidence Summary and Evidence Gaps
{: .hl-tier-2}
{: .hl-tab-confidence}

The case rests on the operator's own files and server: its builds, scripts, logs, exports and listings, captured from its open directory. That makes the evidence strong on what the operator built, ran and staged, and silent on what the university's own systems recorded, because I hold no victim-side telemetry. The single source that would do the most damage if wrong is the operator server's HTTP log, since the inside-address requests and every first-served time rest on it alone. Each load-bearing judgment below carries its confidence and the observable that would move it.

| Claim | Confidence | What would change it |
|---|---|---|
| Seven of the eight Sliver builds dial the operator server directly; the eighth is a pivot to an internal parent | HIGH | A disassembly of a garbled build's configuration constructor showing a recovered address is not the live one |
| The five mTLS builds share one Sliver CA, a common server configuration and trust lineage, not shown to be one physical server | HIGH | A build in this set carrying a different CA |
| All six stagers call back to the operator server | HIGH | A re-decode of the stageless loader's configuration giving another address |
| Four university servers are ACCESS SHOWN; the domain controller is COMPROMISED on bind output only; no domain-admin session is shown; the ESXi tooling was staged with no target contact | HIGH | Host-side output from the domain controller, a host identity for the unresolved session, or VMware scan or exploit output naming a target |
| The 7 and 8 November requests came from an address registered to the university's research network; which device and who operated it are not shown | HIGH | A registry record placing the block with another body, or NAT or proxy evidence putting the client outside the university |
| Of 3,804 accepted spray names, one account is validated and six match directory accounts exactly | MODERATE | The domain controller's authentication logs for the spray |
| The operator server held five university table files of 328,942 rows; when, from where and by what route is not shown | HIGH | Per-table record dates and matches against the university's source tables, or a deduplication showing far fewer records |
| A running poller kept writing on the operator server until at least 16 November, not a person at the keyboard | HIGH | Evidence that the log was replayed or copied rather than written live |
| `cytomate[.]xyz` is a same-label front distinct from the vendor's publicly associated domain; its owner is not established | HIGH | Vendor or registrar records showing the vendor registered it |
| Whether the vendor whose name the front uses has any role in it; the .xyz shares no registrar, privacy service or Cloudflare name-server pair with the vendor's domain | INSUFFICIENT | The vendor's own statement, or the registrar's account records for the domain |
| The activity is an unauthorised intrusion | MODERATE | The university's written statement that no engagement existed would raise it; an engagement document naming the host, dates and data classes would lower it |
| No named actor, and no operator link in the measured comparison of my cases | INSUFFICIENT | The Sliver CA, the origin certificate or a build key on another operator's server at low prevalence |
| No second operator server presents the Sliver CA (last 45 days), the host's SSH keys (since 18 October) or the origin certificate in a commercial scanning platform's records | HIGH for those scans and windows | A server outside those scans or windows presenting any of them |
| The operator ran Sliver on its server from 19 August 2026, about eleven weeks before the university activity | MODERATE, resting on the platform's service label | A history showing the 31337 listener was another service before November |
| The `github.com/google/gvisor` module root marks plain Sliver builds family-wide, not this operator | HIGH | The operator's Sliver version lacking that rewrite |
| The 157 names once listed on port 8091 suggest further tooling whose relation to the university, this operator and other victims is unresolved | LOW | The file bytes, or an administrator or tenancy record for the server |
| No prior public reporting on this host, front or campaign in the search forms whose controls passed | MODERATE | A report on the host found in the IP-string, page-title or certificate forms, which are NOT CHECKED |
| Motive: financial gain leads, with collection for a sponsor also live | LOW | A ransom demand, leak listing or sale tied to the university's tables; or a tasking record for a sponsor |
| My assessment, not a finding: an extortion-type operation that may have been stopped before an ESXi objective | No confidence label: an unsettled read, held as my own | A ransom demand, leak listing or sale tied to the university's tables would raise it; an engagement record would end it |

### The alternative I could not kill

The most credible alternative to my working judgment is an authorised engagement: a red team, a breach-and-attack simulation, a teaching exercise, or an authorised deployment that was later misused. The vendor-run, independent and lab versions of that reading each carry only weak inconsistencies in my analysis of competing hypotheses, and none is eliminated. The record that would kill it is the university's own written statement that no engagement existed, covering internal teams and subcontractors; a vendor statement alone could not establish the university's consent. Until that exists, "unauthorised intrusion" stays at MODERATE.

### Evidence gaps

- No victim-side telemetry exists, so no grade, rule or timeline entry here is confirmed from the university's own logs.
- Initial access is not identified. No web, VPN or authentication log of the university's is held.
- Persistence on any university host is NOT CHECKED, not absent: no named search over all 57 script bodies was run.
- Whether any Sliver build, stager or command loop ever ran on a university host is not shown.
- The outputs of the host surveys, the bettercap runs, the Zerologon tests, the Administrator brute force and the Oracle login probe are not held.
- Two infrastructure lookups are still NOT CHECKED: a search for other look-alike domains registered around 12 September 2026, and the vendor domain's history older than the domain-history export reaches. The certificate, SSH-key, WHOIS and DNS lookups are done and are bounded negatives (Section 10).
- The bytes of the 157 port-8091 names and of 25 further listed files are not obtainable.
- Beacon intervals, jitter and proxy settings of every Sliver build, `vmupd.exe`'s HTTP profile and any WireGuard configuration are not recovered; the garbled builds' C2 has no second-method confirmation.
- The two `Insecure-EV` certificate files were never parsed.
- The comparison with reported university intrusions did not cover local-language news or national advisories in Pakistan, and reporting on the 2026 wave names almost no tradecraft.

## 17. References
{: .hl-tier-2}
{: .hl-tab-confidence}

- BishopFox, Sliver source and documentation: [github.com/BishopFox/sliver](https://github.com/BishopFox/sliver). The module-root rewrite for non-debug builds, certificate backdating and the pivot examples discussed above were read from the source on the default branch, not the operator's version.
- burrowers, garble: [github.com/burrowers/garble](https://github.com/burrowers/garble), the Go obfuscator whose literal encryption the five garbled builds use.
- chvancooten, NimPlant: [github.com/chvancooten/NimPlant](https://github.com/chvancooten/NimPlant), whose stock listener returns the 23-byte 404 body and server banner seen on port 8445.
- jpillora, Chisel: [github.com/jpillora/chisel](https://github.com/jpillora/chisel), the upstream source of the three stock tunnel builds.
- Kevin Robertson, Inveigh: [github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh), the LLMNR, NBNS and SMB capture tool.
- bettercap: [github.com/bettercap/bettercap](https://github.com/bettercap/bettercap), the network attack framework staged with the launcher scripts.
- LOLDrivers: [loldrivers.io](https://www.loldrivers.io/), the community catalogue four of the six listed drivers match by hash.
- TechTarget, Alexander Culafi (8 February 2023): [CISA battles ESXiArgs ransomware campaign with recovery tool](https://www.techtarget.com/cybersecurity/news/365530874/CISA-battles-ESXiArgs-ransomware-campaign-with-recovery-tool), reporting CERT-FR's updated advisory that the ESXiArgs attackers appeared to have targeted ESXi's SLP service through flaws including CVE-2021-21974.
- NIST NVD, CVE-2021-21974: [nvd.nist.gov/vuln/detail/CVE-2021-21974](https://nvd.nist.gov/vuln/detail/CVE-2021-21974), the OpenSLP heap overflow in VMware ESXi that the staged exploit targets.
- BleepingComputer (November 2026): [Vanderbilt University hit in BYOD ransomware attack, data theft claimed](https://bleepingcomputer.com/news/security/vanderbilt-university-hit-in-byod-ransomware-attack-data-theft-claimed), on the university extortion attack that surfaced on 9 November; no link to this operator.
- Help Net Security (27 October 2026): [report on the University of New Mexico hospitals cyberattack](https://www.helpnetsecurity.com/2026/10/27/university-of-new-mexico-hospitals-cyberattack), one of the incidents read in full for the comparison in Section 14.
- The Record (2026): [report on the BYOD incident at Michigan State University](https://therecord.media/michigan-state-university-byod-gang-cyber-incident), read in full for the same comparison.
- The Record (2026): [report on ransomware at the University of Illinois Chicago](https://therecord.media/ransomware-university-illinois-chicago), on the Booba encryption incident, read in full for the same comparison.
- Comparitech (2026): [Education ransomware roundup, Q3 2026](https://www.comparitech.com/news/education-ransomware-roundup-q3-2026-stats-on-attacks-ransoms-and-data-breaches/), on the 2026 rise in attacks on higher education.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
