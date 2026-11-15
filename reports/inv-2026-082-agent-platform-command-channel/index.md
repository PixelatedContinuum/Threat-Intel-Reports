---
title: "A Threat Actor Configured an Enterprise AI-Agent Platform as a Command and Relay Channel"
date: '2026-11-15'
layout: post
permalink: /reports/inv-2026-082-agent-platform-command-channel/
hide: true
figures: inline
unlisted: true
sitemap: false
preview_cover_label: "Platform Abuse"   # preview only: header cover while the catalog entry is parked; drop at go-live
preview_severity: high
category: "AI-Agent Platform Abuse"
description: "An operator rewrote a consumer-electronics maker's own AI-agent platform configuration to serve as an execution and relay channel, with a scripted fake model server and a model-free tool-server plant. This note gives the method, the detections and what the evidence does and does not show."
detection_page: /hunting-detections/inv-2026-082-detections/
ioc_feed: /ioc-feeds/inv-2026-082-agent-platform-command-channel-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "198[.]44[.]116[.]69"
    note: "Operator server: directory, endpoint, relay, receivers"
  - value: "b660141d80bcc05457e881e2db687120677473c8d43c62b26c2c413fbd50b885"
    note: "mcp_plant.py, tool-server plant (SHA-256)"
  - value: "d08901561f5f60d5b1dccc6847f00e6a8cc474e6fae8351df05494d6e58b235a"
    note: "own_llm.py, scripted model endpoint (SHA-256)"
  - value: "76d901ac74f377e8dc2e307407ab4b1125e90ecae828dbfa8a67ebd19a4e2f85"
    note: "hb.py, reverse SOCKS worker (SHA-256)"
figure_nav:
  - image: inv-2026-082-command-relay-channel-map.svg
    parts:
      - label: "Operator's rented server"
        anchor: "#6-infrastructure-one-rented-server-and-a-shared-tunnel"
      - label: "Pod: execution inferred"
        anchor: "#2-victims-who-was-hit-and-how-far-the-operator-got"
      - label: "Stage 4 scripted endpoint"
        anchor: "#4-the-attack-chain-token-repoint-plant-relay"
      - label: "Detection anchors"
        anchor: "#9-detection-and-hunting-guidance"
---

**Campaign Identifier:** AgentPlatform-ConfigChannel-OpenDirectory-198[.]44[.]116[.]69<br>
**Last Updated:** November 15, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary
{: .hl-tier-1}
{: .hl-tab-overview}

An operator configured a consumer-electronics maker's own AI-agent platform to serve as an execution and relay channel into its Hong Kong cloud estate, and never attacked a model to do it. Through an unauthenticated token route on the platform's public gateway, they pointed one agent's model address at a fake model server they ran, and wrote the platform's configuration so that its tool loop and a tool-server entry would run their code. Whether any of those commands ran inside the platform's pods is not shown by anything I hold, and the route into a pod is not identified. What I can show is the configuration they wrote, the scripts they built to use it, and a cloud credential and internal records that reached their server.

- The attack surface was the platform's configuration. Three settings did the work: a model base URL, a scripted server that answers an agent with the next queued tool call, and a tool-server entry whose command is an inline Python downloader that the platform's runtime starts without asking a model.
- I grade the victim COMPROMISED and no higher. The operator held a worker node's cloud role credential (issued 05:48Z, first used 09:52Z on 30 October 2026), listed the company's instances across seven regions, and logged into a door-access console in the same estate with its vendor default password and queued 20 commands to five terminals. No command output from a pod is held, and no door is shown to have opened.
- Data left the estate in a way I cannot measure. Two small uploads of 441 bytes each reached the operator's collector from a source its log does not record, copies of victim data sit on the operator's server, and the volume that left is unknown. The operator's open directory then served 36 of those staged files to unrelated addresses, 180 times.
- My read of the operator is one person running several AI coding agents at once, and I hold that at LOW. Three other readings fit the same traces and I cannot exclude any of them.
- The detections do not depend on the model. An agent whose model address is outside the platform's catalogue, a tool-server entry with an inline interpreter call, and a worker-node role listing instances from a public address are the signals that held up, and the detection file carries 15 alertable rules built on them.
- This is the first case of its kind in our corpus. Section 11 sets out what is documented as research and what I am not aware of in the wild.

Overall risk: HIGH, because the operator held a cloud role credential and internal records for the estate (Section 2 sets out the basis). The activity is not shown to be current: the latest dated operator activity is 12:13Z on 31 October 2026, though the operator server still answered on 14 November on ports I did not analyse. The shared source-control credential has no known expiry, so the exposure outlasts the activity.

The affected parties have been notified. The rest of this note grades the victim by system, walks the mechanism, and gives the indicators, the detections and what I cannot say.

## 2. Victims: Who Was Hit and How Far the Operator Got
{: .hl-tier-2}
{: .hl-tab-victims}

The victim is a mobile-phone and consumer-electronics manufacturer, reached through the cloud estate it runs in a Hong Kong region, and that estate also hosts the physical access-control platform of one of its South Asian manufacturing sites. Below is the operator's target list, graded by what the operator's own files show, one organisation or group per row, and where two grades fit I record the lower. COMPROMISED means the operator holds material that only working access returns, but the route that produced it is not in anything I hold. REACHED means a response from the target is held in the operator's files and nothing more; a script written to reach a target, or a login tried, does not count. LISTED means the operator's files name the party and show nothing else.

Of the 2 rows, the grades are 0 ACCESS SHOWN, 1 COMPROMISED, 0 REACHED and 1 LISTED.

| Organisation | Grade | What the operator's files show | Latest dated evidence |
|---|---|---|---|
| A mobile-phone and consumer-electronics manufacturer: its Hong Kong cloud estate, agent platform, internal services, DevOps and source-control services, and a manufacturing site's door-access platform that is an instance in the same cloud account | COMPROMISED | A worker node's cloud role credential in the shape the node's metadata service returns, used from outside; an instance inventory of 1,162 records; internal service-registry records pulled by an unknown route; configuration and workspace writes on the agent platform that returned 200 in the one captured output | 2026-10-30 09:52:29 UTC, the credential's first dated use |
| The owner of another tenant's agent workspace on the victim's shared pods | LISTED | Scripts that read that tenant's workspace files, including a model-key field, off the pod filesystem; no output of the read is held | No dated evidence held |

The row is COMPROMISED and not ACCESS SHOWN because presence inside a pod is an inference. The credential reached the operator by a route I cannot identify, and a request forged from outside the pod would produce the same file. No held file excludes that, so under the rule that I never upgrade on inference, the lower grade stands. It would rise to ACCESS SHOWN on a relay console log naming worker hosts, the output of an operator command run in a pod, or a pod process listing.

The strongest pointer toward presence is a docstring in the operator's relay server script that says its statistics showed 182 dead and 207 live pod connections, about 389 workers. It is the operator's own text, undated, about an earlier version of the script, and no held log names a worker host. I carry it as a pointer and not as evidence of a run.

| System (by function) | Grade | What is held | What is not |
|---|---|---|---|
| Cloud account control plane | COMPROMISED | One temporary role credential, valid 6 h 11 m 11 s, used from outside; caller identity returned; 1,162 instance records across the 7 regions queried | Any write or execute call; account-wide completeness of the list is NOT CHECKED |
| Agent-platform configuration and workspace APIs | COMPROMISED | Configuration calls with minted headers that returned 200; one chat turn with a planted agent that returned 200 | Delivery of the planted payload and any tool-call output |
| Worker node and its agent pod | COMPROMISED | The metadata-shaped credential, whose issue time of 05:48:10Z is a lower bound on when it was fetched | Command output, a process listing, a victim-side log |
| Internal service registry | COMPROMISED | Records with live lease times, pulled by an unknown route | The route; the pull time of four larger health dumps (559 applications, 1,243 instances) is NOT CHECKED |
| DevOps admin panel | COMPROMISED | A saved 200 response that embeds a shared source-control credential | Whether that credential authenticated anywhere |
| Door-access console | COMPROMISED | The vendor default administrator login accepted, the console read, a data-push destination added and persisted | Execution of any queued terminal command |
| Source control | LISTED | The credential in scripts that try it four ways; the one held direct run shows every call timing out | A response of any kind from the source-control host |
| Container registry | REACHED | One guessed hostname answered HTTP 400 on one port | Any answer to the registry API calls the scripts make |
| Messaging tenant, configuration centre, one database | LISTED | Default-login and secret-exchange scripts, intended only | Any response |
| Five door terminals | REACHED | 20 commands queued: shell, unlock and 2 reboot commands | A return for any of them; all five read Offline afterwards, which fits a reboot without showing one |

The credential did little harm on its own. It belonged to a read-only role (5 of 78 permission probes were allowed) and expired 6 h 11 m after it was issued, at 11:59:21Z on 30 October. The exposure that is still open is the shared source-control credential, which has no known expiry and sat in a file fetched by six unrelated addresses.

## 3. Technical Classification: Configuration Written to Make a Platform Run the Operator's Code
{: .hl-tier-2}
{: .hl-tab-chain}

The capability here is a way of using an agent platform. The operator wrote the platform's own configuration so that one agent talked to a model server they controlled, and so that a tool-server entry ran a downloader without a model in the loop, and then built a reverse SOCKS relay so the platform's pods would be the egress and their server the console. I name no malware family. Every operator-written item in the directory is a Python or shell script or a data file, and no compiled operator-written binary is held (HIGH).

The scripted model endpoint and the model-free tool-server plant are the two pieces worth a defender's attention. Of the 422 captured files that bear on the agent platform, 108 are top-priority scripts for configuration rewrite, token minting, the plant and the scripted endpoint, which is the largest single body of work in the directory. The operator also used public tools: fscan 2.2.2, the gogo scanner, the bore tunnel client and a chisel build. Those are commodity and do not narrow who the operator is.

The sample set is 1,043 captured files of the 1,060 the directory listed, taken from one rented server. Other counts here use other bases: 1,042 held files for the dating figure in Section 5 (1,040 from the capture service plus 2 held only in the crawler's store, before the later chisel capture made 1,043), and 1,038 files for the output sweep in Section 13, a subset of the held files. The detection file's 1,040 is the capture-service count.

## 4. The Attack Chain: Token, Repoint, Plant, Relay
{: .hl-tier-2}
{: .hl-tab-chain}

The chain has seven stages, and the evidence thins as it goes. The first three are scripted with a captured 200 behind them, the fourth is code I read, and everything from the plant onward is intent shown with delivery and execution not shown.

| Stage | What the operator did | Where it is shown |
|---|---|---|
| 1. Mint a token | Called the gateway's mock login route with an empty JSON body and got a token pair, then sent every later call with a fixed header naming the platform's system principal; when the route started answering 405 they tried 24 variants (8 paths by 3 methods) | One captured output in which the 200s share one header set, MODERATE |
| 2. Register a private agent | Created an agent through the config service under an innocuous name, so that no other concurrent session (the operator's scripts call these "siblings") could rewrite its model block | Scripted |
| 3. Repoint the model | Wrote `config.json` under both owner scopes the platform accepts, published the agent (publishing rewrites the model block from the catalogue, which is the obstacle), then wrote `config.json` again with `llm.baseUrl` set to the operator's endpoint and a dummy key, without republishing, and pushed it into the running pod with the platform's reload route | One captured 200 and one planted-agent chat reply |
| 4. Answer with tool calls | Ran a small HTTP server in place of a model that returns the next queued tool call on every turn and logs each tool result the platform posts back | Code read, HIGH |
| 5. Plant a model-free entry | Wrote a workspace file declaring a stdio tool server whose command is `python3 -c` with a one-line downloader, started by a chat message or a reload | Intent shown; delivery and execution not shown |
| 6. Relay | Had the downloaded worker connect to the operator's relay, take a `host port` line and pipe a socket to it, so the relay and not the platform chooses targets | Worker class held; the exact planted payload is not held and has 0 logged requests |
| 7. Re-assert and evade the filter | Re-read and rewrote the operator block, reloaded and fired a chat in a claim-then-fire loop of six rounds, and staged a source-control credential through hex, octal escapes, a netrc file and a curl config to get past a command filter on the victim's platform | Scripted |

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/inv-2026-082-agent-platform-command-channel/inv-2026-082-command-relay-channel-map.svg" | relative_url }}" alt="Diagram of the operator's command and relay channel on a dark canvas, two columns joined by five numbered links. The left column is a box titled Operator's rented server, one host with roles split by port, holding three cards. A red card, Stage 4 scripted endpoint, is a fake model server that returns the next queued tool call each turn; marked code read, HIGH. A yellow card, Stages 5 to 6 payload server, covers payload download and the pod downloader; marked planted payload not held. A deep red card, Stage 6 reverse SOCKS relay, takes a host and port line and pipes a socket to it; marked no log names a worker host. The right column has an orange card, Stages 1 to 3 agent platform: token minted, private agent registered, config.json written with the model base URL set to the operator endpoint, then reloaded; marked captured 200s, MODERATE. Below it is a dashed box titled Pod: execution inferred, not shown, holding a dashed red card, Stage 5 MCP stdio plant, a model-free tool-server entry whose command is an inline downloader, delivery not shown, and a dashed deep red card, Stage 6 SOCKS worker, which dials the operator relay. Solid links: 1 operator to platform config write, 2 platform reload into the pod. Dashed links: 3 pod model turns to the scripted endpoint, 4 the plant fetching the worker, 5 the worker dialling the relay. A footer names two detection anchors and a colour legend.">
  <figcaption><em>Figure 1: The command and relay channel as one picture. Only the configuration write and reload have a captured 200 behind them; the pod and every link out of it are inferred, which is why the grade in Section 2 stays at COMPROMISED and not ACCESS SHOWN.</em></figcaption>
</figure>

The scripted endpoint is the part I have not seen described anywhere. It answers the model-list request with the platform's own model name so the catalogue check passes, then answers each completion request in the platform client's streaming format by popping the next item off a local step queue. Two copies differ only in state prefix and default port, a third is parameterised, and a versioned clone imitates a sibling's wire format. A single port on the operator server carries the endpoint and the tunnel worker together, because that was the one port the operator believed the pod could reach.

The model-free path matters more to a defender, because it removes the model from the detection picture. The stdio entry and the platform's runtime mode both execute tools directly. The same entry appears in three addressing variants: a bare address, a wildcard-DNS name for the same address, and a public tunnel port. The held worker's own docstring says it is launched as a stdio tool-server command.

I scanned 2,023 quoted strings across the 108 top-priority files and 165 matched a command kind:

| Command kind | Strings | Files |
|---|---|---|
| Reverse relay or SOCKS worker launch | 45 | 26 |
| Configuration re-assert | 42 | 41 |
| Download and run | 38 | 29 |
| Host and environment probes | 29 | 24 |
| Base64-wrapped shell | 6 | 6 |
| File staging | 4 | 4 |
| Credential-path read | 1 | not counted |

The "persistence" look of the re-assert strings is misleading, since true scheduler or cron markers occur in only 3 corpus files.

Delivery to a victim pod is not shown. The log lines that first looked like delivery are fetches of the operator's open directory by crawler-pattern addresses and other third parties. The operator's own scanners found nothing: the gogo sweep reports 0 alive over 49,152 address-port probes. The operator's undated docstrings blame a SOCKS client fault and a lost buffer. I rate that explanation MODERATE and the zero as no evidence of absent hosts, because a relay that was not yet working at 06:22 fits it equally.

## 5. Timeline
{: .hl-tier-2}
{: .hl-tab-timeline}

The dated activity runs from the early morning of 30 October to midday on 31 October 2026. The earliest log row is 06:22 on the server clock and the final tunnel connection is 12:13:43Z the next day, about 30 hours; counted from the first zone-explicit event, the cloud call at 09:52:29Z, it is about 26 hours. Times marked Z are UTC stated in the line itself. Times marked "server clock" come from the operator server's web logs, which print no zone, and I take them as UTC at MODERATE.

| Date | Observation |
|---|---|
| 2026-10-30 05:48:10 Z | The worker node's role credential is issued. This is the earliest possible fetch time and a lower bound, not an operator event: the fetch lies somewhere between here and the first dated use. |
| 2026-10-30 06:22 to 06:45 (server clock) | An internal sweep of three /24 ranges, 49,152 probes, runs through the server's local SOCKS listener and finds 0 alive. It is the earliest operator-generated event and shows aim through a relay, not that the relay worked. |
| 2026-10-30 09:52:29 Z | First dated cloud API call with the credential. |
| 2026-10-30 10:01 to 10:23 (server clock) | Port scans of the victim's public cloud hosts. |
| 2026-10-30 10:54:44 Z | First request reaches the operator's receive-only sink on port 8088. |
| 2026-10-30 10:55:37 Z | Two operator files are fetched by a Python urllib client with a spoofed user agent and no logged source address. It is the only held request that could be a payload fetch from the victim side, and I rate it INSUFFICIENT. |
| 2026-10-30 11:22:59 (server clock) | The operator's port-80 server starts publishing the working directory, and the exposure begins. |
| 2026-10-30 11:59:21 Z | The role credential expires. |
| 2026-10-30 14:33 to 14:37 Z | Latest lease renewals in the service-registry records. The route through the relay is inferred from a script, not a log line, so these times are a lower bound on the pull. |
| 2026-10-30 16:32 (server clock) | First bulk crawl of the open directory by an unrelated address. |
| 2026-10-30 22:34:43 Z | The operator's tunnel client connects on remote port 19620. |
| 2026-10-31 11:56:55 to 12:13:43 Z | Last operator-side activity in the corpus: tunnel connections, seen only in the later revision of the tunnel log. |
| 2026-11-14 | The operator server answers on 17 ports that match none of the October roles; one new binary (the chisel build) is listed. None of it is analysed. |

Only 42 of the 1,042 held files carry a timestamp, so 1,000 are undated. The 843 script files (623 Python and 220 shell by name) therefore give a volume and not a rate, and the 26 to 30 hour span bounds the logs, not the whole operation. One clock caveat travels with every server-clock time: a scanner's `GET /` appears at 17:36:56 in one log and 23:36:56 in the other, an exact six-hour offset, so the zone is not settled. A line carrying both a local and a UTC stamp would settle it.

## 6. Infrastructure: One Rented Server and a Shared Tunnel
{: .hl-tier-2}
{: .hl-tab-timeline}

Every operator role ran on one rented server, `198[.]44[.]116[.]69`, split by port, and nothing else in the corpus is operator-owned (HIGH). The roles that matter are these:

| Port | Role |
|---|---|
| 80 | Open directory of the whole working directory, the exposure |
| 8460 | Single-port front: the scripted model endpoint and the reverse-tunnel worker listener together, and the target of the agent base-URL rewrite |
| 8444, 8445, 8902, 9443 | Scripted-endpoint ports used as the agent base URL at different stages |
| 9004, 9100 | Reverse SOCKS entry and pod link |
| 9011 | Payload download: the worker, gogo and fscan |
| 19611 | Pod downloader for the planted payload |
| 8088, 9020, 9012, 9300 | Receive-only sinks and collectors, including the door console's data-push target |

The server's hosting is unresolved. WHOIS for the covering /24 names one provider and passive sources show another, which is consistent with a range announced under a second owner label, and the abuse contact is NOT CHECKED. I make no bulletproof-hosting claim.

The tunnel service is third-party. The operator ran the open-source bore client on the server and in the pod, and claimed a fixed remote port, 1811, on the public bore server, `bore[.]pub`, whose single address `159[.]223[.]110[.]159` serves every user of the service. It sits in the feed's hunt-only list, because a block there is a service block and not a takedown. The operator fought for that port with what its scripts call sibling sessions, a contest that matters for the operator read in Section 10.

The exposure the operator caused is a second finding. In the latest held revision of its web log, 36 distinct staged files in 13 directories were fetched with status 200, 180 times, by addresses that were not the operator's: 144 by seven crawler-pattern addresses and 36 by other fetchers. Three of those files are at the top of the victim's list: the DevOps panel response that embeds the shared source-control credential (6 fetches by 6 addresses), the full instance inventory (7 by 6), and the temporary credential file (8 by 7, all after it expired). The third parties are not shown to be actors.

The log records address, time, request line and status, with no user agent and no size, so no transfer size can be derived. No request arrives from a private-range address and no victim pod is identifiable in it. That is a limit and not an absence, and matching the pod's egress address against the 275 fetcher addresses would settle it.

## 7. MITRE ATT&CK Mapping
{: .hl-tier-2}
{: .hl-tab-chain}

I mapped the case to 50 procedure rows over 43 distinct technique IDs in 13 tactics of ATT&CK Enterprise v20.0, and this note carries the 21 rows that bear on the method and the outcome. The Status column uses three values. OBSERVED means I hold a result for the procedure, which includes a retained attempt that failed where the attempt is itself the procedure. INFERRED means the operator's tooling is built to do it and a request or script is held, but no execution result is. NOT SHOWN marks a boundary and claims no impact.

Of the 21 rows, 12 are OBSERVED, 7 are INFERRED and 2 are NOT SHOWN, and row confidence is HIGH on 11, MODERATE on 9 and DEFINITE on 1. OBSERVED never means a victim log, because I hold no victim telemetry: it is always the operator's own record or a saved response. Every row that depends on code running inside a pod is INFERRED at most.

Two things have no Enterprise technique. Repointing an agent's model endpoint, and a scripted endpoint built to drive a platform's tool loop, appear only by their effects, under Web Protocols and the execution rows. I considered prompt injection and rejected it, since the model is replaced or bypassed here and never prompted. Door-unlock commands, which have a physical effect, are also unmapped.

<details markdown="1" class="hl-teardown">
<summary>The 21 procedure rows, with status, confidence and evidence</summary>

| Tactic / Technique | Name | Status | Conf. | Evidence |
|---|---|---|---|---|
| Resource Development / T1587.001 | Malware | OBSERVED | MODERATE | Operator-written endpoint, relay and sink scripts |
| Initial Access / T1190 | Exploit Public-Facing Application | OBSERVED | MODERATE | Unauthenticated token route; the 200s share one header set |
| Initial Access / T1078.004 | Cloud Accounts | OBSERVED | HIGH | Node role credential used from outside, valid 6 h 11 m |
| Initial Access / T1078.001 | Default Accounts | OBSERVED | HIGH | Door console vendor default admin login accepted |
| Credential Access / T1552.005 | Cloud Instance Metadata API | INFERRED | MODERATE | Metadata-shaped credential held; fetch route unknown |
| Credential Access / T1552 | Unsecured Credentials | OBSERVED | HIGH | Panel response embedding the shared source-control credential |
| Execution / T1059.006 | Python | INFERRED | MODERATE | Stdio entry with inline downloader; execution not shown |
| Execution / T1059.004 | Unix Shell | INFERRED | MODERATE | 35 execute and 9 write-file tool steps queued |
| Execution / T1651 | Cloud Administration Command | OBSERVED | HIGH | Cloud assistant run-command denied with 403 |
| Stealth / T1027.010 | Command Obfuscation | INFERRED | MODERATE | Base64, hex and octal wrapping to pass a command filter |
| Discovery / T1580 | Cloud Infrastructure Discovery | OBSERVED | HIGH | 1,162 instance records, 7 regions queried |
| Discovery / T1526 | Cloud Service Discovery | OBSERVED | HIGH | 78 probes: 5 allowed, 42 denied, 30 inconclusive |
| Discovery / T1046 | Network Service Discovery | OBSERVED | HIGH | Port scans of the victim's public cloud hosts, outputs held |
| Discovery / T1018 | Remote System Discovery | OBSERVED | HIGH | Health dumps listing 559 applications, 1,243 instances |
| Collection / T1213 | Data from Information Repositories | OBSERVED | HIGH | Door console read: 21 users, 5 terminals, 20 attendance rows held (console counter reads 204,276) |
| Command and Control / T1572 | Protocol Tunneling | OBSERVED | HIGH | Operator bore client, 15 paired sessions |
| Command and Control / T1090 | Proxy | INFERRED | MODERATE | Reverse SOCKS relay; link to registry records rests on a script |
| Command and Control / T1105 | Ingress Tool Transfer | NOT SHOWN | HIGH | Delivery to a victim pod not shown; port-80 fetches are crawlers |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | INFERRED | MODERATE | Collectors built; two 441-byte POSTs received, source unlogged; volume unmeasured |
| Exfiltration / T1020 | Automated Exfiltration | INFERRED | MODERATE | Push destination persisted on the door console (observed); data flow to it NOT SHOWN |
| Impact / T1529 | System Shutdown/Reboot | NOT SHOWN | DEFINITE | 2 reboot commands queued; the reboot is not shown |

</details>

## 8. Indicators of Compromise
{: .hl-tier-2}
{: .hl-tab-indicators}

The indicators are operator-side only: the operator's server and ports, the URL paths it served, the scripts it wrote and the strings it chose. The machine-readable set is [`inv-2026-082-agent-platform-command-channel-iocs.json`](/ioc-feeds/inv-2026-082-agent-platform-command-channel-iocs.json), at TLP:CLEAR. It carries 92 operator-side indicator entries: 27 SHA-256 hashes, the operator's IP address, 21 host-and-port endpoints, 2 wildcard-DNS names, 30 URLs, 1 file path and 10 behavioural strings. The 92 are the entries the feed's validator read, and 3 further hunt-only entries sit outside them.

Hashes of operator scripts change with any edit, so the endpoints and strings carry more of the weight. Stock fscan and gogo are not listed by hash, because their hashes match anyone using the public tools. The shared tunnel service sits in the hunt-only list, since a block on it reaches every user of the service.

| Indicator | What it is | Confidence | Action |
|---|---|---|---|
| `198[.]44[.]116[.]69` | Operator server, every role by port | HIGH | Block, time-boxed: commercial hosting that can be reassigned |
| `198[.]44[.]116[.]69:8460` | Single-port front carrying the scripted model endpoint and the tunnel worker; target of the base-URL rewrite | MODERATE | Block, and hunt for it in agent configuration |
| `198[.]44[.]116[.]69:8444`, `:8445`, `:8902`, `:9443` | Scripted-endpoint ports used as an agent's model base URL at different stages | MODERATE | Hunt in `llm.baseUrl` values |
| `198[.]44[.]116[.]69:19611` | Pod downloader for the planted payload | MODERATE | Block |
| `198[.]44[.]116[.]69:9011` | Payload download server for the relay worker and the scanners | MODERATE | Block |
| `198-44-116-69[.]sslip[.]io` | Wildcard-DNS name for the operator server, used in the plant | HIGH | Block |
| `b660141d80bcc05457e881e2db687120677473c8d43c62b26c2c413fbd50b885` | `mcp_plant.py`, writes the tool-server entry with the inline downloader | HIGH | Block |
| `d08901561f5f60d5b1dccc6847f00e6a8cc474e6fae8351df05494d6e58b235a` | `own_llm.py`, scripted model endpoint | HIGH | Block |
| `76d901ac74f377e8dc2e307407ab4b1125e90ecae828dbfa8a67ebd19a4e2f85` | `hb.py`, reverse SOCKS worker for the pod | HIGH | Block |
| `039c18e9f936d5f8608a22a05f5964da5f64c9c1edc8441282b373414aa4a269` | Operator build of the public chisel tunnel (10,898,264 bytes), listed on a later sweep | MODERATE | Hunt: the tool is public |
| `/tmp/.hb.py` | Where the planted command writes the downloaded worker before starting it detached | MODERATE | Hunt on pod and workspace file systems |
| `mcpServers[].command` containing `python3 -c` that downloads from the operator | The planted tool-server entry | HIGH | Hunt in every agent workspace's tool file |
| `llm.baseUrl` outside the platform's model catalogue | The repoint | HIGH | Hunt in every agent's configuration |
| `rx-<epoch>` and `poc-agent` | Names of the private agents the operator created | HIGH | Hunt in agent listings |
| `bore[.]pub:1811` | The operator's claimed port on the shared tunnel server | HIGH | Hunt only, never block the host |

Several operator-chosen names in the feed come from cloud write scripts for which no output is held, such as key-pair and instance names beginning `probe-`. They are MODERATE or LOW hunt strings for the cloud audit trail in the window of 30 October 2026, and whether the calls ran is NOT CHECKED.

## 9. Detection and Hunting Guidance
{: .hl-tier-2}
{: .hl-tab-indicators}

The [detection file](/hunting-detections/inv-2026-082-detections/) for this case carries 15 alertable rules, 2 Detection and 13 Hunting: 4 YARA (1 detection, 3 hunting), 7 Sigma (1 detection, 6 hunting) and 4 Suricata (0 detection, 4 hunting), plus 4 informational Sigma building blocks that only feed correlation rules. Two Detection rules is a small number on purpose, because most of what the operator did went through a platform's own routes and a rented server. No rule has been confirmed against victim telemetry, since none exists in what I hold, and the Suricata signatures have not been replayed against a capture.

Four signals held up as durable and low-noise. An agent whose model base URL is outside the platform's catalogue is the repoint itself. A tool-server entry whose command is an inline interpreter call that downloads and runs a hidden file is the plant, and the Detection-tier YARA and Sigma rules key on it. A scripted endpoint that answers an agent with tool calls is the model server, and a hunting YARA rule covers its code shape. A worker-node role listing compute instances across several regions, or used from a public source address, covers the cloud half.

Nine of the 21 behaviours I considered have no rule, and each has a reason in the file's coverage section. One of them is the door-access console: its only distinctive strings are one vendor's own product routes, too narrow to be useful as a published rule, and without them it is the public Struts2 S2-045 payload that existing rulesets cover. The unauthenticated token route and the private-agent registration would need the gateway to log request bodies or response codes, which I have no sample of, and the right fix for the token route is to remove it. A base64-wrapped shell step is generic and I saw it only in operator scripts and never in process telemetry. I wrote no rule for the shared credential appearing in a command line, since the held value has no stable format.

Three of the Sigma rules key on the platform's routes, because a gateway log carries nothing else to key on. Whether the platform is a product others run is NOT CHECKED, so the three gateway Sigma rules carry placeholder paths, and a defender fills in their own platform's routes before using them.

## 10. Threat Actor Assessment
{: .hl-tier-2}
{: .hl-tab-attribution}

I cannot tie this operator to a named actor, persona or earlier case, and I assign no tracking designation. Nothing I hold carries a handle, a payment, a language tell or a working-hours pattern I could measure. The operator is external to the victim (HIGH): entry was an unauthenticated route on the victim's public gateway, the work was staged on a rented server outside the victim, and nothing points at an insider.

The operator's tradecraft is better described than their identity. They wrote Python at volume, 843 script files by name (623 Python and 220 shell), and used public scanners and tunnels. They were careful about the platform's command filter, with hex, octal, a netrc file and planted check scripts, and persistent about one contested tunnel port. No custom compiled implant is held (HIGH).

### Authorised or not

My judgment is that this was unauthorised intrusion and not a sanctioned test, and I hold that at MODERATE. Door-unlock commands queued to physical terminals, a data-push destination registered on a production system, and the victim's data left in a public directory are each outside what a sanctioned engagement does. None of the non-log, non-JSON, non-HTML files carries scope, authorisation or red-team language, and a control term that should hit did hit 25 files, so the sweep works. Against that, one created chat session is titled "pentest" and the scripts narrate their own failures.

A sloppy unsanctioned researcher remains possible, and it would change the motive and leave the harm where it is. The motive itself is undetermined, at LOW: no monetisation step is shown, and the work is collection-shaped, with an instance inventory, a service registry, source-control and DevOps credentials and a door-access console, and no destruction.

### The operator read

My read is that one person drove this, running several AI coding agents at once. I hold that at LOW. The scripts name "sibling sessions" that reset the shared agent's provider, contend for the fixed tunnel port and rewrite the same configuration. Nine top-priority files say "sibling", thirteen name the endpoint family `fakellm`, and seventeen reference the contested port.

That the siblings are one operator's concurrent sessions is better supported, at MODERATE, than that the sessions are AI agents. Everything shares one server, one working directory (370 file references), one shared agent object (named in 73 files) and one family of endpoint versions, and a second crew would be a stranger coincidence. What carries the AI reading is the style: 386 of the 623 Python files open with a module docstring by an AST count, and the scripts narrate failed earlier attempts. How many do so was not counted, and nothing ties the style to a coding agent.

Three alternatives fit the same traces and I cannot exclude any of them. The victim's own staff could have reset the agent's provider. Third parties could hold the operator's tooling after the first bulk crawl of the open directory at 16:32 on 30 October. Or a second party could be working alongside. Session or process metadata from the operator server would settle it, as would the docstring style compared against known coding-agent output.

### Linkage

No operator-side identifier recurs in my other investigations. I swept 10 operator-side strings (the server address, its two most-used port forms, three script names, the endpoint-family string and the fixed tunnel-port string) across 5,573 text files, with a control that reproduced, and found 0 other-case files. The limits are that a bare address cannot carry a link on its own, the sweep is a substring test on text files, and it does not see captured-evidence directories or binaries. So this is a recurrence negative at MODERATE, not a linkage finding.

| Hypothesis | Inconsistencies | Where it stands |
|---|---|---|
| One operator running concurrent sessions of AI coding agents | The docstring count is not a cadence; failure narration was not counted; nothing ties the style to an agent | My working read, LOW |
| One operator with several concurrent sessions, not necessarily AI | The sibling signal also fits the three readings below | MODERATE |
| The victim's own staff reset the agent's provider | A staff reset and an operator session produce the same observable | Not excluded; which party reset it is NOT CHECKED |
| Third parties hold the tooling after the 16:32 crawl | Not tested against any held process metadata | Not excluded |
| A second party works alongside | One server, one directory, one agent object and one endpoint family make a second crew a stranger coincidence | Not supported, not killed |
| A sanctioned test or bounty | No scope or authorisation language in the swept files; physical door commands; a data-push destination on a production system | Not supported, not killed: the one chat titled "pentest" stays unexplained |

| Call | What would change it |
|---|---|
| No named actor or persona, INSUFFICIENT | A second case holding any of the operator's identifiers, or session metadata from the server |
| External to the victim, HIGH | Evidence the operator held an insider's account before the token route |
| Unauthorised, MODERATE | The victim confirming or denying an authorised test or a bounty report for 30 to 31 October |
| Motive undetermined, LOW | A disclosure or bounty claim for the window, a sale or leak of the data, or reuse against a strategic target set |
| One operator, several sessions, MODERATE | Process or command-history metadata showing one operator account, or a second set of credentials |
| Parallel AI coding agents, LOW | Docstring style matched against known coding-agent output, or session metadata from the server |

## 11. What Is New and What Is Not
{: .hl-tier-2}
{: .hl-tab-confidence}

Each mechanism here is documented as research, and I am not aware of a published in-the-wild case that combines them. Gateway endpoint repointing with tool calls injected downstream of the model was published in August 2026, and stdio command execution through an agent platform's tool-server configuration in April 2026. This is the first such case in our corpus, and the wording claims the configured combination, not two working channels, because execution is not shown for either. I hold that at MODERATE. A vendor or CERT report of a hands-on agent-platform intrusion that my search did not index would move it.

| Mechanism | Published as | Source |
|---|---|---|
| A model endpoint repointed, with tool calls injected | Gateway form: an administrator changes a model's API base to an attacker gateway; research and red-team technique, no victim case | Embrace The Red, August 2026, restated by Cloud Security Alliance research notes |
| A rogue endpoint receiving real agent sessions | A honeypot received a real coding-agent session and did not cause any tool execution | SANS Internet Storm Center diary 33298, August 2026 |
| A stdio tool-server entry whose command is the payload | Command execution from an agent product's Model Context Protocol (MCP) configuration; vulnerability research, no in-the-wild case on the pages | OX Security, April 2026 |
| A pod reaching the cloud metadata endpoint in an incident run by an AI agent | In the wild, generic; also prior art for the AI-operator framing | Qualys mapping of a Hugging Face intrusion, August 2026 |
| An assistant's extensibility used to run code | In the wild: a poisoned internal AI repository and tampered CLI hooks, giving remote code execution | Mandiant, AI risk and resilience in 2026 (September 2026), case study 3 |
| An LLM co-debugging an attacker's harvesting framework | In the wild: prior art for the AI-assisted operator framing | Mandiant, same report, case study 2 |

The Mandiant hook-tampering case is the nearest in-the-wild one, and it is adjacent. It does not describe a model endpoint repointed, a tool-server entry run as a command, or a tool loop used as a relay. Its case study 2 and the Qualys incident, with an AI agent as the actor, are prior art for reading an operator as an AI-assisted one, which bears on Section 10.

Whether the victim's platform is bespoke or a product other organisations run is NOT CHECKED, and it decides the audience. The class is not bespoke by nature, since many productised agent platforms have a UI that runs stdio commands. If it is a product, the route-level rules have readers; if it is bespoke, they apply to one company's deployment. No CVE is asserted: these are configuration weaknesses on the victim's side, not product vulnerabilities.

## 12. Recommendations
{: .hl-tier-1}
{: .hl-tab-indicators}

An internal agent platform is an execution environment, and this case says to defend it like one. Its configuration writes, model endpoints and tool-server entries are the attack surface, and the points below come from what this operator did.

- Audit every agent's model base URL against the platform's model catalogue. The repoint is one configuration value, it survives until someone looks, and the platform's own publish step rewrites it back, which is why the operator wrote it after publishing.
- Audit every agent workspace's tool-server file for a stdio command that is an inline interpreter call, especially one that fetches from an address or writes a hidden file to a temporary directory. That entry runs without a model, so no model-side guardrail sees it.
- Remove or authenticate any token route that answers an empty request. Here a single unauthenticated route was the start of the whole chain, and the minted tokens were cached and reused after the route began to fail.
- Narrow the worker-node role so it cannot list instances across regions or be used from a public address. The credential in this case did limited harm because its role was read-only (5 of 78 permission probes allowed), and it listed 1,162 instances from outside.
- Change vendor default logins on admin consoles in the same estate and check what any added data-push destination points at. The door console accepted its default administrator login and then took a new receiver that persisted.
- Treat a shared source-control credential in a saved admin-panel response as exposed. It has no known expiry here and was fetched by six unrelated addresses from the operator's open directory.

## 13. Confidence Summary and Evidence Gaps
{: .hl-tier-2}
{: .hl-tab-confidence}

The case rests on the operator's own files: scripts, logs and saved responses captured from its open directory. That makes the evidence strong on what the operator wrote and attempted and silent on what the victim's systems recorded, because I hold no victim-side log. The gaps that matter most are the missing command output, the missing upload-handler logs, and the two newest web-server log revisions, which are not held. Each load-bearing judgment below carries the observable that would move it.

| Claim | Confidence | What would change it |
|---|---|---|
| The victim is COMPROMISED, and ACCESS SHOWN is not supported | HIGH | A relay console log naming worker hosts, stdout of an operator command run in a pod, or a pod process listing |
| The scripts implement the repoint, the scripted endpoint and the plant | HIGH | A script version I do not hold that does something different |
| The configuration writes took effect on the platform | MODERATE | The agent's configuration as stored on the platform for 30 to 31 October |
| Payload delivery to a victim pod | NOT SHOWN, and HIGH that it is not shown | The pod's egress address matched against the 275 fetcher addresses, or the planted payload itself |
| The role credential was used from outside | HIGH | The cloud audit trail for the role |
| 1,162 instance records across 7 regions | HIGH for the dump, MODERATE for the account | The full instance count of the account |
| Copies of victim data sit on the operator's server | DEFINITE | Nothing; the files are held |
| How much data left | INSUFFICIENT | The receivers' upload logs, which are not held |
| 20 door commands were queued | DEFINITE | Terminal command logs, which would show effect |
| The shared source-control credential authenticated | INSUFFICIENT | The source-control host's authentication log for 30 to 31 October |
| Unauthorised, not a sanctioned test | MODERATE | The victim confirming an authorised test for the window |
| One person running several AI coding agents | LOW | Session metadata from the operator server |
| First such case in our corpus; no published in-the-wild equivalent known | MODERATE | A vendor or CERT report of a hands-on agent-platform intrusion that my search did not index |

What I cannot say is also part of the result. I cannot say that any command returned output, that a door opened, that the source-control login worked, or that the intrusion is live at the victim today. The latest dated operator activity is 12:13Z on 31 October 2026, and the operator server answered on 14 November on a port set that matches none of the October roles, with nothing on those ports analysed.

The evidence gaps, none of them closed:

- Output of any command run in a pod. No stdout of any operator command is held, and 0 of 1,038 files swept hold a root-id line, a stdout field or a tool-result marker outside the platform's own API specification.
- The exact planted payload. It is in 0 of 1,060 inventory rows and has 0 logged requests.
- Whether the cloud-side write scripts ran: key-pair creation and import, instance creation, set-description, reboot and delete. No output is held for any.
- The pod's egress address, and the origin of the 10:55:37Z urllib fetch, which could be a pod or an operator test.
- Whether attendance data ever flowed to the operator, and whether any door command executed.
- The contents of the six source-control repositories named in the panel response.
- 17 listing rows the capture could not obtain, 18 capture summary items missing from the archive, and the operator host's 17 current ports. Another 284 ports timed out.
- The hosting abuse contact, since two provider names conflict.
- Every detection rule against victim telemetry or a packet capture.

## 14. References
{: .hl-tier-2}
{: .hl-tab-confidence}

- Embrace The Red, Wunderwuzzi (3 August 2026): [LLM Heist: Hijacking LiteLLM for Traffic Interception, Key Theft, and Tool-Call Injection](https://embracethered.com/blog/posts/2026/hijacking-litellm-for-fun-and-profit/), the gateway form of endpoint repointing with tool calls injected downstream of the model.
- Cloud Security Alliance Labs (20 August 2026): [LLM Heist: Post-Compromise Abuse of LiteLLM Gateways](https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-gateway-hijacking-llm-heist-202608/), a research note that restates the first and cites it as its source.
- SANS Internet Storm Center (31 August 2026): [The Coding-Agent Trap: When a "Free" LLM Endpoint Is the Adversary](https://isc.sans.edu/diary/33298), a honeypot that received a real coding-agent session.
- OX Security (April 2026): [The Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp), command execution through an agent product's MCP configuration.
- Qualys (26 August 2026): [Hugging Face AI-agent intrusion, Qualys detection mapping](https://blog.qualys.com/product-tech/2026/08/26/hugging-face-ai-agent-intrusion-qualys-detection-mapping), an incident in which a pod reached the cloud metadata endpoint and the actor was an AI agent.
- Mandiant (September 2026): [AI risk and resilience in 2026](https://cloud.google.com/security/resources/ai-risk-and-resilience-2026), case study 3 on tampered assistant hooks and case study 2 on an LLM co-debugging an attacker's framework.
- Google Threat Intelligence Group (8 September 2026): [From Prompting to Autonomy](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai), actors targeting agent configuration files that store keys and custom endpoints.
- Microsoft DART (3 November 2025): [SesameOp](https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/), a provider API used as a command channel, a different mechanism.
- Invariant Labs (1 April 2025): [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification), the poisoned tool description, adjacent and not a command entry.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
