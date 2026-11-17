---
title: "Detection Rules: INV-2026-082 Cloud and AI-Agent Intrusion"
date: '2026-11-14'
layout: post
permalink: /hunting-detections/inv-2026-082-detections/
hide: true
---

**Campaign:** INV-2026-082
**Date:** 2026-11-14
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 3 | T1059.006, T1105, T1071.001, T1090 | 0 |
| Sigma | 1 | 6 (plus 4 building-block rules) | T1059.006, T1105, T1572, T1090, T1580, T1078.004, T1565.001, T1110 | 0 |
| Suricata | 0 | 4 | T1572, T1105, T1041 | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader or key on a name the operator can change, for scoping and threat-hunting. Expect to review the hits.

The file carries 15 alertable rules (2 Detection, 13 Hunting) and 4 informational building blocks that exist only to feed correlation rules. Two Detection rules is a small number on purpose. Most of what the operator did went through a victim platform's own routes and a rented server, so the durable, low-noise signals are few. Everything I considered and did not write is listed under Coverage Gaps with its reason.

---

## How this file was built, and what it does not claim

These rules come from a static reading of an operator's open directory (1,040 files captured from one rented server). The operator held a temporary cloud credential with the shape a node metadata service issues, which reached them by a route I could not identify, and configured an enterprise AI-agent platform's own routes to serve as an execution channel into a victim's Kubernetes pods. Execution inside a pod is inferred, not shown, and no command output is held, so which commands ran is not shown. I found no victim-side telemetry, so no rule below was confirmed against a victim log. Where a rule depends on how a product logs an event, it says so and the Validation line reads NOT CHECKED for that part.

**Behaviours considered.** The 15-step agent-platform chain (17 items counting steps 2a and 2b) plus four other threads: the cloud credential, source control, the door-access platform probes, and the receivers and tunnels. That is 21 behaviours. Twelve have at least one rule here (chain steps 4, 5, 6, 7, 9, 11, 13, 14 and 15, and three of the four threads). Nine are in Coverage Gaps or Considered and Cut with a reason (steps 1, 2, 2a, 2b, 3, 8, 10 and 12, and the door-access probes).

**The rules are operator-side and environment-neutral.** Account ids, agent ids, internal hostnames and credentials are specific to each environment and a defender adds their own. Whether the agent platform is bespoke or a product others run is NOT CHECKED, so the three gateway Sigma rules carry placeholder paths, and the defender fills in their own platform's routes. The publish, then save, then reload ordering is what carries over. The product's own service names and model names are left out. The only operator values are public: the operator address and ports go to the IOC feed, and bore.pub is a shared third-party service.

**Validation in numbers.**

- YARA: 5 rules, `yarac` 4.5.8 on the workstation and on the lab peer, 0 errors, 0 warnings. Hit test against the peer copy of the corpus: 1,040 files scanned, 48 distinct files hit, every hit inside the target family it was written for (per-rule counts under each rule). Benign check: 0 hits in 8,069 workstation files and 0 hits in 98,283 peer files. Known false negative: `mcpx.py`, a reverse-worker variant that dials with a different call, is not matched.
- Sigma: `sigma check` with the SigmaHQ configuration: 0 errors, 0 condition errors, 0 issues over 6 files. `tests/test_rules.py` OK. `yamllint`: 0 errors, 5 document-start warnings (the multi-document correlation files). `tests/test_logsource.py` FAILS on the two cloud correlation and base files because SigmaHQ has no `alibaba` logsource, so those cannot go upstream as written. Converted to Lucene and EQL with the `ecs_windows` pipeline: the 3 plain rules convert on both; the 3 correlation files fail on Lucene ("Backend does not support correlation rules") and convert on EQL.
- Whole-file gate: `detection-validation.py` PASS, 0 errors, 5 warnings. The warnings are prevalence NOT CHECKED on all 4 Suricata rules (no Webamon key set) and prior art NOT CHECKED on the Alibaba rule (no canonical logsource class).
- Suricata: `suricata -T` on the sensor accepted all 4 rules. No packet capture exists for this case, so the replay gate is NOT CHECKED.

---

## Multi-Family Organization

Rules are grouped by the operator tool family or the platform they act on, as a bold label inside each tier: **MCP Plant**, **Scripted LLM Endpoint**, **Relay Workers**, **Cloud Credential**, **Agent Platform Gateway**, **Source Control**, **Tunnel**.

## YARA Rules

The rules scan text, not PE or ELF files, so none carries a magic-byte check. They are meant for pod and workspace file systems, operator hosts and collected script directories. Every hit count below is a count of files in the peer copy of the corpus (1,040 files, scanned recursively).

### Detection Rules

**MCP Plant**

#### MAL_AgentPlatform_MCP_Stdio_Python_Downloader_Plant

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1059.006 (Python), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. A legitimate MCP server entry runs a named server program; one whose command is `python3 -c` with an inline URL fetch, a write to a hidden `/tmp/.x.py` and a `Popen` of that file is a downloader. 0 hits in 8,069 workstation files and 0 in 98,283 peer files (Python, JSON, JS and shell under system and tool directories).
**Blind Spots:** Misses a plant that downloads with curl or wget, with a different interpreter, or that does not write a hidden file. Misses a tools file that holds the code in an escaped form the regexes do not allow for. Does not see a plant held only in memory or in a database.
**Validation:** Hit test on the corpus: 9 of 9 hits are plants (the `tools.json` backup `bak_tools.json` and 8 operator scripts, each of which also names the operator host or a bore address). Control: `mcp_plant.py` hit. 1,031 other files, 0 hits.
**Deployment:** Workspace volumes of agent pods, agent-platform config storage, operator and staging hosts. A benign case that must not fire: any MCP config whose stdio command is a named server binary.
**Basis:** The operator's `tools.json` bootstrap in three addressing variants and one held backup of the planted file, all with the same python3 -c downloader shape (`mcp_plant.py`, `mp2.py`, `mp3.py`, `wt.py`, `i1.py`, `bak_tools.json`).

```yara
rule MAL_AgentPlatform_MCP_Stdio_Python_Downloader_Plant {
   meta:
      description = "Detects a stdio MCP server entry whose command is python3 -c with an inline downloader (fetch a URL, write the bytes to a hidden .py under /tmp, start it with subprocess.Popen), either as a tools.json workspace file or as the operator script that writes one"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/"
      date = "2026-11-14"
      hash1 = "b660141d80bcc05457e881e2db687120677473c8d43c62b26c2c413fbd50b885"
      hash2 = "85b27a02024523973d2b12621e944856f62011d6"
      hash3 = "4b1397ff3c226feaa5034913ba1b87fa"
      family = "AgentPlatform-MCP-Plant"
      id = "27a257cc-c52f-5ba2-9b40-7ec4e9fe18cd"
   strings:
      $mcp = "mcpServers" ascii
      $stdio = /\\?"transport\\?"\s*:\s*\\?"stdio\\?"/ ascii
      $cmd = /\\?"command\\?"\s*:\s*\\?"python3?\\?"/ ascii
      $dashc = /\\?"args\\?"\s*:\s*\[\s*\\?"-c\\?"/ ascii
      $fetch = "urllib.request.urlopen(" ascii
      $drop = /open\('\/tmp\/\.[A-Za-z0-9_]{1,16}\.py','wb'\)\.write\(/ ascii
      $spawn = /subprocess\.Popen\(\['python3?','\/tmp\/\.[A-Za-z0-9_]{1,16}\.py'/ ascii
   condition:
      filesize < 100KB and all of them
}
```

### Hunting Rules

**Scripted LLM Endpoint**

#### MAL_AgentPlatform_Scripted_LLM_Endpoint_SSE_ToolCall_Queue

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**ATT&CK Note:** The endpoint is a command channel carried over an ordinary model-API protocol; no technique names that, so I used the closest transport technique.
**Confidence:** MODERATE
**False Positives:** A test double for an agent framework that replays canned tool calls over server-sent events would match. I found none in the 8,069 workstation files or 98,283 peer files, but those are not full coverage of developer repositories.
**Blind Spots:** Misses a rewrite that uses another web framework or another event vocabulary, and the `mcpx`-style variants that do not carry every event name.
**Validation:** Hit test: 6 of 6 hits are the endpoint family (`own_llm.py`, `axllm.py`, `own_llm3.py`, `own_llm4.py`, `my_llm.py` and a versioned `int_llm_*` clone). 1,034 other files, 0 hits. Synthetic-fixture self-test PASS; `yarac` 4.5.8 0 errors on workstation and peer.
**Deployment:** Operator hosts, pod volumes, collected directories. Hunting because a legitimate mock server can look the same.
**Basis:** The scripted endpoint answers the platform's model call with the next queued tool call and logs the tool output the platform posts back (`own_llm.py`).

```yara
rule MAL_AgentPlatform_Scripted_LLM_Endpoint_SSE_ToolCall_Queue {
   meta:
      description = "Detects a small Python HTTP server that imitates a Responses-style LLM endpoint: serves server-sent events with function_call items, pops the next tool call from a local step file on every turn, and records the function_call_output the platform posts back"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/"
      date = "2026-11-14"
      hash1 = "d08901561f5f60d5b1dccc6847f00e6a8cc474e6fae8351df05494d6e58b235a"
      hash2 = "ed8f4c3047685131e5e8b3e6b6ea90176fd3c1ee"
      hash3 = "5b24067a14a490742421af01960ce996"
      family = "AgentPlatform-Scripted-LLM"
      id = "63c56d31-99fc-5cd9-a973-f646c4fcc401"
   strings:
      $ev1 = "response.output_item.added" ascii
      $ev2 = "response.function_call_arguments.delta" ascii
      $ev3 = "response.function_call_arguments.done" ascii
      $in = "function_call_output" ascii
      $fc = /"type"\s*:\s*"function_call"/ ascii
      $sse = "text/event-stream" ascii
      $srv1 = "BaseHTTPRequestHandler" ascii
      $srv2 = "ThreadingHTTPServer" ascii
      $json1 = "json.loads(" ascii
      $json2 = "json.dumps(" ascii
   condition:
      filesize < 64KB and all of ($ev*) and $in and $fc and $sse and 1 of ($srv*) and all of ($json*)
}
```

**Relay Workers**

#### MAL_ReverseSOCKS_Pod_Worker_Host_Port_Line_Ack_Protocol

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090 (Proxy)
**Confidence:** MODERATE
**False Positives:** A handshake test server or a small port-forwarding helper that acks with the bytes 1 and 0 after a dial would match. 0 hits in the benign sets named above.
**Blind Spots:** Misses a worker that dials with another call (`mcpx.py` in the corpus), reads a different line format, or is rewritten in another language.
**Validation:** Hit test: 5 of 5 hits are reverse workers (`hb.py`, `muxpod.py`, `mxpod.py`, `mxpod2.py`, `pxmcp2.py`). 1,035 other files, 0 hits. Known false negative: `mcpx.py`. `yarac` 4.5.8 0 errors on workstation and peer. Self-test on a synthetic fixture built from the rule's own strings: PASS.
**Deployment:** Pod volumes and operator directories. Hunting because the whole shape is a convention of one author's scripts, which they can change in an afternoon.
**Basis:** The pod worker holds idle sockets to a relay, reads a host and port line, dials it, answers 1 or 0, then pipes (`hb.py`, `muxpod.py`).

```yara
rule MAL_ReverseSOCKS_Pod_Worker_Host_Port_Line_Ack_Protocol {
   meta:
      description = "Detects the pod-side worker of a reverse SOCKS pair: holds idle sockets open to a relay, reads a newline-terminated host and port line, dials it, answers with the single byte 1 or 0, then pipes the sockets"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/"
      date = "2026-11-14"
      hash1 = "76d901ac74f377e8dc2e307407ab4b1125e90ecae828dbfa8a67ebd19a4e2f85"
      hash2 = "5b87c465ca646b21ef18a62c5c18116b0056f4a6"
      hash3 = "9119df78f2c4f737145c7d392bba6573"
      family = "ReverseSOCKS-Pod-Worker"
      id = "8ce0d078-78bb-5f69-9950-745e07155de7"
   strings:
      $ack1 = /\.sendall\(b"1"\)/ ascii
      $ack0 = /\.sendall\(b"0"\)/ ascii
      $dial = /create_connection\(\(host, ?(int\()?port/ ascii
      $nl = "\\n" ascii
      $thr = "threading.Thread(" ascii
   condition:
      filesize < 32KB and all of them
}
```

#### MAL_Pod_Socks5_Relay_Batch_Helper_Docstring_Family

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090 (Proxy)
**Confidence:** MODERATE
**False Positives:** Another project that copies the same helper header would match; I know of none. 0 hits in the benign sets.
**Blind Spots:** Anchored on docstring and comment text the author chose, so any edit to those lines evades it. It is a family finder for these 24 files, not a behaviour rule.
**Validation:** Hit test: 24 of 24 hits are the numbered `pod_b*m.py` helpers, which are every file in the corpus carrying the header. 1,016 other files, 0 hits. `yarac` 4.5.8 0 errors on workstation and peer. Self-test on a synthetic fixture built from the rule's own strings: PASS.
**Deployment:** Collected directories and pod volumes, to find the rest of a batch once one is known.
**Basis:** The shared header of the `pod_b1m.py` to `pod_b25m.py` scripts (24 held). Robustness 1 because the anchors are free text.

```yara
rule MAL_Pod_Socks5_Relay_Batch_Helper_Docstring_Family {
   meta:
      description = "Detects the numbered in-pod SOCKS5 relay helper scripts that share one module header: a minimal bidirectional relay with a half-close pump, a getaddrinfo-based connect helper and a subprocess shell helper"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/"
      date = "2026-11-14"
      hash1 = "6166a55d058ce8cddacd2e458c340e6e5280fade0852d87a16095de995b81da3"
      hash2 = "959b9a062e8a336016dea8f0b9ea4a9c40cb60f7"
      hash3 = "4609a8f6e268aaf6090e9d8bf69a9488"
      family = "Pod-Socks5-Relay-Helpers"
      id = "0e8375d9-64d0-5524-b21d-8ea6725ed447"
   strings:
      $doc = "Minimal in-pod socks5 relay" ascii
      $pump = "half-close b so the peer sees EOF" ascii
      $conn = "def conn(host, port, to=8)" ascii
      $noaddr = "raise IOError(\"noaddr\")" ascii
      $s5 = /b"\\x05\\x00"/ ascii
   condition:
      filesize < 64KB and 4 of them
}
```

---

## Sigma Rules

### Detection Rules

**MCP Plant**

#### Python Inline Downloader Writing A Hidden Script To Tmp And Spawning It

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1059.006 (Python), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Installer or bootstrap one-liners that fetch a script into a hidden temporary file and start it. I know of no routine software that does all four things in one `python -c` program.
**Blind Spots:** Misses a downloader written with curl, wget or another interpreter, a program longer than the logger keeps, and hosts with no command-line logging. I did not see this process event in any telemetry: the command comes from the plant's own string, and the platform runtime executes that string.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Converts to Lucene and EQL with `ecs_windows` (Linux field names are left unmapped by that pipeline, so the deployed ECS mapping is NOT CHECKED). Benign case that must not fire: `python3 -c 'import sys; print(sys.version)'`. Upstream: 0 files in the SigmaHQ clone (dated 2026-09-12) contain `urlopen`, but I did not read the conditions of general python one-liner rules.
**Deployment:** Linux process creation with full command lines on agent pods and servers, from auditd or an EDR feed.
**Basis:** The command string in the planted `tools.json` entry, which the agent runtime starts directly (`mcp_plant.py`, `bak_tools.json`). Robustness 2: the invariant is the download, write and spawn, not the file name or host.

```yaml
title: Python Inline Downloader Writing A Hidden Script To Tmp And Spawning It
id: 0b0d8ba2-0394-49c8-a0b1-d6ca6b03ad64
status: experimental
description: >-
  Detects a python interpreter started with an inline -c program that fetches a URL with urlopen, writes the bytes to a hidden file under /tmp and starts it with Popen.
  An AI-agent platform runtime executes exactly this command when a workspace tools file declares a stdio MCP server whose command is python3 -c, which gives the planter code execution without the model in the loop.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.execution
    - attack.t1059.006
    - attack.command-and-control
    - attack.t1105
    - stp.3
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
    definition: 'Requires process creation logging that populates the full CommandLine, for example auditd execve records normalised to process_creation or an EDR process feed. Inline programs longer than the logger truncation limit are not matched.'
detection:
    selection_img:
        Image|contains: '/python'
    selection_cmd:
        CommandLine|contains|all:
            - ' -c '
            - 'urlopen('
            - 'Popen('
            - '/tmp/.'
    condition: all of selection_*
falsepositives:
    - Unlikely, installer or bootstrap one-liners that fetch a script into a hidden temporary file and start it
level: high
```

### Hunting Rules

**Tunnel**

#### Bore Tunnel Client Exposing A Local Port Through A Remote Server

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1090 (Proxy)
**Confidence:** HIGH
**False Positives:** Developers who use bore to share a local service during testing.
**Blind Spots:** Misses a renamed binary (the rule keys on the image name ending in `/bore`) and a client that is not bore.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Converts to Lucene and EQL. NOT CHECKED against live process telemetry.
**Deployment:** Linux process creation on servers and pods where no one should publish a local port.
**Basis:** `bore local PORT --to bore.pub` run on the operator's server and written to run in a victim pod (`bore_up.sh`, `claim1811.sh`, `bore9101.sh`; 8 distinct command shapes in the corpus).

```yaml
title: Bore Tunnel Client Exposing A Local Port Through A Remote Server
id: a8893ad2-acdd-4ae4-8118-f1c020c52dbc
status: experimental
description: >-
  Detects the open-source bore client run as bore local PORT --to SERVER, which publishes a local TCP port on a remote rendezvous server.
  The operator in INV-2026-082 ran it on a rented server and, by the scripts that were written to run in a pod (execution there inferred, not shown), in a victim pod to expose the scripted LLM endpoint, a payload server and a result receiver on public ports of the free bore.pub server.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
    - https://github.com/ekzhang/bore
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.t1090
    - stp.2
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
    definition: 'Requires process creation logging with CommandLine, for example auditd execve normalised to process_creation or an EDR process feed.'
detection:
    selection:
        Image|endswith: '/bore'
        CommandLine|contains|all:
            - ' local '
            - ' --to '
    condition: selection
falsepositives:
    - Developers who use bore to share a local web service during testing
level: medium
```

**Cloud Credential**

#### ACK Worker Node Role Listing Compute Instances In Several Regions (with base rule)

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1580 (Cloud Infrastructure Discovery)
**Confidence:** MODERATE
**False Positives:** A cross-region inventory or cost tool that was granted the node role. A node role belongs to one cluster in one region, so a single event from the base rule is normal.
**Blind Spots:** Needs ActionTrail in the SIEM with the documented field names. I read the field list from the vendor page; I did not see a real event. The default role name prefix is assumed. The EQL conversion of the correlation is `sequence by userName [..] by acsRegion with runs=4`, which counts four events in the same region, not four distinct regions, so it does NOT express this rule. Lucene cannot run it. Only a backend that supports distinct-count correlation can, and I did not test one.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Lucene: base converts, correlation unsupported. EQL: base converts, correlation converts but with the wrong meaning (above). `tests/test_logsource.py` FAILS (no `alibaba` logsource in the SigmaHQ taxonomy), so this file cannot go upstream as written. Hunting, not Detection, because I cannot show it runs correctly on the stack I have.
**Deployment:** ActionTrail management events in a SIEM that supports value_count correlation.
**Basis:** One temporary node-role credential returned 1,162 compute-instance records across the 7 regions queried (account-wide completeness NOT CHECKED), from the operator's own host (`03_ecs_dump.py`, `ecs_all.json`; probe results `probe2.json`). Robustness 3 for the behaviour, Hunting for the deployability.

```yaml
title: ACK Worker Node Role Session Calling DescribeInstances
id: 57f7d699-d6a3-4aad-a28a-8c2c10347b74
name: ack_worker_role_describeinstances
status: experimental
description: >-
  Detects an ActionTrail event in which a session of the default managed-Kubernetes worker node role calls the compute DescribeInstances API.
  The node role's own agents call it for their own region, so a single event is normal and the rule is the base of the multi-region correlation in this file.
  In INV-2026-082 a temporary credential with the shape of a node metadata-service credential was used to list every compute instance in 7 regions.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
    - https://www.alibabacloud.com/help/en/actiontrail/user-guide/management-event-structure
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.discovery
    - attack.t1580
    - stp.3
    - detection.emerging-threats
logsource:
    product: alibaba
    service: actiontrail
    definition: 'Requires ActionTrail management events delivered to the SIEM as JSON with the documented field names (eventName, userIdentity.type, userIdentity.userName, sourceIpAddress, acsRegion). The default worker node role name prefix KubernetesWorkerRole is an assumption about clusters created with default settings; renamed roles are missed.'
detection:
    selection:
        eventName: 'DescribeInstances'
        userIdentity.type: 'assumed-role'
        userIdentity.userName|startswith: 'KubernetesWorkerRole'
    condition: selection
falsepositives:
    - Node role agents and cluster autoscaler calling DescribeInstances for their own region
level: informational
---
title: ACK Worker Node Role Listing Compute Instances In Several Regions
id: eb1c1dcc-2dc5-4a4f-8039-1d889f29ec1d
status: experimental
description: >-
  Detects a single worker node role session calling DescribeInstances in four or more regions within 15 minutes.
  A node role belongs to one cluster in one region, so a sweep across regions is a stolen credential being used to inventory the account.
  The INV-2026-082 operator swept 7 regions with one temporary node-role credential and held a 1,162-instance inventory afterwards.
  Needs ActionTrail events and a backend that supports Sigma correlation (value_count).
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.discovery
    - attack.t1580
    - stp.4
    - detection.emerging-threats
correlation:
    type: value_count
    rules:
        - ack_worker_role_describeinstances
    group-by:
        - userIdentity.userName
    timespan: 15m
    condition:
        gte: 4
        field: acsRegion
falsepositives:
    - A cross-region inventory or cost tool that was granted the node role
level: high
```

#### ACK Worker Node Role Session Used From A Public Source Address

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1078.004 (Cloud Accounts)
**Confidence:** LOW
**False Positives:** Every node that reaches the API through a public address or a NAT gateway, and cloud services that report a service identifier in the source field. This rule cannot work without a local filter for your own egress.
**Blind Spots:** Cannot name "outside the cloud": it only excludes the private ranges. Misses use of the credential from inside the victim's own address space.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Converts to Lucene and EQL. Not applied to real ActionTrail data. Same `alibaba` logsource limit as above.
**Deployment:** ActionTrail in a SIEM, after a local egress filter is added.
**Basis:** The credential was used from the operator's own host while its role was bound to a cluster node (`ali.py`). I treat the source field as the only available discriminator.

```yaml
title: ACK Worker Node Role Session Used From A Public Source Address
id: bb9d396e-a73b-4bd0-8c09-74acc0fc7c2e
status: experimental
description: >-
  Detects an ActionTrail event in which a session of the default managed-Kubernetes worker node role makes an API call from a source address outside the private ranges.
  A node role credential is issued to code running on the node, so a call from an address that is neither the node nor your own egress is a stolen credential.
  This rule cannot know your egress ranges, so every node that reaches the API through a public address or NAT needs a filter before the rule is usable.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
    - https://www.alibabacloud.com/help/en/actiontrail/user-guide/management-event-structure
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.persistence
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1078.004
    - stp.3
    - detection.emerging-threats
logsource:
    product: alibaba
    service: actiontrail
    definition: 'Requires ActionTrail management events delivered to the SIEM as JSON with the documented field names (userIdentity.type, userIdentity.userName, sourceIpAddress). The documentation says sourceIpAddress holds the client address in most cases and a service identifier when a cloud service sends the request, so service identifiers must be handled in the filter. KubernetesWorkerRole is the default node role name prefix; renamed roles are missed.'
detection:
    selection:
        userIdentity.type: 'assumed-role'
        userIdentity.userName|startswith: 'KubernetesWorkerRole'
    filter_private:
        sourceIpAddress|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter_private
falsepositives:
    - Nodes that reach the API through a public address or a NAT gateway, which must be listed in a local filter
    - Cloud services that act on the role and report a service identifier in sourceIpAddress
level: medium
```

**Agent Platform Gateway**

#### Agent Platform Internal Workspace Reload Route Called Through The Gateway (with publish, save and ordering correlation)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1565.001 (Stored Data Manipulation)
**ATT&CK Note:** No ATT&CK technique names tampering with an AI agent's configuration. Stored Data Manipulation is the closest, and I have not claimed a tactic beyond what `sigma check` accepts.
**Confidence:** LOW
**False Positives:** The platform's own editor and services if they call the reload route through the gateway after a save. I cannot tell from the held files how often that happens, so the standalone reload rule is only a lead.
**Blind Spots:** The access log shows the path and not the body, so the rule cannot see that the model endpoint was changed, or to what. Needs a gateway that logs the route. Correlation support: Lucene cannot run the ordering rule; EQL converts it as a three-step sequence by client address.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Lucene: plain rules convert, correlation unsupported. EQL: converts. NOT CHECKED against gateway logs. Correlation files cannot go upstream as written (SigmaHQ has none in `rules/`; `correlation_` filename prefix applied).
**Deployment:** Gateway or ingress access logs of the agent platform, with a client address field. The three path values are placeholders: put in your own platform's publish, workspace-save and internal reload routes before deploying. The publish, then save, then reload ordering is the part that carries over.
**Basis:** Steps 5 to 7 of the chain: publish, then rewrite the model block, then reload without republishing, so the platform does not restore its own model block (`final2.py`, `order.py`, `claimfire.py`). 69 corpus files call the reload route.

```yaml
title: Agent Platform Publish Request
id: 9993f791-aeb8-4789-b4f6-802249886c02
name: agent_platform_publish
status: experimental
description: >-
  Detects a POST to the publish route of an AI-agent platform's config service.
  Building block for the publish, save, reload ordering correlation in this file; it is not meant to alert alone.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.impact
    - attack.t1565.001
    - stp.2
    - detection.emerging-threats
logsource:
    category: proxy
    definition: 'Requires gateway or ingress access logs that record the request method, path and client address. The path value is a placeholder for your platform''s route; the route names vary by platform.'
detection:
    selection:
        cs-method: 'POST'
        c-uri|contains: '/REPLACE-publish-route/'
    condition: selection
falsepositives:
    - Every legitimate publish
level: informational
---
title: Agent Platform Workspace File Save Request
id: 95931ef0-a119-4073-a122-a40474582913
name: agent_platform_workspace_save
status: experimental
description: >-
  Detects a request to the workspace file save route of an AI-agent platform's config service.
  Building block for the publish, save, reload ordering correlation in this file; it is not meant to alert alone.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.impact
    - attack.t1565.001
    - stp.2
    - detection.emerging-threats
logsource:
    category: proxy
    definition: 'Requires gateway or ingress access logs that record the request method, path and client address. The path value is a placeholder for your platform''s route; the route names vary by platform.'
detection:
    selection:
        c-uri|contains: '/REPLACE-workspace-save-route/'
    condition: selection
falsepositives:
    - Every legitimate workspace edit
level: informational
---
title: Agent Platform Internal Workspace Reload Route Called Through The Gateway
id: 2f8c5d64-66d6-4077-a599-0a185ba958f2
name: agent_platform_reload
status: experimental
description: >-
  Detects a POST to the internal workspace reload route of an AI-agent platform through the public or shared gateway.
  The route pushes a changed agent configuration into the running pod without a republish.
  In INV-2026-082 the operator called it after rewriting an agent's model endpoint so the change took effect without the platform restoring its own model block.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.persistence
    - attack.impact
    - attack.t1565.001
    - stp.2
    - detection.emerging-threats
logsource:
    category: proxy
    definition: 'Requires gateway or ingress access logs that record the request method, path and client address. The path value is a placeholder: replace it with your platform''s internal reload route. Route names vary by platform.'
detection:
    selection:
        cs-method: 'POST'
        c-uri|contains: '/REPLACE-internal-reload-route'
    condition: selection
falsepositives:
    - The platform's own editor or services, if they call this route through the gateway after a configuration save
level: medium
---
title: Agent Configuration Written After Publish Then Reloaded Without Republish
id: ab3ec12c-a6bd-43a9-a4ea-a7f6d6a1baee
status: experimental
description: >-
  Detects, for one client address within two minutes, a publish, then a workspace file save, then the internal workspace reload, in that order.
  A normal edit saves first and publishes after. The INV-2026-082 operator published first, wrote the agent's model endpoint afterwards and reloaded, which keeps the platform from restoring its own model block over the operator's endpoint.
  The access log shows the save only as a path, so what was written is NOT CHECKED by this rule.
  Needs the gateway logs of the base rules and a backend that supports Sigma correlation (temporal_ordered).
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.impact
    - attack.t1565.001
    - stp.3
    - detection.emerging-threats
correlation:
    type: temporal_ordered
    rules:
        - agent_platform_publish
        - agent_platform_workspace_save
        - agent_platform_reload
    group-by:
        - c-ip
    timespan: 2m
falsepositives:
    - An editor that publishes before saving and then reloads
level: medium
```

**Source Control**

#### GitLab API User Lookup Rejected Repeatedly From One Source (with base rule)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1110 (Brute Force)
**ATT&CK Note:** The operator replayed one stolen shared secret rather than guessing, so Brute Force is only the nearest fit for the rejection burst.
**Confidence:** LOW
**False Positives:** A CI job or integration with an expired token retrying.
**Blind Spots:** Cannot name the pod or the shared account, because those are specific to each environment. A local filter must add the pod egress and the account name. The held outputs show no successful GitLab response, so I do not know the burst was followed by a success. A rule for a successful sign-in by the shared account from a new source needs the account name and is a Coverage Gap.
**Validation:** `sigma check` with the SigmaHQ configuration, `yamllint` and `tests/test_rules.py`: 0 errors, 0 issues. Lucene: correlation unsupported. EQL: converts. NOT CHECKED against GitLab logs.
**Deployment:** GitLab or its reverse proxy access logs with the path, status and client address mapped.
**Basis:** One shared service-account secret tried as an account password, as a personal-access-token header and as git-over-HTTP basic auth (`gitlab_probe.py`, `podgl2.py`, `gl_check.py`).

```yaml
title: GitLab API User Lookup Rejected
id: 8a46e348-da01-4b1b-abc7-22b9a9a5ef03
name: gitlab_api_user_rejected
status: experimental
description: >-
  Detects a rejected request to the GitLab user endpoint.
  Building block for the repeated-rejection correlation in this file; it is not meant to alert alone.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1110
    - stp.2
    - detection.emerging-threats
logsource:
    category: proxy
    definition: 'Requires GitLab or its reverse proxy access logs with the request path, status and client address mapped to c-uri, sc-status and c-ip.'
detection:
    selection:
        c-uri|startswith: '/api/v4/user'
        sc-status: 401
    condition: selection
falsepositives:
    - Every expired token or mistyped credential
level: informational
---
title: GitLab API User Lookup Rejected Repeatedly From One Source
id: 2a79d4b5-8144-4767-a57b-173101a77fbf
status: experimental
description: >-
  Detects four or more rejected requests to the GitLab user endpoint from one source address within 10 minutes.
  In INV-2026-082 one harvested shared service-account secret was tried as an account password, as a personal-access-token header and as git-over-HTTP basic auth against the same GitLab instance, which produces a burst of rejections from the pod that holds it.
  Whether any attempt succeeded is NOT CHECKED, because the held outputs show no successful response.
  Needs the access logs of the base rule and a backend that supports Sigma correlation (event_count). A pod using a shared service account cannot be named without local values, so add the pod egress and account name in a local filter.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/
    - https://docs.gitlab.com/ee/administration/logs/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1110
    - stp.2
    - detection.emerging-threats
correlation:
    type: event_count
    rules:
        - gitlab_api_user_rejected
    group-by:
        - c-ip
    timespan: 10m
    condition:
        gte: 4
falsepositives:
    - A CI job or integration with an expired token retrying
level: low
```

---

## Suricata Signatures

Rule identifiers (`sid`) are local placeholders; the feed generator renumbers them. All four rules passed `suricata -T` on the sensor in one run (exit 0). None is Detection tier. The bore session shape is a protocol fingerprint, but the tool is dual use. The other three key on file names, a domain or a path the operator chose, so they are Hunting by the tiering rules, and the same indicators go to the IOC feed.

### Hunting Rules

**Tunnel**

#### THL HUNT INV-2026-082 bore Tunnel Client Hello Frame (Open-Source Reverse Tunnel Session)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling)
**Confidence:** MODERATE
**False Positives:** Any developer using the bore client to any server. The frame is the open-source tool's own: its source defines the client message `Hello(u16)` and frames messages as JSON delimited by a null byte, with a control port of 7835 on the default server.
**Blind Spots:** Misses a bore session that sends a different first message (the authenticated variant begins with the Authenticate message), a tunnel inside TLS, and a different tunnelling tool. Source: the bore repository, `src/shared.rs`.
**Validation:** `suricata -T` on the sensor: PASS. Replay NOT CHECKED, because no packet capture exists for this case and I did not build a synthetic one. Not tied to any port, so a bore server on another port is still seen.
**Deployment:** Egress sensors that see cleartext TCP leaving the network.
**Basis:** The operator ran the bore client on its server and, by scripts written to run in a victim pod (execution there inferred, not shown), in the pod against the public bore.pub server (`bore_oe.log`, `bore_up.sh`). The first bytes of such a session are `{"Hello":PORT}` and a null byte.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-082 bore Tunnel Client Hello Frame (Open-Source Reverse Tunnel Session)"; flow:established,to_server; dsize:13<>20; content:"{|22|Hello|22 3a|"; startswith; content:"}|00|"; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/; classtype:policy-violation; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

#### THL HUNT INV-2026-082 bore.pub Public Tunnel Server DNS Query (Shared Service, Do Not Block On This Alone)

**Tier:** Hunting
**Robustness:** 0
**ATT&CK Coverage:** T1572 (Protocol Tunneling)
**ATT&CK Note:** A bare domain scores Robustness 0. It is written as a rule only because the tiering rules allow a domain-only signature at Hunting, with the same indicator also in the IOC feed.
**Confidence:** HIGH
**False Positives:** Everyone who uses the free public bore.pub server. It is a shared third-party service, so a block on it hits other people's tunnels and not the operator.
**Blind Spots:** Misses a client that connects by address, which the operator's own scripts did as a fallback.
**Validation:** `suricata -T` on the sensor: PASS. Replay NOT CHECKED, because no packet capture exists for this case and I did not build a synthetic one. Limited to one alert per source per hour.
**Deployment:** DNS sensors. Use for scoping, never as a block.
**Basis:** The operator's tunnel scripts address `bore.pub` throughout (`claim1811.sh`, `take1811.sh`, `bore_up.sh`).

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT INV-2026-082 bore.pub Public Tunnel Server DNS Query (Shared Service, Do Not Block On This Alone)"; dns.query; content:"bore.pub"; nocase; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/; classtype:policy-violation; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

**MCP Plant**

#### THL HUNT INV-2026-082 Python urllib Fetch Of Operator Payload File Name (Agent-Platform Plant Downloader)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** A script that fetches a file with one of these names using the default Python urllib user agent. Generic names like `b.py` and `boot.py` will occur on other people's internal servers.
**Blind Spots:** Misses a fetch with another client, a changed file name, and HTTPS. The pod's own curl-based fetches in the corpus use another user agent and are not matched.
**Validation:** `suricata -T` on the sensor: PASS. Replay NOT CHECKED, because no packet capture exists for this case and I did not build a synthetic one. The pattern is gated behind a `.py` content match.
**Deployment:** Egress sensors that see cleartext HTTP from servers and pods.
**Basis:** The planted command downloads `/b.py`; the receiver log shows `hb.py`, `own_llm.py`, `axllm.py`, `boot.py` and `mcp_plant.py` served to clients (`sink80.log`). Robustness 1 because the file names are the operator's choice.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-082 Python urllib Fetch Of Operator Payload File Name (Agent-Platform Plant Downloader)"; flow:established,to_server; http.method; content:"GET"; http.user_agent; content:"Python-urllib/"; startswith; http.uri; content:".py"; endswith; pcre:"/^\/(?:hb|b|boot|deployhb|own_llm|axllm|mcp_plant)\.py$/"; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

**Receivers**

#### THL HUNT INV-2026-082 POST To /up With name Query And Python urllib Client (Operator Receiver Shape)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel)
**Confidence:** LOW
**False Positives:** Any internal tool that uploads with a Python script to an `/up?name=` endpoint.
**Blind Spots:** Misses curl uploads, the `X-Tag` variant, HTTPS, and any receiver with another path. The held logs do not show that any upload reached the receiver, so this rule describes the receiver's request shape and not proven exfiltration.
**Validation:** `suricata -T` on the sensor: PASS. Replay NOT CHECKED, because no packet capture exists for this case and I did not build a synthetic one. 
**Deployment:** Egress sensors.
**Basis:** The sink script accepts `POST /up?name=<file>` and stores the body; the pod's push script posts to it (`sink.py`, `push1.py`). Robustness 1.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-082 POST To /up With name Query And Python urllib Client (Operator Receiver Shape)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/up?name="; startswith; fast_pattern; http.user_agent; content:"Python-urllib/"; startswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-082-detections/; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

---

## Considered and Cut

| Candidate | Disposition | Reason |
|---|---|---|
| A rule keyed on the operator host address and its ports | Cut, routed to the IOC feed | A single hard-coded address scores Robustness 0. Removing it leaves nothing. |
| A rule on the mock login route called with an empty body | Cut | The route belongs to one victim's platform and the fix is to remove it. A published rule on it would be a rule on a victim's route name, with no telemetry evidence of how it is logged. |
| YARA for the receiver scripts (`sink.py`, `hitrecv.py`, `vps_serve.py`) | Cut | Each is a short stock `http.server` upload handler, indistinguishable from thousands of benign scripts. |
| YARA for the server-side relay scripts (`muxsrv*.py`, `relay9111.py`) | Cut | Same stock socket code; the worker-side rule already covers the protocol. Not run against benign files, so a rule here would be untested. |
| Rules for the `fscan` and `gogo` scanners | Cut | Public tools. I did not check upstream coverage, so it is NOT CHECKED whether rules exist. |
| YARA for the door-access console probe scripts | Cut | Its distinctive strings are one vendor's own product routes, too narrow to publish as a rule. Without them the rule is the public Struts2 S2-045 payload, which existing rulesets cover. |
| Suricata for the S2-045 Content-Type payload | Cut | It is the public Struts2 exploit and I did not check existing network rulesets. |

---

## Coverage Gaps

I could not write a rule, or could not honestly tier one, for these. Each says what would enable it.

- **The door-access platform probes.** The only distinctive strings are one vendor's own product routes, too narrow to publish as a rule (see Considered and Cut). A defender running that product can hunt for the public Struts2 S2-045 payload against its console.

- **Chain step 1, 2, 2a and 2b: the unauthenticated login and token minting.** The evidence is the route and an empty-body request. A rule needs the platform's gateway to log request bodies or response codes for that route, which I have no sample of. The remediation is to remove the route.
- **Chain step 3: private agent registration.** The create routes are 6 shapes; a rule would be a rule on a victim product's routes. It needs a log of agent creation with the creating principal.
- **Chain step 4 and 6, what was written.** Whether `config.json` was changed to an endpoint outside the platform's model catalogue is the real signal. It needs request-body logging or a periodic audit of the workspace file against the catalogue. My ordering correlation only shows the path sequence.
- **Chain step 8 and 10: read-back and trigger chat.** Ordinary calls; no distinguishing field.
- **Chain step 12: base64-wrapped shell step.** The `printf | base64 -d | bash` form is generic and I saw it only in an operator script, never in process telemetry, so I did not write a rule for it.
- **A pod using a shared service account to sign in to GitLab.** A specific rule would need the account name and the pod egress address, which are specific to each environment. The generic burst rule is written; a successful-sign-in rule is not.
- **The shared service-account secret appearing in a URL or netrc.** A secret-in-command-line rule needs the secret's format. The held evidence is a 20-character value; no stable format.
- **Cloud write and execute.** No successful write or execute call is shown (the cloud assistant call was denied), so there is no behaviour to detect past discovery.
- **Network contact with the operator host.** The operator's own script comments say pod egress to the host was blocked (the operator's belief, not an observed control; the operator moved to bore.pub for that reason), so most pod traffic would be to bore.pub, which is why the bore rules are Hunting.
- **Replay and live validation.** No Suricata replay (no capture), no ActionTrail, gateway or GitLab sample, and no Linux process telemetry for the Sigma rules. Every Validation line above says which of these it lacks.
- **Upstream coverage.** I recorded `NOT CHECKED` for the two Detection rules. I did not read the conditions of existing upstream rules.

---

## License

Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
