---
title: "Flask C2 & MSSQL CLR Backdoor on a Windows Post-Exploitation Staging Host"
date: '2026-06-12'
layout: post
permalink: /reports/flaskc2-postex-toolkit-67-215-232-25/
thumbnail: /assets/images/cards/flaskc2-postex-toolkit-67-215-232-25.png
hide: true
category: "Post-Exploitation Toolkit"
description: "A live single-host IIS/MSSQL post-exploitation staging operation pairing a bespoke Flask C2 beacon API with a sandbox-evading custom MSSQL CLR reverse-shell backdoor and a public SeImpersonate-to-Active-Directory escalation kit."
detection_page: /hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
ioc_feed: /ioc-feeds/flaskc2-postex-toolkit-67-215-232-25-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Suricata Signatures"
    anchor: "suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "coverage-gaps"
ioc_highlights:
  - "67.215.232[.]25"
  - "hxxp://67.215.232[.]25:8080/health"
  - "hxxp://67.215.232[.]25:1337/"
  - "a7029ef2b6a541ef2b7508e1316d3c2efd3493108975ee457bcdb73043a25262"
stix_bundle: /stix/flaskc2-postex-toolkit-67-215-232-25.json
---

**Campaign Identifier:** FlaskC2-PostEx-Toolkit-67.215.232.25<br>
**Last Updated:** June 12, 2026<br>
**Threat Level:** MEDIUM

> **Risk vs. Campaign Threat Level:** The post-exploitation toolkit analyzed in this report scores **HIGH** on capability — it is a complete, working SYSTEM-to-Domain escalation chain anchored by a custom MSSQL backdoor that evades generic sandboxes and the two most widely deployed AV engines. The overall campaign threat level is nonetheless rated **MEDIUM** because the command-and-control panel is currently **idle** (zero active beacons, zero pending and zero completed commands across the full observation window), there are **no confirmed victims**, the infrastructure is a **single host** with no sibling C2 found, and the staging host has been live but exposed for roughly three months without activation — a posture more consistent with between-victims staging than an active engagement. If the C2 activates or victims are confirmed, the threat level should be reassessed to **HIGH**.

---

## 1. Executive Summary

A live single-host Windows post-exploitation operation at `67.215.232[.]25` pairs a **bespoke Flask C2 beacon API** with a **custom MSSQL SQL-CLR reverse-shell backdoor** and a complete public privilege-escalation toolkit. This report delivers the first public documentation of that C2's beacon route surface and its shared-host link to the reverse-engineered tooling. Three co-located services run on one budget US VPS: an open directory on port 1337 caching a 17-file toolkit, the Flask C2 panel on port 8080, and an opaque second Flask listener on port 5000. The operator's objective is unambiguous from the toolkit's composition: gain a foothold as a service account that holds SeImpersonatePrivilege — through either an IIS webshell or the MSSQL backdoor — escalate to SYSTEM with the "Potato" suite, then pivot through Active Directory with Kerberos and dMSA abuse, all orchestrated through the Flask panel.

This report exists to fill a specific gap. The C2 panel itself was first documented publicly by Breakglass Intelligence on 2026-04-09 [Source: intel.breakglass.tech post #158873]; that disclosure covered the panel and its unauthenticated `/health` route but did not reverse-engineer the staged toolkit, did not establish the toolkit-to-C2 link, did not map the complete beacon route surface, and did not profile the single-host infrastructure. Those four are the original contributions here, and two of them form the report's analytical spine: **(1)** the bespoke Flask C2 beacon API — a minimal three-route, in-handler-authenticated headless control plane with a distinctive "servers" vocabulary that matches no known public C2 framework, and **(2)** the toolkit-to-C2 shared-host linkage that ties the reverse-engineered kit to the live panel. The remainder of the report characterizes the one genuinely bespoke compiled component, `cmd_exec.dll`, and documents the public toolkit precisely enough to detect it.

**Honest framing is the credibility spine of this report, and it is maintained throughout.** Most of this toolkit is public, commodity tooling. The five operator-recompiled .NET tools (EfsPotato, GodPotato, SweetPotato, Rubeus, SharpSuccessor) are identified as their public counterparts by YARA type-library-GUID matches, VirusTotal detections, and capa signature matches — **not** by byte-for-byte hash identity with a public release. The one bespoke compiled artifact, `cmd_exec.dll`, is a **custom build of a publicly documented MSSQL CLR technique** (Metasploit `mssql_clr_payload`, NetSPI, `evi1ox/MSSQL_BackDoor`), not a novel capability — its value is a detection one, because its host-process dependence makes it invisible to generic sandboxes. The `CVE-2026-20817` proof-of-concept staged on the host is a **non-weaponized demonstration** of a Windows Error Reporting vulnerability that Microsoft **patched in January 2026**; reverse engineering confirms it cannot elevate. No novelty, zero-day, or named-actor attribution is claimed.

**Attribution is not possible from the available evidence.** Two independent intelligence corpora return no actor association (VirusTotal `related_threat_actors`: none; Hunt.io threat-actor catalog: none), no security vendor at any credibility tier attributes this activity, and the prior public reference likewise reports attribution as unknown. Behaviorally the operation is most consistent with a financially-motivated individual or small-group cybercrime operator — an actor-*class* read at MODERATE confidence — but no specific actor can be named, and The Hunters Ledger assigns no internal tracking designation to a single-host, idle, sibling-less footprint. The few identity-adjacent artifacts (a globally-reused Chinese-language commodity webshell title, a pop-culture webshell password, a preference for one researcher's privilege-escalation tooling) are characteristics of the *tools*, not the *operator*, and explicitly do not indicate any nationality or named group.

**The defensive bottom line:** the custom MSSQL CLR backdoor is the highest-value detection target in this campaign because automated tooling will not catch it. VirusTotal sandboxing rates it harmless at 98% confidence, and Microsoft and Kaspersky score it clean — a host-process-dependent backdoor that only activates inside SQL Server is invisible to generic sandboxes and most signature engines. The deployable detection package accompanying this report (a YARA banner anchor, Sigma rules for `sqlservr.exe`→`cmd.exe` and the MSSQL CLR install sequence, IIS webshell behavioral rules, native-tool imphashes, and a low-false-positive Flask C2 `/health` network signature) fills that gap. Any MSSQL, IIS, or Active Directory environment is in scope, and the January-2026 Windows Error Reporting patch should be applied where it is missing.

### Key Takeaways

- **A single host runs the entire operation.** `67.215.232[.]25` (AS36352, HostPapa/ColoCrossing, US) co-locates the open-directory toolkit cache (`:1337`), the Flask C2 panel (`:8080`), and an opaque second Flask listener (`:5000`). It is IP-only — no domain has ever resolved to it — so IP-level blocking fully covers the known infrastructure. Five convergent negative pivots confirm no sibling C2 exists (HIGH confidence).
- **The Flask C2 is bespoke and minimal.** Only three routes exist: an unauthenticated `GET /health` status endpoint and two POST-only beacon endpoints (`/api/heartbeat`, `/api/report`). Authentication is enforced inside the handler, not at the route. The vocabulary — beacons are called "servers" — matches no public C2 framework (MODERATE-HIGH confidence).
- **The one bespoke binary evades sandboxes by architecture.** `cmd_exec.dll` is a custom build of a known MSSQL SQL-CLR reverse-shell technique that exposes a `[SqlProcedure] reverse_shell(ip, port)` stored procedure. It cannot fire outside a SQL Server host, so generic sandboxes rate it harmless and most AV scores it clean (DEFINITE classification).
- **Two parallel footholds, one escalation chain.** IIS webshells (`w3wp.exe`) and the MSSQL backdoor (`sqlservr.exe`) both land as SeImpersonate-holding service accounts — the exact context the co-located public Potato suite (six tools) escalates from, feeding Rubeus and SharpSuccessor for Active Directory lateral movement.
- **The CVE PoC is a patch callout, not a live threat.** `CVE-2026-20817` is a January-2026-patched Windows Error Reporting LPE; the staged build is a non-weaponized demonstration that cannot elevate (DEFINITE, via reverse engineering). Apply the patch where missing; do not treat it as an active exploit.
- **Detection coverage is deployable now.** The accompanying package targets the sandbox/AV blind spot directly: see the [detection rules]({{ page.detection_page }}) and the machine-readable [IOC feed]({{ page.ioc_feed }}).

---

## 2. Campaign Architecture and Kill Chain

> **Analyst note:** This section maps how the operator intends to move from initial access on a target server all the way to domain control, using the tools staged in the open directory. Think of it as a blueprint: each stage hands off to the next, and every tool on the list serves a specific step in that path.

The operation is a textbook IIS+MSSQL/Active-Directory post-exploitation chain assembled almost entirely from public components, with two custom pieces — the MSSQL backdoor and the Flask C2 — bolted to commodity tooling. Every tool in the open directory advances the same path from an initial service-account foothold to domain control.

### 2.1 The operator's intended path

The toolkit composition leaves no ambiguity about operational intent. The operator stages two interchangeable initial-execution surfaces, a complete privilege-escalation suite tuned to "whatever Windows build the target turns out to be," and a terminal Active Directory escalation layer:

1. **Initial foothold (two parallel surfaces).** The operator establishes code execution as a Windows service account through *either* an IIS webshell (`miss.asp` or `NPCInfoList1.aspx`, executing inside `w3wp.exe`) *or* the MSSQL CLR backdoor (`cmd_exec.dll`, executing inside `sqlservr.exe`). Both contexts hold SeImpersonatePrivilege by default — this is the pivot that makes the rest of the kit work.
2. **Local escalation to SYSTEM.** From a SeImpersonate-holding service account, the operator runs whichever "Potato" variant matches the target's Windows version to abuse the privilege and spawn a SYSTEM process. Staging all six variants is a deliberate hedge against not knowing the target patch level in advance.
3. **Active Directory escalation and lateral movement.** With SYSTEM achieved, the operator uses Rubeus for Kerberos abuse (Kerberoasting, ticket forging, delegation abuse) and SharpSuccessor for the dMSA/BadSuccessor technique against Windows Server 2025 domain controllers — the terminal step toward domain compromise.
4. **Control.** The bespoke Flask C2 panel orchestrates the operation. Beacons (which the operator's own vocabulary calls "servers") check in via POST and submit command output via POST; the command-queueing mechanism is not exposed on the public panel.

The diagram below renders this chain. Each stage carries its own analyst note in the deep-dive sections that follow.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/flaskc2-postex-toolkit-67-215-232-25/flaskc2-postex-kill-chain.svg" | relative_url }}" alt="Vertical four-step kill-chain infographic for the FlaskC2-PostEx-Toolkit on 67.215.232.25. Step 1 (orange, Initial Access dual foothold): two entry vectors converge on one privilege - an IIS webshell running in w3wp.exe, or the cmd_exec.dll MSSQL CLR backdoor running in sqlservr.exe; both run as a service account holding SeImpersonatePrivilege by default; detection hint is w3wp.exe or sqlservr.exe spawning a cmd.exe child. Step 2 (red, Local Privilege Escalation to SYSTEM): the public Potato suite (EfsPotato, GodPotato, JuicyPotato, PrintSpoofer, RoguePotato, SweetPotato) abuses SeImpersonate to steal a SYSTEM token, with the operator picking the variant matching the target Windows build; detection hint is service-account to SYSTEM token theft and native-tool imphashes. Step 3 (red, AD Lateral Movement / Domain Escalation): Rubeus for Kerberos abuse and SharpSuccessor for the BadSuccessor dMSA technique move from SYSTEM-on-host toward domain compromise. Step 4 (deep red, Command and Control): a bespoke Flask C2 on port 8080 with POST /api/heartbeat, POST /api/report, and GET /health endpoints, idle at the time of analysis. The footer lists detection anchors including sqlservr.exe and w3wp.exe spawning cmd.exe, the SQL Server CLR backdoor banner string, the AES key-equals-IV value ca63457538b9b1e0, and the Flask /health field-combo.">
  <figcaption><em>Figure 1: The end-to-end post-exploitation chain. Two interchangeable footholds (IIS webshell or MSSQL CLR backdoor) both yield a SeImpersonate-holding service account, from which the public Potato suite reaches SYSTEM, Rubeus and SharpSuccessor drive Active Directory escalation, and the bespoke Flask C2 provides control. The SeImpersonate convergence at Step 1 is the reason a privilege-escalation-heavy toolkit is the right kit for this access model.</em></figcaption>
</figure>

**Stage-by-stage at a glance:**

| Stage | Components | Result | Confidence |
|---|---|---|---|
| Ingress | Open directory `:1337` | Toolkit retrieved onto victim | HIGH |
| ① Initial access | `miss.asp`, `NPCInfoList1.aspx`, `cmd_exec.dll` | Code execution as a SeImpersonate service account | HIGH |
| ② Privilege escalation | Potato suite (6 tools); CVE PoC (non-weaponized) | SYSTEM | HIGH (Potato) / MODERATE (CVE scaffold only) |
| ③ AD escalation / lateral movement | Rubeus, SharpSuccessor | Kerberos abuse, dMSA inheritance | MODERATE (capability staged, not observed executing) |
| ④ Control | Flask C2 `:8080` | Beacon orchestration | HIGH (panel) / MODERATE (beacon protocol inferred) |

### 2.2 What is bespoke versus public

The single most important distinction for a reader assessing this campaign is which parts are custom and which are off-the-shelf. The honest answer is that very little is custom:

| Component | Status | Basis for the call |
|---|---|---|
| Flask C2 beacon API | **Bespoke** (infrastructure) | No public C2 framework match across 9 frameworks checked; distinctive vocabulary and route structure |
| Toolkit↔C2 shared-host link | **Original finding** | Established by this investigation; not in the prior public reference |
| `cmd_exec.dll` MSSQL CLR backdoor | **Custom build of a public technique** | Technique is documented (Metasploit/NetSPI/evi1ox); banner string is operator-specific; not a novel capability |
| EfsPotato, GodPotato, SweetPotato, Rubeus, SharpSuccessor | Public tools, **operator-recompiled** | Identified by YARA HKTL-GUID + VT + capa signature, not by public-release hash identity |
| JuicyPotato, PrintSpoofer, RoguePotato, RogueOxidResolver, nc64 | Public tools, **prebuilt** | Hash-match public builds byte-for-byte; retain stock release dates |
| `CVE-2026-20817_PoC.exe` | Public PoC, **non-weaponized** | Patched January 2026; reverse engineering confirms it cannot elevate |
| Webshells (`miss.asp`, `NPCInfoList1.aspx`) | Commodity, reused | Public Ghost小组 / Godzilla-style families; globally reused |

The craft signal in this campaign is narrow and worth stating plainly: the operator recompiles the .NET tooling from source (which defeats hash-based detection of those specific components) while downloading prebuilt native tools and reusing commodity webshells as-is. That is an intermediate, mid-tier practice — deliberate, but not novel and not nation-state-grade.

---

## 3. Technical Classification

| Attribute | Assessment |
|---|---|
| **Type** | Windows post-exploitation / privilege-escalation toolkit (staging collection) — not a single self-contained malware family |
| **Primary bespoke component** | `cmd_exec.dll` — MSSQL SQL-CLR reverse-shell backdoor (custom build of a public technique) |
| **Toolkit composition** | Complete public SeImpersonate "Potato" suite (6 tools) + Rubeus + SharpSuccessor + Netcat + 2 webshells + 1 CVE PoC + 1 Rubeus dependency library |
| **Component families** | Potato/SeImpersonate hacktools; Rubeus (GhostPack); SharpSuccessor (BadSuccessor/dMSA); Godzilla-style .NET loader webshell; Ghost小组 ASP webshell |
| **Family confidence** | Tool identifications **HIGH/DEFINITE** (VT hash + YARA + capa). `cmd_exec.dll` = MSSQL CLR reverse-shell backdoor **DEFINITE** (decompilation). `CVE-2026-20817_PoC.exe` = non-weaponized demo PoC **DEFINITE** (disassembly). |
| **Sophistication** | **Intermediate / mid-tier.** No novel capability. Craft signal = operator recompiles .NET tooling from source but downloads prebuilt native tools and reuses commodity webshells. |
| **Threat level** | Capability **HIGH** · Campaign **MEDIUM** (idle C2, no confirmed victims, single host, ~3-month stable exposure) |
| **First seen** | Open directory first observed 2026-03-11 (Hunt.io `malicious_open_dir`); Flask listeners first observed 2026-03-09; operator .NET build cluster 2026-03-20 to 2026-03-23 |
| **Attribution** | **Unknown / INSUFFICIENT.** No named-actor link in any corpus. Campaign described by infrastructure: `FlaskC2-PostEx-Toolkit-67.215.232.25` |

The campaign is not a single malware family and should not be described as one. It is a staging collection — a curated set of post-exploitation tools cached on an open directory, plus one bespoke backdoor and a bespoke C2 — assembled to execute a single operational workflow. The classification depth in this report is therefore distributed: the bespoke `cmd_exec.dll` and the Flask C2 receive full reverse-engineering treatment (Sections 4 and 5), the webshells and CVE PoC receive component-level analysis (Section 6), and the public Potato/Rubeus/SharpSuccessor tooling is documented at the depth needed to detect and contextualize it (Section 7) without re-deriving well-published research.

---

## 4. The MSSQL CLR Reverse-Shell Backdoor (cmd_exec.dll)

> **Analyst note:** This section dissects the one piece of custom compiled code in the toolkit — a tiny .NET library designed to be loaded *inside* Microsoft SQL Server, where it gives the operator a remote command shell running with SQL Server's privileges. The same design that makes it powerful (it only runs inside the database engine) is exactly what makes it nearly invisible to automated malware scanners, which never load it into a real SQL Server. That blind spot is the central detection lesson of this report.

`cmd_exec.dll` is the only genuinely bespoke compiled artifact in the sample set and the highest-value detection target in the campaign. It is a 4,608-byte managed .NET DLL (x86, compile timestamp 2026-03-21) that exposes a single SQL Server stored procedure, `reverse_shell(ip, port)`, which opens an outbound TCP connection and routes operator commands through `cmd.exe`. Classification is **DEFINITE**, established by direct decompilation (in a .NET decompiler, dnSpy).

### 4.1 What it is and how it loads

SQL Server supports loading managed .NET assemblies through a feature called SQL-CLR (Common Language Runtime integration). An administrator — or an attacker with sufficient database permissions — can register an assembly with `CREATE ASSEMBLY`, then expose one of its methods as a stored procedure with `CREATE PROCEDURE ... EXTERNAL NAME`. Once registered, the method runs in-process inside `sqlservr.exe` whenever the stored procedure is called. `cmd_exec.dll` is built to be installed exactly this way and invoked with `EXEC reverse_shell '<ip>', <port>`.

The deployment prerequisites are the standard ones for this technique: the SQL-CLR feature must be enabled (`sp_configure 'clr enabled', 1`), and the operator needs either sysadmin rights or the specific `CREATE ASSEMBLY` permission, typically with the target database flagged `TRUSTWORTHY` or the assembly registered as `UNSAFE`. An operator who already holds a foothold as the SQL Server service account — which is precisely the foothold the rest of this kit is built to exploit — has the access required.

**What this means:** the backdoor turns the database server itself into a command-execution platform. Because the code runs as the SQL Server service account, and because that account holds SeImpersonatePrivilege by default, a successful install lands the operator in the exact privilege context the co-located Potato suite escalates from. `cmd_exec.dll` is, functionally, the MSSQL twin of the IIS webshells — a second, independent way into the same SYSTEM-escalation chain.

### 4.2 Runtime behavior (decompiled)

A single public class, `StoredProcedures`, exposes one `[SqlProcedure]` method:

- **`reverse_shell(string ip, int port)`** opens an outbound `TcpClient(ip, port)`, writes the banner `[*] Connected to SQL Server CLR backdoor` to the socket, then enters a read-execute-respond loop: it reads a command line from the socket; breaks on a null line or the literal `"exit"`; otherwise passes the line to `ExecuteCommand` and writes the result plus a newline back to the operator. The entire loop body sits inside a swallow-all `try/catch`, so a failing command cannot crash the hosting `sqlservr.exe` process — an important reliability choice for a backdoor living inside a production database. The network stream is configured with `AutoFlush = true`.
- **`ExecuteCommand(string cmd)`** runs `cmd.exe /c <cmd>` via `ProcessStartInfo` with `UseShellExecute = false`, both stdout and stderr redirected, `CreateNoWindow = true`, and the window hidden. It returns combined stdout and stderr, or `"Error: " + message` on failure.

Two characteristics matter for defenders. First, there is **no hardcoded C2** — the destination IP and port are supplied as parameters at `EXEC` time, so the backdoor file itself contains no network indicator to block. Second, the channel is **plaintext** raw TCP with no protocol framing or encryption; the command and the response cross the wire in the clear.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/flaskc2-postex-toolkit-67-215-232-25/cmd-exec-dll-reverse-shell-decompiled.png" | relative_url }}" alt="Decompiled C# source of cmd_exec.dll showing the reverse_shell method opening a TcpClient, writing the banner '[*] Connected to SQL Server CLR backdoor' to the socket, and looping to read commands and call ExecuteCommand, which runs cmd.exe /c via ProcessStartInfo with stdout and stderr redirected.">
  <figcaption><em>Figure 2: dnSpy (.NET decompiler) view of cmd_exec.dll. Top — the SQL-CLR <code>reverse_shell</code> method: a <code>TcpClient</code> loop that writes the <code>[*] Connected to SQL Server CLR backdoor</code> banner, reads operator commands, and exits on a null line or <code>"exit"</code>. Bottom — <code>ExecuteCommand</code> running <code>cmd.exe /c</code> with redirected output and a hidden window. The banner string is the report's strongest YARA anchor.</em></figcaption>
</figure>

> **Reproduction note:** an earlier working hypothesis during reverse engineering held that `cmd_exec.dll` might be the in-memory payload (`class K`) delivered by the `NPCInfoList1.aspx` webshell. Direct decompilation disproved it: the exposed class is `StoredProcedures` (a SQL-CLR component), not `K`, and the webshell's `class K` assembly is delivered at runtime and is not staged in the open directory. The decompilation overrode the circumstantial build-cluster inference — a useful reminder that artifact identity is settled by the bytes, not by co-location.

### 4.3 The sandbox and AV blind spot — the key detection finding

> **Analyst note:** "Sandbox" here means an automated system that runs an unknown file in isolation and watches what it does. These systems decide a file is malicious by observing bad behavior. This backdoor does nothing observable unless it is loaded into a real SQL Server — which a sandbox never does — so it looks completely harmless to automated analysis. This is not a flaw in any one product; it is a structural gap that applies to every backdoor of this class.

This is the finding that justifies the report's detection package. VirusTotal sandboxing, reconfirmed during this analysis, tags the DLL as **`idle`**; the Zenbox sandbox rates it **harmless at 98% confidence**; the C2AE sandbox returns undetected; and all four sandbox behavior reports are **empty** — no network activity, no `cmd.exe`, no `sqlservr.exe`. The reason is architectural: the sandbox executes the file through a generic DLL load (`rundll32 cmd_exec.dll,#1` / `loaddll32`), which maps only to a generic DLL-execution technique and **never reaches the SQL-CLR entry point**. `StoredProcedures.reverse_shell()` is only invoked when SQL Server loads the assembly and a T-SQL `EXEC` calls it; no generic sandbox provides that context.

Among signature engines the picture is nearly as bad: of the popular AV engines, **only Symantec** fires (a generic heuristic, `Trojan.Gen.MBT`), while **Microsoft and Kaspersky — the two most widely deployed engines — score it clean**. The aggregate VirusTotal ratio (32/72) is driven largely by engines flagging the SQL-CLR-plus-reverse-shell string combination, not by behavioral conviction.

**The transferable lesson:** a host-process-dependent backdoor that only activates inside a specific service looks benign to every generic sandbox and most signature engines. Defending against this class requires either a string/structure anchor that fires on the file at rest (the YARA approach) or behavioral telemetry from the host process itself (`sqlservr.exe` spawning `cmd.exe`, or initiating outbound TCP). Both are provided in the [detection package]({{ page.detection_page }}); the `[*] Connected to SQL Server CLR backdoor` banner is the strongest single anchor because it is operator-specific and absent from any public reference implementation.

### 4.4 Static fingerprint

The DLL's static profile is clean and fully telegraphs its function — there is no packing, no obfuscation, and no overlay. Overall entropy is low (3.73), there is a single import (`mscoree.dll!_CorDllMain`, the generic managed-PE stub), and the string table names every capability:

- **SQL-CLR markers:** `StoredProcedures`, `SqlProcedureAttribute`, `Microsoft.SqlServer.Server`
- **Reverse-shell plumbing:** `TcpClient`, `NetworkStream`, `GetStream`, `System.Net.Sockets`
- **Command execution:** `ExecuteCommand`, `ProcessStartInfo`, `set_UseShellExecute`, `set_RedirectStandardOutput`, `set_RedirectStandardError`, `set_CreateNoWindow`, `WaitForExit`
- **Operator banner (strongest anchor):** `[*] Connected to SQL Server CLR backdoor`

A capability-detection tool (capa) summarizes the behavior cleanly: "act as TCP client," "create a process with modified I/O handles and window," "create process on Windows," and "terminate process" — a precise static description of a reverse-shell-to-`cmd` loop.

### 4.5 Prior art — a known technique, not a novel one

The MSSQL SQL-CLR command-execution and reverse-shell technique is public and well documented; `cmd_exec.dll` is a custom *build* of it, not a new capability. The lineage is explicit in the public record:

- **Metasploit `mssql_clr_payload` module** (Rapid7) — the canonical automated implementation: it builds a CLR assembly from hex-encoded DLL bytes, registers a stored procedure, and calls it to execute a payload [Source: github.com/rapid7/metasploit-framework, module `mssql_clr_payload`].
- **NetSPI, "Attacking SQL Server CLR Assemblies"** — a comprehensive walkthrough of CLR assembly import, a `cmd_exec` stored-procedure deployment, `ALTER ASSEMBLY` persistence, and detection via `sys.assemblies` queries; the described `cmd_exec` implementation matches the operator's build's functionality exactly [Source: netspi.com/blog].
- **`evi1ox/MSSQL_BackDoor`** — an open-source .NET CLR backdoor for MSSQL using hex-encoding for fileless deployment and the `UNSAFE` permission set [Source: github.com/evi1ox/MSSQL_BackDoor].
- **HackingArticles, "MSSQL for Pentester: CLR Assembly"** — an operator-oriented walkthrough of CLR assembly deployment for RCE and persistence [Source: hackingarticles.in].

The report's position, stated plainly: this component is **detection-valuable, not novel**. Its operator-specific banner string is a strong YARA anchor, and its architectural evasion is a genuine defender gap — but the underlying technique has been documented and tooled for years.

---

## 5. The Bespoke Flask C2 Beacon API

> **Analyst note:** This section documents the operator's command-and-control server — the system that infected machines report back to and receive instructions from. Unlike off-the-shelf C2 frameworks (Cobalt Strike, Sliver, and similar), this one appears to be hand-built in Python. It is deliberately minimal: it exposes only three web addresses, has no login page or dashboard, and uses an unusual internal vocabulary. Mapping that small, distinctive surface is one of the two original contributions of this report, and it yields a low-false-positive network signature defenders can deploy.

The Flask C2 is the second of the report's two original-contribution pillars. The C2 *panel* was first documented publicly by Breakglass Intelligence on 2026-04-09 — that disclosure is credited here, and it covered the panel's existence, its `Werkzeug/3.1.6 Python/3.12.3` stack, and its unauthenticated `/health` route [Source: intel.breakglass.tech post #158873]. What this investigation adds is the **complete beacon route surface**, the **authentication model**, the **operator vocabulary**, and the **shared-host link to the toolkit** — none of which appeared in the prior reference.

### 5.1 The complete route surface — only three routes

A 38-path sweep of the `:8080` listener confirmed that the C2 exposes only **three routes**, with no hidden web UI:

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/health` | GET | None (unauthenticated) | Status JSON: `active_servers`, `pending_commands`, `completed_commands`, `status`, `timestamp` |
| `/api/heartbeat` | POST only | In-handler (unauthenticated POST → `401`) | Beacon check-in; drives `pending_commands` |
| `/api/report` | POST only | In-handler (unauthenticated POST → `401`) | Beacon output submission; drives `completed_commands` |

There is no `/login`, `/dashboard`, `/admin`, or `/panel`. This is a minimal, headless beacon API — there is no operator-facing web interface on this port at all. The operator interacts with the panel some other way; the public surface exists only for beacons to talk to.

### 5.2 The authentication model — in-handler, not route-level

A defender-relevant subtlety distinguishes this C2 from a framework built on a web-auth middleware. Authentication is enforced **inside each POST handler's body, not at the route level**. The evidence is in the HTTP responses: `GET /api/heartbeat` returns `405 Method Not Allowed` (standard Werkzeug method routing), not `401` or `403`. If the application used a `@before_request` hook or an authentication decorator, an unauthenticated request would be rejected with `401`/`403` regardless of method. Instead, the method router answers first (rejecting the wrong verb with `405`), and only a correctly-formed POST reaches the handler body where the credential check lives and returns `401` when it fails [the unauthenticated-POST→`401` behavior is corroborated by the Breakglass reference]. This is the signature of hand-rolled, per-handler auth logic rather than a framework-level gate.

### 5.3 The vocabulary fingerprint — beacons are "servers"

The `/health` JSON exposes the operator's internal naming, and it is distinctive. Active beacons are labeled **`active_servers`**; queued work is tracked as **`pending_commands`** and **`completed_commands`**. Calling the beacons "servers" is unusual — most frameworks call them agents, implants, bots, sessions, or beacons — and this naming, combined with the three-route structure and the in-handler auth pattern, does not appear in any known public framework fingerprint.

**No public C2 framework match** (MODERATE-HIGH confidence). The panel was checked against Cobalt Strike, Sliver, Havoc, Mythic, Metasploit/Meterpreter, Covenant, Merlin, and Brute Ratel; the vocabulary, route structure, and auth pattern match none of them. The honest caveat: the absence of a public match does not rule out a private or underground framework variant not indexed in public sources — but on the available evidence the panel reads as a bespoke, purpose-built implementation.

### 5.4 The inferred beacon protocol

The route semantics imply a straightforward beacon protocol, though the implant that drives it was not recovered (see §5.6). An agent POSTs to `/api/heartbeat` to check in and to collect queued commands — activity that would increment `pending_commands`. The agent POSTs results back to `/api/report`, which would move work into `completed_commands`. The `/health` counters are the externally visible state of that queue. The mechanism by which the operator *enqueues* commands is not exposed on `:8080`; the most likely candidate is the second Flask listener (see §5.5).

It is important to mark the confidence boundary here: the three-route surface, the auth model, and the vocabulary are **directly observed** (HIGH). The beacon protocol semantics are **inferred** from the route names and the `/health` counter behavior (MODERATE) — a reasonable reading, but not a decompilation of the server or the implant.

### 5.5 The opaque second listener (:5000)

A second Flask listener runs on port 5000 with the **identical** `Werkzeug/3.1.6 Python/3.12.3` stack as the C2 panel, but every one of the 38 probed paths returns `404`. Its role is undetermined. The most plausible reading is an operator control-plane — the interface through which commands are enqueued for beacons to pick up via `:8080` — but with no observable route this is a candidate, not a conclusion. It is carried as a MODERATE-confidence IOC (the `:5000` listener exists and is part of the operator's stack) with its function flagged as an open question.

### 5.6 The toolkit-to-C2 linkage — and its honest limit

The fourth original contribution is the link between the reverse-engineered kit and the live panel. The open-directory toolkit (`:1337`), the C2 panel (`:8080`), and the opaque listener (`:5000`) **co-reside on one host under one operator**. The prior public reference documented the panel in isolation; this investigation ties it to the staged tooling.

The linkage must be stated with its precise strength: it is **shared-host only**. No sample in the toolkit embeds the C2 endpoint strings — neither `cmd_exec.dll` (which takes its destination as a runtime parameter) nor any other staged file references `:8080`, `/api/heartbeat`, or `/api/report`. The connection is infrastructure-level (same host, same operator, same time window), not a code-embedded callback. This is an honest, defensible link — the toolkit and the C2 are demonstrably one operation — but it does not reach the strength of an implant that names its own C2, because the beacon implant that would carry that string was not recovered.

---

## 6. Initial-Access and LPE Components

This section covers the operation's two webshell footholds and the carried CVE proof-of-concept. The webshells are the IIS half of the dual-foothold model (the MSSQL half, `cmd_exec.dll`, is covered in Section 4); the CVE PoC is a patch callout rather than a live threat.

### 6.1 NPCInfoList1.aspx — AES in-memory .NET loader webshell

> **Analyst note:** This is a small web page planted on an IIS server that acts as a loader: when the operator sends it an encrypted command, it decrypts the payload and runs it entirely in memory, writing nothing to disk. In-memory execution is a deliberate evasion — there is no file for a disk scanner to find. The decryption key is hardcoded in the page, which is what makes the loader itself detectable even though its payloads are not.

`NPCInfoList1.aspx` is 1,138 bytes of ASP.NET C# implementing a simplified version of the well-known Godzilla (哥斯拉) .NET webshell pattern. Its logic is compact: if an incoming request carries any cookie, it reads the HTTP POST body, decrypts it with AES-128-CBC/PKCS7 using **key = IV = `ca63457538b9b1e0`** (a hardcoded ASCII value used for *both* the key and the initialization vector), then calls `Assembly.Load(decrypted)` followed by `CreateInstance("K")` — the constructor of the loaded class `K` runs the payload in memory. If the request carries no cookie, the page returns a bare `"OK"`, a naive-crawler and sandbox evasion that makes the shell look like an inert page to anything that does not know to send the trigger.

The reused-key configuration is both a behavioral tell and a detection gift. Canonical Godzilla derives its key as `md5(password)[:16]`; this variant uses a raw 16-byte key and reuses it as the IV, marking it as a simplified adaptation rather than the original tool. For defenders, the literal string `ca63457538b9b1e0` is a strong, low-false-positive YARA anchor (it is highly unusual for a 16-byte hex value to serve as both AES key and IV in legitimate code). The class-`K` payload that the loader executes is delivered at runtime, AES-encrypted in transit, and **was not recovered** — it is never written to disk and is not staged in the open directory.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/flaskc2-postex-toolkit-67-215-232-25/npcinfolist-aspx-aes-loader.png" | relative_url }}" alt="Decompiled C# source of NPCInfoList1.aspx showing a request-cookie check, the hardcoded AES key and IV value ca63457538b9b1e0, RijndaelManaged CBC/PKCS7 decryption of the POST body, Assembly.Load of the decrypted bytes followed by CreateInstance of class K, and a bare 'OK' response when no cookie is present.">
  <figcaption><em>Figure 3: NPCInfoList1.aspx — the Godzilla-style AES in-memory .NET loader. The hardcoded 16-byte value <code>ca63457538b9b1e0</code> is reused as <em>both</em> AES key and IV (CBC/PKCS7); the decrypted POST body is passed to <code>Assembly.Load</code> and run via <code>CreateInstance("K")</code>. A request with no cookie returns a bare <code>"OK"</code> — a crawler/sandbox evasion. The reused key=IV is the loader's low-false-positive detection anchor.</em></figcaption>
</figure>

### 6.2 miss.asp — Ghost小组 full-feature ASP webshell

`miss.asp` is a 128,193-byte VBScript.Encode-obfuscated ASP webshell that decodes to 2,295 lines (decoded with the Didier Stevens `decode-vbe.py` table). Its cleartext configuration exposes the password `UserPass="Aatrox"` and a green-on-black operator interface. The gb2312-encoded title `Ghost小组最新过防火墙马` identifies it as a member of the public Chinese **Ghost小组** ASP webshell family.

Functionally it is a full-feature interactive shell. It plants a **stored eval backdoor** — any request carrying the `Aatrox` parameter is `Execute`d server-side and persisted in Session state via `Execute Session("Aatrox")`, so the eval gadget survives across requests — and it probes for a complete component set: `Scripting.FileSystemObject` (file manager), `WScript.Shell` (command execution), ADO/ADOX/JRO (database browser), multiple file-upload components, JMail/CDONTS (mailer), and `Microsoft.XMLHTTP` (downloader). It contains 22 functions and 3 subroutines and carries no hardcoded C2 — it is operator-browsed interactively.

This shell is **commodity, reused as-is**. The `Ghost小组` family is globally reused across many unrelated operators, and the VBScript.Encode wrapper is already covered by public YARA (for example, Neo23x0's `WEBSHELL_ASP_Encoded`). Its presence is an indicator of compromise, not an identity signal — a point developed in Section 9.

> **No-attribution guard:** the gb2312 Chinese-language title and the `Aatrox` password are **commodity signals, not operator identity, and they do not indicate a Chinese or any named-actor nexus.** Ghost小组 webshells are reused worldwide; `Aatrox` is the name of a *League of Legends* champion in broad popular use. Both are logged as detection anchors and explicitly ruled out as attribution leads (see Section 9).

### 6.3 CVE-2026-20817_PoC.exe — non-weaponized WER ALPC LPE demonstration

> **Analyst note:** This is a proof-of-concept program for a Windows privilege-escalation bug in the Windows Error Reporting service. Two facts make it a low-priority item despite its alarming filename: Microsoft fixed the underlying bug in January 2026, and reverse engineering shows this particular build does not actually carry out the attack — it only demonstrates the surrounding scaffolding. The correct response is to confirm the January 2026 patch is applied, not to treat the operator as holding a working exploit.

`CVE-2026-20817_PoC.exe` is a native x64 binary (148,992 bytes, compile timestamp 2026-02-18) that *self-describes* as a Windows Error Reporting (WER) ALPC Elevation-of-Privilege demonstration and claims it "allows low-privileged users to execute arbitrary commands as SYSTEM" — but the code **does not deliver that claim**. Classification of the build as **non-weaponized is DEFINITE**, established by disassembly (in the Ghidra reverse-engineering suite) of its import surface.

The observed `main` flow is a scaffold, not an exploit:

1. Prints a colored CVE/WER banner.
2. Enables SeDebugPrivilege and SeImpersonatePrivilege on its **own** token.
3. Creates a 520-byte anonymous shared memory section and writes the textbook staged payload string `C:\Windows\System32\cmd.exe /c whoami > C:\poc_wer.txt & calc.exe`.
4. Prints the WER ALPC port name `\WindowsErrorReportingService` — but **never connects to it** (no ALPC API is present).
5. Sleeps 2 seconds, enumerates running processes looking for `WerFault.exe`, and on a match opens it with read-only `TOKEN_QUERY` rights and prints each of its token privileges as ENABLED or DISABLED.
6. Cleans up and returns. No further action.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/flaskc2-postex-toolkit-67-215-232-25/cve-2026-20817-wer-alpc-decompiled.png" | relative_url }}" alt="Ghidra decompilation of CVE-2026-20817_PoC.exe showing the WER ALPC port name string for WindowsErrorReportingService and a CreateToolhelp32Snapshot and Process32FirstW loop enumerating running processes to find WerFault.exe.">
  <figcaption><em>Figure 4: Ghidra (disassembler) view of CVE-2026-20817_PoC.exe. The build prints the WER ALPC port name <code>\WindowsErrorReportingService</code> but never connects to it, then uses <code>CreateToolhelp32Snapshot</code> / <code>Process32FirstW</code> to enumerate processes looking for <code>WerFault.exe</code> — the reconnaissance scaffold around the vulnerability. No ALPC, token-duplication, or process-creation APIs are present, which is why the build is classified non-weaponized.</em></figcaption>
</figure>

**Why it cannot elevate (import-surface absence, DEFINITE).** The binary imports process-enumeration, `OpenProcess`, `OpenProcessToken`, `GetTokenInformation`, `AdjustTokenPrivileges`, privilege-lookup, and file-mapping/console APIs. **Decisively absent** are any ALPC (`NtAlpc*`), RPC, or WER (`WerReport*`) API; `DuplicateTokenEx`; `ImpersonateLoggedOnUser` / `SetThreadToken`; `CreateProcessWithTokenW` / `CreateProcessAsUserW`; and any `CreateProcess*` at all. The single `OpenProcessToken` uses read-only `TOKEN_QUERY` — it inspects a token, it never duplicates one. Token theft, impersonation, the SYSTEM-process spawn, and the actual ALPC trigger are all missing. The program demonstrates the reconnaissance around the vulnerability; it does not perform the exploitation.

**Public CVE context (corroborates the reverse engineering).** CVE-2026-20817 is a real, publicly documented WER service ALPC EoP. Its root cause is the `SvcElevatedLaunch` function launching `WerFault.exe` with an attacker-supplied command line drawn from a shared memory section, without validating the caller — a low-privileged attacker who controls that section content can cause `WerFault.exe` to run arbitrary commands as SYSTEM. The public description matches this build's reverse-engineered behavior exactly (the ALPC port name, the 520-byte shared section, the `WerFault.exe` enumeration), which validates the static analysis against the public record. Microsoft **patched it in the January 2026 Security Update** (affecting Windows 10/11 before that update and Windows Server 2019/2022). A public PoC by the researcher @oxfemale [Source: github.com/oxfemale/CVE-2026-20817] and a technical writeup by the researcher itm4n [Source: itm4n.github.io/cve-2026-20817-wersvc-eop/] both exist; the itm4n writeup credits Denis Faiustov and Ruslan Sayfiev (GMO Cybersecurity) for the original discovery.

**Honest framing (maintained).** This report does **not** claim the operator holds a working CVE-2026-20817 exploit, and does **not** call this build "the public PoC" — whether it derives from the oxfemale release is unconfirmed (no hash comparison was performed), and ours is non-weaponized while the public PoC is described as working, so they may differ. The accurate statement: the operator carries a *non-weaponized demonstration PoC* for a recently-patched LPE. This is a **patch-action callout**, not a live exploit threat. The operational read is that the operator relies on the proven commodity Potato escalators and experiments with newer LPE research on the side.

**Tradecraft observation (characterization, not attribution).** The kit is notably **itm4n-sourced**: PrintSpoofer and RoguePotato are itm4n / closely-associated tools, and this is a PoC for an itm4n-documented CVE. The operator curates from the published SeImpersonate/Windows-LPE research ecosystem. This describes the operator's sourcing habits; it is developed as profiling, not identity, in Section 9.

---

## 7. The Public Post-Exploitation Toolkit

The bulk of the staged toolkit is public, commodity tooling — six SeImpersonate "Potato" escalators, the GhostPack Rubeus Kerberos toolkit, SharpSuccessor for dMSA abuse, and Netcat. This report documents each at the depth needed to detect and contextualize it within the operator's chain, without re-deriving the well-published research behind each tool. The honest-framing distinction from Section 2.2 carries throughout: five of these are operator-recompiled .NET builds identified by signature, and the native tools are prebuilt public binaries identified by hash.

### 7.1 The SeImpersonate "Potato" suite (six tools)

> **Analyst note:** Windows grants certain service accounts (including the accounts IIS and SQL Server run under) a privilege called SeImpersonate, which lets a process briefly act as another user who connects to it. The "Potato" family of tools abuses this by tricking the operating system into connecting to the attacker as SYSTEM — the highest-privilege account — and then stealing that connection's identity. Each tool in the family targets a slightly different Windows mechanism; staging all six is how the operator guarantees one will work whatever the target's Windows version and patch level.

SeImpersonatePrivilege is granted by default to Windows service accounts, including IIS application pool identities (`w3wp.exe`) and SQL Server service accounts (`sqlservr.exe`) — the exact two contexts this operation's footholds land in. A process holding the privilege can impersonate a higher-privileged token that authenticates to a service it controls; the Potato family forces a SYSTEM-level authentication to an attacker-controlled named pipe, COM object, or RPC endpoint and then impersonates the resulting token to spawn a SYSTEM process. The six staged variants are evolutionary branches of this one idea, each working around mitigations applied to earlier variants:

| Tool | Primitive | Build form | Relevant Windows targets |
|---|---|---|---|
| JuicyPotato(NG) | DCOM CLSID manipulation | Native, prebuilt (hash-match) | Pre-Win10 1809 / Server 2016; the NG fork extends support |
| PrintSpoofer | Print spooler named pipe | Native, prebuilt (hash-match) | Win10, Server 2016/2019 |
| RoguePotato | NTLM relay via external OXID resolver | Native, prebuilt (hash-match) | Win10 1809+, Server 2019 |
| EfsPotato | MS-EFSR coercion (EFS RPC pipes) | .NET, operator-recompiled | Win10 1803–22H2, Server 2019/2022 |
| GodPotato | COM-based (IRemUnknown2) | .NET, operator-recompiled | Server 2012–2022, Win 8–11 |
| SweetPotato | Combined Potato omnibus | .NET, operator-recompiled | Multiple Windows generations |

The operator also staged the RoguePotato OXID-resolver helper (`RogueOxidResolver.exe`, native prebuilt), which RoguePotato requires. Staging all six variants plus the helper is consistent with targeting a range of Windows builds without knowing the target patch level in advance — GodPotato is the most current and broadly compatible option, but carrying the full set ensures a working variant on any target. Microsoft has progressively mitigated the print-spooler vector (degrading PrintSpoofer reliability on patched systems), while GodPotato, EfsPotato, and RoguePotato remain effective across current Windows versions per public community research (MODERATE — sourced from community documentation and repository update histories, not a formal vendor statement).

**Detection.** The five operator-recompiled .NET tools are already covered by existing public YARA rules — `HKTL_NET_GUID_SweetPotato` (type-library-GUID based, Neo23x0 signature-base), `tool_efspotato` and `tool_sharpefspotato_strings`, and Elastic's `Windows_Exploit_FakePipe` — which were confirmed firing on the operator builds via VirusTotal. Those rules are referenced rather than re-authored. The native tools carry stable import-table hashes (imphashes) that survive file renaming and are the durable host indicators for the prebuilt binaries; they are listed in the [IOC feed]({{ page.ioc_feed }}) and built into a Sigma imphash rule in the detection package. Behaviorally, the whole class surfaces as a service-account process (`w3wp.exe` / `sqlservr.exe`) spawning a child that then runs at SYSTEM integrity, plus named-pipe creation for the spooler-based tools.

### 7.2 Rubeus — GhostPack Kerberos abuse

`Rubeus.exe` (515,584 bytes, operator-recompiled, compile timestamp 2026-03-23) is the open-source GhostPack Kerberos toolkit by Will Schroeder (harmj0y), identified here by HKTL-GUID YARA signatures and VirusTotal rather than by public-release hash. It provides the full range of Kerberos abuse — Kerberoasting, AS-REP roasting, Pass-the-Ticket, Overpass-the-Hash, Golden and Silver ticket forging, S4U delegation abuse, and Kerberos event monitoring. In the operator's chain it is the Active Directory lateral-movement layer reached after SYSTEM is achieved via the Potato suite. The operator's recompilation defeats hash-based detection of the public release, but signature-based file detection remains available, and behavioral detection is well established: Windows Security Event ID 4769 (service-ticket requests with RC4-HMAC — the Kerberoasting signal), Event ID 4768 (TGT-request anomalies), and command-line parameters (`kerberoast`, `asktgt`, `asreproast`, `s4u`, `tgtdeleg`) covered by existing SigmaHQ rules and Splunk Security Content [Source: GhostPack/Rubeus README; Splunk Security Content]. The toolkit also staged `NtApiDotNet.dll` — a public library bundled as a Rubeus dependency.

### 7.3 SharpSuccessor — BadSuccessor / dMSA abuse

`SharpSuccessor.exe` (13,312 bytes, operator-recompiled) automates the "BadSuccessor" technique discovered by Yuval Gordon of Akamai Security Research in 2025 [Source: Akamai Security Research, "Abusing dMSA for Privilege Escalation in Active Directory"]. It is the most narrowly-targeted tool in the kit — it exploits the delegated Managed Service Account (dMSA) feature introduced in Windows Server 2025. The attack abuses how dMSAs inherit privileges during migration: an attacker with `CreateChild` rights on an Organizational Unit creates a dMSA object, sets `msDS-ManagedAccountPrecededByLink` to point at a target privileged account and `msDS-DelegatedMSAState` to 2 (signaling completed migration), and when a Kerberos ticket is requested for the malicious dMSA, the Key Distribution Center builds the PAC using the target account's SIDs — granting the dMSA the target's full permissions. The attack does not require the organization to actually use dMSAs; any domain with at least one Windows Server 2025 domain controller is exposed.

Microsoft assessed BadSuccessor as Moderate severity; an August 2025 patch to `kdcsvc.dll` mitigated the one-way-link exploitation path, though post-patch analysis indicates an attacker who can write both sides of the dMSA pairing can still complete the attack [Source: AlteredSecurity post-patch analysis]. SharpSuccessor requires the operator to first reach a context with `CreateChild` rights on an OU (achievable from SYSTEM via the Potato chain), making it the terminal escalation step toward domain compromise. Detection requires explicitly enabled auditing — Windows Server 2025 does not log the relevant events (5137 dMSA creation, 5136 attribute modification, 2946 dMSA authentication) by default.

### 7.4 Netcat (nc64)

`e.exe` is a renamed `nc64.exe` (64-bit Windows Netcat, compile timestamp 2011-09-16) with a 7 KB overlay stripped during preprocessing. It is standard commodity tooling for reverse shells, file transfers, and port forwarding; the prebuilt binary hash-matches the public release, and its imphash (`567531f0…`) survives renaming and is the primary anchor when the original filename is absent.

### 7.5 Infrastructure profile

> **Analyst note:** This subsection describes the operator's server hosting — where the staging host lives, who provides it, and what the surrounding history tells us. The key defensive point is simple: the entire operation runs on one rented server with no backup and no domain name, so a single block at the network perimeter covers everything currently known.

The operation runs on a **single host**, `67.215.232[.]25`, with no sibling infrastructure (HIGH confidence). The host is an Ubuntu VPS on **AS36352 (HostPapa / ColoCrossing)**, a budget US commodity datacenter provider registered in Buffalo, NY (geolocated to Los Angeles). VirusTotal scores the IP 15/91 malicious; Hunt.io flags it as a malicious open directory with `threat_actor: null`. This is a commodity provider with a moderate abuse history reflecting its low-cost, low-verification model — **not** bulletproof hosting (it is US-based, ARIN-registered, and subject to US legal process). The host is fully attacker-controlled: the operator installed custom Python services (the Flask C2, the open-directory server) on custom ports, which requires root-level control of the VPS.

**Single-host operation is confirmed by five convergent negative pivots:**

| Pivot | Method | Result |
|---|---|---|
| SSH host-key reuse | Hunt.io key-history search | Key triplet appears on 0 other IPs |
| Bespoke backdoor hash | AttackCapture hash lookup | 1 host only |
| Backdoor filename `cmd_exece.dll` | AttackCapture filename lookup | 1 host only |
| Webshell filename `NPCInfoList1.aspx` | AttackCapture filename lookup | 1 host only |
| TLS / JARM / certificate | Hunt.io SSL fields | None present (HTTP-only host — no TLS pivot possible) |

The host is **IP-only** — VirusTotal records zero DNS resolutions, meaning no domain has ever pointed to it. IP-level blocking therefore fully covers the known infrastructure; DNS-layer blocking is neither required nor sufficient. The HTTP-only posture also eliminates the TLS, JARM, and certificate-transparency pivot dimensions entirely — this is a confirmed absence, not a gap in analysis.

**Two service eras** appear in the host's port history. An earlier era (2025-11-21 to 2025-12-23) ran an apparent multi-port HTTP forward-proxy service across roughly 35 ports in the 5222–5455 range, all returning `407 Proxy Authentication Required`, plus a Prometheus exporter. The current campaign era (2026-03-09 onward) brought up the Flask listeners and, two days later, the open-directory toolkit. Whether the proxy-era tenant and the current operator are the same party is **LOW/INSUFFICIENT** and is deliberately excluded from the campaign IOCs — ColoCrossing recycles IPs across tenants, and the proxy-era ports (5222–5455) are excluded from the feed for that reason.

**Operational tempo.** The infrastructure went live 2026-03-09; the toolkit was staged by 2026-03-11; the operator's .NET build cluster (EfsPotato 03-20, `cmd_exec.dll` 03-21, Rubeus 03-23) postdates the infrastructure standing up — a stand-up-then-tool workflow. The C2 has been **idle for the entire three-month observation window** (`active_servers=0`, `completed_commands=0` as of 2026-06-12), and the operator made no observable opsec change after the 2026-04-09 public disclosure of the panel. The SSH host-key triplet (ed25519 `aa5372bf…`, RSA `0d244225…`, ECDSA `e9c481fe…`) is retained as a future monitoring anchor for operator infrastructure reuse; it is not a blocking IOC.

---

## 8. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`. The Confidence Summary in Section 11 organizes findings by confidence level for the higher-level view. Mappings describe capability staged in the toolkit; where a capability is staged but not observed executing, it is marked. Technique IDs were validated against the MITRE ATT&CK Enterprise matrix.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Initial Access / T1190 | Exploit Public-Facing Application | IIS webshells + MSSQL CLR backdoor as footholds on internet-facing services |
| Persistence / T1505.001 | SQL Stored Procedures | `cmd_exec.dll` — `[SqlProcedure] reverse_shell` registered via `CREATE ASSEMBLY` / `EXTERNAL NAME` |
| Persistence / T1505.003 | Web Shell | `miss.asp` (Ghost小组 ASP) + `NPCInfoList1.aspx` (AES .NET loader) under `w3wp.exe` |
| Execution / T1059.003 | Windows Command Shell | `cmd_exec.dll` and both webshells route operator input through `cmd.exe /c` |
| Execution / T1059.005 | Visual Basic | `miss.asp` VBScript.Encode webshell; `Execute Session("Aatrox")` server-side eval |
| Defense Evasion / T1027.010 | Command Obfuscation | `miss.asp` VBScript.Encode (`#@~^…^#~@`) wrapper |
| Defense Evasion / T1620 | Reflective Code Loading | `NPCInfoList1.aspx` — AES-decrypt POST body → `Assembly.Load` → `CreateInstance("K")`, in-memory |
| Defense Evasion / T1140 | Deobfuscate/Decode Files or Information | AES-128-CBC decrypt of POST body, key=IV `ca63457538b9b1e0` |
| Privilege Escalation / T1134.001 | Token Impersonation/Theft | Potato suite abuses SeImpersonatePrivilege (6 tools) → SYSTEM |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | `CVE-2026-20817_PoC.exe` — intended WER ALPC LPE, **scaffold only, not completed in this build** (MODERATE) |
| Privilege Escalation / T1078.002 | Domain Accounts | `SharpSuccessor.exe` — BadSuccessor / dMSA abuse for AD privilege escalation |
| Credential Access / T1558.003 | Kerberoasting | `Rubeus.exe` `kerberoast` |
| Credential Access / T1558.001 | Golden Ticket | `Rubeus.exe` ticket request/forge capability (`asktgt`/`ptt`) staged (MODERATE) |
| Credential Access / T1550.003 | Pass the Ticket | `Rubeus.exe` `s4u` / ticket injection staged (MODERATE) |
| Discovery / T1057 | Process Discovery | `CVE-2026-20817_PoC.exe` process enumeration hunting `WerFault.exe` |
| Discovery / T1082 | System Information Discovery | Potato variant selection implies host-build enumeration; webshell host recon (MODERATE) |
| Command and Control / T1071.001 | Web Protocols | Bespoke Flask C2 — `/api/report` + `/api/heartbeat` POST beacons on `:8080` |
| Command and Control / T1095 | Non-Application Layer Protocol | `cmd_exec.dll` raw reverse-TCP shell channel (operator-supplied ip/port) |
| Command and Control / T1105 | Ingress Tool Transfer | Open directory `:1337` stages the toolkit for retrieval onto victims |
| Lateral Movement / T1021 | Remote Services | Rubeus/SharpSuccessor-enabled Kerberos/AD lateral movement (capability, post-SYSTEM) (MODERATE) |

**Tactic-coverage check.** Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Defense Evasion, Discovery, Command and Control, and Lateral Movement are all represented. Collection, Exfiltration, and Impact are **not** mapped — no collection, staging, or destructive capability is present in the sample set. This is a privilege-escalation and lateral-movement staging kit, not a data-theft or ransomware payload.

---

## 9. Threat Actor Assessment

Attribution to a named threat actor is **not possible** from the available evidence. Two independent intelligence corpora return no actor association (VirusTotal `related_threat_actors`: none; Hunt.io threat-actor catalog: none, live-verified 2026-06-12), no security vendor at any credibility tier attributes this activity, and the single prior public reference (Breakglass Intelligence, 2026-04-09) likewise reports attribution as unknown. The confidence in attribution is **INSUFFICIENT (<50%)** — the formal designation is **Unknown threat actor**.

### 9.1 Why attribution cannot be made

The evidence offers no overlap surface and no actor-distinctive technique:

- **The infrastructure is a single, idle, sibling-less, IP-only host on commodity US hosting.** Five convergent negative pivots (Section 7.5) return single-host results, and the HTTP-only posture eliminates TLS/certificate pivots entirely. There is no infrastructure depth to correlate against a known cluster.
- **The tradecraft is generic.** A standard IIS+MSSQL/Active-Directory post-exploitation chain (SeImpersonate Potato → SYSTEM → Rubeus/SharpSuccessor) built from public tooling contains no actor-distinctive technique.
- **The only bespoke code is a custom build of a public technique no actor owns.** `cmd_exec.dll` implements the publicly documented MSSQL CLR reverse-shell technique; it carries no actor signature. The genuinely unique artifact — the Flask C2 implant — is unrecovered, so no code-similarity comparison against known families is possible. This unrecovered implant is the decisive gap: it is the single most likely path to a named attribution, and it is closed at the OSINT level.
- **The C2 has been idle the entire observation window.** With zero completed commands, there is no victim, sector, or geography telemetry to align with any actor's known objectives.

### 9.2 Actor-class read (operator profiling, not attribution)

The best-supported intelligence statement about *what kind* of operator this is — distinct from named attribution — is **MODERATE** confidence: the operation is **most consistent with a financially-motivated individual or small-group cybercrime operator**. An Analysis of Competing Hypotheses found this hypothesis carries zero inconsistencies. The named-APT hypothesis is rejected with six: zero corpus overlap, budget shared hosting rather than bulletproof or compromised infrastructure, no infrastructure depth, commodity tooling, public webshells, and no opsec reaction to the public disclosure — collectively the opposite of a typical state-nexus signature. A red-team/penetration-tester hypothesis is the runner-up but carries two inconsistencies: a sanctioned engagement would be unlikely to leave a live C2 panel and open tool directory exposed for roughly three months, nor to ignore a public disclosure. This is operator profiling — it resolves "what kind of operator," not "which operator" — and is kept strictly distinct from named attribution.

### 9.3 The three identity-adjacent signals — ruled out, on the record

Three artifacts in the toolkit could be mistaken for identity leads. None is, and each is ruled out explicitly so a reader who notices it sees immediately why it is not a lead:

- **`Ghost小组` (gb2312 webshell title).** This is the commodity branding of a globally-reused public Chinese ASP webshell family — **not operator identity, and not a China-nexus cue.** Hunt.io confirms no matching actor (a search for "Ghost" returned only unrelated `Ghost*` actors, a string collision). The Chinese-language origin is a property of the *tool*, which is reused worldwide by operators of every nationality; it does not indicate that this operator is Chinese, Chinese-speaking, or China-aligned.
- **`Aatrox` (webshell password / eval parameter).** A commodity password — the name of a *League of Legends* champion in broad popular use. A Hunt.io search returned zero actor results. It is a detection anchor only, not an identity artifact.
- **itm4n-sourced tool curation.** The kit favors itm4n / closely-associated tooling (PrintSpoofer, RoguePotato, the CVE-2026-20817 PoC). itm4n's tools are public and ubiquitous in modern Windows-privilege-escalation kits; this is a tradecraft and sourcing observation that informs the operator profile (competent, current on published research), **not** actor naming.

> **No-China-nexus statement:** the Chinese commodity webshell title is tool-origin, not operator-nationality. This report does not render the operator as Chinese, Chinese-speaking, or China-aligned, and a false-flag reading was considered and dismissed — the single Chinese-language cue is too cheap and common to carry false-flag intent, and no corroborating high-effort contradictory tells exist.

### 9.4 No tracking designation assigned

The Hunters Ledger assigns **no internal tracking designation (no UTA)** to this operation. It is a single-host, idle, sibling-less footprint with no cross-investigation links, which does not meet the threshold for a trackable-actor label — minting one would manufacture trackability the evidence does not support. The campaign is described by its infrastructure: `FlaskC2-PostEx-Toolkit-67.215.232.25`. Two markers are retained as future monitoring anchors that could reopen the question if they recur on infrastructure tied to additional activity: the Flask C2 vocabulary/route fingerprint, and the SSH host-key triplet. Until then, they are anchors, not the basis for a designation.

**Prior art credited.** Breakglass Intelligence first documented the C2 panel on 2026-04-09 and likewise reported attribution as unknown [Source: intel.breakglass.tech post #158873].

---

## 10. Indicators of Compromise

The complete, validated, machine-readable IOC feed is published separately at the **[IOC feed]({{ page.ioc_feed }})** (JSON, no defanging — SIEM/EDR-ingestible). This section summarizes the highest-value indicators and the exclusion rationale; it is not the full feed, and IOCs are not embedded in this report.

**Indicator counts:** 15 SHA256 file hashes (1 DEFINITE bespoke backdoor, 14 HIGH), 6 native-tool imphashes (renaming-resistant), 1 IPv4, 5 URLs, 1 host file path, and 6 string indicators. The feed groups indicators by family so each maps to the correct detection rule.

**Highest-value anchors (defanged here; the feed is not defanged):**

| Type | Indicator | Confidence | Note |
|---|---|---|---|
| SHA256 | `a7029ef2…a25262` | DEFINITE | `cmd_exec.dll` — bespoke MSSQL CLR backdoor (specific operator build) |
| String | `[*] Connected to SQL Server CLR backdoor` | HIGH | Backdoor banner — strongest, operator-specific YARA anchor |
| String/key | `ca63457538b9b1e0` | HIGH | AES-128 key=IV in the `NPCInfoList1.aspx` loader |
| IPv4 | `67.215.232[.]25` | HIGH | Single staging host (AS36352); 15/91 VT malicious; IP-only |
| URL | `http://67.215.232[.]25:8080/health` | HIGH | Flask C2 unauthenticated status route (distinctive JSON field-combo) |
| URL | `http://67.215.232[.]25:8080/api/report` · `…/api/heartbeat` | HIGH | Flask C2 POST-only beacon endpoints |
| imphash | `f9a28c45…`, `545a8124…`, `959a8304…`, `576d6e02…`, `567531f0…` | HIGH | JuicyPotato / PrintSpoofer / RoguePotato / RogueOxidResolver / nc64 — survive renaming |

**Deliberately excluded from the feed** (documented so the exclusion is auditable): the proxy-era ports 5222–5455 on this IP (Nov–Dec 2025 tenancy — different-tenant/reallocation risk); two benign VirusTotal downloaded files (`autodiscover.xml` and the `:1337` directory-index page); `inostage.ru` / `panel.inostage.ru` (public-tool co-host noise); and the generic .NET runtime imphashes (`f34d5f2d…`, `dae02f32…`, non-discriminating managed-PE stubs). The `Aatrox` and `Ghost小组` strings are included as detection anchors but carry an explicit note that they are commodity-reuse signals, not operator identity.

---

## 11. Risk Assessment

The toolkit's *capability* ceiling is HIGH, but the *campaign* threat level is MEDIUM — the operation is idle and unvictimed. The override callout at the top of this report explains the distinction.

### 11.1 Key risk factors

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
<tr><td>System Compromise</td><td>8/10</td><td>Two independent service-account footholds (IIS webshells, MSSQL CLR backdoor) feeding a complete, working SYSTEM-escalation chain. Capped below maximum because each foothold requires the operator to already reach a SeImpersonate service-account context.</td></tr>
<tr><td>Privilege Escalation</td><td>8/10</td><td>Complete public Potato suite (6 variants) covering essentially every Windows-build path from SeImpersonate to SYSTEM, plus dMSA/BadSuccessor for AD escalation. The carried CVE LPE PoC is non-weaponized and does not add to this score.</td></tr>
<tr><td>Lateral Movement</td><td>6/10</td><td>Rubeus (Kerberos abuse) + SharpSuccessor (dMSA) provide a strong, AD-centric, hands-on-keyboard lateral-movement capability — but it is staged, not observed executing, and there is no self-propagation.</td></tr>
<tr><td>Detection Difficulty</td><td>7/10</td><td>The bespoke MSSQL backdoor evades generic sandboxes (Zenbox 98% harmless) and is scored clean by Microsoft and Kaspersky; .NET tooling is recompiled to defeat hash matching. Offset by strong, deployable string/behavioral anchors.</td></tr>
<tr><td>Campaign Activity</td><td>2/10</td><td>C2 idle the entire ~3-month window (zero active beacons, zero completed commands); no confirmed victims; single host; IP-only and fully blockable. This is the dimension that pulls the overall campaign rating down to MEDIUM.</td></tr>
</tbody>
</table>

**Overall campaign risk: 6.2/10 — MEDIUM.** The capability dimensions are uniformly high (6–8), but the campaign-activity dimension (2/10) — idle C2, no victims, single blockable host — governs the overall rating per the threat-level override at the top of this report. Were the C2 to activate or victims to be confirmed, the activity score would rise sharply and the overall rating would move to HIGH.

### 11.2 Potential impact (risk framing)

Against an unprepared MSSQL, IIS, or Active Directory environment, this toolkit enables an attacker to convert a single service-account foothold into full SYSTEM control and then domain-level compromise, moving laterally through Kerberos and dMSA abuse. The custom MSSQL backdoor's low detectability means the initial foothold can persist unnoticed by signature-based defenses and generic sandboxes. The two unrecovered runtime payloads — the Flask beacon implant and the webshell's `class K` module — mean an operator-pushed second stage could carry capabilities not visible in this analysis. There is no self-propagation: lateral movement is operator-driven, not automated worm-style spread.

### 11.3 Confidence summary

- **DEFINITE:** `cmd_exec.dll` identity as an MSSQL CLR reverse-shell backdoor (decompilation); `CVE-2026-20817_PoC.exe` non-weaponized status (disassembly, import-surface absence); the IP-only single-host infrastructure (zero DNS resolutions).
- **HIGH:** all public-tool identifications (VT + YARA + capa); the host and network IOCs; the dual-vector foothold model; no sibling infrastructure (five convergent negative pivots); the Flask C2 three-route surface, in-handler auth, and vocabulary fingerprint.
- **MODERATE-HIGH:** the Flask C2 as a bespoke, no-public-framework-match implementation.
- **MODERATE:** the inferred beacon protocol semantics; the operator stage (staging / between-victims); the Rubeus/SharpSuccessor lateral-movement capability (staged, not observed executing); the `:5000` listener's control-plane role; the financially-motivated cybercrime actor-*class* read.
- **INSUFFICIENT:** attribution to a named actor; whether the operator holds a working CVE-2026-20817 exploit; whether the proxy-era tenant is the same operator.

---

## 12. Detection and Response Guidance

A complete, deployable detection package accompanies this report: **[detection rules]({{ page.detection_page }})** (4 YARA rules, 7 Sigma rules, 3 Suricata signatures) and the machine-readable **[IOC feed]({{ page.ioc_feed }})**. Detection rules are not embedded in this report. The package is built around the campaign's central problem — the bespoke MSSQL backdoor that automated tooling misses — and it includes coverage for the IIS webshell vector, the native-tool imphashes, and the distinctive Flask C2 network signature. The detection file's [Coverage Gaps]({{ page.detection_page }}#coverage-gaps) section documents, honestly, what could not be covered (the unrecovered beacon implant and webshell payload, and the reliance on existing public rules for the recompiled .NET tooling).

The brief orientation below is intended only to point defenders at *what to address*. It is not an incident-response procedure; organizations with an active incident should engage their own IR process.

**Top detection priorities:**
1. **MSSQL CLR backdoor** — `sqlservr.exe` spawning `cmd.exe`, outbound TCP initiated by `sqlservr.exe`, and the `[*] Connected to SQL Server CLR backdoor` banner string. Highest value: generic sandboxes and most AV miss this entirely.
2. **IIS webshell foothold** — `w3wp.exe` spawning `cmd.exe` / `WScript.Shell`; the `Aatrox` eval-gadget request parameter; the hardcoded AES key `ca63457538b9b1e0`.
3. **Flask C2 network signature** — the `/health` JSON field-combo (`active_servers` + `pending_commands` + `completed_commands` + `status` + `timestamp`) and the POST-only `/api/report` + `/api/heartbeat` URI pair on a `Werkzeug/3.1.6` listener. The beacon implant itself was not recovered (see §13), but any internal host initiating outbound POST to `:8080` `/api/heartbeat` or `/api/report` is a strong compensating hunt — the route names are not used by any known legitimate service.

**Persistence targets to locate and remove (artifact names/locations only):**
- MSSQL: the `reverse_shell` `EXTERNAL NAME` stored procedure and its `CREATE ASSEMBLY` object; review the `clr enabled` configuration state.
- IIS: the dropped webshell files `miss.asp` and `NPCInfoList1.aspx` (and any `class K` assembly delivered to the loader at runtime).
- Host artifact (if the CVE PoC was executed): `C:\poc_wer.txt`.

**Containment categories (action labels):**
- Isolate affected MSSQL and IIS hosts.
- Block `67.215.232[.]25` at the perimeter (all known ports).
- Apply the January-2026 Windows Error Reporting patch on unpatched Windows 10/11 and Server 2019/2022.
- Review Active Directory for Kerberos ticket abuse and dMSA/BadSuccessor exposure (the latter on any domain with a Windows Server 2025 domain controller).

---

## 13. Gaps and Limitations

These are documented limits of passive, OSINT-and-static analysis of an idle host — not failures of analysis.

- **The beacon implant was not recovered.** The "server" binary that POSTs to `/api/heartbeat` and `/api/report` is not staged in the open directory, and VirusTotal records zero communicating files for the IP. It is a runtime-delivered (Type B) artifact, recoverable only from a victim capture or the operator's builder. Its absence closes the most likely path to named attribution and prevents authoring a client-side network signature (User-Agent, beacon interval).
- **The webshell `class K` payload was not recovered.** It is AES-encrypted in transit and delivered on demand, never written to disk. The detection package covers the *loader* but cannot cover the *payload*.
- **The `:5000` listener's role is undetermined.** All 38 probed paths return 404; the operator control-plane reading is a candidate, not a conclusion.
- **The beacon protocol is inferred, not decompiled.** The route surface, auth model, and vocabulary are directly observed; the check-in/report protocol semantics are inferred from route names and counter behavior (MODERATE).
- **No dynamic analysis was performed, by design.** The two missing artifacts are runtime-delivered and cannot be reproduced by detonating the available samples, and `cmd_exec.dll` is sandbox-resistant by architecture — a full MSSQL detonation would only reproduce the already-known `sqlservr → cmd → reverse-shell` pattern. The detection package is fully static-authorable.
- **The proxy-era to C2-era same-operator linkage is unresolved (LOW/INSUFFICIENT)** and excluded from the campaign IOCs.
- **Attribution carries an OSINT ceiling.** VirusTotal and Hunt.io are the corpora consulted; paid/commercial threat intelligence could in principle surface non-public overlaps. The Unknown-actor conclusion is correct on the available evidence, with the explicit caveat that it could move with commercial TI or future telemetry.

---

## 14. References and Sources

**Prior public reference (credited):**
- Breakglass Intelligence (2026-04-09): "Flask C2 — 67.215.232.25 unauth /health" — first public documentation of the C2 panel; reports attribution unknown. `https://intel.breakglass.tech/post/flask-c2-67-215-232-25-unauth-health-hostpapa` (post #158873). Tier 3.

**MSSQL CLR technique lineage (public, pre-dating this build):**
- Rapid7 Metasploit — `mssql_clr_payload` module. Tier 2.
- NetSPI — "Attacking SQL Server CLR Assemblies." Tier 2.
- `github.com/evi1ox/MSSQL_BackDoor` — open-source MSSQL CLR backdoor. Tier 3.
- HackingArticles — "MSSQL for Pentester: CLR Assembly." Tier 3.

**CVE-2026-20817 (patched January 2026; public PoC):**
- @oxfemale — `github.com/oxfemale/CVE-2026-20817` (public PoC). Tier 3.
- itm4n — "CVE-2026-20817 WerSvc EoP" (2026-03-22), technical writeup; credits Denis Faiustov and Ruslan Sayfiev (GMO Cybersecurity) for discovery. Tier 3.

**Active Directory / dMSA:**
- Akamai Security Research (Yuval Gordon, 2025) — "Abusing dMSA for Privilege Escalation in Active Directory" (BadSuccessor). Tier 2.
- AlteredSecurity — BadSuccessor post-patch analysis. Tier 3.

**Tooling and webshell context:**
- GhostPack/Rubeus README (Will Schroeder); Splunk Security Content (Rubeus detection). Tier 2–3.
- itm4n — "PrintSpoofer" (2020). Tier 3.
- HHS HC3 — "The Godzilla Webshell" analyst note (2024-11-12); Trend Micro Godzilla research; Malpedia Godzilla Webshell entry. Tier 2.
- HackTricks — SeImpersonate / Potato suite documentation. Tier 3.

**Enrichment corpora (live-verified 2026-06-12):**
- VirusTotal MCP — IP report (15/91 malicious, resolutions 0, communicating_files 0, related_threat_actors 0); `cmd_exec.dll` (32/72, Zenbox harmless, sandbox idle). Tier 2.
- Hunt.io MCP — `enrichment-ip`, `search-ip-history-port`, `search-ip-history-ssh`, `search-ip-risk`, AttackCapture, threat-actor catalog (threat_actor null). Tier 2.

Source credibility tiers follow the project-wide hierarchy (Tier 1 government/multi-source; Tier 2 single major vendor; Tier 3 reputable journalism/researcher blogs; Tier 4 unverified). No Tier-4 source is relied upon as a sole basis for any claim in this report.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
