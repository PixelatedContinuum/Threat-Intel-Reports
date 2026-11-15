---
title: "A Credential-Access Rig Aimed at a US Federal Agriculture Department"
date: '2026-11-15'
layout: post
permalink: /reports/inv-2026-083-federal-ad-credential-access-rig/
hide: true
unlisted: true
sitemap: false
preview_cover_label: "Credential Access"   # preview only: header cover while the catalog entry is parked; drop at go-live
preview_severity: high
category: "Credential-Access Toolkit"
description: "An unidentified operator built a rig to take over a US federal agriculture department's Active Directory, delivered an implant to an address on the department's network, and held 239 of its Kerberos service tickets, using a Linux HTTPS agent and a OneDrive-controlled Windows loader signed with a Rockstar Games certificate key."
detection_page: /hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
ioc_feed: /ioc-feeds/inv-2026-083-federal-ad-credential-access-rig-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "151[.]236[.]22[.]111"
    note: "Operator host: open directory, implant and chisel delivery, chisel server, NTLM and HTTP capture servers (M247 and Edis, rented)"
  - value: "www[.]customerlop[.]top"
    note: "Command-and-control host baked into the Linux agent, TCP 443 behind Cloudflare"
  - value: "a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096"
    note: "agent.bin, static Linux HTTPS agent (SHA-256)"
  - value: "f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b"
    note: "msedge.dll, side-load loader with an embedded OneDrive beacon, Rockstar Games signature (SHA-256)"
---

**Campaign Identifier:** OpenDirectory-ADCredentialAccess-USFedAgriculture-151[.]236[.]22[.]111<br>
**Last Updated:** November 15, 2026<br>
**Threat Level:** HIGH

> **Risk vs. Campaign Threat Level:** The toolset scores MEDIUM, 5.5 out of 10 (Section 2), because the evidence shows capability and preparation far more often than a result. The campaign is HIGH because of who the operator pointed it at and what it got: a US federal department's network, 239 of that department's Kerberos service tickets, and an implant delivered to an address on its egress.

---

## 1. Executive Summary
{: .hl-tier-1}
{: .hl-tab-overview}

An unidentified operator spent late October 2026 building a way into a US federal agriculture department's Active Directory, and it got further than its failed password spray suggests. The operator's own server log shows an address on the department's network fetching the operator's implant 49 seconds after the operator tested the download, and the operator holds 239 Kerberos service tickets for 89 of the department's accounts. Where it stopped is as important: nothing in the files I hold shows an account being used, a cluster accepting the administrator certificate it forged, or any of its 13 prepared container-platform steps running. The detail I would carry away is how the operator dressed its tools. A Windows loader carries a Rockstar Games code-signing certificate key's signature, rides in under a genuine Microsoft binary, and takes its commands from a OneDrive folder, so what a defender sees is Microsoft traffic and a validly signed file.

The grades below are defined in Section 3. ACCESS SHOWN means evidence that the operator acted on the victim's system, COMPROMISED means the operator holds material only working access normally returns, REACHED means a reply from outside with nothing above the network layer, and INSUFFICIENT means the evidence supports no call.

- The department is the one victim with real depth. I grade it ACCESS SHOWN overall: the delivery of the implant to an address in the department's egress range is HIGH as an event, and that the operator controlled the host that fetched it is MODERATE, because a proxy, sandbox or other client fetching is not ruled out.
- The department's Active Directory realm is COMPROMISED on possession of the ticket material, which I hold at HIGH. How the tickets were obtained is unknown, and no cracked password, logon or working credential use is in the evidence.
- The container platform is REACHED at TCP level only, and cluster-admin access is INSUFFICIENT. The operator forged an administrator-named client certificate and holds its key, but nothing in the files I hold shows any cluster trusts the issuer.
- A US media organisation appears once, as a shell banner arriving at the operator's server. I grade it ACCESS SHOWN at MODERATE, with a researcher, sandbox or shared-egress source still open.
- My read is that this is an initial access broker building footholds to show or sell. I grade actor type INSUFFICIENT and I cannot name the operator, so I carry that read as mine and set the evidence that leaves it open beside it (Section 14).
- The defender point is to know what normal looks like, and the urgent hunt is the delivery window of 2026-10-29 and the signed-DLL pattern, with the realm and platform logs next. A signed file from a game publisher that does no gaming, a Microsoft binary running from the wrong directory and a refresh-token sign-in from a process with no browser are all detectable, and none of them is a reason to allow a file because its signature checks out.

The rest of the report grades each victim, takes both implants apart, and gives the hunt anchors and the indicators. Both implants have no public match in my bounded searches, which is not the same as saying they are new, and I keep the two apart throughout.

## 2. Business Risk Assessment
{: .hl-tier-1}
{: .hl-tab-overview}

The toolset is a credible risk to any organisation that allows Microsoft cloud traffic and trusts a signed file, and a smaller one than the campaign headline, because most of what I can prove is capability and preparation. I score it 5.5 out of 10, MEDIUM, as a weighted average of six dimensions, each tied to a finding in this report. The campaign is HIGH on what the operator reached, which Section 3 grades one victim at a time.

| Risk Dimension | Score | Rationale |
|---|---|---|
| Data Exfiltration (20%) | 5/10 | Both implants read and upload files, the Linux agent up to 100 MiB, but no collected file is in the evidence. The operator did retrieve 23 files of the department's deployment source and application inventory, and whether that repository is public is unchecked. |
| System Compromise (20%) | 6/10 | The department host fetched the implant (HIGH) and a tunnel-shaped session followed (MODERATE), but execution of either implant on a victim host is NOT CHECKED. |
| Persistence Difficulty (15%) | 3/10 | The Linux agent has no persistence code. The Windows loader has a scheduled-task verb, which I read at MODERATE without reading the routine that registers it. |
| Evasion Capability (15%) | 7/10 | An argument-vector spoof and in-memory re-execution on Linux, a Microsoft-signed host binary, a valid but untrusted signature and a Microsoft-hosted command channel on Windows. None disables a security tool. |
| Lateral Movement Risk (15%) | 6/10 | A tunnel carried 27 proxied connects into private address space, 11 addresses accepted a connection on the container API port, and 13 privileged-pod manifests are prepared. Nothing above TCP is shown. |
| Detection and Encryption Challenge (15%) | 6/10 | The Windows beacon uses two Microsoft hosts almost every tenant allows, so it cannot be blocked at the network. It is detectable by process, signature and directory, which is why this is not higher. |
| Overall | 5.5/10 | MEDIUM as a toolset. The campaign is HIGH because of the target and the ticket possession. |

What this means for the reader is that the damage ceiling is higher than the evidence floor. If the operator's access to the department was real and is still open, the 239 tickets and a working administrator route would be the start of a much larger problem. I cannot show either, and I do not score on what the files merely allow.

## 3. Victims: Who Was Hit and How Far the Operator Got
{: .hl-tier-2}
{: .hl-tab-victims}

The department is the only victim with real depth, and every other row is one data point. I grade each party from what the operator's own files show, and I name no host, address, realm, account or person on the victim side. Where two grades fit I record the lower one.

The four grades answer different questions for a defender deciding what to do first. ACCESS SHOWN means host-side evidence of the operator acting on the victim's system. COMPROMISED means the operator holds material only working access normally returns, with the route that produced it not shown. REACHED means the operator touched the system from outside and got a reply, with nothing above the network layer. LISTED means the party is named in the operator's files and no operator action against it is shown.

Of the 7 rows, the grades are 2 ACCESS SHOWN, 1 COMPROMISED, 1 REACHED and 3 LISTED.

| Organisation | Grade | What the operator's files show | Latest dated evidence |
|---|---|---|---|
| A US federal agriculture department (the agency) | ACCESS SHOWN | An address in the department's own egress range fetched the implant and a tunnelling tool 49 s after the operator's loopback test (HIGH as an event); operator control of the fetching host is inferred (MODERATE); a self-reconnecting, tunnel-shaped session followed; 27 proxied connects reached private address space, 7 of them to two agency-range hosts; 239 service tickets for 89 accounts are held | 2026-10-29 05:19:52 UTC, the last successful proxied connect into private address space (every later attempt through 2026-10-30 07:30:11 UTC failed) |
| A US media organisation | ACCESS SHOWN | One interactive shell banner from an address in its assigned range reached the operator's port-80 server at 01:52:54 UTC on 2026-10-29, and the same address held a zero-payload connection of at least 17 minutes and an established session on 2026-10-30; no command output; MODERATE | 2026-10-30 10:01 UTC, the end of the established session |
| Rockstar Games, Inc., as the holder of the signing key | COMPROMISED | Both signatures on `msedge.dll` verify under its Rockstar Games certificate key, so someone holding that private key signed a 2026 build (HIGH); who acquired the key, how and when is unknown | Not dated: the file was built on or after 2026-09-19 per its PE timestamp, which the builder controls |
| The owner of one host in a private range with no established owner | REACHED | The host answered SMB (16 of 30 attempts), MSRPC, NetBIOS, rpcbind and NFS (1 of 12) through the operator's tunnel; nothing above TCP is held; it is not counted as the agency's | 2026-10-29 05:19:52 UTC |
| The owner of one 4096-bit private key naming an unplaced internal domain | LISTED | A single key file with no certificate; provenance unknown, no operator action against that domain | No dated evidence held |
| The owner of the Microsoft Entra tenant and OneDrive account behind the beacon | LISTED | A tenant identifier and a live-looking refresh token decode from the beacon's configuration; whether the tenant is the operator's own or a hijacked user's is unknown | No dated evidence held |
| Two third-party addresses that polled the operator's capture servers | LISTED | An Amazon cloud address (30,147 events) and a carrier address (8,288 events) sent inbound polls; no operator action addressed to either; I read them as monitors (MODERATE) | 2026-11-05 for the carrier address; the cloud address was still polling at the last pull |

The agency row carries seven surfaces of its own. The organisation takes the highest grade any surface earns, and each surface keeps the grade its evidence supports.

| Surface | Grade | Basis |
|---|---|---|
| The host that fetched the implant | ACCESS SHOWN | Delivery HIGH; tunnel-shaped session MODERATE; execution of the implant on the host is NOT CHECKED |
| The Active Directory realm | COMPROMISED | Possession of 239 realm-labelled service tickets for 239 distinct service names and 89 accounts (HIGH); acquisition route unknown; no working credential use |
| The container platform | REACHED | 11 of 762 addresses accepted a connection on port 6443, from scan output that was only partly recovered, and 8 proxied connects to 6443 all failed; 13 privileged-pod manifests are prepared only; cluster-admin access INSUFFICIENT |
| The application estate | REACHED | Two hosts answered through the tunnel, one on 443 (4 of 24) and one on MSSQL (3 of 16); the SAP ports answered 0 of 8; the operator holds an inventory of 88 JBoss instances, and every instance not reached is LISTED |
| Internal source control | REACHED | 23 files of two projects were retrieved through the tunnel; whether the repositories are public is unchecked, so I do not record it as exfiltration |
| A web application on a host whose certificate key the operator holds | LISTED | The operator holds the private key of the host certificate and forged a client certificate with it; no request to the application is logged and the key's origin is NOT CHECKED beyond 3 of 195 public image tags |
| The SQL host and domain controller named in the pod scripts | LISTED | Named in prepared scripts with two embedded credentials; no output of any script is held |

Three caveats travel with those grades. The agency's ACCESS SHOWN rests on a delivery event in the operator's own log and on the shape of a session, not on anything the agency recorded, and the independent branch where an egress proxy or analyst sandbox fetched the files is open. The 27 private-address successes are 7 to two agency-range hosts and 20 to a range whose owner is unknown, so I never count all 27 as the agency's. The media organisation row is withdrawn rather than lowered if the shell turns out not to be the operator's, because there would then be no operator action against it at all.

Rockstar's row is a grade on the key, not an accusation about the company or the operator. The key is out of Rockstar's control, and I do not claim this operator stole it. I held 333 files from the open directory, 208 of them distinct by hash because many repeat, and I did not sweep the full set of 208 for further organisations. The party list comes from my reads of the operator's scripts, logs and infrastructure, so zero unlisted parties is not a completeness finding.

## 4. Technical Classification: A Credential-Access Rig With Two Implants
{: .hl-tier-2}
{: .hl-tab-chain}

The capability is a credential-access and foothold rig run from one rented server: scripts to enumerate accounts and spray passwords against a Kerberos realm, capture servers for NTLM authentication, tickets collected for offline cracking, and two remote-access implants, a Linux HTTPS agent and a Windows loader that takes its commands from OneDrive. It is built to get working Active Directory credentials and a way onto hosts, and what the access was for is undetermined. None of the 333 files I searched shows a ransom, a sale, a listing or a tasking.

The two implants are the most distinctive part, and I want to be exact about what that means. I found no public report of either one, of their command-and-control zone, of the container pod chain or of the numbered work-directory convention in my bounded searches. That is a statement about my search, and family novelty is NOT CHECKED, because the pages I read went through summarising readers and I did not open the primary vendor reports. The classes are well documented, Zig-built Linux implants that load plugins from memory and OneDrive or Graph command channels delivered by DLL side-loading, and I claim no lineage with any named family.

| Component | What it is | Grade |
|---|---|---|
| `agent.bin` | Stripped static Linux ELF, 686,504 bytes, beacons over TLS 1.2 to `www[.]customerlop[.]top`, runs shell commands, moves files up to 100 MiB, loads ELF plugins from memory | Capability read in code, HIGH; execution on any victim host NOT CHECKED |
| `msedge.dll` with `edge.exe` and `config.bin` | Genuine Microsoft `cookie_exporter.exe` renamed, side-loading a 312,488-byte DLL that runs a 49,696-byte embedded implant taking commands from a OneDrive folder | Capability read in code, HIGH; execution NOT CHECKED |
| Spray, enumeration and capture scripts | Account probes, an LDAP spray, zero-credential Netlogon probes, NTLM relay listeners and HTTP and SMB capture servers | Exercised and refused, or captured nothing in the held logs |
| 13 pod manifests | Privileged Kubernetes pod specifications for one named node, authored for a relay, coercion and registry-save chain | Prepared only; no run marker in 333 files |
| `chisel` | A stock public tunnelling build, known to VirusTotal since 2024-10-10 | No attribution value; a presence indicator on the delivery path |

Side-loading is the trick worth a plain explanation. A genuine Microsoft program asks Windows to load a library by name from its own directory, and if the attacker has put a library of that name there, the genuine program runs the attacker's code. The operator's loader does exactly that, so the process a defender sees is a Microsoft binary that was never touched. The signature on the DLL adds appearance, not a bypass, and Section 7 sets out what it does and does not prove.

## 5. The Attack Chain
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's work runs as a build-out of access rather than a clean intrusion: stand up the rig, probe the realm, fail to log on, end up holding ticket material, deliver an implant and a tunnel, and prepare the next step without showing it taken. The stages below follow the operator's own files and keep the grades from Section 3. Most of the evidence is the operator's logs and scripts, and almost none of it is anything a victim recorded.

| Stage | What the operator did | Where it is shown |
|---|---|---|
| 1. Stage the rig | Rented a server at M247 and Edis, left its directory open to the internet, registered the command-and-control zone at Gname on 2026-05-22 (160 days before the chisel server started), and built a Linux agent and a Windows loader whose PE timestamp is on or after 2026-09-19 | Provider and registry records, the implants' configuration, the directory listing |
| 2. Map the realm | Sent 253 account probes (138 exist), banner-probed 6 domain controllers, and scanned 762 addresses on the container API port, where 11 accepted a connection | The probe, banner and scan outputs in the operator's files |
| 3. Try to log on | Ran a lockout-aware LDAP spray of 136 binds with 0 successes, 20 zero-credential Netlogon probes on 6 controllers with 0 vulnerable, and armed relay listeners that relayed 0 authentications | The spray log, the Netlogon results and the relay and capture logs |
| 4. Hold ticket material | Held 239 Kerberos service tickets for 89 accounts and 111,559 captured NetNTLMv2 responses, ten names carrying 81 percent of them | The ticket file and the capture files; the responses are captured traffic, not credentials |
| 5. Deliver and tunnel | Tested the download from loopback at 01:49:16 UTC on 2026-10-29, saw an address in the department's egress range fetch `agent.bin` and `chisel` 49 s later, ran a chisel server, and sent 27 proxied connects into private address space between about 05:17 and 05:19:52 UTC | The operator's HTTP server log, the packet summaries and the proxy log |
| 6. Forge and prepare | Minted an administrator-named client certificate at 03:20:58 UTC on 2026-10-29 under the private key of a department web host's certificate, and authored 13 privileged-pod manifests for one named node | The certificate and key files and the manifests; no acceptance or run is shown |
| 7. Keep collecting | Left capture servers running and the directory open; the media organisation's shell banner arrived at 01:52:54 UTC on 2026-10-29 | The capture logs and the HTTP log |

Read top to bottom, the interesting thing is how much of the operator's effort went into getting credentials and how little of it worked on its own terms. The spray never landed, the relay received nothing, and the coercion and pod steps were never shown to run. The tickets are what the operator actually holds, and even they arrived by a route I cannot see.

Stage 5 is where the grade turns. The delivery event is in the operator's own log, which is a strong source for what reached the operator's server and a weak one for what happened inside the department. The 49-second gap after the operator's test is why I think the fetch was the operator's, and it is also why I leave the proxy, sandbox and analyst branch open.

## 6. Technical Teardown: The Linux HTTPS Agent
{: .hl-tier-3}
{: .hl-tab-chain}

`agent.bin` is a small, competently assembled remote shell, file mover and plugin loader, and what makes it hard to spot is its costume more than its code. It calls itself `/lib/systemd/systemd --user`, re-executes from an anonymous memory file, and talks to a command server over HTTPS paths copied from a WordPress theme. Everything I say about it is capability read in 32 of its 35 application functions. Nothing here is an observed execution, and I ran it nowhere.

<details markdown="1" class="hl-teardown">
<summary>Identity, build and execution flow</summary>

The file is a static, stripped x86-64 ELF of 686,504 bytes with SHA-256 `a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096`. Its `.comment` section records two producers, Zig's bundled clang and LLD 19.1.7 for the link and Debian's GCC 15.2.0 for at least one object, and the runtime is musl with mbed TLS 3.6.0 compiled from source in `/tmp`. Only 35 functions between `0x1033ae0` and `0x1036cef` are the operator's; everything above `0x1037000` is library or runtime.

`main` at `0x1036c30` does the following, in order. It seeds its random generator from the clock and ignores child-exit signals, then daemonises with a double fork if its parent process id is 3 or more. It reads `/proc/self/exe`, and if the target is not already an in-memory file, it copies itself into `memfd_create("")`, maps the copy read-write-execute and calls `execl("/proc/self/fd/N", "/lib/systemd/systemd --user", NULL)`. It then overwrites its argument vector with the same spoofed string, sets its process name to the 15-byte truncation `/lib/systemd/sy`, and builds a 32-character random session token.

The token and a 44-byte string baked into the binary together form a 76-byte XOR key. The agent registers, then loops: sleep 60 seconds with plus or minus 10 percent jitter, so 54 to 66 seconds, then poll. Every message is a new TCP connection, a new TLS handshake and one HTTP POST with `Connection: close`.

</details>

<details markdown="1" class="hl-teardown">
<summary>Command channel, paths and the command table</summary>

The command-and-control host is `www[.]customerlop[.]top`, port 443, held in a plaintext configuration slot and used for the connection, the TLS server name and the Host header. TLS is 1.2 only, and the server certificate is never verified (authentication mode set to none), so a sinkhole presenting any certificate would be accepted. The POST carries `Content-Type: application/json`, no User-Agent and no cookies. The application layer is a repeating-key XOR followed by base64, and the key tail is sent in the clear at registration, so a captured registration plus the binary decrypts a session.

| Path | Purpose |
|---|---|
| `/wp-content/themes/b2/Assets/fonts/iconfont.css` | Register: hostname, OS, user, internal address, process id, process name, sleep, group |
| `/wp-admin/admin-ajax.php` | Poll for tasks with a cleartext `check` body |
| `/wp-content/themes/b2/Assets/admin/gd_block.css` | Return a task result |
| `/wp-content/themes/b2/Assets/fontend/mobile.css` | Send a victim file to the server, refusing anything over 104,857,600 bytes |
| `/wp-includes/js/jquery/jquery.min.js` | Fetch a file or plugin from the server |

Taken one at a time, each path is an ordinary WordPress path. The set is the family-level anchor. The command table is short, and the plugin command is the extension point, because any further capability arrives as a plugin that I do not hold.

| Command | Behaviour |
|---|---|
| 1 | Run a shell command through `popen` and return the output |
| 2 | Read a local file, up to 104,857,600 bytes, and POST it to the server |
| 3 | Fetch a blob by token and write it to a destination path |
| 4 | List a directory in `ls -l` style |
| 6 | Set the beacon sleep and jitter |
| 7 | Exit |
| 15 | Rename a path, or delete one recursively |
| 16 | Download an ELF, write it to `memfd_create("plugin")`, execute it with supplied arguments and environment, and return its output |

Every other command number replies "Unknown command". The agent has no credential theft, keylogging, screenshot, scan, SOCKS or tunnelling code, no privilege escalation, and no anti-debugger or virtual-machine checks. A tunnel, if the operator wanted one from this implant, would arrive as a plugin.

</details>

<details markdown="1" class="hl-teardown">
<summary>Configuration, persistence and what I could not read</summary>

The configuration sits in plaintext 256-byte slots at virtual addresses `0x10a98c0` to `0x10aa1d0` in `.data`: the process-name spoof, the port, the host, the five paths, the sleep and jitter values and the 44-byte key string. That layout is from this build only, and I have not checked whether other builds keep it.

I found no persistence code. I searched the whole file for `crontab`, `cron`, `.bashrc`, `.profile`, `authorized_keys`, `rc.local`, `ld.so.preload`, `.service`, `systemctl`, `init.d` and `/etc/profile`, with zero hits for each and a control that hit as expected. That is a statement about this file, not proof the operator had no persistence elsewhere. The original binary also stays on disk wherever it was launched.

I did not read about 1,780 library functions, which I classed and did not read, and the three application functions I did not read in full are the base64 routines and the directory formatter, which I read by their strings and callers. I computed no JA3 or JA4 because I ran no handshake. The sha256 of the 44-byte static string is `642fedfa569003ed5427715a9b6a8ea6365f8e10edc935758e0017aeb17aa0d0`, and another build reusing it would be the same builder or key, though I compared no other sample.

</details>

## 7. Technical Teardown: The Signed OneDrive Side-Load
{: .hl-tier-3}
{: .hl-tab-chain}

This is the part of the case that surprised me most. To my knowledge I have not seen a side-load that takes its commands from OneDrive and also carries a signature that looks right, and I think it would pass most analysts looking at it. A named publisher in the file properties, a genuine Microsoft program loading it and traffic to two Microsoft hosts are three reasons to move on. The signature verifies and Windows still rejects it, and I explain below why that matters less than it sounds.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/inv-2026-083-federal-ad-credential-access-rig/inv-2026-083-federal-ad-credential-access-rig-signed-onedrive-side-load-chain.svg" | relative_url }}" alt="Vertical six-step infographic titled The Signed OneDrive Side-Load, on a dark background. Step 1, orange band: a genuine Microsoft binary starts. edge.exe is Microsoft's signed cookie_exporter.exe from Edge 134, renamed, and it loads msedge.dll from its own directory with LoadLibraryExA and the application-directory flag. Step 2, red band: the Rockstar-signed DLL answers. msedge.dll is 312,488 bytes with 288 exports copied from Microsoft's DLL, only ExportSpartanCookies carries logic, and both signatures verify under an expired 2017 Rockstar Games key while Windows rejects them. Step 3, red band: shellcode runs on the calling thread, with API names built by adding 1 to each byte and 49,696 bytes copied from the data section and run as an EnumWindows callback. Step 4, yellow band: the implant takes the mutex Global backslash OdMutex and decrypts config.bin, 1,488 bytes of AES-256-CBC holding a tenant identifier and a refresh token, both withheld. Step 5, deep red band: a refresh-token grant to login.microsoftonline.com, then Microsoft Graph, with the WinINet agent string Mozilla. Step 6, deep red band: OneDrive is the command server, polled every 20 seconds at cmd/command.txt with output written to cmd/output.txt. The footer lists the detection anchors and states that execution on a victim host is NOT CHECKED.">
  <figcaption><em>Figure 1: The six hops from a genuine Microsoft binary to a OneDrive command folder. Nothing in the chain connects to an operator-owned address, which is why the hunt anchors sit on the directory, the signature, the mutex and the sign-in pattern and not on a network indicator.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>Signature, side-load mechanism and loader</summary>

`msedge.dll` is 312,488 bytes with SHA-256 `f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b`, a PE64 DLL built with MSVC 19.36 and stamped 2026-09-19 11:35:14 UTC in its header, a date the builder controls. Its companion `edge.exe` (SHA-256 `47b956eeb628b9f00327c2a45cbae6b07e317ccad7df83dbe7d30b72fb5ca7e9`) is Microsoft's genuine `cookie_exporter.exe`, Edge 134.0.3124.51, validly signed by Microsoft and renamed. It calls `LoadLibraryExA("msedge.dll")` with the application-directory flag, resolves the export `ExportSpartanCookies` and calls it. That is Edge's normal behaviour, and the abuse is only that the directory holds the operator's DLL.

Both Authenticode signatures on the DLL, the primary SHA-1 and the nested SHA-256, verify cryptographically under the Rockstar Games, Inc. signer key (Entrust OVCS1, valid 2016-03-04 to 2017-03-20), and both digests bind to the file's bytes, so someone holding that private key signed a 2026 build. That is HIGH, and a control that flips one byte breaks the binding. Windows reports the signature untrusted, because it expired in 2017 and carries no timestamp, and I show no allow-list or application-control bypass. The signature's role is appearance.

Who acquired the key is a separate question, and the answer is unknown. A signing service, an insider and an earlier leak are all open, and I do not say this operator stole it. Whether the key is publicly known as leaked is NOT CHECKED.

The DLL exports 288 names copied from Microsoft's real `msedge.dll`, each with its own stub, and only `ExportSpartanCookies` carries logic (the other 287 I did not decompile, so "stubs" for them is MODERATE). That function builds `VirtualAlloc`, `VirtualProtect` and `kernel32.dll` at run time by adding 1 to each stored byte, copies 49,696 bytes from `.data` into the allocation, marks it executable and hands it to `EnumWindows` as the callback. The shellcode therefore runs on the calling thread with no remote injection, and the loader does not import the library it uses.

</details>

<details markdown="1" class="hl-teardown">
<summary>The OneDrive command channel and the verbs</summary>

The embedded implant resolves its Windows functions by walking the process environment block, creates the mutex `Global\OdMutex` and exits if it already exists. It then decrypts `config.bin`, 1,488 bytes read in full as a 32-byte AES-256 key, a 16-byte IV and 1,440 bytes of ciphertext, which is obfuscation against string scanners and no protection against anyone holding the file. The plaintext is a JSON object with two fields, a tenant identifier and a 1,357-character refresh token. I withhold both, since the tenant's owner is unknown and the token looks live.

The channel is Microsoft's own. The implant posts a refresh-token grant to `login.microsoftonline.com` under `/<tenant>/oauth2/token?api-version=1.0` with the client identifier `d3590ed6-52b3-4102-aeff-aad2292ab01c`, which I believe, without having verified it, is Microsoft's first-party Office public client (MODERATE). It then reads `/v1.0/me/drive/root:/cmd/command.txt:/content` from Graph and writes `cmd/output.txt`, polling every 20 seconds and refreshing the token every 15 minutes. WinINet's agent string is exactly `Mozilla`. No operator address or domain exists in the DLL, the shellcode or the decoded configuration, and the account that owns the OneDrive is the command server.

The verbs are `cmd`, `sleep`, `whereami`, `active`, `deactive`, `schtasks`, `fsys`, `download`, `exit` and `uninstall`. Unless the operator sends `active` within about 10 polls, the beacon stops, which I read as a dead-man switch at MODERATE from the verb dispatch alone. A `cbt.bin` file holds an install window of 4 to 6 days, and I could not settle which side of the comparison makes the implant exit.

I did not read the `fsys` and `download` handlers, the COM routine that registers the scheduled task, the direction of the `cbt.bin` comparison or the TLS callback table. I ran no detonation, deliberately, because presenting a live-looking token to the operator's channel would be contact with it. Whether either implant ever executed on a victim host, and whether the token still works, are NOT CHECKED.

</details>

What I take from this for a defender is the approach rather than the code. No signature and no vendor name makes a file normal. The discriminators are the directory the Microsoft binary runs from, a game publisher's expired signature on a DLL that does no gaming, and a browserless process doing refresh-token sign-ins.

## 8. Technical Teardown: The Credential-Access and Pod Chain
{: .hl-tier-3}
{: .hl-tab-chain}

The 239 Kerberos tickets are the only part of this chain that produced anything, and I cannot say how the operator got them. Everything built around them either failed on its own terms or was prepared and never shown to run. The operator's design is clear enough, and it is a design: enumerate accounts, spray gently, collect tickets and NTLM responses, then relay and coerce from a privileged pod on the department's container platform.

<details markdown="1" class="hl-teardown">
<summary>Enumeration, spray, Netlogon probes and the capture servers</summary>

The account sweep sent 253 Kerberos AS-REQ probes and confirmed 138 accounts to exist, none roastable without pre-authentication. A scan of 762 addresses in three /24 ranges on port 6443 found 11 that accepted a connection and 50 that refused, and 36 banner and TLS probes covered 6 ports on 6 domain controllers. Anonymous root-DSE and SMB sessions answered on all 6 controllers.

The LDAP spray made 136 binds, 135 logged as attempts and 1 as an error, with 0 successes, as one 8-password cycle across 136 accounts built to stop on a lockout. Its Kerberos twin made one attempt and then crashed. The Zerologon-style probes sent 20 zero-credential Netlogon challenges to 6 controllers and found 0 vulnerable, and the scripts never call the password-set operation, which is the step that would have changed anything.

The capture side was just as quiet in the logs I hold. The two live HTTP capture servers took 43,317 connections and 31 type-1 NTLM negotiates with 0 type-3 responses, the SMB capture server rejected 5,082 SMB2 negotiations with 0 `AUTHENTICATE`, and two relay listeners received 0 authentications. The operator's capture files nevertheless hold 111,559 NetNTLMv2 responses under one fixed server challenge, and they came from capture paths whose logs are not in the case.

Ten account names carry 81 percent of those responses, three of them generic administrator names. That is the shape of repeated automated logons, and it is not a population of people. They are responses captured, not credentials harvested, and nothing in the files I hold links the population to the department.

</details>

<details markdown="1" class="hl-teardown">
<summary>The ticket set and the forged administrator certificate</summary>

The ticket file holds 239 lines, 239 distinct service names, 89 accounts and 1 realm, all encryption type 18 (AES-256), with at most 16 tickets for one account and 56 accounts with a single ticket. The file has 0 malformed lines. Possession is HIGH.

How the operator got them is unknown, and I name three routes that all fit. A principal authenticated to the realm's key distribution centre could have requested them, an account without pre-authentication could have produced them, or the operator could have been handed an existing dataset. The corpus holds no ticket-requesting tool, no cracked password and no crack output, and the ticket file has no timestamps, so a short-window burst of requests is something I would look for in the department's logs and not something I observed.

The administrator certificate is a separate finding. A client certificate with subject `CN=system:admin` and organisation `system:masters`, Kubernetes' built-in cluster-admin group, was issued at 03:20:58 UTC on 2026-10-29, valid for a year, and its private key sits on the operator's server. It verifies under the public key of a self-signed host certificate for one of the department's web applications, so whoever minted it held that host certificate's private key, and I hold at HIGH that the operator holds it.

Nothing in the files I hold shows any cluster trusts that issuer, and the host certificate's shape is a web-server certificate, not a cluster authority. So cluster-admin access is INSUFFICIENT. Where the host key came from is NOT CHECKED beyond 3 of the department's 195 public image tags, the operator-pinned release and the two either side of the certificate's 2022 start date, where 84 of 84 layers verified and a planted-key control was found. The key is absent from those three, which weakens the public-image explanation without excluding it.

The directory also holds a copy of a Drupal-style web application's upload folder, with eleven files: four PHP and phar command stubs, five extension probes, a handler-enabling `.htaccess` and a write-marker file. That is a staged file-upload kit. The upload primitive, any execution of the stubs and whether the folder copy came from a victim system or the operator's own test are all NOT CHECKED, so I map the web shells and the Exploit Public-Facing Application row as NOT SHOWN, and the web application stays LISTED in Section 3. The directory also holds 17 private-key and certificate files, most of them not the department's, and where they were gathered is NOT CHECKED, so the Credentials In Files row is INFERRED.

</details>

<details markdown="1" class="hl-teardown">
<summary>The 13 prepared pod manifests</summary>

Thirteen Kubernetes manifests were authored for one named node of the department's platform, and I treat them as prepared only. Each asks for a privileged pod with host process, network and IPC namespaces, mounts the node's root at `/host` and runs its commands through `chroot /host`. They share one `app` label carrying the operator's work-directory number, and their names mark the function: `su` setup, `r1` to `r6` relay rounds, `t1` a retest, `e1` to `e3` coercion rounds, `rec` and `rec2` reconnaissance.

The relay chain installs a relay runner and a systemd unit on the node, triggers authentication toward a node alias, enumerates services through the relayed session, then saves the `SECURITY` and `SAM` registry hives from a SQL host. The coercion rounds use EFS-RPC and PetitPotam against two addresses, one round enumerates domain groups by the recursive membership rule, and the journal checks grep for endpoint-security product names after the fact, which is trace checking and not tampering. Two passwords are embedded in the scripts and their origin is NOT CHECKED.

Zero of 15 run markers appear in the 333 files I searched, and no Kubernetes audit log, API response or client tooling is among them. So execution of any pod or node-side step is NOT CHECKED, and the platform stays REACHED. The 13 manifests were also public: 887 distinct addresses downloaded them from the open directory, in 4,712 requests between 2026-10-31 and 2026-11-14, from a log that holds 1,024 addresses in all. That is a count of manifest downloads, not of visitors, and the directory stayed open for 17 days.

</details>

The pod set is where the operator's intent ran furthest beyond its evidenced access. A complete relay-and-coerce chain, written to the point of fixing earlier rounds' bugs in later ones, with no artefact that it ran, tells me what the operator wanted next and nothing about whether it got there.

## 9. Timeline
{: .hl-tier-2}
{: .hl-tab-timeline}

The operator's hands-on activity against the department fits in about four hours of 2026-10-29, from the chisel server start at 01:02 UTC to the last successful proxied connect at 05:19:52 UTC. Everything after that in the logs I hold either failed or was passive collection. The operator's clock is UTC to within about a minute.

| Date | Observation |
|---|---|
| 2016-03-04 to 2017-03-20 | The Rockstar Games certificate on `msedge.dll` is valid; it carries no timestamp countersignature |
| 2022-04-13 | The validity of the department web host certificate whose private key the operator holds begins |
| 2026-05-22 | The command-and-control zone `customerlop[.]top` is registered at Gname behind a Cloudflare name-server pair, 160 days before the chisel server started |
| 2026-09-19 11:35:14 UTC | PE timestamp of `msedge.dll`; the builder controls this field, so it bounds nothing |
| 2026-09-22 to 2026-11-11 | `mail[.]customerlop[.]top` points at a BlueVPS address continuously |
| 2026-10-10 | The operator host's current SSH host key is first seen, an upper bound for the tenant's start; the three newer sibling zones are registered between 2026-10-10 and 2026-10-14 |
| 2026-10-28 | A Cloudflare Origin certificate for `*.robonode[.]shop` becomes valid on the BlueVPS mail address; the first operator-identifiable markers appear on the operator host |
| 2026-10-29 01:02:19 | The chisel server starts on port 80 with reverse tunnelling |
| 2026-10-29 01:49:16 | The operator tests `HEAD /agent.bin` from loopback |
| 2026-10-29 01:50:05 | An address in the department's egress range fetches `/agent.bin`, HTTP 200; `/chisel` follows at 01:50:06 |
| 2026-10-29 01:52:54 | An interactive bash banner from an address in the media organisation's range reaches port 80 |
| 2026-10-29 02:49:45 to 02:53:37 | A tunnel-shaped session of 76,436 packets in and 73,483 out runs between the department's egress address and the operator's port 80 |
| 2026-10-29 02:57:00 | The HTTP capture servers go live; the TLS one follows at 02:58:39 |
| 2026-10-29 03:20:58 | The administrator-named client certificate is issued |
| 2026-10-29 04:29:48 to 05:19:52 | The operator's racing proxy makes 126 successful connects; 27 reach private address space from about 05:17 |
| 2026-10-30 07:30:11 | The last proxied attempt, which failed, like every attempt after 05:19:52 on the previous day |
| 2026-10-30 09:55 to 10:01 | The media organisation's address holds an established session to the operator host |
| 2026-10-31 to 2026-11-14 | 887 distinct addresses download the 13 pod manifests, 4,712 requests in all |
| 2026-11-04 | An Amazon cloud address begins polling a capture server at about 2,840 requests a day |
| 2026-11-05 | The carrier address stops polling; the TLS capture server's log freezes at 07:39:04 |
| 2026-11-14 | The directory is still open at the last pull, after 17 days open to the internet |

## 10. Infrastructure
{: .hl-tier-2}
{: .hl-tab-timeline}

The infrastructure is rented and ordinary, and the one piece worth acting on first is the command-and-control name. I tie the operator to it through the implant alone, which is strong for the name and says nothing yet about who owns the zone.

The operator host `151[.]236[.]22[.]111` sits in an Edis allocation announced by M247 (AS9009), and its hosting identity is DEFINITE from three agreeing sources. It has had at least four occupants since 2023, including a web-hosting panel, a Windows remote-desktop tenant and a `sabbias[.]store` mail host, so I treat its older domains as bystanders. The current SSH key was first seen on 2026-10-10 and stayed the same through the capture-server certificate, which makes one occupant from that date a MODERATE claim.

| Asset | Role | Tie to the operator | Grade |
|---|---|---|---|
| `151[.]236[.]22[.]111` | Open directory, delivery, chisel server, capture servers | The operator's own server | Hosting identity DEFINITE; control for the window HIGH |
| `www[.]customerlop[.]top` | Command-and-control host in `agent.bin` | Plaintext in the implant that the operator host served | Name HIGH; registration by the operator and exclusive control MODERATE |
| `mail[.]customerlop[.]top` at `45[.]143[.]167[.]96` | Unproxied sibling name on a BlueVPS address | The zone's own records point there | Pointer HIGH; operator control of the host MODERATE |
| `update[.]customerlop[.]top` at `45[.]143[.]167[.]122` | Unproxied sibling name on a SoftEther VPN host | The zone's own records point there | Pointer HIGH; operator control MODERATE |
| `robonode[.]shop` | Zone of a Cloudflare Origin certificate served from the mail address | One non-commodity certificate leg | MODERATE |
| `transportdustry[.]my`, `healthgenius[.]icu` | Newer sibling zones | Reach the C2 zone only through `robonode[.]shop` and the mail host | LOW; held out of the feed |
| `118[.]128[.]151[.]28` | South Korean VPS at MOACK with Python and NTLM listeners | Sent a SOCKS5 greeting to the operator's port 80 at start-up | Attacker-run HIGH; same operator MODERATE |

The C2 zone was registered at Gname on 2026-05-22 behind a Cloudflare name-server pair, and three sources agree on that date, which is DEFINITE. Its web origin is hidden behind Cloudflare, so the unproxied `mail` and `update` names are siblings and not the C2 web origin. Whether the C2 name resolves to a live server today is NOT CHECKED beyond dated samples, and I state no uptime or outage duration.

`robonode[.]shop` is the link that decides how far the cluster reaches. A Cloudflare Origin certificate for `*.robonode[.]shop`, valid from 2026-10-28, is served from the address the C2 zone's mail name resolves to, and that certificate is issued to whoever runs the zone's origin and installed by hand, which is why I do not treat it as commodity. The subject comes from one source with the timing corroborated by a second, and a shared or re-let host is not killed, so the tie to the C2 zone is MODERATE and the cluster as a whole is MODERATE, not STRONG.

The commodity legs carry no weight. A registration and passive-DNS source counts about 260,575 and 175,331 domains per Cloudflare name server (the pair's population is at most 175,331, and I did not count the intersection), about 13.0 million domains at Gname and about 187.8 million names with the registrant redaction placeholder. The JARM value the operator host shares with the Korean VPS was on the operator's address under an unrelated tenant 17 months earlier, so it carries none either.

I tie the Korean VPS to the operator at MODERATE only. It greeted the operator's port 80 and was first source on both capture servers, but the operating-system stack differs, no SSH key or passive-DNS name is shared, and two users of one public toolchain remains open. The two persistent pollers of the capture servers are monitors at MODERATE, not victims and not operator infrastructure. The `iNNNNN` work-directory number appears in 14 of 14 hits on the operator host and in 0 of 7,011 files on 12 other open-directory hosts, so it is operator-specific within my corpus, and "engagement number" is my wording, not the operator's.

Two disruption levers matter most. The Microsoft account and tenant behind the beacon are its command server, and Microsoft can disable the account, revoke its tokens and remove the `cmd` folder, which ends copies using this recovered configuration. The registrar and DNS host for `customerlop[.]top` end every build that carries that name, though the operator can repoint a new build by changing one configuration slot.

## 11. MITRE ATT&CK Mapping
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's behaviour maps to 52 procedure rows with 52 distinct technique IDs in 13 tactics of ATT&CK Enterprise v20.1, every ID live and none revoked. The Status column has three values. OBSERVED means the behaviour is in an artefact I hold, a log line, a file or code I read in a recovered implant, and it includes an attempt that failed where the attempt is itself the procedure. INFERRED means a conclusion drawn from artefacts and not itself in one. NOT SHOWN marks a step the operator authored or staged with no artefact that it ran, and it claims no impact.

The counts are 37 OBSERVED, 4 INFERRED and 11 NOT SHOWN, and row confidence is HIGH on 41 and MODERATE on 11. Four of the OBSERVED rows are refused attempts: the Netlogon probes (two rows), the password spray and the relay and capture servers. For the implant rows OBSERVED is capability read in code, and I show no execution of either implant on a victim host.

I map no Impact row and no Defense Impairment row, because nothing in the files I hold shows encryption, wiping or a tool being disabled, and the pod scripts only look for endpoint-security names after the fact. I map no Valid Accounts row, because how the operator got the tickets is unknown, and for the same reason the Kerberoasting row is INFERRED and not OBSERVED: the ticket file is held, the request that produced it is not. I map no Develop Capabilities row for the two implants, because who built them is not shown and the grade would be LOW, and no row for using a cluster-admin identity, because no use artefact exists. The side-load row uses T1574.001 because the older DLL side-loading sub-technique is revoked in v20.1.

<details markdown="1" class="hl-teardown">
<summary>All 52 procedure rows, with status, confidence and evidence</summary>

| Tactic / Technique | Name | Status | Conf. | Evidence |
|---|---|---|---|---|
| Reconnaissance / T1595.001 | Scanning IP Blocks | OBSERVED | HIGH | 762-address sweep of three /24s on 6443 |
| Resource Development / T1583.003 | Virtual Private Server | OBSERVED | HIGH | Rented M247/Edis host; MOACK VPS |
| Resource Development / T1588.003 | Code Signing Certificates | INFERRED | MODERATE | Rockstar-key signature on a 2026 build; acquirer unknown |
| Resource Development / T1608.001 | Upload Malware | OBSERVED | HIGH | `agent.bin` and `chisel` served; 5,762 HTTP 200s on three servers |
| Initial Access / T1190 | Exploit Public-Facing Application | NOT SHOWN | MODERATE | File-upload kit staged for a web application; the upload primitive and any execution are NOT CHECKED |
| Execution / T1059.004 | Unix Shell | OBSERVED | HIGH | `agent.bin` cmd 1 `popen` |
| Execution / T1059.003 | Windows Command Shell | OBSERVED | HIGH | `cmd` verb over `CreatePipe`; hidden `cmd /c` on uninstall |
| Execution / T1610 | Deploy Container | NOT SHOWN | HIGH | 13 pod specs; 0 of 15 run markers in 333 files |
| Persistence / T1053.005 | Scheduled Task | OBSERVED | MODERATE | `schtasks` verb; registration routine not read |
| Persistence / T1543.002 | Systemd Service | NOT SHOWN | HIGH | `r1` writes a relay unit; no unit seen |
| Persistence / T1505.003 | Web Shell | NOT SHOWN | HIGH | Four PHP and phar shell files in an upload folder; no output |
| Privilege Escalation / T1611 | Escape to Host | NOT SHOWN | HIGH | Privileged pod, hostPID, `hostPath: /`, `chroot /host` |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | OBSERVED | HIGH | 20 Netlogon probes on 6 controllers, 0 vulnerable (refused) |
| Lateral Movement / T1210 | Exploitation of Remote Services | OBSERVED | HIGH | Same Netlogon probe set (refused) |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | NOT SHOWN | HIGH | SMB answered 16 of 30 attempts on one host; a port reply, with no share use shown |
| Discovery / T1087.002 | Domain Account | OBSERVED | HIGH | 253 AS-REQ probes; 138 accounts exist |
| Discovery / T1046 | Network Service Discovery | OBSERVED | HIGH | 36 banner and TLS probes on 6 controllers |
| Discovery / T1082 | System Information Discovery | OBSERVED | HIGH | `agent.bin` `uname` and `comm` collection |
| Discovery / T1016 | System Network Configuration Discovery | OBSERVED | HIGH | `getifaddrs` first non-loopback IPv4 |
| Discovery / T1033 | System Owner/User Discovery | OBSERVED | HIGH | `$USER`, `/proc/self/comm` |
| Discovery / T1083 | File and Directory Discovery | OBSERVED | HIGH | `agent.bin` cmd 4 directory listing; capability read in code |
| Discovery / T1057 | Process Discovery | NOT SHOWN | HIGH | `ps` and `/proc/<pid>/cmdline` in `rec2` |
| Discovery / T1069.002 | Domain Groups | NOT SHOWN | HIGH | Recursive membership query in `e2` |
| Credential Access / T1110.003 | Password Spraying | OBSERVED | HIGH | 136 LDAP binds, 0 successes; Kerberos twin crashed (refused) |
| Credential Access / T1558.003 | Kerberoasting | INFERRED | MODERATE | 239 tickets, 239 service names, 89 accounts, etype 18; possession is HIGH, but the operator requesting them is inferred because the route is unknown |
| Credential Access / T1557.001 | Name Resolution Poisoning and SMB Relay | OBSERVED | HIGH | 2 relay listeners, 0 relayed; 5,082 SMB rejections (refused) |
| Credential Access / T1187 | Forced Authentication | NOT SHOWN | HIGH | EFS-RPC and PetitPotam rounds `e1` to `e3` |
| Credential Access / T1003.002 | Security Account Manager | NOT SHOWN | HIGH | `reg save` SECURITY and SAM in `r5`; no hive held |
| Credential Access / T1552.001 | Credentials In Files | INFERRED | MODERATE | 17 key and certificate files held in the directory; where the search for them ran is NOT CHECKED |
| Credential Access / T1649 | Steal or Forge Authentication Certificates | OBSERVED | HIGH | Forged `system:admin` client certificate and key; possession only |
| Collection / T1005 | Data from Local System | OBSERVED | HIGH | `agent.bin` cmd 2 reads any path; no collected file held |
| Collection / T1213.003 | Code Repositories | OBSERVED | HIGH | 23 files retrieved by `bbget.sh` and `bbsearch.py` |
| Stealth / T1574.001 | DLL | OBSERVED | HIGH | `LoadLibraryExA("msedge.dll")` then `ExportSpartanCookies` |
| Stealth / T1036.005 | Match Legitimate Resource Name or Location | OBSERVED | HIGH | argv `/lib/systemd/systemd --user`, `PR_SET_NAME` |
| Stealth / T1553.002 | Code Signing | OBSERVED | HIGH | Rockstar signature verifies; Windows reports it untrusted |
| Stealth / T1027.013 | Encrypted/Encoded File | OBSERVED | HIGH | `config.bin` AES-256-CBC, key and IV in the file |
| Stealth / T1620 | Reflective Code Loading | OBSERVED | MODERATE | `memfd_create`, RWX map, `execve` of `/proc/self/fd/N` |
| Stealth / T1480 | Execution Guardrails | OBSERVED | MODERATE | `cbt.bin` install window of 4 to 6 days |
| Stealth / T1070.004 | File Deletion | OBSERVED | MODERATE | Recursive unlink (cmd 15); `uninstall` deletes four files |
| Command and Control / T1071.001 | Web Protocols | OBSERVED | HIGH | HTTPS POST to `www[.]customerlop[.]top:443` |
| Command and Control / T1573.002 | Asymmetric Cryptography | OBSERVED | HIGH | mbed TLS 1.2, authentication mode none |
| Command and Control / T1573.001 | Symmetric Cryptography | OBSERVED | HIGH | Repeating-key XOR before base64 |
| Command and Control / T1001.003 | Protocol or Service Impersonation | OBSERVED | MODERATE | Five WordPress theme and AJAX paths |
| Command and Control / T1132.001 | Standard Encoding | OBSERVED | HIGH | base64 on the outer layer and on files |
| Command and Control / T1105 | Ingress Tool Transfer | OBSERVED | HIGH | `agent.bin` and `chisel` delivered at 01:50 UTC |
| Command and Control / T1102.002 | Bidirectional Communication | OBSERVED | HIGH | Graph GET `command.txt`, PUT `output.txt` |
| Command and Control / T1572 | Protocol Tunneling | OBSERVED | MODERATE | chisel reverse server; session shape; listener not settled |
| Command and Control / T1090.001 | Internal Proxy | OBSERVED | HIGH | 27 of 112 private-address connects answered |
| Command and Control / T1090.003 | Multi-hop Proxy | OBSERVED | HIGH | Racing proxy over 10 upstream SOCKS ports; 232 requests |
| Command and Control / T1095 | Non-Application Layer Protocol | INFERRED | MODERATE | Interactive bash banner held at least 17 minutes |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | OBSERVED | HIGH | `agent.bin` cmd 2 POST; capability only |
| Exfiltration / T1567.002 | Exfiltration to Cloud Storage | NOT SHOWN | HIGH | The loader PUTs its own `cbt.bin` timer file to its command folder; the `download` handler is unread and no victim file is shown moved |

</details>

The shape of the table is the operator's profile. Credential Access and Command and Control carry the evidence, execution on a victim host is thin and rests on one delivery event, one banner and one refused probe set, and the NOT SHOWN rows cluster in the pod set, where intent ran furthest beyond evidence.

## 12. Indicators of Compromise
{: .hl-tier-2}
{: .hl-tab-indicators}

The indicators here are operator-side only: the operator's server, its command-and-control names, the files it built and the host and network behaviour of its two implants. No victim value is in the feed. The full machine-readable set is the IOC feed, [`inv-2026-083-federal-ad-credential-access-rig-iocs.json`](/ioc-feeds/inv-2026-083-federal-ad-credential-access-rig-iocs.json).

It carries 38 operator-side indicator entries: 9 file hash entries (5 SHA-256, 2 MD5, 1 SHA-1 and 1 import hash), 4 IPv4 addresses, 5 domains, 7 URLs, 1 mutex, 10 behavioural entries and 2 network signatures. The count is of feed entries, so one entry can yield more than one row in the viewer table. A short set worth acting on first:

| Indicator | What it is | Confidence | Action |
|---|---|---|---|
| `151[.]236[.]22[.]111` | Operator host: open directory, delivery, chisel server, capture servers | HIGH | Block, time-boxed: a rented address with at least four earlier occupants |
| `www[.]customerlop[.]top` | Command-and-control host in `agent.bin` | HIGH | Block; do not block Cloudflare's front addresses |
| `customerlop[.]top`, `mail[.]customerlop[.]top`, `update[.]customerlop[.]top` | The C2 zone's apex and its two unproxied names | HIGH | Block |
| `a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096` | `agent.bin`, static Linux HTTPS agent | DEFINITE | Block |
| `f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b` | `msedge.dll`, side-load loader with embedded OneDrive beacon | DEFINITE | Block |
| `862e4d023f8326042066561d62768169ab4b1d3f4d7e16f58013e3a444581671` | `config.bin`, the beacon's AES-256-CBC configuration | DEFINITE | Block |
| `7c48e8e30eec255a62d51aa18c0b09522b71d33ccc6b58b05c71ae7c9a52b044` | The extracted 49,696-byte shellcode implant | HIGH | Block |
| `5da1d555e3f32e0d20e5986dac1c2a71` | Import hash of `msedge.dll` | HIGH | Hunt |
| `0a76c28f5452dbbc146752d0b4e28b10779a337091f59650b94f5e938545572c` | Stock public `chisel` build, delivered to an agency-egress host | HIGH | Hunt; ties the operator to nothing |
| `/lib/systemd/systemd --user` as one argument | Process name spoof of `agent.bin`; the real one passes `--user` separately | HIGH | Hunt in process telemetry |
| `Global\OdMutex` | Mutex of the OneDrive beacon, read in code and not seen running | HIGH | Hunt |
| `45[.]143[.]167[.]96`, `45[.]143[.]167[.]122` | Shared BlueVPS addresses behind the zone's `mail` and `update` names | MODERATE | Monitor; earlier tenants exist |
| `robonode[.]shop` | Zone of the Cloudflare Origin certificate on the mail address | MODERATE | Monitor |
| `118[.]128[.]151[.]28` | South Korean VPS, attacker-run, same operator MODERATE | MODERATE | Monitor |
| `642fedfa569003ed5427715a9b6a8ea6365f8e10edc935758e0017aeb17aa0d0` | SHA-256 of the 44-byte static key string in `agent.bin`; a retro-hunt handle, not a file hash | HIGH | Hunt |

Several things are left out of the blocking buckets on purpose. `login.microsoftonline.com`, `graph.microsoft.com` and the client identifier `d3590ed6-52b3-4102-aeff-aad2292ab01c` are Microsoft services that almost every tenant allows, so they sit in the feed as hunt-only values and the beacon cannot be blocked at the network. The Entra tenant identifier is withheld from this report and is a proxy-log hunt key only. The Rockstar certificate thumbprint `C9793F4A2E629D88F2213622D7A0C170D9C7CBC6` and its serial are hunt-only, because genuine Rockstar binaries from 2016 and 2017 carry the certificate.

The genuine `edge.exe` is the side-load carrier and not malicious. Earlier tenants of the recycled addresses, the two capture-server pollers and the newer sibling zones `transportdustry[.]my` and `healthgenius[.]icu` are held out of the feed, because blocking them would hit bystanders or rest on a LOW link.

## 13. Detection and Hunting Guidance
{: .hl-tier-2}
{: .hl-tab-indicators}

The [detection file](/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/) for this case carries 25 rules: 6 YARA (3 detection, 3 hunting), 13 Sigma (4 detection, 9 hunting) and 6 Suricata (1 detection, 5 hunting). The 8 Detection-tier rules key on artefacts specific to this case, and none has a measured false-positive basis beyond the file counts below, so I rate them for alerting on that reasoning and not on a measured result. The 17 Hunting-tier rules key on broader behaviour or a name the operator can change, so their hits need review. Three of the Sigma rules are correlation rules, each with its own base rule. The Sigma Detection-tier rules match a `msedge.dll` loaded without a Microsoft signature, the Edge helper running outside the Edge install directory, a privileged pod with the node root mounted and a staged base64 script, and a Linux process run from an in-memory file with a systemd command line. The Suricata one matches the chisel WebSocket upgrade, and the YARA ones match the agent's request templates, the loader's export name and the beacon's shellcode immediates.

All 6 YARA rules fire on their own real sample (the agent for three, the loader for three). For the three whose synthetic self-test passed, I found 0 hits across 33,059 files in System32, 32,993 in Program Files and 62,815 in a tools directory. For the other three, I have no usable false-positive result, so their zero is NOT CHECKED. The two Linux rules were tested only against a Windows image, which says little about Linux false positives.

No Sigma or Suricata rule was tested against live telemetry or a benign baseline. Upstream coverage was read from a local SigmaHQ clone dated 2026-09-12: an upstream rule may already cover 8 of the Sigma rules, 2 are NOT CHECKED against upstream, and upstream coverage for the Suricata and YARA rules is NOT CHECKED. The two Kubernetes pod rules read a Kubernetes audit log source, so a team without that log cannot run them as written. No rule was confirmed against a victim log, because I hold none.

What the case gives a detection engineer, in order of durability:

- The process shape of the Linux agent comes first. A process whose command line is the single argument `/lib/systemd/systemd --user`, whose `/proc/<pid>/exe` link points at `/memfd:` and whose name is `/lib/systemd/sy`, is a high-fidelity host signal, and the `memfd_create`, read-write-execute map and `execve` of `/proc/self/fd/N` sequence in one process is its syscall form.
- The Windows loader shows as a genuine `cookie_exporter.exe` named `edge.exe` loading `msedge.dll` from a directory that is not Microsoft's Edge install, with a signature status of Expired and the signer Rockstar Games. The same binary name pairing under the real Edge directory is legitimate, which is why the directory is the discriminator.
- The beacon's sign-in is the browserless one: the WinINet agent string exactly `Mozilla`, a refresh-token grant against the v1 `/oauth2/token` endpoint, then Graph reads and writes under a `cmd` folder. In the token owner's tenant it appears as non-interactive sign-ins for the Microsoft Office application against Graph about every 15 minutes, from the infected host's egress address.
- On the wire, the Linux agent is a TLS 1.2 session to `www[.]customerlop[.]top` every 54 to 66 seconds, and decrypted it is a POST with no User-Agent and a JSON body to the five WordPress paths.
- The three Active Directory correlation rules use starting thresholds and not measured ones, because the harvest and spray files carry no timestamps and I cannot say how fast the operator ran.

I did not write a rule where the case could not support one. There is no rule for the NTLM capture servers or the relay's victim-side effect, which run on the operator's side, none for the Kerberos requests by method, because I hold no requesting tool or log, and none for the forged administrator certificate's acceptance or any pod-side step, because nothing in the files I hold shows either happened. A TLS-fingerprint rule for the Linux agent would be the most durable addition, and it needs one lab handshake I did not capture. The department's domain controller log from 2026-10-29 and the cluster's API-server audit log would turn the correlation rules into measured ones and show whether the forged certificate or any pod specification was used.

## 14. Threat Actor Assessment
{: .hl-tier-2}
{: .hl-tab-attribution}

I cannot attribute this activity to any named threat actor, and I hold that at INSUFFICIENT. No source, vendor report, catalogue entry, infrastructure overlap or code similarity nominates a candidate. I swept the public vendor reports and actor profiles I could reach, and the indicator feeds, by text and found 0 operator-specific hits. The Hunt.io actor catalogue and a comparison against my earlier cases are NOT CHECKED. Where a label is needed I call it an unidentified operator.

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-025 is a tracking label The Hunters Ledger assigns to an actor I have observed but cannot yet link to a publicly named threat group. Other vendors and feeds will not use this label; it is specific to this publication. If later evidence ties the activity to a named actor, I will retire the label and update the report.

UTA-2026-025 tracks a toolset cluster seen on one open directory: the two implants, the Rockstar-signed side-load, the numbered work-directory convention and the combination of techniques. It is not a person, a developer, a state, a motive or a new malware family, and I do not use it to call the operator a broker, a state group or a crew. I hold the cluster at MODERATE, and the designation meets the creation gates on six characteristics, four of them technical or infrastructure, at an Admiralty rating of B2 and no higher.

### My read of the operator

My read is that this is an initial access broker, and I want it labelled as mine. It does not look like a red team from the behaviour. I do not expect a quiet espionage group to run noisy password sprays, because a group working for the long term would be more careful, and that leaves a broker, which fits the targets I see. I would expect a foothold to show real access, to pivot from or to sell. The media organisation supports that read for me, because a second apparently unrelated victim (a MODERATE finding) argues against a single sanctioned engagement and adds to the severity of the operator.

I read the operator as skilled and somewhere in the middle. It is not slamming off-the-shelf tools at a large number of targets, and the implants are not off-the-shelf as far as I can tell. I cannot say this operator wrote them, since shared or sold tooling stays open.

I grade actor type INSUFFICIENT. There is no sale, listing, buyer contact or tasking in the 333 files I searched, and 12 money-side and testing terms returned 0 files against a control term that returned 18. That sweep is a bounded negative and not an authorisation detector, and a sale off the rig would not appear in it. Two details cut against the read. The spray was one 8-password cycle across 136 accounts, built to stop on a lockout, which is gentler than noisy suggests. And the inference that a state-aligned group would not run a noisy spray rests on a base rate I did not measure, so I score it as one weak inconsistency and not an exclusion.

What the behaviour does support is a stated operating model. The operator built and kept access, a tunnel carrying its traffic into private address space, an implant delivered to the agency's egress, 13 prepared relay and dump pods and capture servers still collecting at the last pull. I hold that at MODERATE, as preparation for other attacks. Espionage stays a hypothesis at LOW, because the agency's source and inventory files were retrieved through the tunnel and I cannot say whether that repository is public. Motivation is undetermined at LOW.

### Hypotheses and calls

I tested 8 hypotheses against 18 evidence items, of which 11 discriminate between them. Six survive, counting the false-flag reading that collapses into the unknown self-directed collector, and 2 are weakened, so 8 tested equals 6 surviving plus 2 weakened. The default of a named actor was dropped because no evidence row nominates one, and it is not in the count. No single evidence row carries the conclusion, because removing any one row leaves the same six columns standing.

| Hypothesis | Inconsistencies | Where it stands |
|---|---|---|
| An initial access broker building footholds to show or sell (my read) | None in the evidence | Survives; as a conclusion INSUFFICIENT |
| A state-aligned collector | One weak: a quiet long-horizon group would not spray noisily, resting on an unmeasured base rate | Survives |
| An authorised test within an agreed scope | Three strong and one weak: two apparently unrelated victims, no scope marker in the bounded sweep, a signing key held from a third party, and a directory left open 17 days | Weakened, the least supported reading, not excluded |
| A benign hobbyist or researcher | Three strong and three weak: 239 tickets, two unrelated victims, access shown to a federal department | Weakened, not eliminated |
| A contractor or insider-adjacent supplier | Two weak: a rented external rig, and one operator spanning two unrelated victims | Survives |
| Shared or sold tooling with more than one operator | None; an overlay on the others | Survives |
| An unknown self-directed collector with an own-use purpose | None | Survives |
| A false flag or coincidental overlap | None; no actor is being imitated | Collapses into the unknown self-directed collector |

The authorised-test reading is the one I weigh most carefully, because the evidence does not prove consent absent. Its three strong inconsistencies each rest on an open premise: the media organisation is MODERATE with a researcher or sandbox branch open, the 12-term sweep is not an authorisation detector, and the signing key's provenance is unknown. The deciding fact is the victims' own answer on whether any authorised test covered 2026-10-29 onward. I will not state that the activity was unauthorised at a confidence the case does not hold.

| Call | What would change it |
|---|---|
| No named actor, INSUFFICIENT | A catalogue or vendor match on the signer thumbprint, the C2 zone, the operator host or the tenant identifier, or an actor-linkage pass against past cases with a measured denominator |
| Actor type INSUFFICIENT; my broker read stays mine | A forum listing or buyer hand-off tied to these footholds moves toward a broker; collection of agency documents beyond source and inventory moves toward espionage |
| Motivation undetermined, LOW | A listing, a ransom demand, a decrypted operator note or a tasking artefact |
| Authorised test least supported, not excluded | The department's and the media organisation's confirmation that no authorised test covered the window, which closes the column |
| UTA-2026-025 as a toolset cluster, MODERATE | A second case or an external report tying these tools to a named group, or code comparison with another build that shows shared or sold tooling |

No comparison family is a candidate crew. VoidLink, GraphWorm, GRAPHITE, BirdyClient and Antino share a technique class or structure with parts of this toolset, and I claim no lineage with any of them.

## 15. Recommendations
{: .hl-tier-1}
{: .hl-tab-indicators}

Know what normal is, because that is what finds this operator and others like it. Each item below follows from something the operator did, and none is a tested defence: I hold no victim telemetry, so I cannot say which of these would have fired.

- Treat a signature as appearance and not as a verdict. A valid-looking signature from a game publisher on a DLL that does no gaming, with an Expired status and no timestamp, is the red flag in this case. Hunt for any binary signed with the Rockstar certificate after 2017-03-20 or loaded from a non-game path, and do not allow a file on the strength of a verified publisher name alone.
- Hunt for Microsoft binaries running from the wrong directory. `cookie_exporter.exe` renamed `edge.exe` and loading `msedge.dll` from a directory that is not the Edge install is the side-load, and the genuine binary doing the same call under the real Edge directory is normal.
- Hunt for refresh-token sign-ins from a process with no browser. Non-interactive Microsoft Office sign-ins against Graph about every 15 minutes, from an endpoint where OneDrive is not normally run that way, together with a WinINet agent string of exactly `Mozilla`, are the beacon's footprint. Blocking Graph or the sign-in host is not an option, so detection is by process and pattern.
- Hunt Linux hosts for a process whose command line is the single argument `/lib/systemd/systemd --user`, whose executable link points at `/memfd:` and whose name is `/lib/systemd/sy`.
- Look for the delivery. A plain-HTTP fetch of `/agent.bin` and `/chisel` from `151[.]236[.]22[.]111` from 2026-10-29, or any beacon traffic to `www[.]customerlop[.]top`, means the implant reached a host. In the department's case, the agency's egress record for 01:50 UTC on 2026-10-29 is the observation that would settle whether it executed.
- Check the realm for the 239 tickets. The key distribution centre's log of the 239 service-ticket requests would show which principal asked, in what window and whether pre-authentication was used, and that is the one observation that explains how the tickets were obtained.
- Audit the container platform's API server for a client certificate with subject `system:admin` and group `system:masters` issued 2026-10-29 03:20:58 UTC. Acceptance of it is what would move cluster-admin access off INSUFFICIENT, and a platform owner confirming that no cluster trusts the issuer settles it the other way.
- Block the indicators at the confidence the feed gives them. Block the operator host with a time window, the C2 zone and the file hashes, and monitor the shared BlueVPS addresses, `robonode[.]shop` and the Korean VPS, because blocking an address with earlier tenants can hit someone else.

## 16. Confidence Summary and Evidence Gaps
{: .hl-tier-2}
{: .hl-tab-confidence}

The case rests on the operator's own files: its server logs, scripts, captures and two implants, plus passive records of its infrastructure. That makes the evidence strong on what the operator built and sent and silent on what any victim recorded, because I hold no victim-side telemetry. The single source that would do the most damage if wrong is the operator's own HTTP server log, because the delivery event and the 49-second gap rest on it alone. Each load-bearing judgment below carries its confidence and one observable that would move it.

| Claim | Confidence | What would change it |
|---|---|---|
| An address in the department's egress range fetched `agent.bin` and `chisel` at 01:50 UTC on 2026-10-29 | HIGH as an event | The operator's log lines shown altered, or the address shown not to be the department's |
| The operator controlled the host that fetched them | MODERATE | The department's egress or endpoint record of the fetch, or a decoded chisel handshake (up); the fetch shown to be a proxy or sandbox (down) |
| The department is ACCESS SHOWN overall | MODERATE | The same records; if the fetch is not the operator's, the floor drops to COMPROMISED on the tickets |
| The operator holds 239 service tickets for 89 accounts in one realm | HIGH | A recount giving other than 239 lines, 239 service names, 89 accounts and 1 realm |
| How the operator obtained the tickets | INSUFFICIENT | The key distribution centre's log for the 239 requests |
| The container platform is REACHED at TCP level only | MODERATE | An API-server audit line accepting the forged certificate, or node artefacts of a pod-side step |
| Cluster-admin access to the platform | INSUFFICIENT | An audit line accepting the certificate (up), or a platform owner's statement that no cluster trusts the issuer (down) |
| The operator holds the private key of the web host certificate | HIGH | The client certificate failing to verify under the held key |
| Where that key came from | INSUFFICIENT | The key found in a public image tag outside the three scanned, or shown pulled from a non-public source |
| The 13 pod manifests were authored and are prepared only | HIGH that they were authored | The node's journal or the relay unit showing a pod-side step ran |
| The media organisation is ACCESS SHOWN | MODERATE | Command output or a second artefact in its range tying the shell to the operator (up); the shell shown not to be the operator's, which withdraws the block |
| Both signatures on `msedge.dll` verify under the Rockstar Games key and bind to the file | HIGH | A re-run where the byte-flip control still verifies |
| Who acquired the Rockstar key, how and when | INSUFFICIENT | A leaked-certificate record showing the key public before 2026, or Rockstar's or Entrust's answer on where it was held |
| The owner of the Entra tenant behind the beacon | INSUFFICIENT | Microsoft's sign-in record for the token |
| No public match for either implant, the C2 zone or the pod chain | MODERATE | A sandbox or feed record for any sample hash, or a report naming the C2 zone; family novelty is NOT CHECKED |
| The C2 zone was registered on 2026-05-22 | DEFINITE | A WHOIS or RDAP record giving a different creation date |
| `robonode[.]shop` is tied to the C2 zone | MODERATE | Hunt.io IP history for the mail address, a second source for the certificate subject, or unrelated tenants on the address |
| The Korean VPS is the same operator | MODERATE | A shared SSH host key, certificate or passive-DNS name |
| No named actor | INSUFFICIENT | A catalogue or vendor match on the signer thumbprint, the C2 zone, the operator host or the tenant identifier |
| Actor type | INSUFFICIENT | A listing, buyer or tasking artefact, collection of agency documents, or the victims' answer on an authorised test |
| The detection rules fire on their own samples | HIGH | A re-run where a rule fails to fire on its sample |

### Evidence gaps

- No detonation was run and no victim-side telemetry exists, so execution of either implant on any host, the C2 replies, plugin ELFs and any moved file are NOT CHECKED, and I computed no JA3 or JA4.
- The process that fetched the two delivered files and the listener that held port 80 during the tunnel-shaped session are NOT CHECKED.
- Acceptance of the forged certificate by any cluster, execution of any of the 13 pod steps and the origin of the two passwords embedded in the manifests are NOT CHECKED.
- The ticket acquisition route, the key's origin beyond 3 of 195 public image tags, whether the Rockstar key is publicly known as leaked or the certificate revoked, and whether the beacon's refresh token still works are NOT CHECKED.
- In the loader I did not read the `fsys` and `download` handlers, the scheduled-task routine, the `cbt.bin` comparison direction or 287 export stubs. In the Linux agent about 1,780 library functions were classed and not read.
- Public pages were read through summarising readers and the primary vendor reports were not opened, and the registration-history and sample-hash records for several operator addresses were unavailable, so infrastructure claims that depend on them are carried at the lower grade or NOT CHECKED.
- The 11 open and 50 refused answers on port 6443 are carried unverified, because the intermediate scan output behind them was only partly recovered.
- Whether the C2 name resolves to a live server today, and any uptime duration, are NOT CHECKED.
- Sigma and Suricata rules were not run against live telemetry or a benign baseline, and the false-positive behaviour of three YARA rules is NOT CHECKED.

## 17. References
{: .hl-tier-2}
{: .hl-tab-confidence}

The class of each implant is documented publicly, and I used these sources only for structural comparison. I read each page through a summarising reader and did not open the primary vendor reports, so any claim drawn from them is the summary's rendering.

- Check Point Research (2026-01-13), on the VoidLink Linux framework: a Zig-built implant with in-memory ELF plugins, compared with the Linux agent here. No lineage is claimed.
- Sysdig (2026-01-16), on VoidLink: the memfd loading sequence, compared with the Linux agent's re-execution.
- Cloud Security Alliance (2026-09-30), research note on the Antino family, relaying a Cisco Talos report: a OneDrive and Graph command channel, compared with the loader's.
- Symantec, report on malware that uses the Graph API for command and control: BirdyClient, Graphite, Bluelight, SiestaGraph, Graphican and Graphon, read for the OneDrive and Graph class.
- cyberpress write-up of ESET's GraphWorm report (ESET, 2026-05-20): the folder and output naming of a Graph-based implant, compared with the loader's `cmd` folder.
- Hunt.io, "Treasure Trove of Trouble": an open-directory toolkit with a Kerberoast hash file, read for the numbered-directory convention, which it does not document.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.

