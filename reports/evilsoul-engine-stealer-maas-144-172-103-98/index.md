---
title: "EvilSoul-Engine: A Brazilian Stealer-Builder Malware-as-a-Service"
date: '2026-07-03'
layout: post
permalink: /reports/evilsoul-engine-stealer-maas-144-172-103-98/
thumbnail: /assets/images/cards/evilsoul-engine-stealer-maas-144-172-103-98.png
hide: true
category: "MaaS Operation"
description: "Server-side teardown of the EvilSoul-Engine stealer-builder — a Brazilian Malware-as-a-Service factory that mass-produces uniquely-packed Discord, browser, and crypto-theft payloads with a working Chrome App-Bound-Encryption bypass and Microsoft Defender timing evasion."
detection_page: /hunting-detections/evilsoul-engine-stealer-maas-detections/
ioc_feed: /ioc-feeds/evilsoul-engine-stealer-maas-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Suricata Signatures"
    anchor: "suricata-signatures"
ioc_highlights:
  - "evilsoul[.]cc"
  - "evilsoul[.]xyz"
  - "198.1.195[.]210"
  - "299a2e7fa8a69c495ec19fecf55d93bb766addaa78e89a4e1ad78a9cea59b31c"
stix_bundle: /stix/evilsoul-engine-stealer-maas-144-172-103-98.json
---

**Campaign Identifier:** EvilSoul-Engine-Stealer-MaaS-144.172.103.98<br>
**Last Updated:** July 3, 2026<br>
**Threat Level:** HIGH

> **Report scope.** This is one of two reports on a single Brazilian information-stealer operation whose complete server-side toolkit The Hunters Ledger recovered from a torn-down open directory. This report (Report B) covers the EvilSoul-Engine stealer-builder ecosystem — the payload factory, its packer, its web control panel, and the built stealer payloads (`stealer.js`, the `299a2e7f` Socket.IO variant, and the Maploot/Tinarox Electron twins), plus the commodity Chrome credential-decryption tool the operation adopted. The companion report (Report A) covers the operator's other, concurrently-live product line — the KAIDO Quasar-fork remote access trojan at `144.172.109[.]203`. Both are run by the same actor; this report cross-references Report A where the two lines connect.

---

## 1. Executive Summary

EvilSoul-Engine is a Brazilian stealer-builder Malware-as-a-Service (MaaS) — a productized criminal factory that compiles and auto-distributes uniquely-packed Discord, browser, and cryptocurrency-theft payloads for paying customers. It is operated by the named, self-identified Brazilian actor `n_3_xl` / `@govbrasil`, branded KAIDO (`0xK41`), at HIGH confidence — the same actor whose KAIDO remote access trojan is documented in the companion report. The Hunters Ledger recovered and reverse-engineered the operation's complete server side — the stealer template, an automated builder, a JavaScript packer, a MongoDB-backed web control panel, and an exfiltration/delivery service — after an open-directory sweep surfaced the staging server at `144.172.103[.]98:8888`. This report answers the intelligence question that motivated the investigation: there was no public technical documentation of the EvilSoul-Engine stealer-builder — its Chrome App-Bound-Encryption (ABE-v20) bypass, its process-token-impersonation credential decryptor, or its Microsoft Defender timing-window evasion — and none of the operation's built payloads carried a working detection signature. This report closes that gap and hands defenders behavior-based detection for a threat that hash-blocking cannot durably catch.

**Why this matters.** EvilSoul-Engine weaponizes current-generation credential theft. Its built payloads defeat Chrome's newest cookie protection (App-Bound Encryption) two different ways, disable Microsoft Defender wholesale (whole-drive exclusion, real-time monitoring off, firewall off, antivirus process termination), and sit quietly past Defender's post-launch behavioral-monitoring window before doing anything noisy. Because the operation is a MaaS vendor, this capability does not stay with one operator — every customer who buys a build gets a uniquely repacked payload, and the factory's own packer guarantees that no two builds share a file hash. Across the 21 recovered files, no existing YARA signature produced a single hit. The correct defensive posture is to hunt behaviors, not hashes.

**What was found — at a glance.**

- A complete server-side stealer factory (Section 4): a builder that injects a customer's configuration into a stealer template, runs a multi-layer packer over it, compiles an Electron executable, and pushes the result to multiple file-hosting services and a Telegram bot — logging each build to a database and notifying the operator.
- Three tiers of built stealer payload (Sections 5–7): the Node.js `stealer.js` source; the `299a2e7f` Socket.IO variant, which adds a full real-time remote access trojan (live screen streaming, remote control, and destructive commands) on top of the stealer; and the Maploot and Tinarox Electron twins, two game-masquerading builds that share one exfiltration stack. The `299a2e7f` tier's V8 bytecode defeated static analysis; its runtime behavior and decrypted source were recovered from observed execution (Section 9).
- Current-generation credential theft (Section 5): Discord account takeover including recovery codes and billing; browser passwords, cookies, autofills, and payment cards across roughly 25 Chromium forks plus Firefox; and two independent Chrome App-Bound-Encryption bypasses — a Chrome DevTools Protocol cookie-theft path and a process-token-impersonation decryptor.
- A commodity supply-chain component (Section 8): the operation adopted a public red-team tool (xaitax "ChromElevator") for its App-Bound-Encryption bypass — not novel tradecraft, but a live example of criminal reuse of published offensive tooling.
- A dead staging box, a live operator (Section 3): the recovered directory is a torn-down staging instance — all its channels are dead — but the operator is concurrently active on the KAIDO product line (see the companion report). Killing this infrastructure does not remove the threat.

**Attribution.** The operation is attributed at HIGH confidence to the self-identified Brazilian commodity-malware operator `n_3_xl` / `@govbrasil` (KAIDO / `0xK41`) — a financially-motivated MaaS vendor, not a targeted-intrusion actor. The tooling lineage traces to the EvilSoul-Engine MaaS, whose developer is a separate Brazilian actor, `@breakingupslow` (DEFINITE lineage). These are two distinct people: `n_3_xl` is assessed as a customer, reseller, or affiliate of the EvilSoul operation at MODERATE confidence, not the same individual as its developer. Because a named actor is identified at HIGH confidence, no unattributed-threat-actor (UTA) designation is used. Section 9 sets out the full attribution reasoning.

**Victimology — stated honestly.** The recovered logs contain no confirmed victims: one operator test box and one unresolved possible-victim host (whose harvested personal data is redacted in this report). A recovered file listing 2,229 hardware IDs is not a victim count — its meaning was not determinable from the recovered evidence and it is most plausibly imported license or blocklist data (INSUFFICIENT). Section 3 explains this in full.

**Overall risk: HIGH (8.5/10).** The operation weaponizes credential theft that defeats the newest browser and endpoint protections, disables defenses on the host, evades behavioral sandboxes, and — being sold as MaaS — propagates that capability to arbitrary downstream buyers. It stops short of CRITICAL only because it has no self-propagation or lateral-movement capability and no confirmed victims in the recovered data; distribution is buyer-driven social engineering. Section 2 details the risk scoring.

---

## 2. Business Risk Assessment

EvilSoul-Engine scores 8.5/10 — HIGH, driven by credential-theft capability that defeats current browser and endpoint protections and by a MaaS distribution model that propagates that capability to any buyer. The score is a weighted average across six risk dimensions; each is justified by specific, observed capability rather than family reputation.

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
<tr><td>Data Exfiltration</td><td>10/10</td><td>Full Discord account takeover (tokens, recovery codes, billing, 2FA state), browser passwords/cookies/autofills/payment cards across ~25 Chromium forks plus Firefox, crypto wallets, gaming accounts, and live session tokens. Automated upload to Discord webhooks and cloud file hosts.</td></tr>
<tr><td>System Compromise</td><td>8/10</td><td>The `299a2e7f` tier adds a full interactive remote access trojan — live screen streaming, remote mouse/keyboard control, and arbitrary command execution — over a persistent channel. Not full privilege escalation, but hands-on host control.</td></tr>
<tr><td>Persistence Difficulty</td><td>7/10</td><td>Up to four redundant persistence methods per build (registry Run keys, Startup-folder scripts, a hidden scheduled task masquerading as <code>Microsoft Corporation</code>), plus a watchdog "persistence-of-persistence" chain in the Socket.IO tier. Standard techniques, but layered for resilience.</td></tr>
<tr><td>Evasion Capability</td><td>9/10</td><td>Two Chrome App-Bound-Encryption bypasses, Microsoft Defender behavioral-window timing evasion, an anti-emulation CPU stall, a ~230-entry sandbox blocklist, and a six-function chain that disables Defender, the firewall, and third-party antivirus outright.</td></tr>
<tr><td>Lateral Movement</td><td>2/10</td><td>No worm, no credential-relay pivot, no self-propagation observed. Distribution is buyer-driven social engineering (Discord lures, cracked-software bait). Propagation risk lives at the ecosystem level, not the host level.</td></tr>
<tr><td>Detection Challenge</td><td>9/10</td><td>Every customer build is uniquely repacked (js-confuser → AES-256-GCM → XOR → base64 → in-memory execution); zero YARA hits across 21 recovered files. Hash-blocking has near-zero durability; only behavioral detection holds.</td></tr>
</tbody>
</table>

Weighted overall: 8.5/10 — HIGH. The exfiltration and evasion dimensions dominate; the low lateral-movement score is the single factor keeping this out of the CRITICAL band.

### What this means for defenders

The threat is the capability, not the file. Because EvilSoul-Engine is a builder, the thing to defend against is not a specific executable — it is a set of behaviors that every build performs at runtime regardless of how it was packed. A signature written against Maploot will not catch the next customer's build; a behavioral rule that fires on "a browser relaunched headless with a remote-debugging port by a non-browser parent" will catch all of them. This is why Section 10 leads with behavioral hunts and treats hashes as a secondary, low-durability layer.

The exposure is broad and consumer-facing. The data an EvilSoul-Engine build harvests — Discord accounts with recovery codes, saved browser passwords and payment cards, cryptocurrency wallets, gaming accounts, and live web-session tokens — is the full contents of a typical consumer's digital life. For an organization, the risk arrives through employees' personal browsers and Discord accounts on managed or BYOD endpoints: a stolen browser cookie for a corporate SaaS login is a session-hijack primitive that skips the password and the second factor entirely.

The endpoint's own defenses are a target. Several tiers actively disable Microsoft Defender, the Windows firewall, and installed antivirus before harvesting. A defense that relies solely on the endpoint agent staying healthy is exactly the defense this malware is built to remove. Detection value therefore shifts toward network egress monitoring and centralized log analysis (script-block logging of the Defender-suppression commands, scheduled-task creation events) that survive the endpoint agent being neutered.

---

## 3. Operational Reality and Victimology

Hold two truths at once: the recovered infrastructure is a dead staging box, and the operator behind it is concurrently active. The open directory at `144.172.103[.]98:8888` was a genuine, torn-down staging instance of the operation's newer EvilSoul-Engine stealer-builder line (HIGH confidence — its exact purpose as a pre-production staging box versus a proof-of-concept build environment cannot be distinguished from the recovered artifacts, but both readings agree it was non-production and operator-controlled) — captured over a single roughly one-week window (2026-06-06 to 2026-06-13) and confirmed dead by 2026-06-27. All of its channels are verified offline: the Telegram bot returns `401 Unauthorized`, the Discord webhooks return `10015 Unknown Webhook`, and the origin server is down. But the same operator's KAIDO Quasar remote access trojan command-and-control at `144.172.109[.]203` was live with fresh samples first seen in May 2026 — samples that predate the June open-directory capture. This is a live, multi-product operator caught through one dead staging artifact, not a defunct one-off campaign.

The practical consequence: killing the recovered infrastructure does not remove the threat. This is a vendor node in a supply chain, not the end of a campaign. Each customer build is uniquely repacked, and those builds persist in customers' hands independent of the origin server's status. The takeaway for defenders is the one this report returns to repeatedly — detect behaviors, not hashes.

### Victimology — no confirmed victims, one unresolved host

The recovered operational logs support an honest, deliberately conservative victim assessment. There are no confirmed victims in the captured data.

- **The operator's own test box** (HIGH confidence). One host in the exfiltration logs (hostname tagged `kaido`) shows a 21-minute uptime, a throwaway-looking Discord account, and a trivially small harvest — the signature of an operator testing their own build, not a victim.
- **One unresolved possible-victim host** (AMBIGUOUS — cannot resolve). A second host shows roughly nine days of uptime, a real and populated 107 KB browser-cookie harvest, and an associated Brazilian phone number and full Discord social graph. This is either the operator's own daily-driver machine or a genuine victim — the evidence does not settle which. Per this report's handling of personal data, the specific harvested account, phone, and email identifiers for this host are redacted; they are held only in the local investigation record. Notably, this host's `passwords.txt` and `creditcards.txt` were near-empty stubs — an artifact of the operation's broken server-side decryptor channel, not proof of an empty host, since the cookies (which travel a different, self-contained theft path) came through fully populated.

The 2,229-ID file is not a victim count. A recovered file (`hwids.txt`) lists 2,229 unique 10-digit identifiers. Its meaning is unresolved (INSUFFICIENT confidence) — the panel code that would explain it is compiled to V8 bytecode and was not cost-effective to decompile (Section 16 tracks this as an open question); candidate readings include victim telemetry, license tracking, and a sandbox blocklist. Given zero confirmed victims elsewhere in the logs, the most plausible reading is carried-over or imported data (LOW confidence), not 2,229 live victims of this deployment. This file must not be cited as a victim count, and this report does not do so.

### Targeting profile

Victim targeting is opportunistic and consumer-facing, not sector-specific or geographic. The built payloads harvest Discord, browser, and cryptocurrency-wallet credentials from any infected Windows host, consistent with mass-market stealer-log distribution through Discord lures and cracked-software bait. There is no evidence of enterprise, government, or critical-infrastructure targeting in either product line. The operator's *base* is Brazil (Portuguese-language code, logs, and documentation; Brazilian hosting; Brazilian banking payment rails referenced in public reporting on the EvilSoul brand) — but the *victims* are wherever the customers' lures land.

---

## 4. Technical Classification and Ecosystem Overview

> **Analyst note:** EvilSoul-Engine is a productized stealer *factory*, not a single payload. The recovered open directory is the server side: a builder that injects a customer's configuration into a stealer template, runs a packer over it, compiles an executable, and auto-distributes the result across file hosts and a Telegram bot. This section describes the shape of the operation — its server-side components and the tiers of payload it produces — so the capability deep-dives that follow have a map to sit on. Offensive internals (injector code, exact packer routines) are summarized at capability altitude, not reproduced.

EvilSoul-Engine is best understood as two things at once: a stealer-builder MaaS platform (the server-side factory that customers pay to use) and the family of stealer payloads that factory produces. The recovered open directory is the factory; the payloads analyzed in Sections 5–8 are its output, recovered from separate sources (a builder tarball, VirusTotal samples, and observed execution of two builds).

| Attribute | Assessment |
|---|---|
| Project name | EvilSoul-Engine (npm lockfile name); web panel branded `0xK41-webpanel` / `hXh Enginel-webpanel`; service brand "KAIDO Services" |
| Type | Information-stealer builder/packer + stealer payloads + web control panel |
| Family confidence | EvilSoul-Engine lineage: DEFINITE |
| Builds observed | Node source (`stealer.js`); pkg-Node single-executable (`299a2e7f` Socket.IO variant); Electron (Maploot, Tinarox); four unrecovered `static/*.exe` factory outputs |
| Delivery hosts | gofile.io, catbox.moe, litterbox.catbox.moe, pixeldrain.com, an ngrok tunnel, the Telegram Bot API |
| Exfiltration sinks | Discord webhooks, `evilsoul[.]xyz` / `evilsoul[.]cc` backends, gofile.io, web-panel `/send-*` endpoints |
| Sophistication | Selective — advanced credential-theft (ABE-v20 bypass, CDP cookie theft, Defender timing evasion) on an otherwise commodity structure |
| Status | Recovered open directory dead; sibling Electron and pkg-Node builds live in customers' hands |

### The server-side factory

The recovered directory's orchestrator (`index.js`) forks four services that together form the factory. A defender does not typically see these — they run on the operator's own server — but understanding them explains *why* the built payloads look the way they do.

| Component | Role |
|---|---|
| `stealer.js` (~2,730 lines) | The payload template — Discord/browser/crypto theft, exfiltration, persistence. |
| Builder API (`builder_index.js`, port 1331) | Injects the customer's configuration, runs the packer, compiles the Electron executable, uploads to file hosts, logs to a database, and notifies the operator via Telegram. |
| Packer (`obfuscator.js`) | Wraps each build: js-confuser → AES-256-GCM → XOR → base64 → in-memory execution, with anti-VM and anti-debug checks. |
| Web panel (`panel.exe`, pkg-Node) | The operator control plane — MongoDB, desktop screenshotting, WebSocket, Windows credential-store access, Discord integration, and archiving. |
| Sender + Telegram bot | Exfiltration intake plus build delivery and notification. |

The four unrecovered `static/*.exe` files (~37–40 MB each) were the factory's *output* — customer builds. Everything recovered is the *factory* itself. This distinction matters for detection: the factory components are internal to the operator, while the built payloads are what land on victim endpoints.

### The product tiers

The investigation recovered and analyzed three tiers of built stealer plus one commodity supporting tool. Each is a self-contained subject in the sections that follow; they share the EvilSoul-Engine lineage but differ in form, capability, and how they were recovered.

| Tier | Form | Recovery method | Covered in |
|---|---|---|---|
| `stealer.js` (0xK41 build) | Node.js source | Static reverse engineering of the builder tarball | Section 5 |
| `299a2e7f` Socket.IO variant | pkg-Node single executable (81.9 MB) | Process-memory recovery from observed execution | Section 6 |
| Maploot / Tinarox twins | MSI dropper → Electron (172 MB / 90 MB) | Decryption + dynamic memory resolution; webcrack deobfuscation | Section 7 |
| xaitax ABE tool pair | Win64 executable + companion DLL | Static reverse engineering (commodity) | Section 8 |

Across all 21 recovered files, no existing YARA signature produced a single hit, and none of the four `static/*.exe` outputs were present on VirusTotal at analysis time. That is a testament to the factory's per-build repacking, and it is the reason this report's detection guidance (Section 10) leads with build-independent behavioral signals — the operator-signature packer constant that survives obfuscation, the CDP browser-relaunch cookie-theft pattern, the process-token-impersonation credential decryptor, and the Microsoft-masquerade scheduled task — rather than file hashes.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/obfuscator-operator-signature.png" | relative_url }}" alt="Packer source code showing a hardcoded constant named STATIC_XOR_KEY_SECRET set to the string 'see-you-in-the-hellwizard-1082@239$328927bA', alongside random per-build key-generation functions.">
  <figcaption><em>Figure 1: The operator-signature packer constant inside the EvilSoul-Engine obfuscator. Every customer build randomizes its per-build keys (the <code>generateRandomKey</code>/<code>generateRandomXorKey</code> routines), but this fixed <code>STATIC_XOR_KEY_SECRET</code> value invokes the obfuscated code and therefore survives the js-confuser layer unchanged across all tiers. It is the highest-durability, near-zero-false-positive YARA anchor in the report — the single string that identifies the factory regardless of how a build was repacked.</em></figcaption>
</figure>

---

## 5. Technical Capabilities — The Built Stealer Payload

The EvilSoul-Engine stealer harvests a consumer's full credential footprint — Discord accounts, browser secrets, cryptocurrency wallets, and gaming accounts — and defeats the newest browser protection (Chrome App-Bound Encryption) to do it. This section walks each capability class with the specific evidence recovered from `stealer.js` and its sibling builds, then translates what each means for defenders. The capabilities are stated at the level of *what the malware does and how it is detected*; the offensive code paths are described at capability altitude, not reproduced.

### 5.1 Discord account takeover

> **Analyst note:** Discord tokens are stored client-side in the app's local database. A stealer that lifts a token can impersonate the account without the password — and with the enrichment steps below, can also lift the account-recovery codes that would let a victim (or an attacker) restore access. This section explains how the theft works and why it amounts to full account takeover rather than a nuisance.

#### Deep technical analysis

The stealer steals authentication tokens from the local storage of every Discord client variant — Discord, Canary, PTB, Development, and Lightcord — by reading their LevelDB stores. It then validates each token against the Discord API (`discord.com/api/v9/users/@me`) and enriches every valid one with the account's full context: billing and saved payment sources, friends and relationships, guild (server) memberships, badges, Nitro subscription status, two-factor-authentication state, email, phone number, and — critically — **account recovery codes**.

Lifting the recovery codes is what turns token theft into durable account takeover. A victim who notices the compromise and resets their password can be locked back out by an attacker holding the recovery codes.

One build-specific detail is a useful detection anchor. Discord's encrypted-token storage carries a recognizable prefix (`dQw4w9WgXcQ:`) that signature authors key on. The `stealer.js` build deliberately hides this prefix behind a base64-and-XOR encoding (a small decoder call, `_xd('D2VGTBwNZh8zV2A=','k41x')`) specifically to dodge YARA rules that look for the plaintext prefix. The `299a2e7f` build, by contrast, carries the prefix in plaintext — a difference that helps distinguish the tiers.

#### Executive technical context

**What this means:** stealing a Discord token is like stealing a signed, pre-authenticated door badge rather than the key. The attacker walks straight in as the victim, and by also grabbing the recovery codes, changes the locks behind them.

**Security impact:** for consumers, this is loss of a primary social and, increasingly, financial identity (Discord accounts carry billing data and are gateways to communities and marketplaces). For organizations, a compromised employee Discord account is a social-engineering launchpad and, where Discord is used for coordination, a foothold into internal discussion.

**Detection strategy:** the enrichment traffic — a burst of requests to `discord.com/api/v9/` endpoints (`/users/@me`, billing, relationships) from a non-browser process shortly after execution — is a behavioral tell that survives repacking. Exfiltration of the harvest lands on Discord webhooks (Section 5.6).

### 5.2 Browser credential and cookie theft — three mechanisms

> **Analyst note:** This is the operation's center of gravity and its most technically serious capability. Modern Chrome protects saved cookies with "App-Bound Encryption" (ABE), a scheme meant to stop exactly this kind of theft by tying the decryption key to the browser's own process identity. EvilSoul-Engine builds defeat it three different ways — one commodity, two advanced. This section explains each at capability altitude and, for each, the behavioral signature a defender can hunt.

The stealer reads passwords, cookies, autofill data, browsing history, and saved payment cards across roughly 25 Chromium-based browsers (all profiles) plus Firefox. It reaches that data through three distinct mechanisms of escalating sophistication.

#### Mechanism 1 — DPAPI and SQLite (the commodity path)

The baseline path is the long-standing commodity technique: copy the browser's `Local State` file to obtain the master key, decrypt that key using the Windows Data Protection API (DPAPI, via `ProtectedData.Unprotect`), then read the `Login Data`, `Cookies`, `Web Data`, and `History` SQLite databases directly. This yields passwords, cookies, autofills, and credit cards on older browser versions and remains the fallback everywhere.

This path is well-understood and broadly detected, but it still works against any browser that has not moved sensitive data behind App-Bound Encryption. It is the floor of the operation's capability, not the ceiling.

#### Mechanism 2 — Chrome DevTools Protocol cookie theft (App-Bound-Encryption bypass, advanced)

The advanced cookie-theft path sidesteps App-Bound Encryption entirely by making the browser decrypt its own cookies. The stealer relaunches the victim's own browser in headless mode, pointed at the victim's real profile directory, with a remote-debugging port enabled — then connects to that port over the Chrome DevTools Protocol (CDP) and calls `Network.getAllCookies`, which returns the cookies already decrypted by the browser itself. No administrator rights are required, and App-Bound Encryption is never confronted because the browser is doing the decryption in its normal course of operation.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/cdp-cookie-theft-browser-relaunch.png" | relative_url }}" alt="Stealer source code for a startBrowserDebug function that spawns the victim's browser executable with a randomized --remote-debugging-port, a --user-data-dir pointing at the real profile, and headless flags, then waits several seconds for the debug port to come up.">
  <figcaption><em>Figure 2: Capability evidence — the first half of the CDP App-Bound-Encryption bypass. The stealer relaunches the victim's own browser against its real profile directory with a randomized <code>--remote-debugging-port</code>, <code>--user-data-dir</code>, and headless flags. This exact parent-child pattern — a browser binary spawned with these three arguments by a non-browser parent — is the highest-value credential-access hunt in the report (Section 14) and is build-independent, so it holds regardless of how the payload was packed.</em></figcaption>
</figure>

From the recovered cookies, the stealer additionally lifts platform session tokens directly — Roblox `.ROBLOSECURITY`, Instagram and TikTok `sessionid`, and Spotify `sp_dc` — each of which is a ready-made session-hijack primitive.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/cdp-cookie-theft-getallcookies.png" | relative_url }}" alt="Stealer source code that queries the local debug port's /json endpoint for the WebSocket debugger URL, opens a WebSocket to it, and sends a Chrome DevTools Protocol Network.getAllCookies request.">
  <figcaption><em>Figure 3: Capability evidence — the second half of the CDP bypass. After the relaunch, the stealer reads the debugger WebSocket URL from the local <code>/json</code> endpoint and issues a <code>Network.getAllCookies</code> DevTools call, which returns every cookie already decrypted by the browser itself — defeating App-Bound Encryption without ever confronting it. The distinctive detection anchor is the loopback connection to the debug port and the <code>getAllCookies</code> request from a non-browser process, not any single fixed string.</em></figcaption>
</figure>

A stolen live session cookie is worse than a stolen password: it represents an already-authenticated session, so it skips both the password prompt and the second factor. This is the single most valuable thing the operation steals, and its behavioral signature is unusually clean — a browser binary spawned with `--remote-debugging-port`, `--headless`, and `--user-data-dir` pointing at the real profile, by a parent process that is not itself a browser or a developer tool. That pattern is the highest-value hunt in this report (Section 10) and does not vary between builds.

#### Mechanism 3 — process-token-impersonation decryptor (App-Bound-Encryption v20, the one genuinely advanced component)

The `stealer.js` build carries a second, distinct App-Bound-Encryption bypass — the operation's most sophisticated single component. *(App-Bound Encryption is Chrome's cookie- and credential-protection scheme, introduced in Chrome 127; "v20" denotes the specific key-blob generation this decryptor targets.)* It downloads a portable Python runtime from the operator's server, pipes a decryptor script to it over standard input (so no `.py` file is ever written to disk), elevates its own privileges, impersonates the security context of the Windows `lsass.exe` process, and uses that borrowed context with a Windows cryptographic provider to unwrap the app-bound key and decrypt the stored blobs.

At capability altitude: this technique borrows the identity of a highly-privileged system process to unlock a key that is otherwise gated to the browser's own process identity. The analysis assesses it as lifted from a public proof-of-concept rather than original tradecraft — the technique class has public precedent — but its presence in a commodity stealer is notable.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/abe-v20-lsass-impersonation-decryptor.png" | relative_url }}" alt="Python decryptor code for an impersonate_lsass context manager that enables SeDebugPrivilege, locates the lsass.exe process, duplicates its access token as an impersonation token, and assigns it to the current thread before restoring the original token.">
  <figcaption><em>Figure 4: Capability evidence — the process-token-impersonation ABE-v20 decryptor, the operation's most sophisticated single component. This decryptor script is piped to a downloaded portable Python runtime over standard input, so no <code>.py</code> file ever touches disk. It enables <code>SeDebugPrivilege</code>, borrows the security context of <code>lsass.exe</code>, and uses that privileged identity to unwrap the app-bound key. The detection anchor is the behavioral chain — <code>python -u -</code> reading from stdin, enabling the debug privilege, and opening a handle to <code>lsass.exe</code> in short succession (Sysmon Event ID 1 + 10) — because file-scanning alone cannot catch a script that is never written to disk.</em></figcaption>
</figure>

**Detection strategy:** the behavioral signature is specific and high-value — a Python process reading a script from standard input (`python -u -`), enabling the debug privilege, and opening a handle to `lsass.exe`, all in short succession from a stealer parent. This maps to Sysmon process-creation (Event ID 1) plus process-access (Event ID 10) telemetry and is the second-highest-value hunt in this report. Because the script never touches disk, file-scanning alone will miss it; the process-behavior chain is what catches it.

**Reality check.** These three mechanisms are not equally novel. Mechanism 1 is commodity and broadly detected. Mechanism 2 (CDP cookie theft) is an increasingly common technique across the stealer landscape, not unique to this operation, but it is genuinely effective against App-Bound Encryption. Mechanism 3 is the sophisticated component, and even it is assessed as adapted from public proof-of-concept code. The operation's skill is in *integration and evasion*, not in inventing primitives.

### 5.3 Cryptocurrency and gaming theft

Beyond credentials, the stealer targets stored financial and gaming value:

- **Exodus cryptocurrency wallet** — both session data and a brute-force path against the wallet.
- **Steam** — a hardcoded Steam Web API key (`440D7F4D810EF9298D25EDDF37C1F902`) is embedded in the Electron builds and drives account enrichment.
- **Minecraft and Roblox** — session and account theft.

Cryptocurrency wallet theft is direct, irreversible financial loss; there is no chargeback on a drained wallet. Gaming accounts (Steam in particular) carry real resale value in criminal markets and often store payment methods. The hardcoded Steam API key is also a durable detection anchor — it is byte-identical across the Maploot and Tinarox builds (Section 7), which is part of what proves those two builds share one operator.

### 5.4 Defense evasion

> **Analyst note:** This section covers how the built payloads avoid being caught while they work. Two techniques stand out as more than commodity: a timing trick that waits out Microsoft Defender's post-launch inspection window, and a chain of commands that disables endpoint defenses outright. Both are described at the level a defender needs to hunt them, not at the level needed to rebuild them.

#### Microsoft Defender behavioral-window timing evasion

> **Analyst note:** Behavioral security tools (Microsoft Defender included) typically watch a new process closely for the first few minutes, then ease off. This technique exploits that pattern directly — the malware does nothing suspicious until the watcher has moved on, then does everything suspicious at once.

The `stealer.js` build sequences its work to defeat behavioral monitoring. It runs its *quiet* operations first, then sleeps for a randomized 7 to 10 minutes — long enough to outlast Microsoft Defender's post-launch behavioral-monitoring window — and only then runs its *noisy* operations (the SQLite reads, the DPAPI calls, the remote-debug-port cookie theft). A behavioral sandbox or an EDR agent that inspects the first few minutes of a process's life and then relaxes will see nothing interesting; the malicious behavior begins after the watcher has looked away. A separate sub-five-second CPU stall defeats automated malware emulators that give up quickly.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/defender-behavioral-window-evasion.png" | relative_url }}" alt="Stealer source code with a developer comment reading 'Anti-emulation: Defender emulator has ~2-3s timeout' above a busy-loop that spins a sine-summation for at least 4500 milliseconds before continuing, followed by a showDecoyWindow function that displays a fake loading screen.">
  <figcaption><em>Figure 5: Capability evidence — the anti-emulation stall and decoy window that accompany the Defender behavioral-window timing evasion. The operator's own comment ("Defender emulator has ~2-3s timeout") states the intent: burn more than 4.5 seconds of pointless CPU so an automated emulator that gives up quickly never reaches the malicious code, while a fake loading screen occupies the victim. This is the short-stall companion to the 7-10 minute pre-harvest sleep. For defenders, the stall itself is not the anchor — the reliable signal is the burst of credential-access behavior that follows the delay (Section 14).</em></figcaption>
</figure>

**Note on the timing figure.** The sleep duration (7-10 minutes) is directly observed in the code; the specific claim that this outlasts "a 2-4 minute Defender window" is an inference from observed behavior, not a vendor-published constant. The general technique — timing operations to outlast behavioral monitoring — is well-documented.

**Detection strategy:** a long, deliberate sleep early in a process's life followed by a burst of credential-access behavior is itself a suspicious sequence. More reliably, the *noisy* operations that follow the sleep (CDP cookie theft, DPAPI calls) are what detection should target — the sleep delays them but does not hide them.

#### Endpoint-defense suppression

The `299a2e7f` build carries a six-function suppression chain that disables host defenses before harvesting. Observed at capability altitude, it: masquerades its process as a service, adds a whole-drive Microsoft Defender exclusion (`Add-MpPreference -ExclusionPath 'C:\'`), turns off Defender real-time monitoring (`Set-MpPreference -DisableRealtimeMonitoring $true`), disables the Windows firewall on all profiles (`netsh advfirewall set allprofiles state off`), terminates a broad list of antivirus processes (Microsoft, McAfee, Symantec, Kaspersky, Avast, AVG, Bitdefender, Trend Micro, Webroot), and stops the Windows Defender service (`net stop WinDefend`).

This is not evasion, it is demolition. A whole-drive Defender exclusion means *nothing on the disk is scanned* thereafter. Real-time monitoring off and firewall off remove the two controls most likely to flag the subsequent exfiltration.

**Detection strategy:** these commands are the single best centralized-log detection in the report, because they are executed through PowerShell and land in PowerShell script-block logging (Windows Event ID 4104) regardless of the endpoint agent's health. Even after the payload has disabled Defender, the *record of it disabling Defender* is in the event log. A rule on `Add-MpPreference -ExclusionPath 'C:\'` or `Set-MpPreference -DisableRealtimeMonitoring $true` from an unexpected parent is high-signal and low-false-positive.

#### Anti-analysis

> **Analyst note:** Before doing anything harmful, the malware checks whether it is running on a real victim machine or inside a security researcher's analysis environment (a sandbox or virtual machine) — and quietly exits if it thinks it is being watched. This is a standard commodity technique, not something unique to this operation.

The `stealer.js` build checks the machine's hardware UUID (`WMIC csproduct get UUID`) against a roughly 230-entry blocklist of known sandbox and analysis-VM identifiers, and checks the username against a blocklist; a match triggers a clean exit. It also spoofs a Chrome/120 user-agent and decodes strings at runtime to frustrate static analysis. These are commodity anti-analysis techniques — the copy-paste blocklist in particular is a known artifact shared across many stealer families — and are noted here for completeness rather than as sophistication.

### 5.5 Persistence

Persistence varies by build, but the pattern is redundancy — multiple independent mechanisms so that removing one leaves others intact.

- `stealer.js` installs up to four redundant methods: an HKCU registry Run key, a Startup-folder VBScript, an HKLM registry Run key, and — most notably — a hidden scheduled task that masquerades as `Microsoft Corporation`.
- `299a2e7f` uses a Startup-folder `update.bat` plus a reconnect lock, and layers a "persistence-of-persistence" watchdog chain: a hidden `updatesystem.cmd`, a randomly-named `.lnk`, and a `watcher.vbs` that re-establishes the others if they are removed.

A scheduled task whose XML author field reads `Microsoft Corporation` and carries the hidden flag is designed to blend into the dozens of legitimate Microsoft tasks on any Windows host. But that exact combination — author `Microsoft Corporation` on a *newly-created, hidden* task — is itself a durable detection anchor, because legitimate Microsoft tasks are installed by the OS, not created at runtime by a user-context process. Scheduled-task creation (Windows Event ID 4698) with that author on a task written by a non-system process is the third-highest-value hunt in this report (Section 10).

### 5.6 Exfiltration

The stealer packages its harvest and ships it out through several redundant channels:

- Discord webhooks — the primary exfiltration sink; harvested archives and status embeds are POSTed to hardcoded webhook IDs (Maploot/Tinarox share `1391195207508295750` and `1401355074235793458`).
- Web-panel endpoints — a zip of cookies, autofills, credit cards, and passwords to `/send-data`; status embeds to `/send-embed`; plus `/send-logs` and `/send-recovery-codes`.
- Cloud file hosts — loot archives uploaded to gofile.io.
- Operator backend — the `evilsoul[.]xyz` backend receives injected data and serves tool downloads (`/dcinjection-send`, `/upload-txts`, `/download/panel`).

**Detection strategy:** the network signatures here are strong precisely because they are hardcoded. Discord webhook POSTs to the two known IDs, uploads to gofile, and traffic to the `evilsoul[.]xyz` / `evilsoul[.]cc` backends are all directly hunted in the companion Suricata and IOC content. Because gofile and Discord are legitimate shared services, the *specific* webhook IDs and backend domains are the discriminating indicators, not the services themselves.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/operator-exfil-embed-0xk41.png" | relative_url }}" alt="Web-panel exfiltration log showing repeated /send-data and /send-embed requests keyed to a KAIDO-DAY license key, each carrying a Discord embed authored '0xK41 ~ BrowserData', and each failing with 'Failed to send data to webhook' and 'Unknown Webhook' errors.">
  <figcaption><em>Figure 6: Exfiltration and operator-branding evidence from the recovered web-panel <code>/send-*</code> log. Each harvest is POSTed to the panel's <code>/send-data</code> and <code>/send-embed</code> endpoints under a <code>KAIDO-DAY-*</code> customer license key, wrapped in a Discord embed self-branded <code>0xK41 ~ BrowserData</code>. The repeated "Failed to send data to webhook" / "Unknown Webhook" errors are the dead-channel state described in Section 3 — the staging box's webhooks were already torn down. The <code>0xK41</code> embed branding and the <code>KAIDO-DAY</code> key are attribution anchors tying this exfiltration path to the named operator (Section 10); the <code>/send-*</code> endpoints are durable, operator-provisioned network indicators.</em></figcaption>
</figure>

---

## 6. The 299a2e7f Socket.IO Variant — Stealer Plus Remote Access Trojan

> **Analyst note:** This is a distinct EvilSoul-Engine product tier — not just a fire-and-forget stealer, but a stealer with a full real-time remote access trojan bolted on, driven over a persistent Socket.IO channel. Its payload was V8 bytecode, so static analysis was unable to read it; its decrypted source was recovered from process memory during observed execution. This section describes what the tier can do to an infected host and how each capability is detected. The remote-control internals are summarized at capability altitude.

The `299a2e7f` build (a single 81.9 MB pkg-Node executable) carries all the stealer capabilities of Section 5 and adds a full interactive remote access trojan over a persistent real-time channel to `http://evilsoul[.]cc:80` (Socket.IO version 4, opening with a `?EIO=4&transport=polling` handshake before upgrading to a WebSocket). Once connected, the operator issues named events and the infected client executes them and returns results.

### 6.1 Remote-control capability

At capability altitude, the tier exposes the infected host to the operator across four categories:

- Live screen streaming. The client captures the desktop at roughly 30 frames per second, resizes each frame to 640×360, compresses it, and streams it to the operator as a `screenData` event — a live view of the victim's screen.
- Remote interactive control. The operator drives the victim's mouse and keyboard, executes arbitrary commands, and can download and run additional executables (including a variant that installs the downloaded payload to Startup for persistence).
- Destructive and disruptive commands. The tier can trigger a blue-screen crash (via `NtRaiseHardError`), shut down, restart, lock, or sleep the machine, disable the network adapter to kill Wi-Fi, disable Task Manager, freeze input, and change the wallpaper.
- File discovery. The client enumerates the victim's Desktop, Downloads, Documents, AppData, and Temp folders and reports the listing to the operator.

This tier crosses the line from data theft to hands-on host control. The operator is not just harvesting credentials — they are watching the screen in real time, moving the cursor, and able to brick the machine on command. For a victim, that is the difference between a stolen password and a stranger operating their computer.

### 6.2 Runtime webhook resolution — a detection-relevant design choice

Unlike the Maploot and Tinarox builds (which hardcode their Discord webhooks), the `299a2e7f` build hardcodes no exfiltration webhook at all. Instead, at runtime it POSTs its license key to a relay endpoint — `http://198.1.195[.]210:3000/tralalero` — and receives the current Discord webhook URL in the response. A fallback key (`6D479A7E665F`) is sent in every call.

This design lets the operator rotate exfiltration destinations without rebuilding payloads, which weakens webhook-based blocking. But it introduces a *stronger* fixed indicator: the relay endpoint itself. Every build of this tier phones `198.1.195[.]210:3000/tralalero` on startup, so a network rule on that endpoint catches the tier regardless of which webhook it is currently using. The relay is a single point the operator cannot rotate without rebuilding.

### 6.3 App-Bound-Encryption bypass via GitHub-hosted tools

This tier fetches its Chrome App-Bound-Encryption bypass tooling at runtime from a public GitHub account (`github[.]com/sqlban/configs`), downloading `chromelevator.exe` and `chrome_decrypt.dll` to `%TEMP%\executor\`. The `sqlban` account has since been taken down (now returns 404). Those two tools are the commodity xaitax ABE pair analyzed in Section 8.

**Detection strategy:** the drop of `chromelevator.exe` or `chrome_decrypt.dll` into `%TEMP%\executor\` (Sysmon file-create, Event ID 11) is a direct file-based anchor, and the runtime fetch from a raw GitHub URL by a pkg-Node process is a network-plus-process behavioral tell.

### 6.4 A distinct build in the same family

The `299a2e7f` tier is assessed as a distinct build of the same EvilSoul family (HIGH confidence), not a different malware. It lacks several `stealer.js` features (no Steam key, no `evilsoul.xyz` backend, no hardware-ID blocklist, no Defender timing phase observed in the recovered memory) — it is a different product tier of the same MaaS.

A supporting identity detail: the build references a custom Discord emoji (`evilsoulguild` emoji ID `1389088908117278781`), which differs from the emoji ID referenced by the Maploot and Tinarox builds (`1362105228719034679`). These are custom-emoji identifiers, not Discord server identifiers. Two distinct `evilsoulguild` emoji imply the operation runs at least two separate panel servers or builds — but the operator's real Discord server ID was never recovered, so this is a floor on the number of panel servers, not a server identifier itself. It is retained as a family-linkage anchor, correctly scoped.

Because this tier's payload is V8 bytecode, static analysis was insufficient and the findings above come from process-memory recovery during observed execution (chronological detail in Section 9). Some session-theft function bodies were not fully recovered, and the absence of a hardware-ID blocklist in the examined memory snapshot does not prove one is absent elsewhere in the binary. These are honest gaps, not negative findings.

---

## 7. The Maploot and Tinarox Electron Twins — One Exfiltration Stack, Two Builds

> **Analyst note:** Maploot and Tinarox are two EvilSoul-Engine Electron builds that masquerade as free games and are delivered as MSI installers. Their significance is evidentiary: they prove, at the byte level, that the same operator produced both — and they let defenders watch the factory's packer *evolve* between two builds. This section explains the shared capabilities, the decisive same-operator finding, and what the twins reveal about the builder.

Both Maploot and Tinarox present as free games — the `package.json` author reads `"Unreal Game Inc."`, with Maploot named `maploot` and Tinarox `tinaroxgamesfree` — and are delivered as MSI droppers with low detection (2 of 62 engines) that stage an Electron payload. Their capabilities mirror Section 5: Discord theft (tokens, billing, recovery and 2FA), browser credential theft (DPAPI plus SQLite across roughly ten Chromium forks plus Firefox), Steam, Minecraft, and Exodus wallet theft.

### 7.1 The decisive same-operator finding

After cracking Tinarox's added keyed obfuscation layer with a JavaScript deobfuscator (webcrack), every exfiltration value recovered independently from Tinarox's own code is byte-for-byte identical to Maploot's:

- The primary Discord webhook (`discord.com/api/webhooks/1391195207508295750/…`).
- The secondary Discord webhook (`discord.com/api/webhooks/1401355074235793458/…`, resolved from Maploot's memory).
- The ngrok tunnel (`acf02ac96211.ngrok-free[.]app`) — shared and not rotated between builds.
- The `evilsoul[.]xyz` backend (`/dcinjection-send`, `/upload-txts`, `/download/panel`, `/download/decrypter/<ver>`).
- The gofile upload endpoint (`store8.gofile[.]io/uploadFile`).
- The Steam Web API key (`440D7F4D810EF9298D25EDDF37C1F902`).
- The EvilSoul-family custom emoji (`evilsoulguild` emoji `1362105228719034679` — a custom emoji, not a server identifier).

This shared exfiltration stack is **DEFINITE** evidence of a single operator behind both builds. Identical webhook IDs, an identical API key, and the same unrotated ngrok subdomain across two independently-analyzed builds is about as strong a same-operator signal as passive evidence can provide. It is also a practical detection gift: any one of these hardcoded values catches both builds, and the shared ngrok subdomain and webhook IDs are unrotated across the twins.

### 7.2 Watching the packer evolve

The twins differ only in cosmetic and packing details: per-build encryption parameters (Maploot uses one AES scheme, Tinarox a distinct key/salt/IV), the game-masquerade branding, and — the interesting part — an added obfuscation layer. Tinarox carries a third XOR-and-keyed-string-array layer that Maploot lacks.

The twins are a snapshot of the builder mid-evolution. The operator is actively hardening the packer between customer builds, adding layers to frustrate the exact deobfuscation that recovered these findings. For defenders, the lesson reinforces the report's thesis: the *packed payload* is a moving target, but the *operator-signature constant that lives in the loader* (the packer's XOR key, Section 4) survives every layer because it is what invokes the obfuscated code rather than what gets obfuscated. Detection should target the loader constant and the runtime behaviors, not the packed bytes.

### 7.3 The shared App-Bound-Encryption injector

Maploot's backend serves its own copy of the Chrome App-Bound-Encryption injector at `evilsoul[.]xyz/download/decrypter/chrome_inject.exe`. This is the `evilsoul.xyz` analog of the `299a2e7f` tier's GitHub-hosted `chromelevator.exe` — the same App-Bound-Encryption bypass mechanism, delivered from the operator's own backend rather than from GitHub. It ties the twins' credential-decryption capability to the same commodity tool the Socket.IO tier fetches, analyzed next.

---

## 8. The Commodity App-Bound-Encryption Bypass Tool (Supply-Chain Reuse)

> **Analyst note:** The Chrome credential-decryption tool that multiple EvilSoul-Engine tiers fetch at runtime is not the operator's own invention — it is a public, well-documented red-team tool that the operation adopted. This distinction matters for accurate reporting: it is a supply-chain-adoption story, not a novel-tradecraft story. This section covers what the tool does (at capability altitude), how it is family-named by antivirus vendors, and why its provenance is intel-relevant.

The `chromelevator.exe` and `chrome_decrypt.dll` pair fetched by the `299a2e7f` tier (and mirrored on `evilsoul.xyz`) is the public red-team tool xaitax "Chrome-App-Bound-Encryption-Decryption" (also called "ChromElevator"), authored by security researcher Alexander Hagenah. This is well-documented public prior art — not novel tradecraft invented by this operator. The upstream repository (`github.com/xaitax/Chrome-App-Bound-Encryption-Decryption`) was confirmed accessible and current during the investigation. Antivirus vendors already family-name it on related samples — Kaspersky as `HEUR:HackTool.Win64.ChromElevator.gen`, Microsoft as `HackTool:Win64/PSWDump.MY!MTB`.

### 8.1 What the tool does, at capability altitude

The tool's job is to extract App-Bound-Encryption-protected browser secrets and write them to local JSON files; it does not exfiltrate — the parent stealer performs exfiltration. Confirmed capabilities (all DEFINITE unless noted): it releases the browser's file locks on the credential databases by terminating the browser's network service, extracts the App-Bound master key through the browser's own elevation interface, decrypts the SQLite-stored cookies, passwords, and payment data with a Windows cryptographic provider, and writes the results to a local `output\<Browser>\<Profile>\` folder. It carries anti-debugging and anti-virtual-machine checks. Its output is local-only — the analysis confirmed neither binary contains any exfiltration endpoint.

The tool loads its own payload DLL via direct-syscall reflective process hollowing — bypassing user-mode API hooks by invoking the underlying system calls directly rather than through the monitored `Nt*`/`Kernel32` functions most endpoint tooling watches (the ATT&CK T1055.012 marker in Section 11). This class of loader is a well-documented, commodity red-team technique, not a bespoke evasion the operator engineered — its presence here is further evidence that the operation is assembling public offensive tradecraft rather than inventing its own.

The report deliberately does not reproduce the tool's injection or key-extraction internals; they are public in the upstream project, and the intel value here is *adoption*, not mechanism.

### 8.2 Operator modification — a fork, not pristine upstream

The recovered binaries are an operator-modified fork (HIGH confidence), not the pristine upstream tool. The executable's banner reads verbatim `" by @xaitax / @breakingupslow"` — co-crediting the EvilSoul-Engine developer — and the DLL embeds a copyright line referencing `t.me/evilsoulstealer` after the original author's credit. This is independent, code-level confirmation of the tool's tie to the EvilSoul (`@breakingupslow`) cluster, and it is one of the threads that separates the tooling-lineage actor from the kit operator (Section 9).

### 8.3 Why the provenance is intel-relevant

Two points for defenders:

1. Detection can borrow from the public tool. Because this is a known red-team tool with existing antivirus family-naming, defenders can leverage existing ChromElevator detection (YARA rules, the `%TEMP%\executor\` drop path, the network-service-termination behavior) rather than building from scratch. The companion detection file includes a YARA rule for the pair.
2. Adoption is the story, not novelty. The intel-relevant fact is that a commodity criminal operation reaches for a published offensive tool to solve its hardest technical problem (App-Bound Encryption) rather than developing its own. That pattern — criminal reuse of red-team tooling — is a recurring theme in the commodity-stealer ecosystem and is worth flagging as such, without overstating the operator's own capability.

**Build-specific detection anchors** (from the companion detection file): the fork carries distinctive banner strings, a `PAYLOAD_DLL` embedded resource, a named-pipe completion signal, and a fixed drop path (`%TEMP%\executor\`) and output layout (`output\<Browser>\<Profile>\`). These are stable across the fork and give a durable file-based signature for the ABE tool specifically.

---

## 9. Dynamic Analysis — The 299a2e7f Execution Behavior

> **Analyst note:** The `299a2e7f` Socket.IO variant ships as V8 bytecode, which static tooling cannot read as source. Its behavior and its decrypted JavaScript source were instead recovered from observed execution — the malware's own process memory exposed the source it was running, described in Section 6. This section presents what the sample did, in the order it did it.

The findings below come from observing `EvilSoul-299a2e7f.exe` run and from recovering its process memory during that run, which surfaced the decrypted JavaScript source in two overlapping regions of the process heap — the evidentiary basis for the capability findings in Section 6.

### 9.1 Chronological timeline

All times are relative to process launch (T+00:00).

| Time | Event |
|---|---|
| T+00:00 | The process launches (PID 6032). |
| T+00:00–00:05 | The process unpacks its embedded native modules to a temporary `pkg` cache — a DPAPI credential-decryption binding and a SQLite database binding, both later used for browser-credential theft. |
| T+00:05–00:10 | The process queries the Windows registry for the machine's cryptographic GUID (`REG QUERY … MachineGuid`) via a spawned `cmd.exe` child — the host-fingerprinting step behind the sample's machine-ID generation. |
| T+00:10+ | The sample opens a Socket.IO connection to `evilsoul[.]cc:80`. |
| T+00:10+ (on connect) | The sample attempts its Defender/firewall/antivirus-suppression routine, writes a Startup-folder persistence script, and creates the hidden VBS/LNK watchdog chain described in Section 5.5. |
| T+ (undetermined) | The sample attempts to resolve its exfiltration webhook by POSTing its license key to the relay endpoint (`198.1.195[.]210:3000/tralalero`, Section 6.2). |
| T+ full session | The sample settles into a connected, idle state with its full decrypted source resident in process memory. |

### 9.2 What execution confirmed, and what remains code-only

Confirmed by direct observation: the native-module unpack sequence, the machine-ID registry query, the live DNS resolution and connection attempt to `evilsoul[.]cc`, and the presence of the complete decrypted JavaScript source in process memory (the source that Section 6's capability findings are built on).

Not triggered during this execution — a run-specific gap, not a negative finding. No credential-theft file writes were observed on disk, and no exfiltration traffic reached the operator's real infrastructure. Both gaps have a specific explanation rather than indicating the sample lacks the capability: the operator's own server never issued the `browserData` command that triggers local credential harvesting, and the webhook-resolution relay was unreachable, so no exfiltration destination was ever obtained. The credential-theft and exfiltration capabilities analyzed in Section 6 are established from the recovered source code itself, not from watching them execute — this execution's contribution is confirming the sample's network behavior and recovering that source, not exercising every code path.

---

## 10. Threat Actor Assessment

> **Analyst note:** Attribution here operates on two separate levels that must not be collapsed: *who operates the recovered kit* and *whose builder it is*. These are two different Brazilian actors. This section states each at its assessed confidence, preserves the investigation's corrected conclusions, and flags the one equation that was investigated and retracted so it is not reintroduced.

Attribution rests on identity artifacts recovered directly from the kit's own configuration — the operator contact `t[.]me/n_3_xl` (a channel titled "[KAIDO]"), reciprocally confirmed by the `@govbrasil` support handle whose bio lists "Maldev @n_3_xl" — combined with pervasive `0xK41` / KAIDO brand ownership across configs, embeds, and web panel, and a Brazilian jurisdictional signal corroborated across hosting, country-code domain, and language. Because the operator is a self-branding commodity vendor, the attribution ceiling is a durable *persona*, not a legal identity: every operator domain was privacy-registered from day one, closing the WHOIS path to a real name.

### 10.1 The two actors

**Kit operator (primary attribution):** `n_3_xl` / `@govbrasil` / KAIDO (`0xK41`), Brazil — HIGH confidence (85%). This is the actor who runs the recovered EvilSoul-Engine deployment and the concurrently-live KAIDO product line. The attribution is *self-attested*: the kit's own configuration names `t[.]me/n_3_xl` as the operator contact, that channel is publicly titled "[KAIDO]," and the `@govbrasil` support handle's bio reads "Kaido" and lists "Maldev @n_3_xl." The KAIDO Quasar remote access trojan (documented in the companion report) resolves to the operator-branded `kaidoo[.]com[.]br` and a self-signed `TeamKAIDO` C2 certificate — directly-observed operator infrastructure, not just external reporting. Brazil is corroborated six ways: Portuguese code and logs; EvilSoul reported as a Brazilian Discord stealer; KAIDO reported as a Brazilian banking MaaS; the builder IP on a Brazilian host; prior `evilsoul[.]cc` São Paulo and Brazilian-bank payment references; and a Brazilian phone number in the possible-victim host record. Because a named actor is identified at HIGH confidence, no UTA designation is used or appropriate.

**Tooling lineage:** EvilSoul-Engine MaaS, developer `@breakingupslow`, Brazil — DEFINITE (lineage) / MODERATE (relationship). The recovered kit *is built on* the EvilSoul-Engine MaaS: the npm project is literally named `EvilSoul-Engine`, the build configuration carries `EVIL-DAY-*` license keys, and the kit sits on the same Brazilian hosting ecosystem as the reported EvilSoul cluster. That lineage is DEFINITE. The EvilSoul developer is a separate named actor, `@breakingupslow` (Telegram ID `5834325304`), documented in public reporting as the author of the EvilSoul Discord infostealer. `n_3_xl`'s relationship to that operation — customer, reseller, or affiliate — is assessed at MODERATE confidence: enough evidence to assert a licensing/affiliate tie, not enough to specify its exact commercial form.

### 10.2 The retracted equation — do not reintroduce

An earlier working hypothesis held that `0xK41` / `n_3_xl` is `@breakingupslow` (the same person). That equation is RETRACTED and assessed UNSUPPORTED / LOW (<50%). An Analysis of Competing Hypotheses resolved it as the losing hypothesis with five inconsistencies against zero for the "distinct individuals" model. The decisive disconfirming evidence:

1. **Negative OSINT.** The public reporting that documents `@breakingupslow` maps many of that developer's rebrands (Myth, Swift, Doenerium, and others) but never lists KAIDO, `0xK41`, or `n_3_xl` among them — a meaningful absence for a same-person hypothesis.
2. **Telegram account-age gap.** The KAIDO operator's Telegram account is roughly 2.7 billion numeric IDs newer than `@breakingupslow`'s, indicating a substantially later, distinct account registration.
3. **Consistent cluster separation.** Public OSINT consistently treats the two as separate operators — `@breakingupslow` as the EvilSoul developer, `n_3_xl` as the KAIDO maldev/seller.

The corrected model is two related-but-distinct Brazilian operators, connected by tooling lineage and a shared hosting ecosystem — not one operator running multiple brands. This report states the kit operator as `n_3_xl` / KAIDO and the tooling lineage as EvilSoul-Engine / `@breakingupslow`, and does not equate them. The real-name associations reported for the `@breakingupslow` cluster belong to that cluster and are not attributed to `n_3_xl`, who remains a persona-level attribution.

### 10.3 Confidence statement (project format)

**Threat actor (kit operator):** `n_3_xl` / `@govbrasil` / KAIDO (`0xK41` brand) — Brazilian commodity-malware operator.
**Confidence:** HIGH (85%)
- **Why:** Self-attested operator identity in the kit's own config (`t.me/n_3_xl` titled "[KAIDO]"), reciprocally confirmed by `@govbrasil` ("Maldev @n_3_xl"); pervasive `0xK41`/KAIDO brand ownership; directly-observed KAIDO C2 infrastructure; Brazil corroborated six ways.
- **Missing:** Real-world legal identity (all operator domains privacy-registered from day one).
- **Would increase confidence:** A non-WHOIS identity link (a leak, a reused operator email, a cross-platform handle-to-name correlation), or government/vendor-catalog attribution (none exists).

**Tooling lineage:** EvilSoul-Engine MaaS (developer `@breakingupslow` — a SEPARATE actor).
**Confidence:** DEFINITE (lineage) / MODERATE (`n_3_xl`'s relationship to the EvilSoul operation)
- **Why (lineage DEFINITE):** npm project literally named "EvilSoul-Engine"; EVIL-DAY license keys; shared Brazilian hosting ecosystem.
- **Why (relationship MODERATE):** rests on the EVIL-DAY key plus shared-infra adjacency plus one Tier-3 OSINT source never directly retrieved (persistent access block; triangulated via search index).

**Same-individual (`n_3_xl` == `@breakingupslow`):** RETRACTED — LOW / UNSUPPORTED (<50%)
- An Analysis of Competing Hypotheses resolves this as the losing hypothesis; it is not reintroduced.

**Motivation:** Financially-motivated commodity cybercrime (MaaS vendor) — HIGH
- Tiered "DAY" license keys, a sales subdomain, Telegram customer support, a customer control panel, and multi-host build delivery. No espionage, hacktivism, or targeted-attack indicators.

### 10.4 Source and confidence caveats

Two caveats bound the attribution honestly. First, the primary public source for the `@breakingupslow` / EvilSoul developer identity (a named-researcher OSINT publication, Tier 3) was never directly retrieved — every access path was blocked — and its content was triangulated through a search engine's indexed summary and corroborated by infrastructure overlap the investigation independently confirmed. Claims sourced from it are held at MODERATE and flagged accordingly. Second, the KAIDO brand's reported Brazilian banking/PIX-fraud objective is strongest for the KAIDO product line via external reporting; the specific EvilSoul-Engine builds analyzed here perform Discord, browser, and crypto theft, so the banking objective is not confirmed for these builds and is treated as external-brand context, not an observed capability of this report's subject.

---

## 11. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(DEFINITE)` (directly observed, no alternative explanation) or `(MODERATE)` (code evidence, not fully triggered in the observed runs). The Confidence Summary in Section 14 organizes findings by confidence level for the higher-level view. This table covers the EvilSoul-Engine stealer-builder ecosystem only; the KAIDO Quasar RAT techniques are mapped in the companion report.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Execution / T1059.007 | JavaScript | Core stealer logic (Node/V8, Electron main process) |
| Execution / T1059.001 | PowerShell | DPAPI decrypt, `Set-MpPreference`, mouse/BSOD/wallpaper via `Add-Type` |
| Execution / T1059.003 | Windows Command Shell | `cmd /c REG QUERY MachineGuid`; operator `cmd` events |
| Execution / T1059.005 | Visual Basic | `watcher.vbs`, `open.vbs`, `playMusic.vbs` persistence/control |
| Execution / T1106 | Native API | `NtRaiseHardError` (BSOD), `BlockInput` P/Invoke (`299a2e7f`) |
| Persistence / T1547.001 | Registry Run Keys / Startup Folder | HKCU/HKLM Run (`stealer.js`); `update.bat` + hidden `.lnk` (`299a2e7f`) |
| Persistence / T1053.005 | Scheduled Task | Hidden task masquerading as `Microsoft Corporation` (`stealer.js`) |
| Defense Evasion / T1562.001 | Disable or Modify Tools | Six-function suppression chain; `Set-MpPreference -DisableRealtimeMonitoring` (DEFINITE) |
| Defense Evasion / T1562.004 | Disable/Modify System Firewall | `netsh advfirewall set allprofiles state off` (`299a2e7f`) |
| Defense Evasion / T1036.004 | Masquerade Task or Service | `sc config` service masquerade; `Microsoft Corporation` hidden task |
| Defense Evasion / T1564.001 | Hidden Files and Directories | `attrib +h` on `updatesystem.cmd`, `watcher.vbs`, startup `.lnk` |
| Defense Evasion / T1027 | Obfuscated Files or Information | js-confuser → AES-GCM → XOR → base64; V8 bytecode (pkg-Node) |
| Defense Evasion / T1497 | Virtualization/Sandbox Evasion | ~230-UUID `WMIC csproduct UUID` blocklist + anti-emulation stall + Defender 7–10 min timing delay (`stealer.js`) |
| Defense Evasion / T1055.012 | Process Hollowing | xaitax ABE tool: direct-syscall reflective hollowing (DEFINITE) |
| Defense Evasion / T1620 | Reflective Code Loading | ABE tool ReflectiveLoader (no `LoadLibrary`) |
| Credential Access / T1555.003 | Web Browsers | DPAPI + SQLite across ~25 Chromium forks + Firefox; CDP + ABE-v20 bypass (DEFINITE) |
| Credential Access / T1539 | Steal Web Session Cookie | CDP `Network.getAllCookies` via remote-debug relaunch; Roblox/Instagram/TikTok/Spotify tokens (DEFINITE) |
| Credential Access / T1528 | Steal Application Access Token | Discord token from LevelDB; encrypted-token decrypt via DPAPI |
| Credential Access / T1552.001 | Credentials In Files | Exodus wallet session; Steam Web API key |
| Discovery / T1082 | System Information Discovery | `machineIdSync` → `REG QUERY MachineGuid`; host facts |
| Discovery / T1614 | System Location Discovery | `ip-api.com/json`, `myexternalip.com/raw` |
| Discovery / T1083 | File and Directory Discovery | `fetchFileList` over Desktop/Downloads/Documents/AppData/Temp (`299a2e7f`) |
| Collection / T1113 | Screen Capture | 30fps desktop capture streamed as Socket.IO `screenData` (`299a2e7f`) |
| Collection / T1005 | Data from Local System | Direct read of `Login Data`/`Web Data`/`History`/LevelDB |
| Command and Control / T1071.001 | Web Protocols | Socket.IO to `evilsoul[.]cc`; Discord webhook POST; `evilsoul[.]xyz` backend |
| Command and Control / T1571 | Non-Standard Port | `198.1.195[.]210:3000` relay; builder `:1331` |
| Command and Control / T1105 | Ingress Tool Transfer | Runtime fetch of ABE tools + Python decryptor from C2/GitHub |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | Discord webhook / `/send-*` panel endpoints |
| Exfiltration / T1567.002 | Exfiltration to Cloud Storage | gofile.io `uploadFile` loot archives (DEFINITE) |
| Impact / T1529 | System Shutdown/Reboot | `NtRaiseHardError` BSOD + shutdown/restart commands (`299a2e7f`) (MODERATE) |
| Impact / T1489 | Service Stop | `net stop WinDefend`; AV `taskkill` (`299a2e7f`) |
| Resource Development / T1588.002 | Obtain Capabilities: Tool | xaitax ChromElevator adopted as supply-chain ABE bypass (DEFINITE) |

**Coverage note.** The mapping is credential-access- and defense-evasion-heavy, exactly as expected for a stealer-builder MaaS: the operation's purpose is to harvest secrets (Credential Access, Collection) while removing the controls that would stop it (Defense Evasion) and shipping the results out (Exfiltration). The Impact techniques (BSOD, service stop) belong to the `299a2e7f` interactive tier and are what distinguishes it from a pure stealer.

---

## 12. Infrastructure Analysis

> **Analyst note:** This section maps the EvilSoul-Engine infrastructure cluster — the dead origin, the builder host, and the exfiltration backends. The takeaway for defenders is which indicators are durable (operator-provisioned, safe to block) versus which are shared services (block the specific value, not the provider). The infrastructure attribution is a corroborating layer, not the primary basis for naming the operator.

The infrastructure examined for this report is the EvilSoul-Engine / 0xK41 origin cluster — the recovered kit's own hosting footprint. Every IP examined across the wider investigation is attacker-controlled, not compromised, which means infrastructure characteristics (hosting choices, domain-registration timing, exfiltration-endpoint reuse) are legitimate identity indicators for this operator rather than incidental traits of a hijacked host.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/infra-cluster.svg" | relative_url }}" alt="Two-cluster infrastructure diagram. The left cluster is the dead EvilSoul-Engine origin (developer @breakingupslow) on MagnoHost Brazil and the RouterHosting factory origin at 144.172.103.98:8888. The right cluster is the live KAIDO kit (operator n_3_xl / @govbrasil) with kaidoo.com.br C2. A labelled link marks the DEFINITE tooling lineage between them, and a separate marker shows the same-operator equation retracted to LOW confidence.">
  <figcaption><em>Figure 7: The two-cluster, two-operator infrastructure model. The dead EvilSoul-Engine origin cluster (left — developer <code>@breakingupslow</code>, the recovered "factory" at <code>144.172.103[.]98:8888</code> plus the MagnoHost/Brazil exfiltration backends) is joined to the concurrently-live KAIDO kit cluster (right — operator <code>n_3_xl</code> / <code>@govbrasil</code>, <code>kaidoo[.]com[.]br</code> C2) by a tooling-lineage link, not a shared-operator link. The lineage (KAIDO's toolkit is built on the EvilSoul-Engine MaaS) is DEFINITE; the earlier "same person" equation is shown RETRACTED / LOW — these are two separate Brazilian operators (Section 10). The diagram makes visible why killing the dead origin does not remove the threat: the operator cluster on the right is live and independent.</em></figcaption>
</figure>

### 12.1 The EvilSoul-Engine cluster (dead origin)

| Indicator | Role | Provider / jurisdiction | Confidence |
|---|---|---|---|
| `144.172.103[.]98` | Open-directory origin (`:8888`), `x4m1k[.]com` A-record target | RouterHosting (US) — **DEAD** | HIGH |
| `198.1.195[.]207` | EvilSoul builder default panel target | MagnoHost (Brazil) | HIGH |
| `198.1.195[.]210` | EvilSoul relay (`:3000/tralalero` webhook resolution) | MagnoHost (Brazil), same /24 | HIGH |
| `198.89.99[.]163` | Historical `evilsoul1337[.]xyz` host | MagnoHost (Brazil) | MODERATE |
| `x4m1k[.]com` (+ subdomains) | "0xK41 Panel" control plane | Cloudflare NS, origin exposed | HIGH |
| `evilsoul[.]cc` | Socket.IO C2 for `299a2e7f` | shared `indie`+`rex` Cloudflare account | DEFINITE (role) |
| `evilsoul[.]xyz` | Maploot/Tinarox primary backend | operator backend | DEFINITE (role) |
| `evilsoul1337[.]xyz` | "EvilSoul Panel" (historical) | shared Cloudflare account with `evilsoul.cc` | MODERATE |

Cluster cohesion is **STRONG**. Three independent shared elements bind this cluster: the Brazilian MagnoHost `/24` co-location (`.207`/`.210`/`.163`), a shared Cloudflare account tying `evilsoul[.]cc` and `evilsoul1337[.]xyz` (the same `indie`+`rex` nameserver pair), and — the strongest single technical fact — the shared exfiltration infrastructure across the independently-analyzed Maploot and Tinarox builds (identical Discord webhook IDs, Steam API key, and ngrok subdomain, Section 7). That last element is about as strong a same-operator signal as passive evidence provides.

The Brazilian hosting block's specific autonomous-system number is reported inconsistently across sources (one enrichment source records AS210554, another AS270764). Both agree the block is Brazilian and both resolve, via reverse DNS, to the provider MagnoHost (`*.magnohost.com.br`). This report cites the corroborated fact — MagnoHost, Brazil — and flags the specific ASN number as sourced-with-variance rather than asserting one.

### 12.2 Durable versus shared-service indicators

Not every indicator is equally safe to block. The distinction matters operationally.

**Durable, operator-provisioned (safe to block/monitor):**
- The `evilsoul[.]cc`, `evilsoul[.]xyz`, `evilsoul1337[.]xyz`, and `x4m1k[.]com` domains.
- The relay endpoint `198.1.195[.]210:3000/tralalero` — a fixed point the operator cannot rotate without rebuilding the `299a2e7f` tier.
- The specific Discord webhook IDs (`1391195207508295750`, `1401355074235793458`).
- The specific ngrok subdomain (`acf02ac96211.ngrok-free[.]app`) — operator-provisioned and, notably, unrotated across the Maploot/Tinarox builds.

**Shared services (block the specific value, not the provider):**
- gofile.io — a legitimate file host; the operation uses `store8.gofile[.]io/uploadFile`. Do not block gofile broadly; alert on the specific upload pattern in context.
- ngrok — the service is legitimate; only the specific subdomain token is operator-unique.
- Discord — the platform is legitimate; only the specific webhook IDs are indicators.
- GitHub — the `sqlban` account that hosted the ABE tools is now taken down (404).

### 12.3 Origin exposed despite Cloudflare

The operator's `x4m1k[.]com` panel domain uses Cloudflare nameservers but does not proxy its traffic through Cloudflare's CDN — the A-record resolves directly to the origin IP (`144.172.103[.]98`). This is an operational-security gap: the appearance of CDN fronting without the protection. It is consistent with the operator profile throughout — effort concentrated on payload evasion, inconsistent discipline at the infrastructure layer.

Full infrastructure detail — including the two-cluster model, the certificate/JARM continuity establishing the origin as attacker-controlled, and the bulletproof-hosting assessment — is in the investigation record. The KAIDO Quasar RAT C2 cluster (the operator's separate, live infrastructure) is covered in the companion report.

### 12.4 A residual, unresolved lead

An unrelated co-tenant was observed on the historical `evilsoul1337[.]xyz` host (`198.89.99[.]163`): a Brazilian CPF/name-lookup ("doxing") API and a game-server panel. This is assessed at **MODERATE-LOW** confidence as likely-unrelated co-tenancy — a different customer sharing the same Brazilian VPS — rather than operator-controlled, and it is documented here as a residual lead, not attributed to the operator. Separately, a French-language domain pair (`choix-relay[.]com` / `choixrdv[.]com`) co-resident on other operator-adjacent infrastructure is held at MODERATE confidence as a possible but unconfirmed parallel operation. Neither changes the primary attribution.

---

## 13. Indicators of Compromise

The complete, validated, machine-readable indicator set is published as a separate feed:

**IOC feed:** [`/ioc-feeds/evilsoul-engine-stealer-maas-iocs.json`](/ioc-feeds/evilsoul-engine-stealer-maas-iocs.json)

The feed is formatted for direct ingestion into SIEM and EDR tooling (no defanging in the JSON; credential-type indicators such as bot and webhook tokens are truncated to first-8 + last-4 per the project's secrets-handling rule). The report body does not duplicate the full indicator list — the counts and highest-value indicators below orient a reader; the feed is authoritative.

### 13.1 Indicator summary

| Category | Count (EvilSoul-Engine) | Notes |
|---|---|---|
| File hashes (SHA256) | 19 | Factory components, three built tiers, ABE tool pair, four unrecovered `static/*.exe` outputs |
| C2 / backend domains | 4 primary | `evilsoul[.]cc`, `evilsoul[.]xyz`, `evilsoul1337[.]xyz`, `x4m1k[.]com` |
| Infrastructure IPs | 3 (BR) + 1 (US, dead) | MagnoHost builder/relay + dead RouterHosting origin |
| Network endpoints / URLs | 4+ | Socket.IO handshake, `:3000/tralalero` relay, GitHub ABE-tool URLs |
| Discord webhook IDs | 2 | `1391195207508295750`, `1401355074235793458` |
| Host / behavioral IOCs | 12+ | Drop paths, registry keys, scheduled task, license keys, operator-signature constants |

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/evilsoul-engine-stealer-maas-144-172-103-98/vt-corpus-map.svg" | relative_url }}" alt="Sample corpus map. The dead factory at 144.172.103.98:8888 sits at the top; below it two product families branch out — EvilSoul stealer builds (Maploot, Tinarox, and the 299a2e7f pkg-Node variant) sharing one exfiltration backend, and KAIDO Quasar RAT builds (c7542e82, 385d20ca, 022944768) pointing at the live c2.kaidoo.com.br C2 — each sample annotated with its recovery method and key detection anchors.">
  <figcaption><em>Figure 8: The VirusTotal sample corpus mapped to the torn-down factory. Because the four native factory-output <code>static/*.exe</code> files were never recovered as binaries, VirusTotal samples fill the gap and show what the factory produced: the EvilSoul-Engine stealer builds (Maploot and Tinarox Electron twins plus the <code>299a2e7f</code> pkg-Node Socket.IO variant), which share one byte-for-byte exfiltration stack, and — for cross-campaign context — the operator's separate, live KAIDO Quasar-fork RAT builds. The map orients the reader to how the tiers relate and which are recovered versus inferred; per-indicator confidence and recommended <code>BLOCK</code>/<code>HUNT</code> actions live in the IOC feed. The RAT builds are the subject of the companion report, not this one.</em></figcaption>
</figure>

### 13.2 Highest-value indicators

For a defender triaging quickly, these are the discriminating indicators — chosen because they are durable across the factory's per-build repacking:

- **Operator-signature packer constant** — `see-you-in-the-hellwizard-1082@239$328927bA` (survives js-confuser; near-zero false-positive across all tiers).
- **`299a2e7f` args-file suffix** — `evilsoulblockkstarjkjaksghjhsjkahjskjak81929ijsahsjkj` (near-zero false-positive; unique to the Socket.IO tier).
- **Relay endpoint** — `198.1.195[.]210:3000/tralalero` (fixed webhook-resolution point).
- **Backend domains** — `evilsoul[.]cc` (Socket.IO C2), `evilsoul[.]xyz` (Maploot/Tinarox backend).
- **ABE-tool drop path** — `%TEMP%\executor\chromelevator.exe` and `chrome_decrypt.dll`.
- **Shared Steam API key** — `440D7F4D810EF9298D25EDDF37C1F902` (byte-identical across Maploot/Tinarox).

**Reproduction detail retained:** the SHA256 for the `299a2e7f` Socket.IO WebPanel tier is `299a2e7fa8a69c495ec19fecf55d93bb766addaa78e89a4e1ad78a9cea59b31c`; for Maploot, `763303b69ad589bef248b66d1db93d5e567d9d60f95511806289289ff42a548e`; for Tinarox, `fe55908030318879f08b185b9c5b6e6f9d6f691154c361d60cce80162d844212`. The full set, with per-indicator confidence and recommended action (`BLOCK` / `HUNT`), is in the feed.

A durability caveat, repeated because it governs how these are used: because every EvilSoul-Engine customer build is uniquely repacked, the file hashes have **LOW** durability against *new* builds — they catch the specific samples analyzed, not the next customer's payload. Treat the string/behavioral anchors and the network indicators as the primary detection layer; treat the hashes as a confirming layer for known samples.

---

## 14. Detection and Response Guidance

The full detection content — YARA rules, Sigma rules, and Suricata signatures — is published as a separate file:

**Detection rules:** [`/hunting-detections/evilsoul-engine-stealer-maas-detections/`](/hunting-detections/evilsoul-engine-stealer-maas-detections/)

That file provides 5 YARA rules (targeting the operator-signature packer constant, the built-tier anchors, and the ABE tool pair), 6 Sigma rules (targeting the CDP cookie-theft relaunch, the process-token-impersonation decryptor, the Defender-suppression chain, and the Microsoft-masquerade scheduled task), and 6 Suricata signatures (Socket.IO handshake, relay endpoint, Discord webhook exfiltration). This section explains *what to hunt and why* at the analytical level; the rule syntax lives in the detection file.

### 14.1 The infection lifecycle

The stages below trace a typical EvilSoul-Engine built payload from delivery through exfiltration. Each stage carries the highest-value detection signal for that point in the lifecycle.

#### Stage 1 — Delivery and execution

> **Analyst note:** This is where the payload lands and starts running — typically as an Electron game installer (Maploot/Tinarox) or a packed Node executable delivered through Discord lures or cracked-software bait. There is no exploit here; the victim runs the file. Detection at this stage is weak because the payload is uniquely packed, so the strongest early signal is the file itself matching a durable string anchor if it is scanned before execution.

Delivery is social-engineering-driven — a game download, a cracked application, a Discord attachment. The built payload executes as a Node/Electron process or an MSI dropper that stages an Electron payload. The durable detection here is a **YARA scan of the staged file** for the operator-signature packer constant, which survives the js-confuser layer because it lives in the loader. Because every build is repacked, pre-execution file scanning is a confirming layer, not a reliable gate — the behavioral stages below are where detection is strongest.

#### Stage 2 — Anti-analysis and defense suppression

> **Analyst note:** Before doing anything noisy, the payload checks whether it is being watched (sandbox and analysis-VM checks) and, in some tiers, disables the host's defenses outright — turning off Microsoft Defender, the firewall, and installed antivirus. This is the single best centralized-log detection opportunity in the whole lifecycle, because the disabling commands are logged even after the defenses are gone.

Two behaviors define this stage. First, the hardware-UUID and username checks against a sandbox blocklist (a clean exit on a match). Second, and far more detectable, the **Defender-suppression chain**: a whole-drive Defender exclusion (`Add-MpPreference -ExclusionPath 'C:\'`), real-time monitoring off (`Set-MpPreference -DisableRealtimeMonitoring $true`), firewall off (`netsh advfirewall set allprofiles state off`), and antivirus process termination. These land in **PowerShell script-block logging (Windows Event ID 4104)** regardless of the endpoint agent's health, making this the highest-signal, lowest-false-positive hunt in the report. The `stealer.js` timing evasion (a 7-10 minute sleep before noisy operations) sits at this stage too — detection should target the noisy operations that follow the sleep, not the sleep itself.

#### Stage 3 — Credential access (the objective)

> **Analyst note:** This is what the malware is for — harvesting Discord accounts, browser passwords and cookies, crypto wallets, and gaming accounts, and defeating Chrome's App-Bound Encryption to reach the cookies. Two behaviors here are unusually clean detection signals that hold regardless of how the payload was packed, because they involve spawning other processes in distinctive ways.

The two anchor behaviors, both build-independent:

- **CDP browser-relaunch cookie theft** — a browser binary spawned with `--remote-debugging-port`, `--headless`, and `--user-data-dir` (pointing at the real profile) by a non-browser, non-developer parent. This maps to Sysmon process-creation (Event ID 1) and network (Event ID 3) telemetry. It is the highest-value credential-access hunt because the parent-child and command-line combination is distinctive and does not vary between builds.
- **Process-token-impersonation decryptor** — a Python process reading a script from standard input (`python -u -`), enabling the debug privilege, and opening a handle to `lsass.exe`. This maps to Sysmon process-creation (Event ID 1) plus process-access (Event ID 10). Because the script never touches disk, only the process-behavior chain catches it.

Discord account theft produces a burst of `discord.com/api/v9/` enrichment requests from a non-browser process; browser theft produces direct reads of `Login Data`, `Cookies`, `Web Data`, and LevelDB stores (Sysmon Event ID 11 / file-access telemetry).

#### Stage 4 — Persistence

> **Analyst note:** The payload plants mechanisms to survive reboot — registry keys, Startup scripts, and a scheduled task disguised as a legitimate Microsoft component. The disguise is also the detection anchor: a runtime-created task claiming to be Microsoft is a contradiction, because real Microsoft tasks are installed by the operating system, not created on the fly by a user process.

Persistence is redundant (Section 5.5). The standout detection is the hidden scheduled task authored as `Microsoft Corporation` — a scheduled-task creation event (Windows Event ID 4698) with that author on a task written by a non-system process. Supporting anchors: hidden `.lnk` and `.cmd` files in `%TEMP%` and Startup written by a non-system process, and the `watcher.vbs` watchdog chain in the `299a2e7f` tier.

#### Stage 5 — Command-and-control and exfiltration

> **Analyst note:** The harvested data leaves the host — over hardcoded Discord webhooks, cloud file-host uploads, or a persistent real-time channel in the interactive tier. Because the destinations are hardcoded, this stage produces the strongest network signatures, and the interactive tier's persistent channel is itself a distinctive protocol pattern.

The network signatures are strong because they are fixed: a **Socket.IO handshake** (`/socket.io/?EIO=4&transport=polling`) to `evilsoul[.]cc`; an HTTP POST to the relay `198.1.195[.]210:3000/tralalero`; **Discord webhook POSTs** to the two known IDs; gofile uploads (`api.gofile.io/servers` → `*.gofile.io/uploadFile`); the ngrok tunnel (`acf02ac96211.ngrok-free[.]app`); and the `evilsoul[.]xyz` backend `/send-*` and `/download` endpoints. The relay endpoint is the most valuable of these for the `299a2e7f` tier because the operator cannot rotate it without rebuilding.

### 14.2 Detection priority ranking

For teams deciding where to invest first, the report's five highest-value, most-durable hunts, in order:

1. **CDP browser-relaunch cookie theft** — browser spawned with `--remote-debugging-port` + `--headless` + `--user-data-dir` by a non-browser parent (Sysmon EID 1/3). Build-independent; catches all tiers.
2. **Defender/AV suppression burst** — `Add-MpPreference -ExclusionPath 'C:\'` and `Set-MpPreference -DisableRealtimeMonitoring $true` (Windows EID 4104). Highest signal, lowest false-positive.
3. **Process-token-impersonation decryptor** — `python -u -` from stdin + debug privilege + `lsass.exe` handle (Sysmon EID 1 + 10).
4. **Microsoft-masquerade hidden scheduled task** — task authored as `Microsoft Corporation`, hidden, created by a non-system process (Windows EID 4698).
5. **Operator-signature and relay network anchors** — the packer XOR constant in staged files (YARA); the `198.1.195[.]210:3000/tralalero` relay and `evilsoul[.]cc` Socket.IO handshake (network).

The detection file's 6 Sigma rules and 6 Suricata signatures back these five priorities directly: Sigma covers hunts 2–4 (Defender/AV suppression, the LSASS-impersonation decryptor, and the Microsoft-masquerade scheduled task), and Suricata covers hunt 5's network anchors (the relay endpoint and the Socket.IO handshake).

### 14.3 Confidence Summary

| Confidence | Findings |
|---|---|
| **DEFINITE** | EvilSoul-Engine tooling lineage; CDP cookie theft / ABE-v20 bypass; Discord/browser/crypto credential theft; Defender-suppression chain; gofile cloud exfiltration; xaitax ABE-tool adoption; Maploot/Tinarox shared exfiltration stack (same operator) |
| **HIGH** | Kit operator = `n_3_xl` / KAIDO (85%); process-token-impersonation decryptor as an advanced ABE-v20 bypass; Defender behavioral-window timing evasion; Microsoft-masquerade scheduled task; `299a2e7f` as a distinct build of the same family; four redundant persistence methods |
| **MODERATE** | `n_3_xl`'s exact relationship to the EvilSoul operation (customer/reseller/affiliate); `299a2e7f` BSOD/shutdown impact commands; residual `choix-relay` parallel-line hypothesis; historical `evilsoul1337.xyz` host attribution |
| **LOW / RETRACTED** | `n_3_xl` == `@breakingupslow` (RETRACTED, UNSUPPORTED); `hwids.txt` as a 2,229-victim count (rejected reading) |

---

## 15. Response Orientation

This is a brief orientation on *what to address*, not a step-by-step incident-response procedure. Teams with an active-response need should engage their own incident-response function or a dedicated playbook.

**Detection priorities (hunt these first):**
- The CDP browser-relaunch cookie-theft pattern (`--remote-debugging-port` + `--headless` + `--user-data-dir` from a non-browser parent) — the single most durable signal, catches every tier.
- The Defender-suppression burst (`Add-MpPreference -ExclusionPath 'C:\'`, `Set-MpPreference -DisableRealtimeMonitoring $true`) in script-block logs.
- The `evilsoul[.]cc` Socket.IO handshake and the `198.1.195[.]210:3000/tralalero` relay in network egress.

**Persistence targets (look for and remove):**
- Hidden scheduled task authored as `Microsoft Corporation`.
- Registry Run keys (`HKCU`/`HKLM`), the whole-drive Defender exclusion, and the `DisableTaskMgr` policy value.
- `%APPDATA%\...\Startup\update.bat` plus a hidden random `.lnk`; `%TEMP%\updatesystem.cmd`, `%TEMP%\watcher.vbs`, and `%TEMP%\executor\chromelevator.exe` + `chrome_decrypt.dll`.

**Containment categories (action labels):**
- Block or monitor the EvilSoul exfiltration domains and relay (`evilsoul[.]cc`, `evilsoul[.]xyz`, `198.1.195[.]210:3000`).
- Alert on the two known Discord webhook IDs and the operator's gofile/ngrok delivery values.
- Isolate hosts exhibiting CDP cookie-theft or Defender-suppression behavior.
- Reset exposed Discord, browser, cryptocurrency, and gaming credentials on affected accounts — and treat stolen session cookies as live, invalidating sessions where possible.

---

## 16. Coverage Gaps and Open Questions

This section lists what the investigation was unable to resolve, so a reader can weigh confidence accurately and knows what further evidence would close each gap.

The main public OSINT article on the EvilSoul developer (decodecybercrime.com, "Evil Soul: Unmasking a Brazilian Discord Infostealer and Its Operators") returned a Cloudflare access block on every retrieval attempt during the investigation. Its content was triangulated through a search engine's indexed summary rather than read directly, and every claim sourced from it is held at MODERATE rather than the higher confidence direct retrieval would support (Section 10.4). **What would close this gap:** direct retrieval of the article, or an alternate archive/mirror of its content.

The 2,229-entry `hwids.txt` file remains unresolved. The panel route code that would explain what this file represents is compiled to V8 bytecode; decompiling it was not cost-effective for the intelligence value it would return. The file is not treated as a victim count anywhere in this report (Section 3) — the most plausible reading is imported license or blocklist data, at LOW confidence. **What would close this gap:** decompilation of the panel's V8 bytecode, or operator-side confirmation of the file's purpose.

The `@breakingupslow` fork attribution has not been checked against source-controlled commit history. Section 8.2 attributes the recovered ChromElevator fork to `@breakingupslow` on the strength of banner-string and copyright-comment evidence (code-level, HIGH confidence) — but the upstream xaitax repository's commit history was not diffed against the recovered binary to confirm which specific upstream commit was forked or whether `@breakingupslow` contributed changes upstream versus maintaining a private fork. **What would close this gap:** a binary-to-commit diff against `github.com/xaitax/Chrome-App-Bound-Encryption-Decryption`.

The four factory-output executables are hash-only. The `static/*.exe` files referenced throughout this report (Section 4, Section 13) were never recovered as full binaries — only their SHA256 hashes survive in the investigation's file index. They are retained in the IOC feed as unconfirmed-content hashes and are not analyzed for capability; nothing in this report describes their behavior beyond "presumed customer builds of the same factory." **What would close this gap:** recovery of the actual files, whether from the dead origin server, a file-hosting mirror, or a VirusTotal submission matching one of the four hashes.

---

## 17. Assumptions, Caveats, and Data Gaps

Section 16 details the four open research questions; this section lists the remaining scope boundaries and interpretive calls that bound how this report's findings should be read.

- **Dual scope.** The technical subject of this report is a *torn-down staging instance*; the actor assessment describes an *active operator* (the KAIDO product line is live — see the companion report). Both are true and are stated as such throughout.
- **Two distinct actors.** The kit operator (`n_3_xl` / KAIDO, HIGH) and the tooling-lineage developer (`@breakingupslow` / EvilSoul-Engine, DEFINITE lineage) are separate people. The same-person equation was investigated and RETRACTED; it is not reintroduced here.
- **No confirmed victims** — one operator test box, one unresolved possible-victim host (personal data redacted).
- **Banking/PIX-fraud objective** is external-brand context for the KAIDO line, not a confirmed capability of the EvilSoul-Engine builds analyzed here.

---

*Report B of a two-report campaign. See the companion report on the KAIDO Quasar-fork RAT (same operator, concurrently-live product line at `144.172.109[.]203`) for the operator's remote access trojan.*

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
