---
title: "KAIDO: A Brazilian Quasar-Fork RAT with Hidden-Desktop Session Hijacking"
date: '2026-07-03'
layout: post
permalink: /reports/kaido-quasar-rat-144-172-109-203/
hide: true
unlisted: true
category: "Remote Access Trojan"
description: "KAIDO is a rebranded 64-bit Quasar RAT fork operated by a named Brazilian actor. Its Hidden-VNC module clones a victim's browser profile to drive their live, authenticated session on an invisible desktop — defeating device-trust and most 2FA. The C2 was live with May-2026 samples."
detection_page: /hunting-detections/kaido-quasar-rat-detections/
ioc_feed: /ioc-feeds/kaido-quasar-rat-iocs.json
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
  - "144.172.109[.]203"
  - "kaidoo[.]com[.]br"
  - "c2.kaidoo[.]com[.]br"
  - "c7542e8265f70d6c1dbf2e3cf6e81a90198cd157d3d6693c6d2a8a49d99a5b8d"
---

**Campaign Identifier:** KAIDO-Quasar-RAT-144.172.109.203<br>
**Last Updated:** July 3, 2026<br>
**Threat Level:** HIGH

> **Risk vs. Campaign Threat Level:** The KAIDO RAT analyzed in this report scores **7.2/10 (HIGH)** on capability. The overall campaign threat level is also rated **HIGH**: the command-and-control server was last confirmed live with fresh May-2026 samples, and the operator is active. If the C2 is confirmed permanently offline and no new samples surface, the threat level should be reassessed downward.

---

## 1. Executive Summary

**KAIDO is operated by a named, self-identified Brazilian commodity-malware actor — `n_3_xl` (Telegram `@govbrasil`), working under the KAIDO / `0xK41` brand — and its command-and-control server was live with fresh samples as recently as May 2026.** This report answers who runs the KAIDO Quasar-fork Remote Access Trojan (RAT), what it does to an infected host, and how defenders detect and respond to it. It is written from the perspective of a third-party threat-intelligence provider: it describes capability and impact at defensive altitude and does not reproduce the offensive implementation.

KAIDO is a rebranded 64-bit fork of the open-source Quasar RAT. Beyond ordinary remote control, it carries a Hidden-VNC (HVNC) module — a hidden-desktop, browser-session-hijack rig. On operator command, KAIDO clones the victim's entire browser profile and relaunches the browser, already logged in, on an invisible desktop the victim never sees. The operator then drives that live, authenticated session directly. This is hands-on-keyboard fraud, not passive credential theft: the bank or exchange sees the victim's genuine device and a genuine live session, which defeats device-trust checks and most two-factor authentication. A dependency stack bundled inside the sample adds microphone and webcam capture on top of the screen-capture HVNC path, making KAIDO a full-spectrum surveillance RAT — screen, audio, webcam, and keystroke.

This report was written to fill a documented gap: there was **no public technical documentation of the KAIDO Quasar-fork RAT** — its HVNC browser-session-hijack primitive, its full-spectrum surveillance dependency stack, its command-and-control gating, or its Mark-of-the-Web self-deletion behavior — and no public attribution tying the product line to the `n_3_xl` / `@govbrasil` / KAIDO (`0xK41`) operator. A search of a commercial threat-actor catalog returned zero entries for "KAIDO," "Quasar-fork," or the operator handles, consistent with a small-scale commodity operator running below the threshold of named-actor tracking rather than an absence of the threat.

The analysis substrate is unusually strong for a commodity RAT. The operator's server-side toolkit was recovered in full from a torn-down open directory, and three KAIDO Quasar RAT builds (all roughly 1 MB 64-bit .NET assemblies masquerading as `svchost.exe`) were reverse-engineered statically and detonated in a contained lab. Static decompilation recovered the AES-256-GCM-encrypted configuration in full — command-and-control endpoints, the Quasar authentication key, the pinned server certificate, and the crypto parameters all decrypted cleanly to plaintext. A contained detonation confirmed the RAT's beacon behavior, its Mark-of-the-Web self-deletion, and a defensive-analysis complication described below.

**The single most important operational finding is that KAIDO withholds its behavior until it reaches its operator.** In the contained lab run, the RAT executed for 606 seconds and did nothing observable — no files dropped, no persistence written, no child processes, no HVNC. All of that behavior is gated behind a successful command-and-control handshake, so the sample looks near-benign to commodity sandboxes that do not simulate the Quasar protocol. Defenders should treat a "clean" automated-sandbox verdict on a suspected KAIDO sample as unreliable and pivot to the static and network indicators in this report.

**Two facts hold simultaneously, and both matter.** The recovered open directory was a genuine, torn-down staging instance — all of its recovered channels are dead. But the operator's separate, longer-lived KAIDO Quasar RAT command-and-control server at `c2.kaidoo[.]com[.]br` → `144.172.109[.]203` was **last confirmed live** carrying three downloadable samples first seen in May 2026, on infrastructure the operator has held since approximately August 2025 (about ten months of continuity). Killing the dead staging box does not remove this threat. There are **no confirmed victims** in the recovered logs — one operator test box and one unresolved possible-victim host — so this report documents a live capability and a live operator, not a confirmed victim population.

KAIDO is one of two product lines run by this operator. The other is the **EvilSoul-Engine stealer-builder**, a separate Node.js/Electron information-stealer factory hosted at `144.172.103[.]98` and built on tooling developed by a distinct Brazilian actor (`@breakingupslow`). That product line is covered in a companion report and is out of scope here; this report is confined to the KAIDO Quasar-fork RAT.

### Key Takeaways

- **Named, active operator.** The KAIDO RAT is attributed at **HIGH confidence** to the self-identified Brazilian actor `n_3_xl` / `@govbrasil` / KAIDO (`0xK41`), based on identity artifacts recovered from the kit's own configuration. Because a specific actor is named at HIGH confidence, no unattributed-actor (UTA) designation is used.
- **Hidden-desktop session hijacking is the hero capability.** KAIDO's HVNC clones the victim's browser profile and drives their live authenticated session on an invisible desktop, defeating device-trust and most 2FA — the operationally significant primitive that separates KAIDO from a stock RAT.
- **Full-spectrum surveillance.** A bundled dependency stack confirms screen capture (DXGI/Direct3D) and indicates microphone (NAudio) and webcam (AForge/DirectShow) capture plus global input hooking — a complete surveillance suite, not just data theft. Screen/HVNC capability is directly evidenced; audio and webcam are inferred from the dependency stack at MODERATE confidence.
- **Behavior is command-and-control-gated.** The RAT does nothing observable until it reaches its operator, so commodity sandbox verdicts are unreliable. Detection must lean on static anchors and network signatures.
- **The C2 was live; detection should target behavior, not hashes.** Each build is separately packed (a signature scan of the full recovered toolkit produced zero hits), so hash blocking is low-value. Prioritize the RAT's raw-TCP Quasar beacon, its operator-branded TLS certificate, its Mark-of-the-Web self-deletion, and its HVNC named-pipe transport.

---

## 2. Risk Assessment

KAIDO earns a **HIGH** rating because it combines full remote control with a session-hijack primitive that defeats controls most organizations rely on as a backstop. The risk here is not that KAIDO steals a password — it is that KAIDO lets an operator sit inside the victim's own authenticated banking or exchange session, on the victim's own device, in real time. Controls that assume "the attacker has the password but not the device" do not help against that.

**Overall risk score: 7.2 / 10 (HIGH).** The score is a weighted average of six dimensions:

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 16%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>9/10</td><td>Wholesale browser-profile cloning across Chrome, Edge, Brave, Opera, Opera GX, and Firefox gives live-session access to credentials, cookies, and autofills; full-spectrum surveillance (screen, audio, webcam, keystroke) captures anything the user sees, says, or types.</td></tr>
<tr><td>System Compromise</td><td>9/10</td><td>A full-featured Quasar-lineage RAT with an operator surface that places a full shell (<code>explorer.exe</code>), a command prompt, and PowerShell on a hidden desktop — arbitrary code execution and complete interactive control.</td></tr>
<tr><td>Persistence Difficulty</td><td>5/10</td><td>Install routines for a registry Run key, a scheduled task, and a Windows service were recovered from decompiled code, but none executed in the contained run (behavior is C2-gated). These are standard, removable mechanisms once identified — not firmware or bootkit-grade.</td></tr>
<tr><td>Evasion Capability</td><td>8/10</td><td>Command-and-control-gated staging renders commodity sandboxes near-blind; Mark-of-the-Web self-deletion suppresses SmartScreen re-checks; sleep-obfuscation anti-analysis is present in the binary.</td></tr>
<tr><td>Lateral Movement</td><td>3/10</td><td>No worm or self-propagation capability observed. Distribution is buyer-driven social engineering; the RAT is remote-control-oriented, not self-spreading. Ecosystem-level spread risk (uniquely packed customer builds) exists but is not host-to-host lateral movement.</td></tr>
<tr><td>Detection Challenge</td><td>8/10</td><td>AES-256-GCM configuration encryption, per-build packing (zero signature hits across the recovered toolkit), and rotated C2 certificates across builds mean hash- and signature-based detection is low-yield; behavioral and network detection carries the load.</td></tr>
</tbody>
</table>

**What this means for a defender.** KAIDO is a consumer-focused RAT distributed through Discord lures and cracked-software bait, so the exposed population is individual Windows endpoints rather than enterprise fleets. But the capability is enterprise-relevant wherever those endpoints touch corporate accounts: a contractor, a remote employee on a personal machine, or a bring-your-own-device host that authenticates to a corporate SaaS platform becomes a live-session pivot the moment KAIDO's HVNC activates. The 2FA and device-trust controls that would normally contain a stolen password do not contain a hijacked live session.

**Current status.** The recovered staging infrastructure is dead. The KAIDO Quasar RAT command-and-control server (`144.172.109[.]203`) was **last confirmed live** on 2026-06-27 with three downloadable May-2026 samples and has not been re-verified since — treat it as "last confirmed active," not "confirmed active today." The operator rotated its command-and-control host within the same US provider rather than switching providers under pressure, which is consistent with an operator not under takedown stress.

---

## 3. Technical Classification

> **Analyst note:** This section states what KAIDO is at a technical level — its family lineage, runtime, and install identity — and what confidence each classification carries. It is written to be readable without a reverse-engineering background; the deep mechanics follow in later sections.

KAIDO is a **rebranded 64-bit fork of the open-source Quasar RAT**, internally versioned "Kaido v2.4.5." The family identification is **HIGH confidence** and rests on a structural fingerprint that survives the operator's obfuscation: the sample's internal namespace tree, `Kaido.Common.Messages.*`, maps one-to-one onto Quasar RAT's own message-class structure. No literal `Quasar` string survives in the binary — the rebrand was deliberate — but the class architecture is unmistakably Quasar's. Quasar is a long-documented, publicly available .NET RAT, and forks of it are a common commodity pattern; what makes KAIDO distinct is its HVNC extension, its full-spectrum surveillance stack, and its Brazilian-operator branding, none of which appear in any public malware-family catalog.

| Attribute | Assessment |
|---|---|
| Family | KAIDO — rebranded 64-bit **Quasar RAT fork** ("Kaido" v2.4.5) |
| Family confidence | **HIGH** — namespace tree `Kaido.Common.Messages.*` maps 1:1 onto Quasar's; no literal `Quasar` string survives |
| Type | Remote Access Trojan with Hidden-VNC (HVNC) + full-spectrum surveillance |
| Platform / runtime | .NET Framework 4.8; dependencies bundled as compressed resources and unpacked to disk on load |
| Install identity | Drops as `svchost.exe` in a subdirectory of `%AppData%`, logs to a `Logs\` subfolder |
| Wire encryption | AES-256-GCM; PBKDF2-HMAC-SHA256, 100,000 iterations; pinned self-signed server certificate |
| Sophistication | Intermediate, with advanced spikes at the HVNC and screen-capture modules |
| First seen | Approximately 2026-05-21 (predates the June open-directory capture) |
| Status | **Live** — command-and-control server active with fresh samples as of May 2026 |

**Samples analyzed.** Three KAIDO builds were reverse-engineered, all approximately 1 MB 64-bit .NET assemblies masquerading as `svchost.exe`. They share a structural hash and sit in a 20-deep cluster of similar files on VirusTotal — evidence of a single operator build lineage from one source tree.

| SHA256 (abbreviated) | Build tag | Decrypted C2 | VirusTotal detections |
|---|---|---|---|
| `c7542e82…a5b8d` | `breach` | `kaidoo[.]com[.]br:4782` | 53 / 72 |
| `385d20ca…1e254` | `kaido-webdav` | `c2.kaidoo[.]com[.]br:443` | 57 / 72 |
| `02294476…aa39fa` | `kaido-webdav` | `c2.kaidoo[.]com[.]br:443` | 33 / 72 |

**Sophistication rationale.** KAIDO's author invests effort selectively — the HVNC and DXGI screen-capture modules are genuinely advanced, while the surrounding RAT is a stock Quasar fork with commodity anti-analysis. This capability-versus-effort gap, combined with single-language Portuguese artifacts and ego-branding throughout, points to an individual commodity operator rather than a structured team. The full-spectrum surveillance capability, the deliberate rebrand, and the browser-session-hijack primitive are where the operator spent real development time.

**What this means.** "Quasar fork" tells a defender two useful things immediately. First, the baseline RAT behavior is well-understood — remote shell, file transfer, keylogging, and screen capture are all standard Quasar features, and existing Quasar detection logic partially applies. Second, the operator went out of their way to strip the `Quasar` name and rebrand, which is why generic Quasar signatures alone will miss this build — the report's KAIDO-specific anchors (namespace, HVNC strings, operator certificate) are what close that gap.

---

## 4. Technical Capabilities Deep-Dive

### 4.1 Hidden-desktop session hijacking (HVNC) — the hero capability

> **Analyst note:** This is the capability that makes KAIDO dangerous beyond a normal RAT. HVNC ("Hidden Virtual Network Computing") lets an operator run and control programs on a second, invisible desktop that never appears on the victim's monitor. KAIDO uses it to hijack the victim's *already-logged-in* browser session. The subsection below describes what the capability does and why it defeats common defenses; it does not reproduce the offensive code.

KAIDO's HVNC module is a hidden-desktop browser-session-hijack rig. When the operator issues the command, KAIDO performs a four-step sequence that ends with the operator driving the victim's genuine, authenticated browser session while the victim sees nothing.

1. **Create a hidden desktop.** KAIDO creates or opens a second Windows desktop named `Default_runhost` and binds a worker thread to it — but never switches the physical display to it. Windows supports multiple desktops natively (the lock screen and the secure-attention sequence use this feature legitimately); KAIDO abuses it so that everything the operator does happens on a desktop the victim's monitor never shows. **The single asymmetry that distinguishes KAIDO's HVNC from legitimate remote-desktop or screen-share tooling is that it binds a thread to the hidden desktop but never surfaces it** — legitimate tools switch the display; KAIDO deliberately does not.
2. **Clone the victim's browser profile.** Rather than pulling out individual cookie or login files, KAIDO copies the victim's *entire* browser profile into a clone directory, using handle-duplication to read the browser's locked databases while the browser is still running. The clone map covers Chrome (64- and 32-bit), Edge, Brave, Opera, Opera GX, and Firefox.
3. **Relaunch the browser, already authenticated.** KAIDO launches the browser against the cloned profile on the hidden desktop. Because the profile carries the victim's live session state, the browser opens already logged in to whatever the victim was logged in to — bank, exchange, email, Discord.
4. **Capture and control the hidden desktop.** KAIDO captures the hidden desktop through a DXGI swap-chain hook (the modern GPU-accelerated capture path; the older screen-grab method renders black against hardware-accelerated Chromium) with a fallback compositor path, and replays the operator's mouse and keyboard input onto the hidden desktop. The operator surface placed on that desktop includes a full file-explorer shell, a command prompt, and PowerShell.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/kaido-quasar-rat-144-172-109-203/kaido-hvnc-browser-profile-clone.png" | relative_url }}" alt="Decompiled KAIDO HVNC routine logging 'Cloning browser profile from ... to ...' and '[BrowserClone] Using handle hijacking for locked files', copying a running browser's locked profile databases via handle duplication.">
  <figcaption><em>Figure 1: Evidence of the browser-profile cloning capability (Section 4.1, step 2). The recovered routine copies the victim's entire browser profile — including databases the running browser holds locked — by duplicating the browser's own file handles rather than reading individual credential files. The embedded status string <code>[BrowserClone] Using handle hijacking for locked files</code> is a durable static detection anchor for this KAIDO-specific capability.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/kaido-quasar-rat-144-172-109-203/kaido-hvnc-hidden-desktop-spawn.png" | relative_url }}" alt="Decompiled KAIDO StartChromeAsync routine that locates the Chrome executable, invokes CloneBrowserProfileAsync, and relaunches the browser against the cloned profile with reflective DLL injection.">
  <figcaption><em>Figure 2: Evidence of the authenticated-browser relaunch on the hidden desktop (Section 4.1, step 3). After cloning the profile, KAIDO relaunches the browser against that clone so it opens already logged in to whatever the victim was authenticated to. Because the session state carries over, the operator inherits a live, authenticated session — the primitive that defeats device-trust and most 2FA.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/kaido-quasar-rat-144-172-109-203/kaido-hvnc-reflective-injection.png" | relative_url }}" alt="Decompiled KAIDO code path performing reflective DLL injection into the relaunched browser process and logging 'Chrome started successfully with reflective DLL injection'.">
  <figcaption><em>Figure 3: Evidence of the capture-DLL delivery into the hijacked browser (Section 4.1, step 4). KAIDO reflectively injects its capture DLL into the relaunched browser process on the hidden desktop, giving the operator a controllable surface without dropping the payload to disk. This is the injection behavior mapped to ATT&CK T1055 (Process Injection); the exact runtime injection APIs remain unobserved because the module is command-and-control-gated.</em></figcaption>
</figure>

#### What this means

**Technical:** HVNC clones the victim's live browser profile and drives the authenticated session on a hidden desktop via a DXGI swap-chain capture hook.

**Simplified:** Imagine a burglar who does not pick your lock or steal your keys. Instead, while you are inside your house with the door open, they quietly walk in through a door you cannot see, sit at your desk, and use your already-open laptop — logged into your bank, in your house, on your device. From the bank's point of view, it is you, at home, on your own machine.

**Security impact:** This is the reason HVNC defeats controls that stop ordinary credential theft. Device-trust and risk-based authentication key off session continuity and device fingerprint — "is this the usual device, in the usual place, in a session that was already established?" With HVNC the answer is yes, because the operator *is* using the victim's device and the victim's already-established session. Two-factor authentication that was satisfied when the victim logged in stays satisfied; the operator never has to pass a second-factor challenge because they never start a new login. This is hands-on-keyboard fraud conducted from inside a trusted session.

**Detection strategy:** Because the behavior is command-and-control-gated, the highest-value host anchors are structural rather than behavioral: the HVNC frame-transport named pipe (`\\.\pipe\kaido_dxgi_<8 hex>`), the hidden-desktop literal `Default_runhost`, and the DXGI transport strings recovered from the binary. Full runtime behavioral detection of the desktop-switch API sequence requires triggering the module against a controlled command-and-control stub — see the companion detection file's Coverage Gaps.

**Why this ties to a banking-fraud objective.** HVNC that drives a victim's live banking session is the code-level primitive behind KAIDO's externally-reported Brazilian banking / instant-payment (PIX) fraud framing. That banking objective is **MODERATE confidence for the specific builds analyzed here** — the recovered code confirms the HVNC session-hijack primitive and generic credential access, but no banking-overlay or payment-clipper code was observed in these three samples. The banking angle is inferred from the fraud primitive plus external reporting on the KAIDO brand, not directly observed in this build.

### 4.2 Full-spectrum surveillance

> **Analyst note:** Beyond remote control, KAIDO bundles the building blocks of a complete surveillance suite. This subsection separates what was directly proven (screen capture) from what is inferred from the software libraries packed into the sample (audio and webcam), and labels the confidence of each so a defender can weigh them appropriately.

KAIDO ships with fourteen third-party helper libraries bundled inside the assembly and unpacked to disk when it loads. These libraries are themselves benign, off-the-shelf components — but their *presence together* reveals the capability the RAT was built to deliver. The stack maps cleanly onto the four channels of a surveillance suite.

| Library family | Capability revealed | Confidence |
|---|---|---|
| SharpDX (DXGI / Direct3D11 / Direct2D1) | GPU-accelerated screen capture — the HVNC capture path | **HIGH** (paired with the HVNC strings recovered from the binary) |
| NAudio (Core / Wasapi / WinMM) | Microphone / audio capture | **MODERATE** (dependency-based inference; not triggered in the contained run) |
| AForge (Video / Video.DirectShow) | Webcam / camera capture via DirectShow | **MODERATE** (dependency-based inference; not triggered in the contained run) |
| MouseKeyHook | Global keyboard and mouse input hooking — HVNC remote input and keylogging | **MODERATE** (dependency-based inference) |

**What this means.** The screen-capture channel is directly evidenced: the SharpDX/DXGI stack pairs with the HVNC capture strings recovered from the binary, so screen surveillance is HIGH confidence. Audio and webcam capture are **inferred from the dependency stack** — the sample bundles the exact libraries used to record a microphone (NAudio) and a webcam (AForge/DirectShow), but neither channel fired in the contained detonation because all such behavior is command-and-control-gated. The honest read is that KAIDO is *built to* record audio and webcam and carries the libraries to do it, assessed at MODERATE confidence, while screen capture and HVNC are directly confirmed. Taken together, a fully activated KAIDO implant can watch the screen, listen through the microphone, see through the webcam, and log every keystroke — a complete surveillance capability, not merely a data thief.

### 4.3 Command-and-control-gated staging — why sandboxes miss it

> **Analyst note:** This subsection explains the behavior that most affects day-to-day triage: KAIDO does nothing until it reaches its operator. Understanding this prevents a dangerous mistake — trusting a "clean" automated sandbox report on a real KAIDO sample.

In a contained detonation, the KAIDO sample ran for **606 seconds and produced no observable malicious behavior** — no files dropped, no persistence written, no child processes spawned, no HVNC activated, no credential access. Every one of those actions is withheld until the RAT completes a valid Quasar handshake with its command-and-control server. This is an execution-guardrail: the payload is conditioned on reaching a live operator.

**What this means.** A commodity automated sandbox that detonates KAIDO without simulating the Quasar protocol observes an almost-benign process — the contained run itself produced a clean-looking verdict (606 seconds, zero drops) despite the sample being fully malicious (DEFINITE, directly observed in this analysis). Defenders triaging a suspected KAIDO sample should not treat a quiet sandbox run as exoneration; they should pivot to the static file anchors (namespace, Costura asset, HVNC strings) and the network signatures (raw-TCP Quasar beacon, operator certificate) documented in this report, which do not depend on the payload detonating its full behavior. One behavior *does* run on every execution regardless of command-and-control state — the Mark-of-the-Web self-deletion described in Section 6 — and it is the most reliable early behavioral tell.

---

## 5. Static Analysis Findings

> **Analyst note:** Static analysis means examining the malware without running it — decompiling the code and reading its embedded data. For KAIDO this was especially productive because the operator's obfuscation renamed identifiers but did not defeat logic-level decompilation, so the configuration and capability map recovered as plaintext.

### 5.1 File structure and configuration recovery

KAIDO's three samples are approximately 1 MB 64-bit .NET assemblies with their dependencies embedded as compressed resources and unpacked to disk on load. The obfuscation renames identifiers but leaves the program logic readable after a standard deobfuscation pass, which is why the configuration, command-and-control endpoints, HVNC path tables, and crypto parameters all recover cleanly.

The encrypted configuration block decrypted in full (**DEFINITE** — an offline decrypt of the embedded `Settings` class):

- **Command-and-control endpoints:** `kaidoo[.]com[.]br:4782` (primary, using the Quasar binary protocol) and `c2.kaidoo[.]com[.]br:443` (secondary), both resolving to `144.172.109[.]203`.
- **Quasar authentication key / pinned-certificate thumbprint:** SHA1 `0acd8c90641e6e8b085aaf5a541c7ac050a65a4a`, identical across all three builds — a strong cross-build static anchor.
- **Embedded pinned server certificate:** self-signed, subject/issuer `CN=ihat tbcs`, valid 2026-03-14 through 2032-03-17. This embedded certificate is **distinct** from the certificate the live host actually presented (the `TeamKAIDO` / `kaido-c2` certificate), which shows the operator rotates command-and-control certificates across builds.
- **Cryptography:** AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation at 100,000 iterations; wire framing of `[12-byte nonce][16-byte tag][ciphertext]`, base64-encoded.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/kaido-quasar-rat-144-172-109-203/kaido-config-c2-defanged.png" | relative_url }}" alt="Recovered KAIDO operator configuration (secrets defanged) showing the 0xK41 brand name, the t.me/n_3_xl operator Telegram contact, exfiltration author templates such as '0xK41 ~ BrowserData', and operator panel and webhook fields.">
  <figcaption><em>Figure 4: Recovered KAIDO operator configuration with credentials and tokens defanged. Beyond the command-and-control and crypto parameters recovered from the client builds, the operator-side configuration exposes the identity artifacts that anchor attribution — the <code>0xK41</code> brand name, the <code>t.me/n_3_xl</code> operator contact, and branded exfiltration author templates (<code>0xK41 ~ BrowserData</code>, Steam/Minecraft/Roblox session labels). These self-attested branding strings tie the tooling to the named operator (Section 10) and survive as recovery evidence.</em></figcaption>
</figure>

**What this means.** Recovering the full configuration offline is the single most valuable static outcome. It gives defenders the command-and-control domains and IP without needing the sample to beacon, it provides the cross-build authentication-key thumbprint as a durable anchor, and it exposes the certificate-rotation behavior that tells a hunter not to over-rely on any single certificate hash.

### 5.2 Surveillance dependency stack

The fourteen bundled libraries described in Section 4.2 are recovered here as static evidence: the SharpDX, NAudio, AForge, and MouseKeyHook families are all present as embedded compressed resources. Their presence is what elevates the surveillance capability from "possible" to "built-in," and their unpack-on-load behavior is why an automated sandbox records them dropping to disk even when the rest of the payload stays gated.

### 5.3 Detection-anchor strings

Static analysis recovered a set of strings that survive the obfuscation pass and serve as high-value, low-false-positive file-detection anchors. The companion detection file builds YARA rules from these.

- Namespace root `Kaido.Common.Messages` and `Kaido.Client.Helper.HVNC.ProcessController`
- Costura-bundled asset `costura.kaido.common.dll`
- Hidden-desktop literal `Default_runhost`
- DXGI transport anchors: the environment variable `KAIDO_DXGI_PIPE`, the pipe prefix `kaido_dxgi_`, the reader-thread label `DXGI FrameReader`, the fallback-thread label `HVNC Capture Loop`, and the frame magic value `0x443F814B`
- Browser-clone debug string `[BrowserClone] Using handle hijacking for locked files...`
- Developer anti-analysis string `[ANTI] Sleep obfuscation ENABLED (fixed: mutex + stack detection + 32MB cap)`

**What this means.** `Kaido.Common.Messages` is the anchor a hunter should reach for first — it is the namespace root of the rebranded fork, it is distinctive enough to carry near-zero false positives, and it survives obfuscation because it is baked into the class structure. The HVNC strings (`Default_runhost`, the DXGI pipe/thread labels) are the second tier: they confirm the session-hijack capability specifically, distinguishing KAIDO from a stock Quasar fork that lacks HVNC.

---

## 6. Dynamic Analysis Findings

> **Analyst note:** Dynamic analysis means running the malware in a contained lab and recording what it does. KAIDO was detonated on an isolated lab host wired to a network sinkhole, so no traffic reached the real command-and-control server. The defining result — that the RAT withholds its behavior until it reaches its operator — is documented chronologically below.

The `c7542e82…` sample was detonated on 2026-06-28 on an isolated lab host (FlareVM on a segregated VLAN) against a simulated-internet gateway. Containment was proven: zero packets reached the real command-and-control server, and the beacon hit the lab sinkhole. The timeline is presented in the order the RAT acted.

**T+0:00 — Launch.** The sample executed as a single process. No child processes were spawned at any point in the run.

**T+2.4s — Mark-of-the-Web self-deletion (DEFINITE).** The RAT read and then deleted its own `Zone.Identifier` alternate data stream — the hidden metadata Windows attaches to a downloaded file to mark it as internet-sourced. A behavioral-monitoring tool (Procmon) captured the read of the `:Zone.Identifier` stream followed immediately by a delete operation. Removing this stream suppresses Windows SmartScreen re-checks, so the file no longer triggers the "this file came from the internet" warning on subsequent launches. This behavior runs on **every** execution, independent of command-and-control state, which makes it the single most reliable early behavioral tell for KAIDO. Detection anchor: a file-delete of a `:Zone.Identifier` stream by the sample within seconds of launch (Sysmon Event ID 23).

**T+2.4s onward — Command-and-control beaconing (confirmed).** The RAT issued a DNS A-record query for `kaidoo[.]com[.]br` and re-resolved it periodically (approximately every 13 minutes across two observations — the interval is MODERATE confidence on two data points). It then attempted the Quasar binary protocol over raw TCP on port **4782**, with a reconnect pattern of four attempts at roughly half-second intervals followed by a five-to-seven-second pause before the next group. This raw-TCP, non-HTTP beacon on a fixed port is a strong network signature.

**Throughout the run — Dependency unpack.** The fourteen bundled libraries (the SharpDX / NAudio / AForge / MouseKeyHook surveillance stack) unpacked to disk when the assembly loaded, regardless of command-and-control state. This is why automated sandboxes record the surveillance libraries dropping even though the surveillance behavior itself never fires without an operator.

**What did not happen — and why it matters.** Across the full 606-second run the RAT wrote no persistence, dropped no additional payloads, activated no HVNC, and collected no credentials. All of that is command-and-control-gated. Of fourteen capabilities documented statically, four were confirmed dynamically (the primary command-and-control endpoint, port 4782, the Mark-of-the-Web deletion, and the single-process reconnect loop), nine were unobserved because of the gating, and **zero were refuted**. The static picture and the dynamic picture agree — the gap between them is the gate, not a contradiction.

### Kill chain summary

> **Analyst note:** This subsection maps KAIDO's confirmed and statically-recovered behavior onto the standard attack-lifecycle stages (delivery, command-and-control, and post-connection actions), so a reader can see where in an intrusion each capability fires without re-reading the full dynamic-analysis timeline above.

The observed and statically-recovered behavior maps to the following stages. Each stage is annotated with the confidence of the underlying evidence.

#### Stage 1 — Delivery and initial execution

> **Analyst note:** How the RAT arrives and first runs. KAIDO is distributed through social lures rather than exploits, so the first defensive opportunity is at the point a user is convinced to run a disguised file.

KAIDO is distributed via consumer-focused social engineering — Discord lures and cracked-software bait — as a file masquerading as a legitimate `svchost.exe`. On first execution it immediately removes its own internet-origin marker (the Mark-of-the-Web self-deletion at T+2.4s) to suppress SmartScreen warnings on later launches. No exploit or vulnerability is involved; delivery depends on user action.

#### Stage 2 — Command-and-control and staging gate

> **Analyst note:** KAIDO's defining stage. Rather than acting immediately, the RAT phones home and waits — all further behavior is unlocked only after it reaches its operator.

The RAT resolves its command-and-control domain and beacons over raw TCP on port 4782 using the Quasar binary protocol. Until a valid handshake completes, it stays dormant — no persistence, no payloads, no surveillance. This gate (mapped to Execution Guardrails, T1480) is what makes KAIDO look benign in a commodity sandbox and is the reason detection leans on the network beacon and static anchors rather than post-infection behavior.

#### Stage 3 — Remote control, session hijacking, and surveillance (command-and-control-gated)

> **Analyst note:** What the operator can do once the implant is live. This stage was recovered statically, not triggered in the contained run, because it unlocks only after the command-and-control handshake.

Once connected, the operator has full Quasar-lineage remote control plus the two KAIDO-specific capabilities: HVNC browser-session hijacking (clone the victim's profile, drive the live authenticated session on a hidden desktop) and full-spectrum surveillance (screen confirmed; audio, webcam, and keystroke capture inferred from the bundled dependency stack). Persistence install routines — a registry Run key, a scheduled task, and a Windows service — are present in the decompiled code but were not reached in the gated run, so their exact artifact names remain unobserved (see the companion detection file's Coverage Gaps).

---

## 7. MITRE ATT&CK Mapping

> **Confidence note:** rows are HIGH confidence unless marked `(DEFINITE)` — directly observed with no alternative explanation — or `(MODERATE)` — supported by static or dependency-based evidence but not triggered in the command-and-control-gated contained run. The Executive Summary and Section 4 provide the higher-level view of which capabilities are directly confirmed versus inferred.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Command and Control / T1219 | Remote Access Software | KAIDO = rebranded Quasar v2.4.5 fork; full RAT plus operator panel |
| Command and Control / T1095 | Non-Application Layer Protocol | Quasar binary protocol over raw TCP 4782, no HTTP layer (DEFINITE) |
| Command and Control / T1071.004 | Application Layer Protocol: DNS | `kaidoo[.]com[.]br` DNS resolution + periodic re-resolution to locate C2 |
| Command and Control / T1573.001 | Symmetric Cryptography | AES-256-GCM config + C2 crypto; PBKDF2-SHA256 100k; pinned certificate |
| Defense Evasion / T1553.005 | Mark-of-the-Web Bypass | `Zone.Identifier` ADS read + delete at T+2.4s, every execution (DEFINITE) |
| Defense Evasion / T1480 | Execution Guardrails | All payloads / persistence / HVNC withheld until valid C2 handshake — 606s run, zero drops (DEFINITE) |
| Defense Evasion / T1497 | Virtualization / Sandbox Evasion | Sleep-obfuscation anti-analysis string present in binary (MODERATE) |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | Installs as `svchost.exe` in `%AppData%` (MODERATE) |
| Defense Evasion / T1055 | Process Injection | HVNC reflectively injects a capture DLL into cloned browser processes (MODERATE) |
| Collection / T1113 | Screen Capture | DXGI swap-chain hook of the hidden `Default_runhost` desktop; fallback compositor (MODERATE) |
| Collection / T1123 | Audio Capture | NAudio (Wasapi / WinMM) dependency stack — microphone (MODERATE) |
| Collection / T1125 | Video Capture | AForge DirectShow dependency stack — webcam (MODERATE) |
| Collection / T1056.001 | Keylogging | MouseKeyHook global input hook (MODERATE) |
| Credential Access / T1555.003 | Web Browsers | Wholesale browser-profile clone → live-session credential and cookie access (MODERATE) |
| Persistence / T1547.001 | Registry Run Keys / Startup Folder | `HKCU\...\Run` install routine in decompiled code (MODERATE) |
| Persistence / T1053.005 | Scheduled Task | Scheduled-task install routine in decompiled code (MODERATE) |
| Persistence / T1543.003 | Windows Service | Service-install path in decompiled code (MODERATE) |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | Stolen data returned via the port-4782 Quasar channel (MODERATE) |

**Reading this table.** The DEFINITE rows are the ones a defender can act on today without caveat — the raw-TCP Quasar beacon, the Mark-of-the-Web self-deletion, and the command-and-control gate were all directly observed. The MODERATE rows describe capabilities that are code-present or dependency-present but were held back by the gate; they are real capabilities of the RAT, not speculation, but their runtime artifacts (exact registry values, task names, injection APIs) were not captured in the contained run. That distinction is exactly why the detection strategy prioritizes the confirmed network and file anchors.

---

## 8. Indicators of Compromise

The complete, machine-readable indicator set is published as a separate JSON feed for direct ingestion into SIEM and EDR platforms: **[`/ioc-feeds/kaido-quasar-rat-iocs.json`](/ioc-feeds/kaido-quasar-rat-iocs.json)**. Indicators are defanged in the prose below for safe reading; the JSON feed carries them in un-defanged, ingestion-ready form. The KAIDO indicator set comprises 5 file hashes, 4 command-and-control network indicators, and a set of host and TLS-certificate anchors.

**Highest-value indicators.** The three anchors below are the ones to deploy first — they are DEFINITE or HIGH confidence and are the least likely to be evaded by per-build repacking.

| Type | Indicator | Confidence | Context |
|---|---|---|---|
| IPv4 | `144.172.109[.]203` | DEFINITE | Live KAIDO Quasar C2; AS14956 RouterHosting (US); ~10-month continuity |
| Domain | `kaidoo[.]com[.]br` | DEFINITE | Primary C2 (port 4782); DNS confirmed in detonation |
| Domain | `c2.kaidoo[.]com[.]br` | DEFINITE | Secondary C2 (port 443); operator-labeled "c2" subdomain |
| Port | TCP 4782 | DEFINITE | Quasar binary-protocol C2 channel (non-HTTP) |
| TLS cert | Issuer Org `TeamKAIDO`, CN `kaido-c2`; JA4X `bbd6cc0fca29_bbd6cc0fca29_795797892f9c` | HIGH | Live-host C2 certificate on `144.172.109[.]203:8443` — fleet-enumeration-grade pivot |

**File hashes (SHA256).** All three RAT builds plus the primary build's MD5 and SHA1 are in the feed. The three builds are packed differently and a signature scan of the full recovered toolkit produced zero hits, so hashes confirm known samples but will not catch new builds.

| SHA256 | Context | Confidence |
|---|---|---|
| `c7542e8265f70d6c1dbf2e3cf6e81a90198cd157d3d6693c6d2a8a49d99a5b8d` | KAIDO RAT, tag `breach`, richest build | DEFINITE |
| `385d20ca574976e3ba3f4f3079420f8a1c3935c0ab4a3f87063beea27d41e254` | KAIDO RAT, live-C2 sibling | DEFINITE |
| `022944768c4326d611fa3edb100eb8277228717a220580e7ffce143341aa39fa` | KAIDO RAT, low-detection sibling | DEFINITE |

**Host and behavioral anchors.**

| Type | Indicator | Confidence | Context |
|---|---|---|---|
| File path | `%AppData%\<subdir>\svchost.exe` | HIGH | Install location (name masquerade). Hunt this path alongside parent-process lineage: legitimate `svchost.exe` runs only from `System32`/`SysWOW64` and is spawned only by `services.exe` — an `%AppData%` path or a non-`services.exe` parent is high-signal. |
| Named pipe | `\\.\pipe\kaido_dxgi_<8 hex>` | HIGH | DXGI HVNC frame transport |
| Behavior | Deletion of the file's own `:Zone.Identifier` stream within 2–3s of launch | DEFINITE | Mark-of-the-Web bypass (Sysmon Event ID 23) |
| Cert (embedded) | Pinned client cert, SHA1 `0acd8c90641e6e8b085aaf5a541c7ac050a65a4a` | DEFINITE | Quasar authentication key, identical across all three builds |
| Passive infra | `179.43.150[.]50` | MODERATE | Current `kaidoo[.]com[.]br` A-record; AS51852 Private Layer (CH) — passive only |

> **Note on the passive host.** `179.43.150[.]50` (Switzerland) is the current A-record for the `kaidoo[.]com[.]br` apex, distinct from the live RAT C2 at `144.172.109[.]203`. It is retained as a MODERATE-confidence passive indicator — a single-observation resolution corroborated by an RDP certificate, not by a second technique. The operator's use of a second provider and jurisdiction for the brand apex is itself an infrastructure-diversification signal.

**A note on infrastructure scope.** A dedicated certificate and fingerprint fleet-sweep across three independent internet-scanning sources (a commercial certificate corpus, Shodan, and Censys) found the `TeamKAIDO` certificate and its JA4X fingerprint on **exactly one host** — `144.172.109[.]203`. As currently observable this is a single-command-and-control-host operation with no enumerable secondary fleet. That absence is bounded by scanner coverage of the non-standard `:8443` port and by data currency; it is a negative result, not proof that no sibling infrastructure ever existed.

---

## 9. Detection and Response Guidance

Full detection content — YARA rules, Sigma rules, and Suricata signatures — is published in a separate file for direct deployment: **[`/hunting-detections/kaido-quasar-rat-detections/`](/hunting-detections/kaido-quasar-rat-detections/)**. That file contains three YARA rules, three Sigma rules, and three Suricata signatures, all derived from the static and dynamic evidence in this report. This section summarizes the detection strategy and its known limits; it does not restate the rules.

### 9.1 Detection strategy — behavior and network over hashes

Because each KAIDO build is separately packed and hash blocking is low-yield, detection should be layered across three evidence types, in priority order:

1. **Static file anchors (highest value, lowest false-positive risk).** The namespace root `Kaido.Common.Messages` and the Costura asset `costura.kaido.common.dll` survive obfuscation and are distinctive compiled identifiers not found in legitimate software. The HVNC strings (`Default_runhost`, the DXGI pipe and thread labels) confirm the session-hijack capability specifically. These are the anchors to deploy first for file scanning and memory scanning of `svchost.exe`-masquerading processes.
2. **Network signatures (fleet-enumeration-grade).** The operator-branded `TeamKAIDO` / `kaido-c2` TLS certificate and its JA4X fingerprint are the highest-value network pivot — a certificate-issuer or JA4X search on an internet-scan platform enumerates the operator's command-and-control fleet directly. The raw-TCP Quasar beacon on port 4782 (no HTTP layer) and DNS queries for the `kaidoo[.]com[.]br` domains are the on-the-wire tells.
3. **Behavioral detection (most reliable early tell).** The Mark-of-the-Web self-deletion — a file deleting its own `:Zone.Identifier` stream within seconds of launch (Sysmon Event ID 23) — runs on every execution regardless of command-and-control state, making it the most reliable behavioral signal. The HVNC named-pipe creation (`\\.\pipe\kaido_dxgi_*`, Sysmon Event ID 17/18) and installation as `%AppData%\...\svchost.exe` by a non-system parent (Sysmon Event ID 1 / Windows Event ID 4688) are the supporting host behaviors.

### 9.2 Known detection limits

The command-and-control gate that defeats sandboxes also constrains behavioral detection. The companion detection file's Coverage Gaps section documents this in full; the practical consequences are:

- **HVNC runtime behavior is covered structurally, not behaviorally.** The hidden-desktop creation, browser-profile clone, and DXGI capture are fully recovered from static analysis but were never triggered dynamically, so a precise behavioral rule for the desktop-switch API sequence cannot be written at DEFINITE confidence from static evidence alone. Coverage rests on the named-pipe transport and the static strings.
- **Persistence artifact names are unobserved.** Install routines for a registry Run key, a scheduled task, and a Windows service are code-present but never executed in the gated run, so their exact value names and task names are not known. Writing a rule against a guessed name would risk false negatives.
- Both gaps close with the same enabler: a command-and-control stub that triggers the gated behavior and captures the exact runtime artifacts.

### 9.3 Response orientation

This is not an incident-response playbook — organizations with a live KAIDO detection should engage their own incident-response process. As a third-party orientation, the priorities are:

- **Detection priorities (hunt these first):** the raw-TCP Quasar beacon on port 4782 and the `TeamKAIDO` / `kaido-c2` TLS certificate; the Mark-of-the-Web self-deletion behavior; the HVNC named pipe `\\.\pipe\kaido_dxgi_*`.
- **Persistence targets (find and remove — artifact locations, not removal commands):** the `%AppData%\<subdir>\svchost.exe` install path and its `Logs\` subfolder; and, if the RAT reached its persistence stage, a registry Run key, a scheduled task, and a Windows service (exact names unobserved — enumerate by parentage and creation time).
- **Containment categories (one-line labels):** isolate hosts showing the Quasar beacon or the HVNC named pipe; block and monitor the KAIDO command-and-control infrastructure (`kaidoo[.]com[.]br`, `c2.kaidoo[.]com[.]br`, `144.172.109[.]203` on ports 4782 and 8443) at the perimeter; reset credentials for any account authenticated on an affected host, since HVNC drives the victim's own live session and can reach accounts whose passwords were never typed by an attacker; treat browser sessions on affected hosts as compromised and force re-authentication.

---

## 10. Threat Actor Assessment

> **Analyst note:** This section states who operates KAIDO and how confident that attribution is. It rests primarily on identity artifacts the operator embedded in their own toolkit and self-published on their own sales channels — self-attested evidence, not third-party inference. Because a specific actor is named at HIGH confidence, no unattributed-actor (UTA) designation applies.

The KAIDO Quasar-fork RAT is attributed with **HIGH confidence (approximately 85%)** to a self-identified Brazilian commodity-malware operator using the handle **`n_3_xl`** (Telegram `@govbrasil`) under the **KAIDO / `0xK41`** brand — a financially-motivated Malware-as-a-Service vendor, not a targeted-intrusion actor. Attribution rests on identity artifacts recovered directly from the kit's own configuration: the operator-contact field points to `t.me/n_3_xl` (a Telegram channel titled "[KAIDO]"), and that link is reciprocally confirmed by the `@govbrasil` support handle whose bio reads "Kaido" and lists "Maldev @n_3_xl." Pervasive `0xK41` / KAIDO branding appears across configs, exfiltration embeds, and the operator's web panel, and a near-unique operator signature string survives the obfuscation intact. The sample-to-brand-to-infrastructure chain is direct: the analyzed RAT builds decrypt to `kaidoo[.]com[.]br`, which carries the operator-branded `TeamKAIDO` command-and-control certificate.

**Confidence statement.**

```
Threat Actor: n_3_xl / @govbrasil / KAIDO (0xK41 brand) — Brazilian commodity-malware operator
Confidence: HIGH (~85%)
- Why this confidence: Self-attested operator identity artifacts recovered from the kit's OWN
  configuration (t.me/n_3_xl, titled "[KAIDO]"), reciprocally confirmed by the @govbrasil support
  handle; pervasive 0xK41/KAIDO brand ownership; the sample-to-brand-to-infrastructure chain
  (c7542e82 -> kaidoo.com.br -> TeamKAIDO cert); and Brazilian jurisdiction corroborated across
  hosting, ccTLD, and language. This is direct, self-attested identity evidence, not inference.
- What's missing: A real-world legal identity — all operator domains were privacy-registered from
  day one, so reverse-WHOIS is a dead end. The ceiling is a durable persona, not a named person.
- What would increase confidence: A non-WHOIS identity link (a leak, a reused operator email, a
  cross-platform handle correlation), or government/vendor-catalog attribution (none exists).
```

**Country: Brazil (HIGH).** The Brazilian nexus is corroborated multiple ways: Portuguese-language code and logs; the `kaidoo[.]com[.]br` country-code domain (Brazilian registration requires a Brazilian tax identifier); the operator's Brazilian hosting for the related builder infrastructure; and external reporting associating the KAIDO brand with Brazilian banking fraud.

**Tooling lineage — a separate actor.** KAIDO's operator built their stealer product line on the **EvilSoul-Engine** Malware-as-a-Service, whose developer is a **distinct** Brazilian actor, `@breakingupslow`. That lineage is DEFINITE for the stealer line, but it is a separate matter from the KAIDO RAT covered here. Critically, **`n_3_xl` and `@breakingupslow` are not the same person.** An earlier working hypothesis equating the two was formally retracted after analysis: public reporting maps many of `@breakingupslow`'s rebrands but never lists KAIDO or `0xK41`, and the two operators' Telegram accounts differ in registration age by roughly 2.7 billion sequential IDs, indicating substantially different, later registration for the KAIDO operator. `n_3_xl`'s relationship to the EvilSoul operation is assessed as a customer or reseller of that product at MODERATE confidence — a supplier-to-reseller tie, not a shared identity. This distinction matters because it keeps the KAIDO RAT attribution clean: KAIDO is `n_3_xl`'s own branded product line, resolving to the operator's own `kaidoo[.]com[.]br` infrastructure and the operator-branded `TeamKAIDO` certificate — directly observed operator infrastructure, independent of the EvilSoul lineage.

**Actor archetype.** The tradecraft points to an individual commodity operator, not a structured group: personality-forward branding, ego strings in embeds, Telegram-handle self-promotion, single-language sloppiness, and a lack of operational-security discipline (the operator left logs and a self-test box in the exposed open directory). The operator invests sophistication only where it defeats detection — the HVNC session-hijack primitive and the DXGI capture — and rides on commodity code everywhere else. This is a "quick-malware-for-quick-targets" vendor running a business, not an espionage actor.

**Motivation: financially-motivated commodity cybercrime (HIGH).** Tiered "DAY" license keys, a sales subdomain, a customer control panel, Telegram customer support, and multi-channel build delivery all describe a Malware-as-a-Service business. There are no espionage, hacktivism, or targeted-attack indicators. Victims are opportunistic consumers — Discord users, gamers, and cryptocurrency-wallet holders.

---

## 11. Threat Intelligence Context

> **Analyst note:** This section situates KAIDO's specific findings against what is publicly documented about the techniques it uses — separating what is original to this operator from what is commodity reuse.

**Quasar RAT lineage.** Quasar is a long-established, publicly available open-source .NET RAT with a mature detection footprint — multiple public YARA rule sets exist, and one such rule matched the KAIDO sample during sandbox triage, corroborating the Quasar-fork identification from an independent direction. Quasar-based forks are a common commodity pattern; the KAIDO rebrand, its HVNC extension, and its Brazilian-operator branding do not appear in any public malware-family catalog, and a commercial threat-actor catalog search returned zero entries for "KAIDO," "Quasar-fork," or the operator handles. That absence reflects the actual state of public coverage for a small-scale commodity operator, not an absence of the threat.

**HVNC is well-precedented; this implementation is the notable part.** Hidden-desktop remote control as a capability class is well-documented across commercial and criminal RAT tooling — hidden-desktop plugins for Quasar and similar families have circulated in underground forums for years. What is operationally significant about KAIDO's implementation is the pairing of HVNC with wholesale browser-profile cloning to hijack a victim's *live authenticated session*, defeating device-trust and 2FA controls that key off session continuity rather than credentials. That specific combination is not independently documented for this operator brand in public sources.

**Mark-of-the-Web self-deletion is a known technique, confirmed present.** The `Zone.Identifier` stream deletion (MITRE ATT&CK T1553.005) is a broadly documented evasion, not novel to this operator — but it was confirmed present, running on every execution independent of command-and-control state, which makes it a reliable behavioral anchor despite being a commodity technique.

**Infrastructure posture.** The KAIDO command-and-control host has shown continuity for approximately ten months (from roughly August 2025) on a US commercial VPS provider, with the operator additionally placing the brand apex on a Swiss provider — a modest infrastructure-diversification signal across two jurisdictions. Bulletproof-hosting status is **SUSPECTED, not confirmed**: no provider was matched against a named, sourced bulletproof-hosting list, and the assessment rests on behavioral indicators (roughly ten months of clearly-malicious, self-branded C2 activity without observed takedown) rather than a retrievable designation.

---

## 12. Confidence Summary

This report is built on strong direct evidence — full static configuration recovery and a contained detonation — but several findings rest on inference rather than direct observation. This section organizes every major finding by confidence level so a reader can weigh each claim without re-deriving it from the narrative sections above.

**DEFINITE** — direct evidence, no ambiguity:

- The command-and-control configuration, endpoints, authentication key, and crypto parameters (offline decrypt of the embedded `Settings` class — Section 5.1).
- The Mark-of-the-Web self-deletion of the `:Zone.Identifier` stream at T+2.4s, on every execution (directly observed in the contained detonation — Section 6).
- The raw-TCP Quasar beacon on port 4782 and the command-and-control staging gate — 606 seconds, zero drops, zero persistence, zero HVNC (directly observed — Section 6).
- The pinned client-certificate SHA1 thumbprint, identical across all three analyzed builds (offline decrypt — Section 5.1).

**HIGH** — strong evidence, minor gaps:

- KAIDO is a rebranded 64-bit Quasar RAT fork (namespace-tree structural match — Section 3).
- The HVNC browser-session-hijack architecture and the DXGI screen-capture path (static recovery plus the SharpDX dependency stack — Section 4.1, 4.2).
- Attribution to the `n_3_xl` / `@govbrasil` / KAIDO (`0xK41`) operator (self-attested identity artifacts embedded in the kit's own configuration — Section 10).
- The `TeamKAIDO` / `kaido-c2` TLS certificate and JA4X fingerprint as a fleet-enumeration pivot (cross-validated across three independent scanning sources — Section 8).
- The Brazilian nexus for the operator (Portuguese-language artifacts, `.com.br` registration requirements, hosting-provider corroboration — Section 10).

**MODERATE** — reasonable evidence, notable gaps:

- **Audio and webcam surveillance** are inferred from the bundled NAudio and AForge dependency stacks, not observed firing — the sample carries the exact libraries to record a microphone and a webcam, but the command-and-control gate held those channels back before the contained run ended. Screen capture and HVNC are directly evidenced; audio and webcam capture are dependency-inferred, not detonation-observed (Section 4.2, 12).
- **The Brazilian banking / instant-payment (PIX) fraud objective** is strongest on the KAIDO brand via external reporting and is MODERATE for the specific builds analyzed — the recovered code confirms the HVNC session-hijack primitive and generic credential access, but no banking-overlay or payment-clipper code was observed in these three samples (Section 4.1, 11).
- Persistence install routines (registry Run key, scheduled task, Windows service), HVNC activation, injection APIs, and credential collection are all code-present but were withheld by the command-and-control gate, so their exact runtime artifacts are unobserved (Section 6, 9.2).
- The operator's relationship to the EvilSoul-Engine tooling lineage is a supplier/reseller tie, not a shared identity — `n_3_xl` and `@breakingupslow` are assessed as different individuals (Section 10).
- The `179.43.150[.]50` passive infrastructure indicator (current `kaidoo[.]com[.]br` A-record) — single-observation resolution, not cross-validated by a second technique (Section 8).
- Bulletproof-hosting status for the operator's US provider is SUSPECTED on behavioral grounds (ten months of unchallenged malicious activity), not confirmed against a named bulletproof-hosting list (Section 11).

**LOW / INSUFFICIENT** — explicit limits on what this report can conclude:

- **No confirmed victims.** The recovered logs show one operator test box and one unresolved possible-victim host — this report documents a live capability and a live operator, not a confirmed victim population.
- **The operator's real-world legal identity is unrecoverable** from registration data — every operator domain was privacy-registered from the first snapshot. The attribution ceiling is a durable persona, not a named individual (INSUFFICIENT for real-identity attribution).
- **The infrastructure fleet-sweep found a single host** for the `TeamKAIDO` certificate — bounded by scanner coverage of the non-standard `:8443` port. Absence of additional infrastructure is a negative result, not proof that no sibling infrastructure exists.

**Companion report.** KAIDO is one of two product lines run by this operator. The EvilSoul-Engine stealer-builder — a separate Node.js/Electron information-stealer factory built on tooling from the distinct actor `@breakingupslow` — is documented in the companion report and is out of scope here.

---

## 13. References and Appendices

This report draws on the tiered source hierarchy defined in the project's source-credibility standard (Tier 1 = government/reproduced Tier-1 corroboration; Tier 2 = major-vendor or structured commercial/OSINT tooling; Tier 3 = named-researcher OSINT or reputable security journalism; Tier 4 = unverified social media, not used as a sole source).

**Tier 1 — direct technical evidence (this investigation):**

- Static reverse engineering and decompilation of three KAIDO RAT samples (`c7542e82…`, `385d20ca…`, `02294476…`) — namespace structure, embedded configuration, crypto parameters.
- Contained dynamic detonation of sample `c7542e82…` on an isolated lab host (2026-06-28), sinkholed with zero packets reaching the real command-and-control server.

**Tier 1–2 — structured platform data (queried directly during the investigation):**

- VirusTotal — file reports, detection counts, sibling-sample clustering, behavioral sandbox correlation.
- Hunt.io — TLS-certificate and JARM/JA4X fleet enrichment (`certificates.inventory` SQL corpus), ASN/hosting attribution, threat-actor catalog check (zero entries for "KAIDO," "Quasar-fork," or the operator handles as of 2026-06-27).
- DomainTools Iris — passive DNS and WHOIS-history change logs confirming ASN/provider attribution for `144.172.103[.]98` and cross-brand infrastructure overlap.
- Direct observation of the operator's own Telegram channel (`t.me/n_3_xl`) and support handle (`@govbrasil`) bios — self-attested identity artifacts, not third-party inference.

**Tier 3 — named-researcher OSINT (contextual, not load-bearing for the KAIDO RAT's technical findings):**

- A named-researcher publication on the EvilSoul brand and its `@breakingupslow` developer (October 2025) is referenced in Section 10 for the tooling-lineage discussion only. **Source-access note:** direct retrieval of this article was blocked by Cloudflare on every path attempted (direct fetch, archive retrieval, proxied request); its content is cited only via a search engine's indexed summary, independently reproduced across separate queries. This is a search-indexed-summary citation, not a direct-article citation, and its claims are capped at MODERATE confidence accordingly — it does not support any claim about the KAIDO RAT itself, only the separate EvilSoul-Engine lineage question addressed in Section 10.

**Not used as sole-source evidence:** Two X/Twitter posts referencing the EvilSoul brand were reviewed during the underlying investigation and treated as Tier 4 supporting color only; no claim in this report rests on them as a sole source.

**Companion materials:**

- Detection rules: `/hunting-detections/kaido-quasar-rat-detections/`
- IOC feed: `/ioc-feeds/kaido-quasar-rat-iocs.json`
- Companion report (EvilSoul-Engine stealer-builder, same operator ecosystem, built on tooling from the distinct actor `@breakingupslow`): see Section 1.

---

*© 2026 Joseph. All rights reserved. See LICENSE for terms.*





