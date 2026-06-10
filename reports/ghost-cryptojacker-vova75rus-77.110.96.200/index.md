---
title: "GHOST Cryptojacker Kit Family — Vova75Rus Kit-Author Supply Chain"
date: '2026-05-25'
layout: post
permalink: /reports/ghost-cryptojacker-vova75rus-77.110.96.200/
thumbnail: /assets/images/cards/ghost-cryptojacker-vova75rus-77.110.96.200.png
hide: true
unlisted: true
sponsored_by: hunt-io
category: "Cryptojacking Kit"
series: ai-agent-frameworks
series_role: member
series_order: 5
description: "End-to-end technical analysis of the GHOST cryptojacker kit — a 4-tier supply chain operation authored by Vova75Rus targeting exposed ComfyUI/GPU-cloud hosts with a userland LD_PRELOAD rootkit, dual-Telegram supply-chain monitoring, and a GitHub Trust & Safety Tier-0 disposition outcome."
detection_page: /hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
ioc_feed: /ioc-feeds/ghost-cryptojacker-vova75rus-77.110.96.200-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Suricata Signatures"
    anchor: "suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "coverage-gaps"
ioc_highlights:
  - "77.110.96.200"
  - "77.110.125.145"
  - "eaaa10c840de23335abae1a9ead0a6a7fb7be5187cd19ad05137feab12bb7301"
  - "e943b58112f58517b95424dba9334bf97c5dc2dd2f069dca04b9e75b9fec56ba"
  - "008bc5ab6e62c9e55e3dd2da5ef31e1e0f05f35c5898a8ef5c7aeaf6e2a2c46f6"
---

**Campaign Identifier:** GHOST-Cryptojacker-Vova75Rus-77.110.96.200<br>
**Last Updated:** June 2, 2026<br>
**Threat Level:** HIGH

> **Part of series:** This is sub-report 1 of 6 in the parent investigation [AI-Agent-Frameworks-MultiActor-2026-05-23](/reports/ai-agent-frameworks-2026-05-23/). The parent report synthesizes the cross-case findings across eight operator cases; this sub-report provides the operator-specific technical deep-dive for Case 9 — the GHOST cryptojacker kit ecosystem, the Vova75Rus kit-author identification, and the GitHub Trust & Safety Tier-0 disposition outcome of 2026-05-25.

---

## 1. Executive Summary

**Bottom line:** The GHOST cryptojacker is a commodity kit, not a single-host campaign — and this investigation named its author. A `PIP_PAYLOAD_REPO` GitHub URL in Operator-B's ComfyUI scanner pivoted (Hunt SQL) to `Vova75Rus/ComfyUI-Shell-Executor`, attributing the kit to **Vova75Rus at HIGH confidence (88%)** (§9.2). The proof the kit is sold, not bespoke: a **byte-identical `libpam_cache.so` LD_PRELOAD rootkit** (MD5 `296a8005...`) shipped to two separate AEZA customer hosts (§5.1), each carrying the kit-author's hardcoded **OWNER Telegram bot** (§4.7). GitHub Trust & Safety suspended Vova75Rus account-wide on 2026-05-25, ~24 hours after disclosure submission — disrupting the kit-author payload channel at the supply-chain's single intervention point.

The kit is GPU-cloud cryptojacking against exposed ComfyUI / Stable-Diffusion / ML-inference services (especially A100-tier instances on Lambda Labs, Datacrunch, Nebius, and hyperscalers) for Monero (XMR) and Conflux (CFX) revenue. It is intermediate-to-advanced at the kit layer and variable at the operator layer; §3 classifies both. The work extends the primary public disclosure (Censys ARC, Mark Ellzey, 2026-04-07), which documented the kit on one host — the seven net-new contributions are listed under *Why This Threat Is Significant* below.

### What Was Found

Each finding is named here and dissected in its home section:

- **A kit, not a single tool** (§3, §4) — a Bash + Python + ELF composite (43-function `ghost.sh` installer, 14,568-byte `libpam_cache.so` rootkit, 74,844-byte `py.py` ComfyUI framework, plus scanner / Hysteria-backdoor / IP-range scripts), pulled in full from open directories on both hosts. Self-named "GHOST v5.1 (Anti-Hisana + Resurrection + Spread + Escape)" in the `ghost.sh` first-line comment.
- **A userland LD_PRELOAD libc-hook rootkit** (§4.1, §5.1) — `libpam_cache.so` hooks `readdir`/`readdir64`/`fopen`/`fopen64` to hide 27 strings and 9 ports from standard libc directory and `/proc/net/tcp` reads. The `libpam_cache` filename is masquerade only: the 98-line C source has zero PAM symbols and zero authentication-flow code (DEFINITE).
- **A 4-tier supply chain with named identities** (§9.1) — UnamSanctam (upstream OSS) → Vova75Rus (kit author, suspended 2026-05-25) → ≥2 customer operators → victim ComfyUI hosts. Operators differ from each other only in a 17-byte wallet/pool config substitution.
- **A dual-Telegram supply-chain monitoring architecture** (§4.7) — every deployment carries the kit-author OWNER bot (8415540095) plus an operator-set MIRROR bot (8315596543 for Operator-A). The OWNER bot is the kit-sales model's structural fingerprint and its highest-value detection string.
- **An active operator iterating live** (§6.3) — Operator-A modified `min1.sh` at 2026-05-24T17:10:29Z, 47 days after the Censys disclosure. Both hosts sit on AEZA Group (AS210644, OFAC/NCA-sanctioned 2025-07-01); AEZA's non-cooperative abuse posture sustains the operation.

### Why This Threat Is Significant

Censys documented the kit on one host with hash-IOC-only coverage and an implied per-victim compilation model. This investigation adds **seven net-new contributions**:

1. **Sibling deployment at 77.110.125.145** — confirms multi-tenant commodity, not a single-host bespoke campaign.
2. **Byte-identical `libpam_cache.so` across customers** (DEFINITE) — refutes per-victim compilation; proves a pre-compiled kit-author artifact with 17-byte per-customer config substitution.
3. **Kit-author OWNER Telegram bot signature** (8415540095) — the campaign's highest-value detection string.
4. **Full 27-string + 9-port hide-list inventory** — Censys reported the rootkit's existence, not its filter list.
5. **Structured YARA/Sigma/Suricata rules** with FP-resistant string combinations, versus hash-IOCs only.
6. **6-week-later VT snapshot** — zero AV-vendor uptake of GHOST signatures (`libpam_cache.so` 0/0 never submitted; `min1.sh` 0/53 undetected; `ghost.sh` 13/63 generic only). Custom kits with low telemetry volume operate below AV automated-analysis triggers.
7. **Conflux drain chain** — Operator-A mining wallet → consolidator → exchange off-ramp (terminal 781,383-tx hot wallet), a subpoena target Censys did not pursue.

### Key Risk Factors

This is an **active and actively-iterating** cryptojacking campaign with confirmed multi-tenant kit distribution and an upstream supply-chain layer. The risk framing reflects what the campaign **enables** (resource hijacking, hidden persistence, container escape into cloud-tenant boundaries) rather than what it does in absolute compromise-count terms.

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 14%;">
<col style="width: 60%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Persistence Difficulty</td><td>9/10</td><td>5-vector persistence chain (/etc/ld.so.preload + systemd system unit + systemd user unit + System V init script + crontab + shell-RC injection); `chattr +i` immutable flags applied to persistence files; scatter-copy redundancy across `/etc/udev/hwdb.d/`, `/var/spool/cron/`, `$HOME/.local/share/.cache/fontconfig/`; inotify_guard cross-process watchdog resurrects deleted persistence components. Standard remediation (single-vector cleanup) will not eradicate the rootkit.</td></tr>
<tr><td>Detection Evasion</td><td>8/10</td><td>Userland LD_PRELOAD libc-hook rootkit hides 27 strings and 9 ports from any process making `readdir` / `fopen` calls — including `ps`, `ls`, `ss`, `netstat`, and `cat /proc/net/tcp` output. Hysteria v2 backdoor uses bing.com SNI masquerade over QUIC/UDP 14433/14444. Deceptive `libpam_cache` filename masquerades as a PAM module. Memfd_create() fileless miner execution. 6-week VT snapshot confirms zero AV vendor signatures.</td></tr>
<tr><td>Resource Hijacking</td><td>8/10</td><td>Primary financial-motivation outcome — XMR (Monero) and CFX (Conflux Octopus algorithm) mining on victim GPUs, especially A100-tier; Hysteria v2 secondary bandwidth-hijacking capability; competitor-displacement function (`_anti_hisana` + `kill_list.patterns` regex against xmrig/xmr-stak/kdevtmpfsi/kerberods/bioset/stratum/cryptonight/randomx/etchash/kryptex etc.) ensures full GPU dedication to the operator's mining wallets.</td></tr>
<tr><td>Container Escape Capability</td><td>7/10</td><td>4 distinct container-escape variants present in `ghost.sh`: cgroup release_agent abuse + bind-mount escape + nsenter via host PID + Docker socket abuse. MODERATE confidence on real-world execution success rate (specific cgroup/runtime configurations required); HIGH confidence on code-level intent. Significant implication for victim cloud-GPU tenants where ComfyUI runs inside a container.</td></tr>
<tr><td>Supply Chain Depth</td><td>9/10</td><td>4-tier supply chain (UnamSanctam upstream OSS → Vova75Rus kit author → ≥2 customer operators → 4,573 candidate victim IPs). Byte-identical kit binary across customer hosts. OWNER Telegram bot baked into every customer deployment provides kit-author real-time monitoring of all downstream operators.</td></tr>
<tr><td>Operator Iteration Tempo</td><td>7/10</td><td>Operator-A actively modified `min1.sh` at 2026-05-24T17:10:29Z — 47 days post-Censys disclosure. 83 ncat invocations in operator bash history (heavy listener tradecraft). 1,472-line bash history with 48 unique Cyrillic words. Live ongoing operations despite public disclosure; AEZA non-cooperative abuse posture enables continuity.</td></tr>
</tbody>
</table>

**Overall Campaign Risk Score: 8.0/10 — HIGH.** The campaign is rated HIGH (not CRITICAL) because (a) GitHub T&S has disrupted the upstream kit-author payload distribution channel (Tier-0 action successful 2026-05-25), (b) Operator-B's host is abandoned (5 days post-Censys), and (c) operator-level capabilities remain bounded by individual infrastructure rather than reaching campaign-scale victim volume. If the AEZA-hosted Operator-A continues live iteration without provider response, or if additional kit-customer operators are discovered on AEZA infrastructure, the threat level should be reassessed.

### Threat Actor Summary

Three identity tiers, detailed with full evidence in §9. Vova75Rus is **not** any customer operator — the wallet-match test refuted the initial conflation (§13.2): his personal XTM/Tari setup (Kryptex worker `1238rkM7gGg3sl`) is distinct from Operator-A's XMR + CFX wallets.

- **Vova75Rus** (kit author, GitHub UID 73169104) — **HIGH (88%), NAMED** (§9.2). Russian-origin; account suspended by GitHub T&S 2026-05-25.
- **UTA-2026-016** *(an internal tracking label used by The Hunters Ledger — see Section 9)* = Operator-A (77.110.96.200) — **LOW (65%, top of the LOW band)**, unattributed (§9.3). DEFINITE Russian-speaking; higher-OPSEC (self-hosted XMR/CFX pool proxies); active.
- **UTA-2026-017** = Operator-B (77.110.125.145) — **LOW (60%)**, unattributed (§9.4). DEFINITE Russian-speaking; lower-OPSEC (public pools); host abandoned ~5 days post-Censys.
- **UnamSanctam** (upstream OSS) — **HIGH (90%) on the passive-OSS-author role, NOT a Case 9 threat actor** (§9.5). Supplies UnamWebPanel / SilentCryptoMiner tooling the kit author bundles.

### For Technical Teams

Five immediate priorities for SOC analysts, threat hunters, and Linux endpoint defenders (rules in §10):

1. **Hunt the OWNER Telegram bot signature.** Search Linux-host egress HTTPS for `api.telegram.org/bot8415540095:*` — one string match catches every GHOST customer worldwide. Broaden with the bash-history token regex `\d{8,10}:[A-Za-z0-9_-]{30,40}` for any plaintext bot token.
2. **Audit `/etc/ld.so.preload`.** Any non-empty value on a production server is suspicious; cross-check its mtime and `libpam_cache.so` under `/lib/security/` (or `/lib/x86_64-linux-gnu/security/`, `/usr/lib/security/`). The filename has no PAM functionality.
3. **Audit ComfyUI `custom_nodes/`** for any Python file with both `class PerformanceMonitor` and `NODE_CLASS_MAPPINGS` (the fake-custom-node persistence). ComfyUI exposes port 8188 unauthenticated by default — restrict to localhost or an authenticated reverse proxy.
4. **Block AEZA Group (AS210644) at egress** absent a business reason for it. OFAC designation (2025-07-01) plus 47 days of unresponsive abuse posture hosting cryptojacker C2 makes this both a security and a compliance position.
5. **Cloud-GPU / ComfyUI operators:** the scanner targeted port 8188 across AWS / GCP / Oracle / Hetzner / Lambda Labs / Datacrunch / Nebius / DigitalOcean / Huawei / Linode / OVH / Scaleway / Tencent / Contabo. If any match your provider, audit ComfyUI exposure and `/etc/ld.so.preload` per tenant.

The technical depth lives in §3–§6 (classification through dynamic analysis), §9 (attribution chain), and §13 (retractions). MITRE ATT&CK (§7) and the full IOC set (§8) ship in the companion detection and IOC files.

---

## 2. Business Risk Assessment

For an organization running GPU-cloud ML inference (or hosting third-party workloads on GPU infrastructure), the GHOST kit poses a dual-layer business risk: immediate resource theft — someone else mines cryptocurrency on your hardware — and deeper compromise, where the kit's container-escape suite, persistence depth, and credential-harvest functions open a follow-on access vector inside the tenant boundary.

### Understanding the Real-World Impact

A successful compromise hands the operator three operational outcomes, each observable in the captured artifacts and each readable directly from the kit's design:

1. **GPU compute hijacking on the victim's hardware** — the primary financial-motivation outcome. The kit configures both XMR (Monero) mining via xmrig and Conflux Octopus-algorithm mining via lolMiner, with A100-tier GPU targeting indicated by the 8-12x consumer-GPU hashrate yield on the Conflux pool. Victim cloud bills accrue at the GPU instance billing rate while the operator collects the mining revenue.
2. **Hidden persistence with anti-removal tradecraft** — the 5-vector persistence chain plus `chattr +i` immutable flags plus scatter-copy redundancy across 5+ locations plus inotify_guard watchdog daemon makes standard remediation (delete the file, reboot) ineffective. A defender who cleans one persistence vector and reboots will find the rootkit re-establishing itself from another vector via the watchdog process.
3. **Container-escape capability into the cloud tenant** — the 4 container-escape variants (cgroup release_agent + bind-mount + nsenter via host PID + Docker socket abuse) mean that a successful exploit of ComfyUI inside a container can elevate to the cloud tenant's host. For multi-tenant cloud GPU providers, this changes the blast radius of a single ComfyUI compromise from a single tenant to the underlying host.

### Impact Scenarios

The following scenarios are derived from observed kit capabilities. Each is **observable** in the captured artifacts — not speculative.

| Scenario | Likelihood | Explanation |
|---|---|---|
| GPU compute hijacking on exposed ComfyUI host | HIGH | This is the kit's primary objective. Any ComfyUI host with port 8188 reachable from the public internet, no authentication enabled, and a vulnerable Manager / CSRF surface is in the target population (4,573 IPs in the operator's scan corpus). |
| Hidden cryptocurrency mining undetected by AV | HIGH | 6-week post-Censys VT snapshot: zero AV vendor signatures. The kit operates below standard AV-detection-pipeline trigger volume. Defenders relying solely on AV file-scanning will not detect this kit. |
| Standard remediation fails (one-vector cleanup leaves rootkit alive) | HIGH | 5-vector persistence + chattr +i + scatter copies + inotify_guard watchdog. A defender who deletes `/etc/ld.so.preload` and reboots will find the rootkit re-established from another vector within minutes. |
| Container escape into cloud tenant host | MODERATE | 4 container-escape variants present in code; real-world execution depends on the specific container runtime configuration (cgroup hierarchy version, Docker socket exposure, namespace isolation). Code-level intent: DEFINITE. Real-world success rate: variable. |
| Lateral movement into adjacent cloud-tenant workloads | MODERATE | If container escape succeeds, the kit's `_anti_hisana` competitor-displacement function and SSH-key harvest (T1552.004) provide both deconfliction (other miners killed) and follow-on credential access for adjacent workloads. |
| Operator-set MIRROR Telegram bot used for exfiltration | MODERATE | The operator-set MIRROR bot (8315596543 for Operator-A) is a configurable channel. The bot API surface supports arbitrary message content, which would enable repurposing for data exfiltration if an operator chose to do so (LOW-confidence indication based on Telegram Bot API capability, not on observed behavior); current observed usage is mining-stats reporting only. |
| AV detection gap persists 6+ weeks post-disclosure | HIGH | Structural: custom kits with low telemetry volume operate below AV vendor automated analysis pipeline triggers. Without active community submission of samples or vendor-side hunt for the OWNER Telegram bot signature, the gap persists. |

### Operational Impact Timeline (If a Host Is Compromised)

The phases below describe the **categories of work** required to investigate and remediate, in priority order. Per The Hunters Ledger's third-party intelligence provider perspective, no organization-specific procedures, vendor-product configurations, compliance timelines, or cost estimates are included — those decisions belong to the responding organization's incident response team.

- **Initial Phase — Confirm and contain.** Verify `/etc/ld.so.preload` contents; verify `libpam_cache.so` presence under `/lib/security/` or sibling locations; capture the ELF binary for forensic preservation (file is small — 14,568 bytes — but check `chattr -i` first to clear the immutable flag). Isolate the host from peer hosts in the same tenant boundary. If the host is a container, isolate at the container-runtime level **and** at the host level — assume the container-escape variants have already executed unless forensic evidence confirms otherwise (the kit attempts all 4 escape variants on installation; success of any one is sufficient for host-level compromise).
- **Investigation Phase — Identify all persistence vectors.** Enumerate all 5 known persistence locations (`/etc/ld.so.preload`, `/etc/systemd/system/systemd-journal-flush.service`, `$HOME/.config/systemd/user/fontconfig-cache.service`, `/etc/init.d/fontcache`, crontab `/var/spool/cron/.font_*`, shell-RC injection in `~/.bashrc` / `~/.profile`). Hunt the bash history for the OWNER and MIRROR Telegram bot token regex. Hunt ComfyUI custom_nodes directories for the `PerformanceMonitor` class signature. Pull and preserve any other operator scripts present in the same temp/spool/cache directories.
- **Remediation Phase — Rebuild the host from known-good media.** The combination of LD_PRELOAD libc-hook rootkit + 5-vector persistence + chattr +i immutable + scatter copies + container escape is collectively beyond reliable surgical cleanup. The defensible position is full host rebuild from known-good media with credential rotation for any service accounts that had keys on the compromised host. Targeted cleanup is viable only if **every** persistence vector has been enumerated with confidence — and the inotify_guard watchdog mechanism makes that confidence difficult to obtain.
- **Enhanced Monitoring Phase — Hunt for kit-author OWNER bot signature across the environment.** A single GHOST customer often implies more — the kit-sales business model produces a non-trivial probability that other hosts in the same organization (or peer organizations on the same hosting provider) are running the kit (MODERATE-confidence indication based on the commodity-kit distribution model documented in Section 3). Deploy the YARA / Sigma / Suricata rules from Section 10 across the broader environment.
- **Ongoing — Audit ComfyUI exposure and container-runtime configuration.** If ComfyUI was the initial-access vector, harden ComfyUI deployment (authentication, restricted listen address, Manager component restricted to localhost). If a container was involved, audit cgroup release_agent permissions, bind-mount surface, Docker socket exposure, and the configuration that allowed `nsenter` via host PID.

---

## 3. Technical Classification

GHOST is a composite cryptojacking *kit* — a userland LD_PRELOAD rootkit, a ComfyUI exploitation framework, a Hysteria v2 backdoor, and legitimate mining binaries, glued by a 1,338-line installer and distributed through a 4-tier supply chain. The subsections below establish its structure and place it against peer threats in the cryptojacking ecosystem.

### Classification & Identification

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 50%;">
<col style="width: 20%;">
</colgroup>
<thead>
<tr><th>Attribute</th><th>Value</th><th>Confidence</th></tr>
</thead>
<tbody>
<tr><td>Malware Type</td><td>Composite cryptojacking platform — userland LD_PRELOAD rootkit + ComfyUI exploitation framework + Hysteria v2 backdoor + 4-tier supply chain</td><td>DEFINITE</td></tr>
<tr><td>Primary Family</td><td>GHOST cryptojacker kit (v5.1 "Anti-Hisana + Resurrection + Spread + Escape"; v6.0 "Domination Edition" referenced by Censys but not captured)</td><td>DEFINITE</td></tr>
<tr><td>Component Inventory</td><td>(1) GHOST kit shell suite (ghost.sh, hyst.sh, min1.sh, check_comfyui.sh, get_all_ranges.sh); (2) libpam_cache.so LD_PRELOAD rootkit; (3) Python ComfyUI exploitation framework (py.py, scan.py); (4) Hysteria v2 QUIC backdoor; (5) xmrig + lolMiner legitimate-upstream mining binaries; (6) UnamWebPanel PHP admin panel (UnamSanctam upstream OSS)</td><td>DEFINITE</td></tr>
<tr><td>Sophistication (kit layer)</td><td>Intermediate-to-Advanced — multi-component architecture, 4 container-escape variants, dual-Telegram supply-chain monitoring, userland rootkit with self-hide capability, competitor displacement against rival Hisana</td><td>HIGH</td></tr>
<tr><td>Sophistication (operator layer)</td><td>Variable — Operator-A higher-OPSEC (self-hosted pool proxies); Operator-B lower-OPSEC (public-pool usage, abandoned host)</td><td>HIGH</td></tr>
<tr><td>Threat Actor Type</td><td>Kit author + customer operators (commodity-kit business model)</td><td>HIGH</td></tr>
<tr><td>Primary Motivation</td><td>Financial — GPU compute hijacking for XMR + CFX cryptocurrency mining revenue</td><td>HIGH</td></tr>
<tr><td>Target Profile</td><td>Exposed ComfyUI / Stable-Diffusion / ML-inference services on cloud GPU infrastructure (especially A100-tier); 14+ cloud-provider IP ranges enumerated via `get_all_ranges.sh`</td><td>HIGH</td></tr>
<tr><td>Campaign Complexity</td><td>Multi-family / loader-chain — 4-tier supply chain spanning OSS upstream + kit author + customer operators + victims</td><td>HIGH</td></tr>
</tbody>
</table>

### Kit File Identifiers (Primary Components)

The full structured IOC inventory is in the separate IOC feed file (link in Section 8). The summary below covers the primary kit components by SHA-256.

| Component | Filename | SHA-256 (truncated) | Size | VT Detections |
|---|---|---|---|---|
| LD_PRELOAD rootkit (binary) | `libpam_cache.so` | `eaaa10c8...12bb7301` | 14,568 B | 0/0 (never submitted) |
| LD_PRELOAD rootkit (source) | `libpam_cache.c` | `edafde0d...e811e6cff` | 2,636 B | Not in VT |
| GHOST kit installer (Operator-A) | `ghost.sh` | `e943b581...9fec56ba` | 45,289 B | 13/63 (generic only) |
| Hysteria v2 backdoor wrapper | `hyst.sh` | `822afb1f...a3894c5c` | 8,670 B | Not in VT |
| Miner installer w/ dual Telegram | `min1.sh` | `008bc5ab...e2a2c46f6` | 4,280 B | 0/53 (undetected) |
| ComfyUI target verifier | `check_comfyui.sh` | `dc232b55...862213a1d` | 974 B | Not in VT |
| Cloud IP-range scraper | `get_all_ranges.sh` | `9023734a...d04bd93e` | 3,007 B | Not in VT |

**The libpam_cache.so MD5 296a800564111b0bad9fe63faf4e63ba is byte-identical across both operator hosts (77.110.96.200 and 77.110.125.145).** This is the central evidence anchor for the kit-sales business model.

### Why This Is a Commodity-Kit Family, Not a Single-Operator Campaign

Five structural indicators distinguish a commodity-kit family from a single-operator campaign:

1. **Byte-identical binary across customers.** A bespoke single-operator campaign would compile per-target; a commodity kit ships a pre-built artifact. GHOST is the latter (DEFINITE evidence).
2. **Per-customer config delta of exactly 17 bytes.** The ghost.sh installer differs between Operator-A and Operator-B copies in 17 bytes — the wallet addresses, pool URLs, and `PIP_PAYLOAD_REPO` GitHub URL. Every other byte is identical. This is the signature of a config-substitution distribution model, not per-customer source modification.
3. **Kit-author OWNER Telegram bot baked into every customer deployment.** The OWNER bot (8415540095) is hardcoded — operators do not configure it; the kit author controls it. This is structurally inconsistent with a single-operator scenario (the operator would not give themselves an OWNER and a MIRROR bot using different tokens; they would consolidate).
4. **Kit-author identity has separate cryptocurrency operation.** Vova75Rus mines XTM/Tari via Kryptex worker `1238rkM7gGg3sl`. Operator-A mines XMR (4BBj3gj4...) + CFX (cfx:aaj5xb...). Different cryptocurrencies, different pools, different destinations. A single actor would not maintain two parallel mining setups with distinct telemetry.
5. **Externally advertised version number.** The first line of `ghost.sh` reads `# GHOST v5.1 (Anti-Hisana + Resurrection + Spread + Escape)`. Single-operator campaigns rarely version their tooling externally; commodity-kit authors do because the version is a market-differentiation signal.

### Comparison to Peer Cryptojackers

**GHOST and Koske are different families — do not conflate them**, even though both use the LD_PRELOAD `readdir()` hijack technique (Koske: Aquasec/SOC Prime/Picus/Dark Reading coverage 2025-2026). Koske is delivered via panda-image polyglot files, exploits JupyterLab, and carries an AI-generated codebase signature. GHOST is delivered via direct script-pull from open directories, exploits ComfyUI, and shows a manually-coded structure (no AI-generated code signature in any component reviewed).

The GHOST kit's `_anti_hisana` competitor-displacement function references "Hisana", a rival cryptojacker known only through GHOST kit artifact references. Hisana has zero independent public threat intelligence; it exists in the public record only as the named target of GHOST's competitor-displacement code (`kill_list.patterns` regex matches `xmrig|xmr-stak|sysagentd|kdevtmpfsi|kerberods|bioset|stratum|cryptonight|randomx|etchash|2miners|rigel|sysdaemon|kryptex`) and the port-10808 C2 port referenced in `ghost.sh`. This is an intelligence gap — independent Hisana coverage is not available.

### Why This Is Professional-Grade (Kit-Layer)

The kit-author tier shows several indicators consistent with professional development:

- **Multi-component architecture with clean separation.** Shell installer, ELF rootkit, Python exploitation framework, QUIC backdoor — distinct components glued by the orchestrator script rather than monolithic.
- **Self-hide capability with comprehensive hide-list.** 27 strings (binary names, paths, wallet prefixes) and 9 ports filtered at the libc layer. This is not opportunistic; it is a planned signature-minimization architecture.
- **4 container-escape variants.** Three would suggest "tried what worked"; four with distinct techniques (cgroup release_agent, bind-mount, nsenter, Docker socket) suggests deliberate coverage of common container configurations.
- **Cross-process resurrection via inotify_guard.** A watchdog daemon that recreates deleted persistence components from scatter copies is a defender-aware design.
- **Competitor displacement before installation.** The `_anti_hisana` function and `kill_list.patterns` regex run before the kit installs — ensuring the operator's mining workload has exclusive use of the GPU and the kit's hide-list does not collide with a rival miner's process names.
- **Dual-Telegram supply-chain monitoring.** The OWNER + MIRROR architecture is structurally a SaaS-vendor telemetry model applied to a malware kit. This is a kit-business design, not a single-operator improvisation.

---

## 4. Technical Capabilities Deep-Dive

The capabilities below build the hidden, persistent cryptojacking outcome summarized in §1: a libc-hook rootkit hides processes/files/ports from standard tooling, a 5-vector chain plus immutable flags and a cross-process watchdog make full host rebuild the defensible remediation, and container-escape variants reach into cloud-tenant boundaries. Each capability's confidence is in the matrix; the subsections that follow give the evidence.

### Capabilities Matrix

| Capability | Impact | Detection Difficulty | Confidence |
|---|---|---|---|
| LD_PRELOAD libc-hook rootkit (libpam_cache.so) | HIGH — process/file/port hiding | HARD (libc-layer hooks) | DEFINITE |
| 5-vector persistence chain | HIGH — survives single-vector cleanup | MODERATE | DEFINITE |
| 4 container-escape variants | HIGH — cloud tenant escape | MODERATE | HIGH |
| Hysteria v2 QUIC backdoor (bing.com SNI) | MEDIUM — covert remote access | HARD (SNI masquerade) | HIGH |
| ComfyUI fake-custom-node persistence (PerformanceMonitor) | HIGH — Python-runtime persistence | MODERATE | DEFINITE |
| Cloud IP-range enumeration (14+ providers) | MEDIUM — target population scaling | EASY (network signature) | DEFINITE |
| Dual-Telegram supply-chain monitoring | LOW direct impact / HIGH detection value | EASY (string + URL pattern) | DEFINITE |
| Competitor displacement (_anti_hisana + kill_list) | LOW — GPU dedication for operator | MODERATE | DEFINITE |
| Self-hosted XMR/CFX pool proxies (Operator-A only) | MEDIUM — wallet-layer attribution break | EASY (port signature) | DEFINITE |
| Multi-cloud target enumeration via bgpview.io | MEDIUM — campaign scaling | EASY (network signature) | DEFINITE |

### 4.1 libpam_cache.so LD_PRELOAD Rootkit

> **Analyst note:** This subsection covers the kit's userland rootkit — a small shared library (~14 KB) that, when loaded into every process on the system via the LD_PRELOAD mechanism, intercepts standard C library calls so that certain processes, files, and network ports become invisible to common diagnostic tools (`ps`, `ls`, `ss`, `netstat`). It is **not** a kernel-mode rootkit and **not** a PAM authentication backdoor despite the misleading filename. The hide-list (27 strings + 9 ports) is the structural fingerprint of the kit family.

**Confidence:** DEFINITE — full source code (98 lines of C) and byte-identical ELF binary pulled from open directories on both customer hosts.

**Technical mechanism.** LD_PRELOAD is a standard userland mechanism: a path-list environment variable that tells the dynamic linker (a userland process-loading component that resolves shared-library symbols at runtime) to load specified shared objects ahead of system libraries when starting any new process. When the dynamic linker resolves a symbol like `readdir`, it returns the LD_PRELOAD-loaded library's version if one exists. The GHOST kit writes `/lib/security/libpam_cache.so` (the deceptively-named rootkit) to `/etc/ld.so.preload` (a system-wide configuration file). From that point forward, every new process on the system loads the rootkit's hook functions before the real libc functions.

**Hooked functions.** Four libc calls are intercepted: `readdir` (32-bit directory enumeration), `readdir64` (64-bit directory enumeration), `fopen` (file open), and `fopen64` (large-file fopen). The rootkit's hook functions call the real libc functions, then filter the results against the hide-list before returning to the caller.

**Hide-list inventory.** 27 strings + 9 ports. The 27 strings cover three categories:

- **Miner binary names:** `xmrig`, `lolMiner`, `lolminer`, `khugepaged_` (disguised binary name with deliberate trailing underscore), `nv_uvm_` (NVIDIA kernel-module camouflage)
- **Kit paths:** `fontconfig/.cpu`, `fontconfig/.gpu`, `.pid_guard`, `libpam_cache`, `inotify_guard`, scattered persistence locations
- **Operator wallet prefixes:** `4BBj3gj4` (Operator-A XMR wallet first-8), `cfx:aaj5xb` (Operator-A CFX wallet first-9) — these are **per-customer** insertions that bake the operator's wallet identity into the rootkit's filter

The 9 ports cover the mining pool service ports (`:3333`, `:4444`, `:5555`, `:7777`, `:8027`, `:8029`, `:9999`) and the Hysteria v2 QUIC ports (`:14433`, `:14444`). The hide-port format string is `:%04X` (uppercase 4-hex-digit zero-padded) — matching the format used in `/proc/net/tcp` which displays port numbers in hex. (The Hysteria admin panel port `:3301` is a separate listening-port reference in `hyst.sh` and is not part of the rootkit's hide-port array.)

**What this means in practice.** A SOC analyst running `ps aux | grep xmrig` on a compromised host sees zero results. `ls /lib/security/` does not list `libpam_cache.so`. `cat /proc/net/tcp` does not show the mining pool connections. `ss -tlnp` does not show the Hysteria admin panel listener. The host appears clean to standard tooling — but the underlying behavior is unchanged. Mining continues; C2 traffic continues; container escape opportunities are unhidden because they happen at the kernel level below the rootkit's userland hooks.

**Why the libpam_cache filename is deceptive.** The naming convention `libpam_*` is the standard Linux PAM (Pluggable Authentication Modules) module naming pattern. A defender encountering `libpam_cache.so` under `/lib/security/` will reasonably treat it as a legitimate PAM module on first inspection — PAM stack modules live under `/lib/security/`, `/lib/x86_64-linux-gnu/security/`, or `/usr/lib/security/`, and the filename convention matches. Direct source inspection of the 98-line C source refutes the PAM-module reading entirely: zero PAM symbols, zero `pam_authenticate` / `pam_handle_t` / `pam_acct_mgmt` references, zero authentication-flow code. The filename is masquerade only (MITRE T1036.005 — Match Legitimate Name or Location).

**Why this is significant.** Most defenders' mental model for "rootkit" is a kernel-mode rootkit that requires kernel exploitation, kernel module loading privileges, or a kernel-vulnerability chain. The LD_PRELOAD libc-hook rootkit pattern requires none of these — only the ability to write `/etc/ld.so.preload` (root-equivalent file write). The detection profile is fundamentally different: no `lsmod` entry, no kernel symbol table entries, no kernel taint flag. Standard rootkit-detection tools that focus on kernel-mode artifacts will miss this entire family.

**Byte-identical across customers is the central evidence anchor.** Both 77.110.96.200 and 77.110.125.145 ship the **same** MD5 296a800564111b0bad9fe63faf4e63ba binary. The per-customer wallet-prefix hide strings (`4BBj3gj4` for Operator-A vs the absence of Operator-A's prefix for Operator-B, and Operator-B's `46a5osgf` substituted in) are present **as static strings inside the binary** — the kit author pre-compiles per-customer binaries with these strings baked in, **not** per-victim. Operator-B's binary on disk is the operator's customer copy as shipped by the kit author. This proves the kit-author tier exists structurally, regardless of how many operators are observed downstream.

**Detection strategy.** YARA rules in Section 10 detect the rootkit on three axes: (1) the combination of `readdir` + `fopen` exports in an ELF64 shared object, (2) the GHOST-specific hide-list strings (`khugepaged_`, `nv_uvm_`, `inotify_guard`, `libpam_cache`), and (3) the hide-port format string `:%04X`. A Sigma rule covers `/etc/ld.so.preload` write events from auditd. A separate Sigma rule covers `libpam_cache.so` creation under any `/lib/*/security/` directory. The detection-engineer also derived behavioral rules for the watchdog process name `inotify_guard` (a process whose name should not appear on legitimate Linux systems).

### 4.2 GHOST Kit Shell-Script Suite

> **Analyst note:** This subsection covers the kit's outer shell orchestration — the bash scripts that handle installation, payload fetch, miner configuration, Hysteria v2 backdoor setup, ComfyUI target verification, and cloud-provider IP-range enumeration. The 1,338-line `ghost.sh` installer is the central orchestrator; the other scripts are operator-facing wrappers. Russian-language operator commentary in `hyst.sh`, `min1.sh`, `check_comfyui.sh`, and `get_all_ranges.sh` is what attributes those scripts to the operator (vs. the kit author).

**Confidence:** DEFINITE — full scripts captured.

**`ghost.sh` (45,289 bytes / 1,338 lines / 43 functions).** The kit's central installer. Captured on both 77.110.96.200 (full SHA-256 `e943b581...9fec56ba`) and 77.110.125.145 (SHA-256 prefix `025d683b...`). The two copies differ in exactly 17 bytes — the wallet addresses, mining pool URLs, and `PIP_PAYLOAD_REPO` GitHub URL — confirming the per-customer config-substitution distribution model.

Key functions (43 total):

- `_anti_hisana` — competitor displacement against the rival Hisana cryptojacker (port 10808 references; wallet-hijack-detect logic)
- `_compile_hide_so` — rootkit-build function. **In practice this is dead code:** the .so ships pre-built from the kit author and is not actually compiled on the victim. The function exists for completeness; the byte-identical binary across customers proves the actual delivery is pre-compiled.
- `_container_escape` — container-escape orchestrator that dispatches to one of 4 variants
- `_escape_via_cgroup` — cgroup release_agent escape variant (T1611)
- `_escape_via_mount` — bind-mount escape variant
- `_escape_via_nsenter` — nsenter via host PID escape variant
- `_escape_via_socket` — Docker socket abuse escape variant
- `kill_list.patterns` — competitor regex (`xmrig|xmr-stak|sysagentd|kdevtmpfsi|kerberods|bioset|stratum|cryptonight|randomx|etchash|2miners|rigel|sysdaemon|kryptex`)
- `_install_persistence` — orchestrates the 5-vector persistence chain (covered in Section 4.5)
- `_setup_hysteria` — Hysteria v2 backdoor installation (covered in Section 4.5)

The first line of `ghost.sh` is the kit-author self-identification comment: `# GHOST v5.1 (Anti-Hisana + Resurrection + Spread + Escape)`. Censys references a v6.0 "Domination Edition" but no v6.0 sample was captured in this investigation; v6.0 capability differences relative to v5.1 are unknown.

**`hyst.sh` (8,670 bytes).** Hysteria v2 backdoor installation wrapper. Russian-language operator commentary (10 Cyrillic words including ИТОГО, Запуск, Перезапуск). Installs the Hysteria v2 server binary, generates random credentials at `/tmp/.hy2_password`, `/tmp/.hy2_port`, `/tmp/.hy2_uri`. Admin panel callback at `http://77.110.96.200:3301` (Operator-A's host). bing.com SNI masquerade configured.

**`min1.sh` (4,280 bytes).** Miner-only installer with the dual-Telegram architecture. Russian-language commentary. **Operator-A's most-modified file** (Last Modified 2026-05-24T17:10:29Z — same day as analysis, 47 days post-Censys). The presence of both OWNER bot 8415540095 (kit-author-baked) and MIRROR bot 8315596543 (operator-set) in the same file is the structural signature of the dual-monitoring architecture. VT detection: 0/53 — undetected by every AV vendor 6 weeks after the Censys disclosure.

**`check_comfyui.sh` (974 bytes).** Operator-A ComfyUI target verification script. Russian-language (4 Cyrillic words including ИТОГО, Найдено). Performs HTTP GETs against `<target>:8188/system_stats` and `<target>:8188/queue` to confirm ComfyUI presence and queue accessibility before payload deployment.

**`get_all_ranges.sh` (3,007 bytes).** Operator-A cloud IP-range scraper. Russian-language (4 Cyrillic words). Queries `bgpview.io` for 12 cloud-provider ASNs (Lambda Labs, Datacrunch, Nebius, Hetzner, Linode, OVH, Scaleway, Tencent, Contabo, AEZA, Huawei, DigitalOcean) plus official Oracle and Google IP-range JSON URLs. The output feeds the ComfyUI scanner pipeline.

### 4.3 Python ComfyUI Exploitation Framework

> **Analyst note:** This subsection covers the kit's exploitation layer — two large Python files (~75 KB and ~63 KB) implementing the ComfyUI port-8188 scanner and the post-exploitation payload deployment. The "PerformanceMonitor fake custom node" pattern uses ComfyUI's legitimate plugin-loading mechanism (NODE_CLASS_MAPPINGS) to register a malicious class that runs every time ComfyUI loads; this provides Python-runtime persistence inside the ComfyUI process itself, separate from the OS-level 5-vector persistence chain.

**Confidence:** DEFINITE — both Python files captured from Operator-A's open directory.

**`py.py` (74,844 bytes).** Python ComfyUI exploitation framework. Kit-author component. Contains the `PerformanceMonitor` class registered into `NODE_CLASS_MAPPINGS` (a ComfyUI dictionary that maps custom-node class names to their implementations). When ComfyUI loads custom nodes at startup, it walks `NODE_CLASS_MAPPINGS` and instantiates each class. The malicious `PerformanceMonitor` class runs its constructor at every ComfyUI startup, providing Python-runtime persistence inside the ComfyUI process.

Key kit-author functions in py.py:

- `plant_backdoor_node` — registers the `PerformanceMonitor` class into the custom_nodes directory
- `_build_python_fetcher` — builds the Python payload-fetcher logic referencing the per-operator `PIP_PAYLOAD_REPO` GitHub URL (the 17-byte per-customer config delta)
- `PerformanceMonitor` class definition with `NODE_CLASS_MAPPINGS` registration

The fact that `py.py` lives at both `/sc/py.py` (Operator-A's full path) and `/c/py.py` (byte-identical duplicate) on the same host shows operator-side scatter-copy redundancy. Same file, two paths — the operator does not trust a single location.

**`scan.py` (63,443 bytes — slow cadence variant; 29293e3c... is a faster variant with 1-hour rescan).** Python ComfyUI scanner. Two cadence variants observed: a slow ~3-4 hour rescan cadence (at `/sc/scan.py`) and a faster ~1 hour aggressive cadence (at `/123/scan.py`). Both scan port 8188 across the IP corpus produced by `get_all_ranges.sh`. The scanner outputs target lists referencing `q10.txt` / `q11.txt` payload corpora.

**`q10.txt` and 4,573-IP scope correction.** The `q10.txt` file (4,573 IPs) was initially read as a victim list. Phase 16 forensic review (Section 13 retraction) confirmed `q10.txt` is the **operator's loose target candidate list** of port-8188-responsive hosts — not a confirmed-compromised victim list. The narrower confirmed-vulnerable population is 78 high-confidence ComfyUI hosts (21 Tier-A confirmed-vulnerable + 57 Tier-B exposed-but-unconfirmed). Alibaba Cloud (9 unique IPs, 6 Tier-A) is the highest-density confirmed-vulnerable provider in the corpus.

**Detection strategy for ComfyUI defenders.** Audit `custom_nodes/` directories for any Python file containing both `class PerformanceMonitor` and `NODE_CLASS_MAPPINGS` (Sigma rule MAL_GHOST_ComfyUI_PerformanceMonitor_Node in Section 10). If ComfyUI is exposed to the public internet on port 8188, this combination is the GHOST persistence signature.

### 4.4 Container-Escape Suite (4 Variants)

> **Analyst note:** This subsection covers the kit's container-escape capability — four distinct techniques for elevating from inside a Linux container (e.g., a ComfyUI Docker container running on a cloud GPU instance) to the underlying host. The four variants cover the common misconfiguration surfaces. Real-world success depends on the specific container runtime configuration (cgroup version, mounted paths, exposed sockets, namespace isolation).

**Confidence:** HIGH on code-level intent (4 variants present in `ghost.sh`); MODERATE on real-world execution success rate (depends on host configuration).

**Variant 1: cgroup release_agent abuse (`_escape_via_cgroup`).** Writes a binary path to a cgroup's `release_agent` file. When the cgroup's last process exits, the kernel executes the specified binary **on the host**, not in the container. Requires cgroup v1 with writeable `release_agent` exposed from the container. MITRE T1611.

**Variant 2: bind-mount escape (`_escape_via_mount`).** Exploits container runtimes that allow bind-mounting the host filesystem into the container (commonly `/var/run/docker.sock` or `/`). Writes attacker payloads to host paths visible through the bind-mount, then triggers their execution on the host.

**Variant 3: nsenter via host PID (`_escape_via_nsenter`).** Uses the `nsenter` command to enter another process's namespaces — specifically PID 1 on the host (kernel-thread `kthreadd` or systemd). If the container shares the host PID namespace (`--pid=host`) or the kernel allows the unshare/setns syscalls from inside the container, the attacker enters the host's namespaces and runs commands as if on the host.

**Variant 4: Docker socket abuse (`_escape_via_socket`).** If `/var/run/docker.sock` is mounted into the container (common in CI/CD container patterns), the attacker can issue Docker API commands from inside the container — including `docker run --privileged -v /:/host` to spawn a new privileged container with the host filesystem mounted.

**Defender implication.** For cloud-GPU multi-tenant environments running ComfyUI inside containers, any of these four variants succeeding elevates a single-tenant compromise to a host-level compromise, potentially affecting all tenants on the same host. The kit attempts all four variants in sequence — defender mitigation requires hardening **all four** surfaces, not just one. Runtime-layer detection of container-escape attempts (T1611) falls to dedicated runtime-security tooling rather than generic Sigma or YARA; the detection file's Coverage Gaps section notes this explicitly and identifies the appropriate tool categories for T1611 coverage.

### 4.5 Hysteria v2 Backdoor + 5-Vector Persistence

> **Analyst note:** This subsection covers the kit's covert remote-access channel (Hysteria v2, a QUIC-over-UDP proxy/backdoor protocol that uses TLS SNI masquerade — making the traffic look like normal HTTPS to bing.com on standard network monitoring) and the 5-vector persistence chain that ensures the kit survives reboots and standard remediation attempts.

**Confidence:** HIGH — Hysteria v2 installer captured, persistence chain enumerated in `ghost.sh`.

**Hysteria v2 backdoor.** Hysteria v2 is a legitimate-upstream open-source QUIC-based proxy server (designed for high-latency network conditions); the GHOST kit deploys it as a backdoor. UDP 14433 + 14444 listener with bing.com SNI in the QUIC TLS handshake. HTTP admin panel on TCP 3301 (the panel's default credentials are admin/pickmezr per Censys documentation; this investigation confirmed the same). The credentials are stored in `/tmp/.hy2_password` plaintext; the URI is at `/tmp/.hy2_uri`.

Why bing.com SNI matters: a network monitoring tool that inspects TLS handshakes (or QUIC ClientHello) will see SNI = bing.com. Without explicit SNI-vs-destination correlation logic, that tool will not flag the mismatch between the SNI (Microsoft) and the destination IP (the operator's host on AEZA), and the traffic will pass as legitimate bing.com HTTPS — most commodity network monitoring stacks lack SNI-vs-destination correlation by default.

**5-vector persistence chain.** The kit installs persistence at five independent locations to ensure that no single-vector cleanup attempt removes the malware:

1. **`/etc/ld.so.preload`** — primary LD_PRELOAD entry pointing to `libpam_cache.so`
2. **systemd system unit** — `/etc/systemd/system/systemd-journal-flush.service` (masquerading legitimate systemd unit name)
3. **systemd user unit** — `$HOME/.config/systemd/user/fontconfig-cache.service` (per-user persistence even if system-level cleanup occurs)
4. **System V init script** — `/etc/init.d/fontcache` (covers older distros or hosts with both systemd and sysv-init present)
5. **Crontab + shell-RC injection** — `/var/spool/cron/.font_<random>` + injection into `~/.bashrc` / `~/.profile`

**Scatter-copy redundancy.** Beyond the 5 persistence vectors, the rootkit binary itself is scatter-copied to multiple locations:

- `$HOME/.local/share/.cache/fontconfig/` (XDG-fontconfig camouflage)
- `/etc/udev/hwdb.d/.backup-cache`
- `/var/spool/cron/.font_<random>`

**Immutable flag protection.** Each persistence file is chmod-protected with `chattr +i` (Linux immutable extended attribute). A defender attempting `rm /etc/ld.so.preload` will see `Operation not permitted` even as root — the file must first be chattr-cleared (`chattr -i`) before it can be deleted. Defenders unfamiliar with extended attributes will likely misread the EPERM error as a permissions issue rather than recognize it as an immutable-flag block (MODERATE-confidence indication based on common SOC analyst familiarity patterns — the `chattr` toolchain is a less-common subset of Linux administrative knowledge than `chmod` / `chown`).

**inotify_guard watchdog daemon.** A separate daemon process named `inotify_guard` (one of the rootkit's hidden process names, present in the hide-list) uses Linux inotify to watch the persistence file paths. When any persistence file is deleted, the watchdog detects the inotify event and re-creates the persistence file from a scatter-copy source. The watchdog runs in a separate process from the rootkit itself; killing the rootkit process does not kill the watchdog.

**Cross-process resurrection.** The combined effect: a defender who runs `chattr -i /etc/ld.so.preload && rm /etc/ld.so.preload && reboot` will find `/etc/ld.so.preload` re-created from a scatter copy via the inotify_guard watchdog within minutes of system startup. Eradication requires enumerating **all** persistence vectors, killing the watchdog, and removing scatter copies in a single coordinated action — or rebuilding the host from known-good media.

### 4.6 Multi-Cloud Target Enumeration

> **Analyst note:** This subsection covers the kit's victim-discovery pipeline — the cloud-provider IP-range enumeration that feeds the ComfyUI port-8188 scanner. The operator does not scan the entire IPv4 space; instead, the kit narrows scanning to IP ranges belonging to specific cloud GPU providers (especially A100-tier providers) before probing for ComfyUI. This targeting model is what makes the campaign GPU-cloud-focused rather than internet-wide.

**Confidence:** DEFINITE — `get_all_ranges.sh` captured with explicit ASN list.

**Target ASN inventory (16+ providers).** From `get_all_ranges.sh`:

- **A100-tier specialized GPU providers:** Lambda Labs, Datacrunch, Nebius
- **Hyperscalers:** AWS, GCP, Oracle, Tencent
- **Mid-tier cloud:** Hetzner, OVH, Scaleway, DigitalOcean, Linode, Huawei
- **Budget hosting:** Contabo, AEZA
- **Sources:** `bgpview.io/asn/<asn>/prefixes` for 12 ASNs + Oracle's official `cloud-public-ip-ranges.json` + Google's `cloud.json`

**Why A100-tier matters.** A100 GPUs running the lolMiner Octopus algorithm against Conflux (CFX) yield 8-12x the hashrate of consumer-grade GPUs. The CFX-Octopus / A100 combination is specifically high-margin for the operator. The Conflux blockchain is liquid on multiple exchanges (Binance, OKX, Gate.io, KuCoin, MEXC, Kraken) providing the off-ramp.

**ComfyUI scanner pipeline.** `get_all_ranges.sh` → IP corpus → `scan.py` probes port 8188 → `check_comfyui.sh` verifies `/system_stats` and `/queue` endpoints → vulnerable hosts go to `q10.txt` / `q11.txt` → exploitation payload deployment. The slow-cadence variant (~3-4 hour rescan) and aggressive variant (~1 hour rescan) likely represent different operational phases.

**Detection at the network level.** Egress DNS to `bgpview.io` from a non-research host is anomalous. HTTP GETs to `cloud.google.com/.../cloud.json` or `docs.oracle.com/.../cloud-public-ip-ranges.json` from a server (rather than a developer workstation) similarly suggest target-enumeration activity. Sigma rule MAL_GHOST_BGPView_Cloud_Range_Enumeration in Section 10 covers this pattern.

### 4.7 Dual-Telegram Supply-Chain Architecture

> **Analyst note:** This subsection covers the kit's most distinctive analytical finding — the dual-Telegram bot architecture in which the kit author maintains an OWNER bot baked into every customer deployment (providing kit-author visibility into all downstream customer operations) and each operator separately configures a MIRROR bot for their own monitoring. The OWNER bot is the highest-value detection string in the entire campaign because a single match catches every GHOST customer worldwide regardless of operator-side variation.

**Confidence:** DEFINITE — both bot tokens captured in `min1.sh`.

**OWNER bot 8415540095 (kit-author).** Baked into every customer GHOST kit deployment by Vova75Rus. The kit author receives Telegram notifications from every downstream operator's mining operations — providing real-time visibility into per-customer mining stats, wallet balances, victim host counts, and operational uptime. This is structurally a SaaS-vendor telemetry channel applied to a malware kit. The OWNER bot is **not** configurable by the operator; the operator-side `min1.sh` references the OWNER token as a hardcoded constant.

**MIRROR bot 8315596543 (Operator-A).** Operator-A's own visibility channel, named ЗЕРКАЛО — ТЫ ("Mirror — You" in Russian) in operator commentary. The MIRROR bot is operator-set and operator-controlled — providing the operator with the same kind of monitoring view the kit author gets via the OWNER bot. Operator-A's MIRROR token was typed in bash history without clearing — an OPSEC failure that confirmed Operator-A's ownership of the MIRROR bot (Section 9 attribution evidence).

**Why this matters analytically.** A single-actor scenario would not maintain two parallel Telegram-bot tokens with different IDs in the same script. The OWNER + MIRROR architecture only makes operational sense in a kit-sales business model where the kit author needs supply-chain visibility independent from each customer's operational visibility. The architecture itself is the structural fingerprint of the commodity-kit business model — and the OWNER bot token is the channel that catches every downstream customer.

**Why this matters operationally.** The OWNER bot is the kit-author-owned channel — disrupting it disrupts the kit-author's supply-chain monitoring across **all** customers globally. The MIRROR bot is operator-specific — disrupting it disrupts one customer only.

**Detection.** The single highest-value detection signature in this campaign: HTTPS request to `api.telegram.org/bot8415540095:*` from any host. Suricata rule MAL_GHOST_OWNER_Telegram_Bot_Indicator in Section 10. YARA byte-string match for `8415540095` in any binary or script catches deployments at-rest. Sigma rule for bash history matching the bot token regex catches operator-OPSEC failures across many cryptojacker families, not just GHOST.

---

## 5. Static Analysis Findings

> **Analyst note:** This section documents the static (file-on-disk, no execution) analysis of the kit's two most important artifacts — the libpam_cache.so ELF binary and the ghost.sh installer script. Static analysis here refers to file structure dissection, string extraction, and source-code review of the captured artifacts; no malware was executed on production infrastructure to produce these findings.

### 5.1 libpam_cache.so ELF Dissection

**File metadata.**
- Filename: `libpam_cache.so`
- SHA-256: `eaaa10c840de23335abae1a9ead0a6a7fb7be5187cd19ad05137feab12bb7301`
- MD5: `296a800564111b0bad9fe63faf4e63ba`
- Size: 14,568 bytes
- File type: ELF 64-bit LSB shared object, x86-64
- Compiler: GCC 13.3.0 (Ubuntu 24.04 LTS)
- libc requirement: GLIBC 2.34+ (matches Ubuntu 24.04 default)
- First seen on VT (host of derivative `libpam_cache.so` SHA `eaaa10c8...`): 2026-04-08T17:42:05Z
- VT detection: 0/0 (this specific hash never submitted to VirusTotal as of analysis date)

**Byte-identical across customer hosts.** The same MD5 (296a800564111b0bad9fe63faf4e63ba) was pulled from open directories on both 77.110.96.200 and 77.110.125.145. The two binaries are bit-for-bit identical. This is the central evidence anchor for the kit-sales business model (Section 3 and Section 9).

**Source-code availability.** Alongside the binary at `http://77.110.96.200/libpam_cache.c` (and the sibling host equivalent), the kit author ships the 98-line C source. Direct C-source inspection refutes any PAM authentication functionality: zero PAM symbols, zero `pam_authenticate` / `pam_handle_t` / `pam_acct_mgmt` references, zero authentication-flow code. The "pam" in the filename is masquerade only.

**Function exports of forensic interest:**

- `readdir` — hooks the standard glibc `readdir(3)` directory enumeration call
- `readdir64` — hooks the LFS-variant `readdir64(3)` for large-file mode
- `fopen` — hooks the standard glibc `fopen(3)` file open call
- `fopen64` — hooks the LFS-variant `fopen64(3)`
- Library constructor (`__attribute__((constructor))`) — runs `unsetenv("LD_PRELOAD")` to hide the LD_PRELOAD environment from inherited processes

**Embedded string inventory (forensically significant subset).** Strings extracted from the binary include the full hide-list inventory:

```
xmrig
lolMiner
lolminer
khugepaged_
nv_uvm_
fontconfig/.cpu
fontconfig/.gpu
.pid_guard
inotify_guard
libpam_cache
4BBj3gj4
cfx:aaj5xb
/proc/net/tcp
/proc/%s/cmdline
/proc/%s/exe
:%04X
LD_PRELOAD
```

The presence of `4BBj3gj4` (Operator-A XMR wallet first-8) and `cfx:aaj5xb` (Operator-A CFX wallet first-9) **as static strings in the binary** is the evidence that the kit author pre-compiles per-customer binaries with operator wallet prefixes baked in. Operator-B's copy of the binary substitutes Operator-B's wallet prefixes (`46a5osgf` for XMR; `cfx:aat5y` for CFX) in the same static-string locations.

**Source-code review highlights.** The 98-line C source is concise. Key implementation details:

- The hide-list arrays (`H[]` for strings, `P[]` for ports) are initialized at compile time, not loaded from a config file. This is what makes per-customer pre-compilation necessary.
- The `readdir`/`readdir64` hooks call the real libc version, then iterate the returned entries and filter against `H[]` by `strstr` substring match. Filtered entries are skipped; the hook returns the next non-matching entry to the caller.
- The `fopen`/`fopen64` hooks check if the requested filename is `/proc/net/tcp` (or its TCP6/UDP/UDP6 siblings). For those paths, the hook opens the real file, reads its contents into a buffer, filters out lines matching any `P[]` port entry (using `:%04X` format string to format candidate hex ports), then returns a `fmemopen`-backed FILE* containing the filtered contents to the caller.
- The library constructor immediately calls `unsetenv("LD_PRELOAD")` so that any child process spawned by the current process does not inherit the LD_PRELOAD environment. This means the rootkit auto-extends to direct children via `/etc/ld.so.preload` (system-wide) but does not propagate through environment inheritance. **Forensic implication:** memory-scanning tools that inspect process environments will find `LD_PRELOAD` absent from running processes even while the rootkit is actively loaded — the constructor strips the variable before any analyst-visible process state is recorded. A defender who sees no `LD_PRELOAD` in a process environment dump should not conclude the rootkit is absent; `/etc/ld.so.preload` must be audited directly.

**No anti-analysis tradecraft.** The binary has no anti-debugger calls, no anti-VM checks, no string obfuscation, no packed sections. Static analysis is straightforward — the author optimized for compactness and reliability, not for anti-analysis evasion. This is consistent with the userland LD_PRELOAD model (the rootkit relies on its hooks running before defender tooling rather than on resisting analysis once captured).

### 5.2 ghost.sh Function-by-Function Walkthrough (Selected Functions)

**File metadata.**
- Filename: `ghost.sh`
- SHA-256 (Operator-A): `e943b58112f58517b95424dba9334bf97c5dc2dd2f069dca04b9e75b9fec56ba`
- SHA-256 prefix (Operator-B): `025d683b3ebcfc6f246bbe05...`
- Size: 45,289 bytes (Operator-A) / 45,306 bytes (Operator-B)
- Line count: 1,338 lines
- Function count: 43 functions
- Per-customer config delta: 17 bytes (wallet addresses, pool URLs, PIP_PAYLOAD_REPO GitHub URL)

**First-line self-identification.** Line 1 reads `# GHOST v5.1 (Anti-Hisana + Resurrection + Spread + Escape)`. This is the kit-author self-description; the four parenthesized terms map to the kit's four marquee capability categories.

**Selected function inventory (43 total functions in the installer):**

**Competitor displacement: `_anti_hisana`** — referenced 16 times across the 2-host Hunt index. Targets the rival Hisana cryptojacker's known indicators (port 10808 listener, specific process names). The function kills observed Hisana instances before installing GHOST to ensure exclusive GPU use.

**Rootkit build (dead code in practice): `_compile_hide_so`** — function that would compile `libpam_cache.so` from `libpam_cache.c` on the victim if the kit author intended per-victim compilation. **In practice the .so ships pre-built** from the kit-author's GitHub-hosted `HIDE_SO_URL`, and the function is not actually invoked in the captured deployment. The function exists for completeness or for a fallback execution path that never executes in normal kit flow. Forensic implication: a defender encountering the source code without the byte-identical binary cross-check is likely to mistakenly conclude that per-victim compilation occurred (HIGH-confidence indication based on the function name and presence of a complete-looking compilation path in the source). The byte-identical binary across both customer hosts refutes this.

**Container escape orchestrator: `_container_escape`** — dispatches to one of the four escape variants based on environmental probes (cgroup version check, mounted-path detection, Docker socket presence, namespace isolation check).

**Container escape variants (4 functions):**
- `_escape_via_cgroup` — writes to cgroup `release_agent` for kernel-triggered host execution
- `_escape_via_mount` — leverages bind-mounted host paths to write attacker payloads into host-visible filesystem
- `_escape_via_nsenter` — uses `nsenter -t 1 --mount --uts --ipc --net --pid -- bash` (or equivalent) to enter PID 1 host namespaces
- `_escape_via_socket` — Docker socket abuse via `docker run --privileged -v /:/host`

**Kill-list regex: `kill_list.patterns`** — single regex matching competitor miner/coinminer process names: `xmrig|xmr-stak|sysagentd|kdevtmpfsi|kerberods|bioset|stratum|cryptonight|randomx|etchash|2miners|rigel|sysdaemon|kryptex`. Note `kryptex` is on the kill-list even though the operator uses Kryptex pools — the kill-list targets process names matching the Kryptex client binary, not the pool URLs.

**Persistence orchestration: `_install_persistence`** — installs the 5-vector persistence chain documented in Section 4.5.

**Hysteria v2 setup: `_setup_hysteria`** — downloads Hysteria v2 binary, generates credentials, configures bing.com SNI masquerade, starts admin panel listener on TCP 3301.

**Memfd_create fileless execution: `_memfd_launch`** — uses the `memfd_create` syscall (T1620 — Reflective Code Loading) to load and execute the miner binary from an anonymous in-memory file descriptor without writing to disk. SysV shm fallback for older systems where `memfd_create` is unavailable.

**Upstream OSS attribution.** Files written by the kit's UnamWebPanel component contain the comment `/* Made by Unam Sanctam https://github.com/UnamSanctam */`. This is the upstream-author attribution from the UnamWebPanel codebase (UnamSanctam is the GitHub identity of the upstream OSS author; the comment is in the original UnamWebPanel source). The presence of this comment in deployed PHP files anchors the UnamSanctam → Vova75Rus supply-chain relationship — Vova75Rus bundles UnamWebPanel into the GHOST kit without modifying the upstream attribution.

---

## 6. Dynamic / Behavioral Analysis

> **Analyst note:** This section documents the operator's actual hands-on-keyboard activity on Operator-A's host (77.110.96.200), reconstructed from a 1,472-line bash history file recovered from the open directory. The bash history is the most direct evidence of operator tradecraft, OPSEC posture, and operational iteration tempo available in this investigation. No malware was detonated by The Hunters Ledger to produce this section; the dynamic analysis is reconstructed from operator-side artifacts left in the open directory.

### 6.1 Operator Bash History Forensics (Operator-A, 77.110.96.200)

**File metadata.** 1,472 lines / ~39 KB. The bash history was readable in the open directory — an OPSEC failure by the operator who had not cleared or scrubbed the history. The history covers operator hands-on activity on the kit's deployment server.

**Volume signals:**

- **83 ncat invocations.** Heavy listener tradecraft — the operator regularly stands up TCP listeners with `ncat -l <port>` for various ad-hoc operational needs. Combined with the kit's mining pool ports (TCP 3333, 4444) and Hysteria admin panel (3301), this host functions as the operator's general-purpose listener.
- **48 unique Cyrillic words** in the bash history. DEFINITE evidence the operator is Russian-speaking — not transliterated English, not machine-translated text, but native vocabulary including: Вытащим (we extract), ГОТОВО (DONE), Генерация (generation), ДЛЯ (FOR), Запуск (launch), ИТОГО (total), КЛИЕНТА (of the client), Конфиг (config), Найдено (found), Обновление (update), Объединяем (we combine), Открыть (open), Перезапишем (we overwrite), Перезапуск (restart), Проверка (check).
- **MIRROR Telegram bot token typed plaintext.** The MIRROR bot token `8315596543:<remainder>` was typed in the bash history without clearing. This is the OPSEC failure that confirmed Operator-A's ownership of the MIRROR bot.

**Operator tempo evidence.**

- `min1.sh` Last Modified: **2026-05-24T17:10:29Z** — same day as analysis, 47 days after the Censys ARC public disclosure on 2026-04-07. The operator is **actively iterating** on the kit despite the public disclosure.
- Bash history shows operator activity spanning multiple weeks; the most recent commands are from the day before analysis.
- The operator does not appear aware that the open directory itself is exposed — files are world-readable with directory listing enabled, an OPSEC failure that enabled the entire investigation.

### 6.2 Operational Sequence Reconstruction (Selected Patterns from Bash History)

The bash history shows the operator's typical operational sequence — a step-by-step ComfyUI exploitation workflow:

**Step 1 — Cloud IP-range refresh.** Operator runs `./get_all_ranges.sh` to refresh the cloud-provider IP corpus. The script queries bgpview.io for 12 cloud-provider ASNs plus official Oracle and Google IP-range JSONs.

**Step 2 — ComfyUI port-8188 scan.** Operator runs the Python scanner (`./scan.py` or `./py.py`) against the refreshed IP corpus. The scanner outputs candidate ComfyUI hosts that respond on port 8188.

**Step 3 — Target verification.** Operator runs `./check_comfyui.sh <target>` for each candidate, performing HTTP GETs against `<target>:8188/system_stats` and `<target>:8188/queue` to confirm ComfyUI presence and queue accessibility. Output lines include Russian-language commentary (Найдено = "found", ИТОГО = "total") for the operator's own status tracking.

**Step 4 — Payload deployment.** For verified targets, the operator runs the GHOST kit installer remotely. The installer fetches `libpam_cache.so` from the kit-author's GitHub-hosted `HIDE_SO_URL` (or from the operator's host as a fallback), installs the 5-vector persistence chain, sets up Hysteria v2, configures the dual-Telegram architecture, and starts mining.

**Step 5 — Monitoring.** The OWNER bot (8415540095) reports back to the kit author; the MIRROR bot (8315596543) reports back to the operator. Operator-A watches both channels via Telegram client.

**Step 6 — Iteration.** Operator-A actively modifies `min1.sh` and other operator-facing scripts to adjust mining parameters, Telegram message formats, or pool routing. The 2026-05-24T17:10:29Z `min1.sh` modification is the most recent observed iteration.

### 6.3 Live-Iteration Evidence: min1.sh Modification 2026-05-24

The `min1.sh` modification at 2026-05-24T17:10:29Z is the investigation's most operationally significant timestamp: Operator-A **actively iterated** on the kit 47 days after the Censys disclosure (2026-04-07) and despite the OFAC sanctions on AEZA (in effect since 2025-07-01).

This raises Operator-A's risk profile above Operator-B, who abandoned 77.110.125.145 five days post-disclosure. Operator-A's continued operation suggests either (a) unawareness of the disclosure, (b) confidence in AEZA's non-cooperative abuse posture, or (c) tempo over OPSEC — the evidence cannot distinguish these.

### 6.4 Network Behavior (Reconstructed from Kit Configuration)

The patterns below reconstruct GHOST's network behavior from the kit's static configuration — mining-pool egress, dual-Telegram C2, Hysteria v2 backdoor traffic, and scanner activity. This investigation did not capture live PCAP (open-directory artifact pull only; honeypot deployment is project-planned but blocked on Protectli/VLAN segmentation), so treat these as configuration-derived rather than observed:

**Outbound mining pool traffic.**
- Operator-A: TCP 77.110.96.200:3333 (self-hosted XMR proxy) → upstream to `xmr.kryptex.network`
- Operator-A: TCP 77.110.96.200:4444 (self-hosted CFX proxy) → upstream to `cfx.kryptex.network`
- Operator-B: TCP `auto.c3pool.org:443` (public XMR pool) and `cfx-asia1.nanopool.org:10543` (public CFX pool)

**Outbound C2 traffic.**
- HTTPS to `api.telegram.org/bot8415540095:*` (kit-author OWNER bot)
- HTTPS to `api.telegram.org/bot8315596543:*` (Operator-A MIRROR bot)
- HTTPS to `github.com/Vova75Rus/*` (kit-author payload fetches)
- HTTPS to `github.com/UnamSanctam/*` (upstream OSS fetches)
- HTTPS to `github.com/jamestechdev-oss/*` (Operator-B PIP_PAYLOAD_REPO — deleted post-Censys)

**Hysteria v2 backdoor traffic.**
- UDP 77.110.96.200:14433 / :14444 with bing.com SNI in QUIC TLS handshake
- HTTP 77.110.96.200:3301/api/* (Hysteria admin panel)

**Scanner traffic.**
- HTTP GETs to `<victim>:8188/system_stats` and `<victim>:8188/queue` from Operator-A's host
- DNS queries to `bgpview.io` for ASN prefix enumeration
- HTTP GETs to Google's `cloud.json` and Oracle's `cloud-public-ip-ranges.json`

**Detection patterns derived from this network behavior are encoded in the Suricata rules in the Section 10 detection file.** These Suricata rules are derived from static kit configuration, not from observed PCAP capture. Defenders should treat them as configuration-derived signatures — higher-yield in controlled environments but potentially carrying elevated false-positive risk in noisy environments where the individual protocol patterns (Telegram API egress, GitHub HTTPS, bgpview.io DNS) overlap with legitimate traffic. The highest-confidence Suricata rule remains the OWNER Telegram bot ID prefix (`8415540095:`) because that specific string has no legitimate use case outside this kit's supply-chain monitoring channel.

---

## 7. MITRE ATT&CK Mapping

> **Analyst note:** This case's behaviors map to MITRE ATT&CK in the companion detection file, where each technique is tied to its detection logic. To keep this report focused, the full technique table is not duplicated inline.

The full ATT&CK technique mapping for this case is maintained alongside the detection rules on the **[detection rules page →](https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/)**.

---

## 8. Indicators of Compromise

> **Analyst note:** The complete IOC set for this case is published as a machine-readable JSON feed for direct SIEM/EDR ingestion — it is not duplicated inline here. The highest-priority indicators are also surfaced in the IOC panel (fingerprint icon) on this page.

**Full IOC feed:** [`/ioc-feeds/ghost-cryptojacker-vova75rus-77.110.96.200-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/ghost-cryptojacker-vova75rus-77.110.96.200-iocs.json) — every indicator for this case, with type / confidence / recommended action.

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-016 and UTA-2026-017 are internal tracking designations assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. These labels will not appear in external threat intelligence feeds or vendor reports — they are specific to this publication. If future evidence links this activity to a known named actor, the designations will be retired and updated accordingly.

Attribution for Case 9 resolves into three identity tiers: a named kit author (Vova75Rus, HIGH 88%), two unattributed customer operators (UTA-2026-016 and UTA-2026-017, both LOW), and a supply-chain context entity (UnamSanctam — explicitly NOT a Case 9 threat actor; included for ecosystem context only).

### 9.1 The 4-Tier Supply Chain Model (Central Attribution Finding)

The central attribution finding for Case 9 is the **4-tier supply chain**:

```
Tier 1: UnamSanctam        — upstream OSS malware tooling (UnamWebPanel, SilentCryptoMiner ecosystem, since 2014)
   ↓ (passive OSS consumption — Vova75Rus bundles UnamSanctam components)
Tier 2: Vova75Rus          — GHOST cryptojacker kit author (HIGH 88%, NAMED actor, GitHub suspended 2026-05-25)
   ↓ (kit-sales distribution with OWNER Telegram bot supply-chain monitoring)
Tier 3: Customer operators — UTA-2026-016 (Operator-A, 77.110.96.200) + UTA-2026-017 (Operator-B, 77.110.125.145)
   ↓ (ComfyUI port-8188 exploitation against cloud GPU victims)
Tier 4: Victims            — Exposed ComfyUI / Stable-Diffusion / ML-inference hosts (4,573-IP target candidate corpus; 78 confirmed-vulnerable)
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/ghost-cryptojacker-vova75rus-77.110.96.200/ghost-kit-4tier-supply-chain.svg" | relative_url }}" alt="Process-tree infographic showing the GHOST cryptojacker kit 4-tier supply chain. Tier 1 at top (grey side-rail): UnamSanctam — OSS malware author on GitHub since 2014, 860 followers, supplies UnamWebPanel and SilentCryptoMiner as free OSS, flagged as passive upstream and NOT a Case 9 threat actor. Connector down to Tier 2 (red side-rail, deep-red border for emphasis): Vova75Rus — kit author, GitHub UID 73169104, Russian native, region code 75 (Zabaykalsky Krai indicator), 5+ year GitHub history; assembles ghost.sh + libpam_cache.so + Python ComfyUI exploitation framework into the GHOST kit; OWNER Telegram bot 8415540095 baked into every customer deployment as supply-chain monitoring signature; byte-identical libpam_cache.so (SHA-256 prefix eaaa10c8) shipped to all customers; account suspended by GitHub T&amp;S 2026-05-25 with 9 URLs returning HTTP 404. Tier 2 connector branches three ways to Tier 3, three customer-operator cards (each with deep-red side-rail). Customer A (77.110.96.200, UTA-2026-016, ACTIVE) on the left: higher-OPSEC, self-hosted XMR pool on port 3333 and CFX pool on port 4444, XMR wallet prefix 4BBj3gj4, CFX wallet cfx:aaj5x with drain chain through operator consolidator to mainstream exchange (~2,426 CFX over 6 months), MIRROR Telegram bot 8315596543, last activity 2026-05-24. Customer B (77.110.125.145, UTA-2026-017, ABANDONED) in the middle: lower-OPSEC, uses public pools auto.c3pool.org and cfx-asia1.nanopool.org, XMR wallet 46a5osgf, CFX wallet cfx:aat5y never drained (nonce=0, balance 19.82 CFX), abandoned since 2026-04-12. Customer C (historical, INACTIVE) on the right: active only Nov-Dec 2025, CFX wallet cfx:aasktcha drained to the SAME consolidator as Customer A (suggests wallet rotation by Operator-A or shared kit operator), no XMR wallet or infrastructure observed (predates Hunt.io coverage window). Footer detection anchors: OWNER bot prefix 8415540095 catches all customer kits, plus the byte-identical libpam_cache.so SHA-256 as the cross-customer rootkit signature.">
  <figcaption><em>Figure 1: GHOST kit 4-tier supply chain. The central attribution finding for Case 9 visualized — UnamSanctam upstream OSS, Vova75Rus kit author (the intervention point), and three downstream customer operators with distinct OPSEC tiers and wallet trails. The GitHub T&amp;S action on the Vova75Rus tier 2026-05-25 disrupted all three downstream operators via a single intervention point, demonstrating the supply-chain takedown leverage that motivates the Tier-0 disposition framing.</em></figcaption>
</figure>

This 4-tier model is the **ruling result** of the Analysis of Competing Hypotheses (ACH) for attribution. The alternative single-actor monolithic attribution hypothesis (H2: one identity is both the kit author and one of the operators) was REFUTED by four pieces of evidence:

- **Wallet-match test:** Vova75Rus mines XTM/Tari via Kryptex worker `1238rkM7gGg3sl`; Operator-A mines XMR (4BBj3gj4...) + CFX (cfx:aaj5xb...). Different cryptocurrencies, different pools, different destinations.
- **OWNER vs. MIRROR bot architecture:** A single actor would not maintain two parallel Telegram-bot tokens with distinct IDs in the same script. The OWNER + MIRROR architecture only makes sense in a kit-sales business model.
- **Byte-identical kit binary across customers:** Single-operator scenarios compile per-target; commodity kits ship pre-built artifacts. GHOST is the latter.
- **Per-customer 17-byte config delta:** The ghost.sh delta is exactly the wallet addresses + pool URLs + PIP_PAYLOAD_REPO URL. This is the signature of config-substitution distribution, not source-modification.

### 9.2 Vova75Rus — HIGH Confidence (88%), NAMED Actor

**Identity attribution.** GitHub UID 73169104, handle `Vova75Rus`. Account created 2020-10-20; suspended by GitHub Trust & Safety 2026-05-25.

**Confidence statement.**
- **Confidence:** HIGH (88%)
- **Why this confidence:** 8 independent evidence anchors (below) covering coherent multi-year account history, Russian regional indicators, Censys independent corroboration, GitHub T&S account-level action, and architectural fingerprints of the kit-sales business model.
- **What's missing:** Real-world identity beyond handle + region + personal-dedication page. No Tier-1 government attribution, no multi-Tier-2 vendor convergence beyond Censys, no Telegram T&S subpoena disclosure of OWNER bot 8415540095. DEFINITE escalation is blocked on these.
- **What would increase confidence:** Telegram T&S response on the OWNER bot identity; multiple independent Tier-2 vendor reports converging on Vova75Rus; government attribution.

**Eight evidence anchors:**

1. **5+ year coherent GitHub account history** (UID 73169104, created 2020-10-20, 9 repositories under the handle including ComfyUI-Shell-Executor, miner, legendary-carnival, Dim, Notes.github.io).
2. **Region code 75 = Zabaykalsky Krai** per the Russian regional plate-code convention (eastern Siberia, bordering Mongolia and China). LOW geographic precision but a coherent identity indicator.
3. **Personal-dedication page** using a Russian-language March 8th / Women's Day greeting on `Vova75Rus/Notes.github.io`. Wayback Machine preserved before GitHub T&S suspension. Personal-attribution artifact consistent with single-individual ownership.
4. **Commit-author noreply email** `73169104+Vova75Rus@users.noreply.github.com` unambiguous to GitHub UID 73169104 across all 9 repositories. Same identity authored all repos.
5. **Censys ARC primary research independent corroboration** (Mark Ellzey, 2026-04-07). Censys identified the GHOST kit on 77.110.96.200 without naming the kit author; this investigation's pivot from `PIP_PAYLOAD_REPO` to `Vova75Rus/ComfyUI-Shell-Executor` closed the attribution gap.
6. **GitHub T&S Tier-0 account-level suspension 2026-05-25** within ~24 hours of disclosure submission. T&S action at the account level (rather than repo level) is consistent with substantive ToS violations across the account's repository inventory — not a single-repo dispute.
7. **OWNER Telegram bot 8415540095 baked into every customer GHOST kit deployment.** Structural fingerprint of kit-sales business model with kit-author supply-chain monitoring. The bot ownership chains back to Vova75Rus via the per-customer config-substitution pattern (operators do not control the OWNER bot; the kit author does).
8. **Byte-identical libpam_cache.so MD5 296a800564111b0bad9fe63faf4e63ba across both customer hosts.** DEFINITE supply-chain root proof. A single actor at the kit-author tier ships the same binary to multiple downstream operators.

**Language precision per attribution confidence scale.** HIGH 88% maps to language like "highly likely", "strong indicators suggest", "probable attribution to". The report avoids "attributed to" (DEFINITE language) for Vova75Rus because the real-world identity remains unverified beyond the GitHub handle.

### 9.3 UTA-2026-016 (Operator-A, 77.110.96.200) — LOW Confidence (65%, top of the LOW band 50-70%)

**Confidence statement.**
- **Confidence:** LOW (65%, top of the LOW band 50-70%) — upgraded from LOW (60%) in the parent campaign via four net-new evidence elements added in this sub-report.
- **Why this confidence:** Russian-speaking attribution is DEFINITE; identity beyond Russian-speaking is INSUFFICIENT. Operator-A is reliably distinguishable from Operator-B and from Vova75Rus, but cannot be linked to a real-world individual.
- **What's missing:** Real-world identity; Telegram T&S engagement on the MIRROR bot 8315596543 pending; Conflux exchange subpoena on the off-ramp wallet pending; Russian carding-forum handle resolution not attempted.

**Evidence elements (4 net-new in this sub-report):**

1. **48 unique Cyrillic words in operator bash history** (1,472 lines / 39 KB). DEFINITE Russian-speaking native vocabulary density.
2. **83 ncat invocations** — heavy listener tradecraft. Operationally active customer.
3. **MIRROR bot 8315596543 token typed in bash history uncleared** — OPSEC failure confirming Operator-A owns the MIRROR bot.
4. **libpam_cache.so hide-port list cross-confirms self-hosted XMR (TCP 3333) + CFX (TCP 4444) pool proxy architecture** — operator-customized infrastructure layout.
5. **min1.sh Last Modified 2026-05-24T17:10:29Z** — same-day operator iteration as analysis (active campaign 47 days post-Censys).

**Conflux drain chain:**

```
Mining wallet         Consolidator           Exchange off-ramp
cfx:aaj5xbzcjuk...    →    cfx:aasv0snvp...    →    cfx:aansses5s4...
22 outgoing tx                  8 outgoing tx              781,383 total tx
~2,426 CFX drained              ~193 CFX held              49M CFX seen
                                                           (exchange deposit address)

Historical wallet (Nov-Dec 2025, now inactive):
cfx:aasktcha7r... → same consolidator → same off-ramp
84 CFX drained; operator wallet-rotation evidence
```

The historical wallet cfx:aasktcha7r... drains to the same consolidator as the current wallet — proving 6-month continuous single-operator campaign and providing a wallet-rotation forensic anchor.

### 9.4 UTA-2026-017 (Operator-B, 77.110.125.145) — LOW Confidence (60%, within the LOW band 50-70%)

**Confidence statement.**
- **Confidence:** LOW (60%, within the LOW band 50-70%) — upgraded from LOW (55%) via the DEFINITE 183-Cyrillic-word finding in `New_scanner.py`.
- **Why this confidence:** Russian-speaking attribution upgraded to DEFINITE. Identity beyond Russian-speaking remains INSUFFICIENT.
- **What's missing:** Real-world identity; reason for abandonment not confirmed; GitHub T&S historical record on deleted jamestechdev-oss organization pending.

**Evidence elements:**

1. **183 unique Cyrillic words in `New_scanner.py` operator wrapper** — DEFINITE Russian-speaking; supplants parent's earlier "INFERRED" attribution.
2. **CFX wallet cfx:aat5y... holds 19.82 CFX, never drained (nonce 0)** — distinct from Operator-A; 2 incoming pool payouts only.
3. **Host abandoned ~5 days post-Censys** (last activity 2026-04-12). Reason for abandonment: 4 alternatives (operator-quit / detection / kit-author intervention / pool-side payout failure) — unresolved.
4. **Operator-B "Asia-based" hypothesis EXPLICITLY RETRACTED.** The earlier inference that Operator-B was Asia-based (based on `cfx-asia1.nanopool.org` pool config) was wrong — pool routing region is operational convenience, not geographic indicator.

### 9.5 UnamSanctam — HIGH Confidence (90%) on Passive OSS Role, NOT a Case 9 Threat Actor

UnamSanctam is included in this section for **supply-chain context only**. UnamSanctam is **not** a Case 9 threat actor.

**Role characterization.** Active GitHub developer since 2014; 860 followers; 6 public repositories with 2,584 cumulative stars (UnamWebPanel 198 + SilentCryptoMiner 1020 + SilentXMRMiner 643 + SilentETHMiner 254 + UnamBinder 279 + UnamDownloader 190). Supplies upstream OSS tooling that downstream malware kits (including GHOST) bundle. SilentCryptoMiner was disabled by GitHub for ToS violations; remaining repositories active.

**Scope of UnamSanctam's involvement in GHOST.** Passive — the upstream attribution comment `/* Made by Unam Sanctam https://github.com/UnamSanctam */` appears in the GHOST kit's deployed PHP files because Vova75Rus bundles UnamWebPanel without modifying the attribution. No evidence of direct UnamSanctam involvement in the GHOST kit's authorship, distribution, or operation.

**Disambiguation from Kaspersky SilentCryptoMiner coverage.** Kaspersky Securelist has documented 2,000+ Russian victims of SilentCryptoMiner campaigns (YouTube delivery and SIEM agent delivery). Those campaigns are attributable to **OPERATORS** using SilentCryptoMiner, not to UnamSanctam as an operator. UnamSanctam is the upstream OSS author; the operators are separate identities. The same architectural distinction applies to GHOST: Vova75Rus is the kit author; Operator-A and Operator-B are separate operator identities.

**Why UnamSanctam is included in this section despite not being a Case 9 threat actor.** The 4-tier supply chain model is incoherent without naming the upstream OSS tier. Defenders evaluating their exposure to the GHOST kit family need to understand that UnamWebPanel components in deployed PHP files do not implicate UnamSanctam — they implicate the downstream kit author who bundled the upstream OSS.

### 9.6 Hisana — INSUFFICIENT (Ecosystem Context Only, Not Case 9 Attribution)

Hisana exists in the public threat-intelligence record only via GHOST kit artifact references — `_anti_hisana` function name, `kill_list.patterns` regex entry, port 10808 C2 port. Zero independent public threat intelligence on Hisana's developer identity, infrastructure, or victim scope. This is a documented intelligence gap.

**Implication for GHOST attribution.** Hisana's existence as a rival cryptojacker that GHOST specifically targets for displacement is consistent with the commodity-kit business model — kit authors compete on the supply side for operator customers, and operators benefit from kit-side competitor displacement to ensure exclusive GPU use. Hisana is therefore **ecosystem context** that strengthens the kit-sales business model framing for GHOST, even though Hisana's identity remains unattributed.

### 9.7 Negative Finding: AI-Generated Code Signature ABSENT from GHOST Kit

The **AI-generated code structural signature is absent** from every GHOST kit component reviewed — a distinctive finding here, since the parent campaign's Cases 1, 2, and 3 all showed it. The Bash scripts, C source, and Python framework all show hand-authored coding patterns (consistent function naming conventions, idiomatic Russian-language commentary, manual error handling, no over-commenting). Vova75Rus authors GHOST manually; this is not an AI-augmented kit.

This negative finding matters for cross-case analysis at the parent campaign level: AI integration into offensive workflows is operator-discretionary, not a campaign-wide default. The GHOST kit author chose to author manually; the Case 1, 2, 3 operators chose to integrate AI tools. The 5 novel TTPs documented in the parent campaign are AI-augmented operator behaviors, not kit-author defaults.

---

## 10. Risk & Detection

**Full detection rule set** is available in the separate detection file:

[**`/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/`**](/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/)

The detection file contains 25 production-ready detection rules covering YARA file-based detection, Sigma log-based detection, and Suricata network-based detection. All rules are authored by The Hunters Ledger under the CC BY-NC 4.0 license and are deployable directly into compatible scanning/SIEM/IDS infrastructure.

### Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 10 | T1014, T1574.006, T1564.001, T1027, T1059.004, T1059.006, T1572, T1102.002, T1595.002 | LOW-MEDIUM |
| Sigma | 12 | T1574.006, T1222.002, T1543.002, T1053.003, T1554, T1480.002, T1620, T1495, T1070.002, T1057, T1595.002, T1102.002 | LOW-MEDIUM |
| Suricata | 6 | T1496.001, T1572, T1071.001, T1071.004, T1102.002, T1595.002 | LOW |

**Priority distribution:** 4 HIGH-priority rules, 6 MEDIUM-priority, 12 LOW-priority across all rule types.

### Highest-Priority Detection: OWNER Telegram Bot Indicator

The single most valuable detection rule across the entire GHOST family is `MAL_GHOST_OWNER_Telegram_Bot_Token_Indicator` — a string-match for `8415540095:` (the kit-author OWNER Telegram bot ID prefix) in any binary, script, bash history, log file, or network egress traffic.

**Why this rule has the highest scope-to-effort ratio:**

- **Catches every GHOST customer worldwide.** The bot is baked into every customer deployment by the kit author. No operator-side variation can evade this signature.
- **Trivial to deploy.** Single string match — works at YARA byte-level, Sigma log-pattern level, and Suricata network-payload level.
- **LOW false-positive risk.** The 10-digit Telegram bot ID prefix has no legitimate use case outside Telegram-bot integrations; combined with the surrounding context (`api.telegram.org/bot` URL prefix; bash-history typing; binary string in script files), the FP risk is negligible.

### Detection Layering Approach

Defenders should deploy the rules in three layers:

**Layer 1 — File-based at-rest detection (YARA).** Scan endpoint filesystems for the rootkit binary, kit scripts, and Python framework. Highest-confidence catch is the byte-identical `libpam_cache.so` (hash match) and the kit scripts (string + structural match).

**Layer 2 — Log-based behavioral detection (Sigma).** Audit auditd file events on `/etc/ld.so.preload`, `/lib/security/`, persistence file paths, `chattr +i` syscalls, container-escape preconditions (cgroup release_agent writes, Docker socket access from non-Docker-group processes). Sigma rules also cover ComfyUI custom-node directory writes containing the `PerformanceMonitor` class signature.

**Layer 3 — Network-based behavioral detection (Suricata).** Egress detection of OWNER + MIRROR Telegram bot HTTPS requests, GitHub-hosted kit payload URLs, ComfyUI port-8188 scanner activity, Hysteria v2 UDP/QUIC traffic patterns with bing.com SNI masquerade, mining pool DNS queries.

### Detection Gap Acknowledgment

The 6-week post-Censys VT detection landscape snapshot confirms **zero AV vendor has shipped GHOST family signatures** as of 2026-05-25. This is a structural gap: custom kits with low telemetry volume operate below AV vendor automated analysis pipeline triggers. The rules in the Section 10 detection file fill that gap for the YARA/Sigma/Suricata-capable defender. Defenders who encounter `libpam_cache.so` or `min1.sh` in their environment are strongly encouraged to submit those samples to VirusTotal — community sample submission is the mechanism that closes the detection gap for the broader defender ecosystem, not just the submitting organization.

### Response Orientation (Brief — Not a Step-by-Step IR Guide)

This is a third-party intelligence publication, not an incident response playbook. Readers with confirmed-compromise scenarios should engage their internal IR team or a dedicated playbook for execution-level detail. The following orientation covers what to address, not how.

**Detection priorities (highest value to hunt for first):**
- OWNER Telegram bot 8415540095 egress + bash-history string
- `/etc/ld.so.preload` non-empty contents + `libpam_cache.so` under `/lib/security/`
- ComfyUI `custom_nodes/*.py` containing `class PerformanceMonitor` + `NODE_CLASS_MAPPINGS`

**Persistence targets to enumerate and remove:**
- `/etc/ld.so.preload` (primary)
- `/etc/systemd/system/systemd-journal-flush.service`
- `$HOME/.config/systemd/user/fontconfig-cache.service`
- `/etc/init.d/fontcache`
- `/var/spool/cron/.font_*` + shell-RC injection in `~/.bashrc` / `~/.profile`
- `inotify_guard` watchdog process (must be killed before file removal)
- Scatter copies: `$HOME/.local/share/.cache/fontconfig/`, `/etc/udev/hwdb.d/.backup-cache`, `/var/spool/cron/.font_*`

**Containment categories:**
- Isolate affected hosts at network and container-runtime level
- Block AEZA AS210644 at egress (perimeter)
- Block kit-author OWNER Telegram bot URL pattern at egress
- Disable ComfyUI public exposure pending audit
- Rotate credentials for any service accounts with keys on the compromised host

---

## 11. Confidence Summary

This summary organizes every finding by confidence level, from DEFINITE down to INSUFFICIENT, per the project's CONFIDENCE LEVELS framework. The MITRE ATT&CK mapping (§7) marks per-technique confidence in the companion detection file; the view below spans all findings, not just the technique table.

### DEFINITE (Direct Evidence, No Ambiguity)

- **GHOST kit identity and structure** — full kit captured from open directories on both customer hosts; kit-author self-identification in `ghost.sh` first-line comment.
- **libpam_cache.so byte-identical across customers** (MD5 296a800564111b0bad9fe63faf4e63ba). Single supply-chain root proof.
- **27-string + 9-port hide-list inventory** — full enumeration from C source + binary string extraction.
- **5-vector persistence chain** — all 5 vectors observed in `ghost.sh` `_install_persistence` function.
- **`libpam_cache.so` is NOT a PAM module** — direct 98-line C source inspection refutes any PAM functionality (zero PAM symbols, zero authentication-flow code).
- **Per-customer 17-byte config delta** — diff between Operator-A and Operator-B `ghost.sh` copies.
- **OWNER Telegram bot 8415540095 baked into every customer deployment** — present in `min1.sh` on both customer hosts.
- **Vova75Rus = GHOST kit author** — Hunt SQL pivot from `PIP_PAYLOAD_REPO` GitHub URL embedded in operator-B's Python scanner.
- **Vova75Rus ≠ Operator-A** — wallet-match test (different cryptocurrencies, different pools, different destinations).
- **GitHub T&S account-level suspension of Vova75Rus 2026-05-25** — 9 URLs return HTTP 404; Wayback Machine preserved.
- **Operator-A is Russian-speaking** — 48 unique Cyrillic words in 1,472-line bash history.
- **Operator-B is Russian-speaking** — 183 unique Cyrillic words in `New_scanner.py`.
- **Operator-A owns MIRROR bot 8315596543** — token typed plaintext in bash history (OPSEC failure).
- **AEZA Group AS210644 is OFAC/NCA sanctioned** — Tier-1 government source (2025-07-01 designation).
- **min1.sh actively modified 2026-05-24** — 47 days post-Censys disclosure; live ongoing operations.

### HIGH (Strong Evidence, Minor Gaps)

- **Vova75Rus NAMED-actor attribution (88%).** 8 evidence anchors covering coherent multi-year account history, Russian regional indicators, Censys corroboration, GitHub T&S action, and architectural fingerprints.
- **4-tier supply chain model** — ruling result of ACH; alternatives refuted by wallet-match, OWNER/MIRROR architecture, byte-identical kit, and per-customer config delta.
- **AEZA bulletproof hosting status** — OFAC Tier-1 source + 47-day post-disclosure unresponsiveness + multi-malware-family hosting pattern.
- **Conflux 3-hop drain chain** — mining wallet → consolidator → exchange off-ramp; 106+ transactions; 6-month window.
- **Operator-A consolidator → exchange off-ramp pattern** — 8 outgoing tx to single address with 781K total tx and 49M CFX seen.
- **Operator-A wallet-rotation** — historical cfx:aasktcha... drains to same consolidator as current cfx:aaj5xb...
- **PerformanceMonitor ComfyUI custom-node persistence** — kit-author Python framework component.
- **Kit-sales business model** — OWNER bot + config delta + byte-identical binary + 5+ year kit-author GitHub presence.

### MODERATE (Reasonable Evidence, Notable Gaps)

- **Container-escape real-world execution success rate.** Code-level intent DEFINITE; runtime success depends on host configuration (cgroup version, Docker socket exposure, namespace isolation).
- **Lateral movement / SSH** (T1021.004). Inferred from bash history `ssh` patterns; full lateral-movement chain not directly observed.
- **Hysteria v2 bandwidth hijacking** (T1496.002). Capability present in code; primary observed use is C2-style covert remote access rather than bandwidth proxying.
- **Operator-B reason for abandonment** — 4 alternatives (operator-quit, detection, kit-author intervention, pool-side payout failure); unresolved.

### LOW (Weak Evidence)

- **UTA-2026-016 / Operator-A attribution (LOW 65%).** Russian-speaking is DEFINITE; identity beyond Russian-speaking is INSUFFICIENT. Cannot link to real-world individual. Upgraded from LOW (60%) via four net-new sub-report evidence elements.
- **UTA-2026-017 / Operator-B attribution (LOW 60%).** Same condition as Operator-A. Upgraded from LOW (55%) via the 183-Cyrillic-word finding.
- **Zabaykalsky Krai geographic precision** — region indicator from handle "75" suffix matching Russian plate-code convention; coherent but low precision (a handle suffix is not a strong geographic anchor).
- **Vova75Rus solo-vs-small-team discrimination** — coherent single-individual indicators present (1-follower account, personal-dedication page) but small-team hypothesis cannot be excluded from available evidence.

### INSUFFICIENT (Not Enough Data to Assess)

- **Hisana** — zero independent public threat intelligence; exists only via GHOST kit artifact references. Ecosystem context only.
- **GHOST v6.0 "Domination Edition"** — referenced by Censys; no v6.0 sample captured in this investigation.
- **ComfyUI exploitation specific CVE** — initial-access vector identified at the network/application surface level but the specific CVE / mechanism remains to be confirmed via detonation testing.
- **Operator-A vs. Operator-B same-individual probability** — ~20% same-individual based on available evidence; UNRESOLVED at real-world identity level.
- **Historical Customer C wallet (cfx:aasktcha...)** — ~80% probability Operator-A wallet rotation vs. ~20% distinct third customer; conclusive Conflux consolidator-behavior analysis pending.

---

## 12. Coverage Gaps

None of the six evidence-data gaps below invalidates a central conclusion of this report; each marks a known limit, surfaced openly so follow-on investigators can prioritize the work that would close it. Closing any of them would extend the current attribution and detection coverage, not overturn it.

- **Hisana cryptojacker family — no independent public threat intelligence.** Hisana exists in the public record only via GHOST kit artifact references (`_anti_hisana` function, `kill_list.patterns` regex entry, port 10808 C2 reference). No independent vendor or community coverage of Hisana's developer identity, infrastructure, or victim scope. Closing this gap requires direct port-10808 infrastructure investigation that was out of scope for this report.
- **Conflux drain chain forensics — confluxscan.io operator-wallet investigation not conducted.** The 3-hop drain chain (mining wallet → consolidator → exchange off-ramp) is documented in Section 9.3 from transaction-count and balance evidence at endpoint addresses, but deeper on-chain transaction-graph forensics via confluxscan.io against operator wallets has not been performed. A full subpoena-grade chain-of-custody trace would require dedicated blockchain-forensics tooling.
- **Kryptex wallet-block outcome not confirmed.** Operator-A's XMR + CFX mining wallets connect to Kryptex pool subdomains, but Kryptex's wallet-block policy is unclear from public documentation, so whether those wallets can be blocked at the pool level is unresolved.
- **PPLN.co Japan-focused article content inaccessible.** A PPLN.co article referenced as relevant to Japan-specific victim IP documentation was truncated and was not fully retrievable during this investigation. Whether Japan-specific victim IPs are documented in that source — which would inform JPCERT/CC coordination routing — is unresolved.
- **Historical Customer C wallet (cfx:aasktcha...) — earliest GHOST deployment timing unknown.** The historical wallet cfx:aasktcha7r... drains to the same consolidator as Operator-A's current wallet, providing wallet-rotation forensic evidence. However, the earliest GHOST kit deployment date associated with this historical wallet is not established — the wallet's first transaction predates the current investigation's evidence window and source data to establish kit-author distribution timing further back is not available.
- **JARM / JA4X TLS fingerprints for both customer hosts not retrieved.** The Hunt MCP namespace required for JARM and JA4X fingerprint retrieval against 77.110.96.200 and 77.110.125.145 was unavailable during this investigation session. JARM/JA4X fingerprints would enable cross-corpus pivoting against the broader Hunt platform IP corpus to surface additional GHOST kit customer operators beyond the two observed here. This is a deferred infrastructure-pivot opportunity rather than a refutation risk.

The central conclusions each gap leaves standing: the 4-tier supply chain model, the Vova75Rus kit-author attribution (HIGH 88%), and the byte-identical `libpam_cache.so` supply-chain proof (DEFINITE).

---

## 13. Calibration Notes / Retractions

Six initial readings were disproven by direct evidence during the investigation and are retracted below — none touches the central conclusions, but each shaped the analysis along the way. Documenting them openly is part of the project's commitment to evidence-based intelligence and source-citation integrity.

### 13.1 T1556.003 mis-mapping → T1014 + T1574.006 + T1564.001 + T1027 (Phase 7 → Phase 15)

**Initial framing (Phase 7 session-start):** `libpam_cache.so` was categorized as a PAM authentication backdoor (T1556.003 — Modify Authentication Process: PAM) based on the deceptive filename matching the standard Linux PAM module naming convention (`libpam_*` under `/lib/security/`).

**Refutation (Phase 15):** Direct source-code inspection of the 98-line C source confirmed the file contains:
- Zero PAM symbols
- Zero `pam_authenticate` / `pam_handle_t` / `pam_acct_mgmt` references
- Zero authentication-flow code
- Zero linkage against `libpam.so`

The "pam" in the filename is masquerade only. The file is a userland LD_PRELOAD libc-hook rootkit, not a PAM module.

**Correct mappings:**
- T1014 (Rootkit) — userland rootkit category
- T1574.006 (Dynamic Linker Hijacking) — `/etc/ld.so.preload` mechanism
- T1564.001 (Hidden Files and Directories) — hide-list of file paths and binary names
- T1027 (Obfuscated Files or Information) — deceptive PAM-style filename

This retraction is reflected in Section 7 ATT&CK mapping and in the detection-file calibration notes.

### 13.2 Vova75Rus = Operator-A conflation REFUTED (Phase 15)

**Initial framing:** Early investigation advanced the hypothesis that Vova75Rus and Operator-A were the same identity (single actor wearing both the kit-author and operator hats).

**Refutation (Phase 15 wallet-match test):**
- Vova75Rus's own mining setup: XTM/Tari via Kryptex worker `1238rkM7gGg3sl` on `xtm-rx-eu.kryptex.network:8038`.
- Operator-A's mining setup: XMR (4BBj3gj4...) + CFX (cfx:aaj5xb...) via distinct wallets.
- Different cryptocurrencies (XTM/Tari vs. XMR + CFX), different pools, different destination wallets, distinct worker IDs.

A single actor would not maintain two parallel mining setups with distinct telemetry. The wallet-match test is the conclusive single piece of evidence refuting the single-actor hypothesis. The 4-tier supply chain model (Section 9) is the correct framing.

### 13.3 q10.txt 4,573-IP scope correction (Phase 16)

**Initial framing:** The `q10.txt` file containing 4,573 IP addresses was initially read as a victim list — implying a 4,573-host compromise scope.

**Refutation (Phase 16):** Direct review of `q10.txt` contents and cross-reference against the ComfyUI scanner pipeline confirmed `q10.txt` is the **operator's loose target candidate list** — IPs that responded on port 8188 during scanning, not IPs that were successfully compromised. The narrower confirmed-vulnerable population is 78 hosts (21 Tier-A confirmed-vulnerable + 57 Tier-B exposed-but-unconfirmed).

The 4,573-IP corpus is not published as an IOC list because most of those hosts are not compromised. Cloud-provider disclosure cascade routing is limited to the 78 confirmed-vulnerable hosts.

### 13.4 VT "dropped_files" SHA-256s 44a3bab2... and ac941ead... mis-attribution

**Initial framing:** VirusTotal's `dropped_files` relationship for `ghost.sh` and `min1.sh` surfaced SHA-256s `44a3bab2c338e3bca24c00f7c3da1301eb4a5a889f1c667cc781e1bdacd3b9e7` and `ac941ead01d5451a7a9fd4be4ba9b60b2d3e4138670ae868e655b3b393253227`. These were initially read as operator miner binaries.

**Refutation:** Direct VT lookup confirmed these are `/var/log/auth.log.1.gz` and `/var/log/kern.log.1.gz` — sandbox-host log archives the kit scripts touched during log-clearing tradecraft, NOT operator miner deliverables. Excluded from the IOC feed and detection rules.

### 13.5 Operator-B "Asia-based" hypothesis EXPLICITLY RETRACTED

**Initial framing:** Operator-B was tentatively framed as Asia-based on the basis of the `cfx-asia1.nanopool.org` pool config in Operator-B's deployment.

**Refutation:** Pool routing region is an **operational convenience** choice (latency optimization), not a geographic indicator. The 183 unique Cyrillic words in Operator-B's `New_scanner.py` upgrade Operator-B's attribution to DEFINITE Russian-speaking. The Asia-based hypothesis is withdrawn.

### 13.6 "First public documentation" framing → "Technical deep-dive extension" framing

**Initial framing:** Early draft material referenced this report as the "first public documentation" of the GHOST cryptojacker kit.

**Refutation:** Censys ARC (Mark Ellzey) published primary research on GHOST on 2026-04-07. This investigation is a **technical deep-dive extension** of Censys's primary disclosure, not a first-publication. The seven net-new contributions over Censys are documented in Section 1 (sibling deployment, byte-identical binary, OWNER bot, full hide-list inventory, structured detection rules, VT detection landscape snapshot, Conflux drain chain). The "first public documentation" framing has been retracted throughout this report; "extends Censys coverage" is the correct framing.

### Why These Retractions Are Documented

Two reasons put these retractions in the analytical record: (a) other defenders are likely to hit the same initial reads given the deceptive filename and pool-routing artifacts (MODERATE — based on the consistency of the surface evidence across analyst perspectives), and (b) the corrected mappings changed downstream detection-rule derivation — the T1556.003 → T1014 retraction directly changed which Sigma rules were authored for the detection file.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.









