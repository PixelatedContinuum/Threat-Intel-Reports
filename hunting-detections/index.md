---
title: Hunting Detections
layout: page
permalink: /hunting-detections/
position: 3
---

<div class="hl-page-header" style="border-left-color: #4ade80;">
  <div class="hl-page-header__label" style="color: #4ade80;">Hunting Detections</div>
  <div class="hl-page-header__title">Sigma, YARA &amp; Suricata Rules</div>
  <div class="hl-page-header__desc">Detection logic from original research, mapped to MITRE ATT&amp;CK. Free to use in your environment under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% include section-header.html label="All Detections" accent="#4ade80" %}

<div class="hl-row-list">
{% include report-row.html title="Detection Rules — ZeroTrace Multi-Family MaaS Operation" date="Mar 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/opendirectory-74-0-42-25-20260316-detections" %}
{% include report-row.html title="Detection Rules — Sliver C2 / ScareCrow Loader Open Directory Kit" date="Mar 2026" severity="high" tags="Sigma,Suricata" url="/hunting-detections/sliver-open-directory-detections" %}
{% include report-row.html title="Detection Rules — Webserver Compromise Kit 91.236.230.250" date="Feb 2026" severity="high" tags="Sigma,YARA,Suricata" url="/hunting-detections/webserver-compromise-kit-91-236-230-250-detections" %}
{% include report-row.html title="Detection Rules — Remcos RAT OpenDirectory Campaign" date="Feb 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/remcos-opendirectory-campaign" %}
{% include report-row.html title="Detection Rules — NsMiner Cryptojacker" date="Feb 2026" severity="med" tags="Sigma" url="/hunting-detections/nsminer-cryptojacker" %}
{% include report-row.html title="Arsenal-237 New Files: full_test_enc.exe (Advanced Rust Ransomware)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-full_test_enc-exe" %}
{% include report-row.html title="Arsenal-237 New Files: new_enc.exe (Human-Operated Rust Ransomware)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-new_enc-exe" %}
{% include report-row.html title="Arsenal-237 New Files: dec_fixed.exe (Ransomware Decryptor)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-dec_fixed-exe" %}
{% include report-row.html title="Arsenal-237 New Files: enc_c2.exe (Rust Ransomware with Tor C2)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-enc_c2-exe" %}
{% include report-row.html title="Arsenal-237 New Files: chromelevator.exe (Browser Credential Theft)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-chromelevator-exe" %}
{% include report-row.html title="Arsenal-237 New Files: nethost.dll (DLL Hijacking Persistence)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-nethost-dll" %}
{% include report-row.html title="Arsenal-237 New Files: rootkit.dll (Kernel-Mode Rootkit)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-rootkit-dll" %}
{% include report-row.html title="Arsenal-237 New Files: BdApiUtil64.sys (Vulnerable Baidu Driver)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-BdApiUtil64-sys" %}
{% include report-row.html title="Arsenal-237 New Files: lpe.exe (Privilege Escalation)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-lpe-exe" %}
{% include report-row.html title="Arsenal-237 New Files: killer_crowdstrike.dll (CrowdStrike-Specific Termination)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-killer-crowdstrike-dll" %}
{% include report-row.html title="Arsenal-237 New Files: killer.dll (BYOVD Process Termination)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-killer-dll" %}
{% include report-row.html title="Arsenal-237: enc/dec Ransomware Family" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/enc-dec-ransomware-family" %}
{% include report-row.html title="Arsenal-237: uac_test.exe" date="Jan 2026" severity="med" tags="Sigma" url="/hunting-detections/uac-test-exe" %}
{% include report-row.html title="Arsenal-237: FleetAgentFUD.exe" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/fleetagentfud-exe" %}
{% include report-row.html title="Arsenal-237: FleetAgentAdvanced.exe" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/fleetagentadvanced-exe" %}
{% include report-row.html title="Arsenal-237: agent_xworm_v2.exe (XWorm RAT v2.4.0)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-xworm-v2-exe" %}
{% include report-row.html title="Arsenal-237: agent_xworm.exe (XWorm RAT v6)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-xworm-exe" %}
{% include report-row.html title="Arsenal-237: agent.exe (PoetRAT)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-exe" %}
{% include report-row.html title="Detection Rules — Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm" date="Dec 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/dual-rat-analysis" %}
{% include report-row.html title="Detection Rules — PULSAR RAT (server.exe)" date="Dec 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/PULSAR-RAT" %}
{% include report-row.html title="Hybrid Loader/Stealer Ecosystem Masquerading as Sogou" date="Nov 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/Hybrid-Loader-Stealer-Sogou" %}
{% include report-row.html title="Houselet.exe — Go-Based Loader Masquerading as PlayStation Remote Play" date="Nov 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/malware-analysis-houselet" %}
{% include report-row.html title="AdvancedRouterScanner" date="Oct 2025" severity="med" tags="Sigma" url="/hunting-detections/AdvancedRouterScanner" %}
{% include report-row.html title="From Webshells to The Cloud" date="Oct 2025" severity="high" tags="Sigma,YARA" url="/hunting-detections/webshells-to-the-cloud" %}
{% include report-row.html title="QuasarRAT + XWorm + PowerShell Loader" date="Oct 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/quasar-xworm-detections" %}
</div>
