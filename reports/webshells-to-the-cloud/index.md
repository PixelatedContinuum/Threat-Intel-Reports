---
title: "From Webshells to the Cloud"
date: '2025-10-20'
detection_page: /hunting-detections/webshells-to-the-cloud-detections/
ioc_feed: /ioc-feeds/webshells-to-the-cloud.json
detection_sections:
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "45[.]118[.]144[.]151"
    note: "Malicious infrastructure server"
  - value: "152[.]32[.]191[.]156"
    note: "Secondary C2 server"
layout: post
permalink: /reports/webshells-to-the-cloud/
thumbnail: /assets/images/cards/webshells-to-the-cloud.png
category: "Web Compromise"
hide: true
description: "A modular multi-phase intrusion chain beginning with web server compromise via PHP webshells, then pivoting to cloud infrastructure abuse for command-and-control, data exfiltration, and automated attack orchestration. The campaign demonstrates systematic exploitation methodology with strong attribution fingerprints across cloud provider APIs."
stix_bundle: /stix/webshells-to-the-cloud.json
---

**Campaign Identifier:** Webshells-To-Cloud-Modular-Intrusion<br>
**Last Updated:** October 20, 2025<br>
**Threat Level:** HIGH


---

## BLUF (Bottom Line Up Front)

### Executive Summary

This campaign chains PHP backdoors, exploit kits, and cloud API abuse into a modular intrusion framework. Attackers compromise web servers via CloudPanel 0-day exploit kits, deploy RSA-encrypted webshells for exclusive persistent access, and exfiltrate data through Dropbox, Rclone, and AWS S3. A reused RSA public key, consistent cookie name (`clp-fm`), and predictable file paths form strong attribution fingerprints across both infrastructure servers.

Defenders should block known infrastructure (`45[.]118[.]144[.]151:8081`, `152[.]32[.]191[.]156:8081`), scan web directories for PHP files containing `__wakeup()` with RSA key blocks, audit cloud API logs for unexpected outbound transfers, and hunt web logs for the `clp-fm` cookie and access to `/file-manager/backend/makefile`. Full technical findings begin at [Technical Analysis](#technical-analysis).

### Key Risk Factors
<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Factor</th>
      <th class="numeric">Score</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Web Server Compromise</strong></td>
      <td class="numeric high">9/10</td>
      <td>Complete server control with data exfiltration and lateral movement capabilities</td>
    </tr>
    <tr>
      <td><strong>Cloud Infrastructure Abuse</strong></td>
      <td class="numeric high">8/10</td>
      <td>Legitimate cloud services abused for C2, exfiltration, and attack infrastructure</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="numeric high">8/10</td>
      <td>Multiple backdoors with RSA encryption ensuring exclusive attacker access</td>
    </tr>
    <tr>
      <td><strong>Attribution Fingerprints</strong></td>
      <td class="numeric medium">7/10</td>
      <td>Strong attribution evidence but may indicate shared tools across threat groups</td>
    </tr>
  </tbody>
</table>

### Recommended Actions

#### Priority 1: Immediate Response
1. **ISOLATE** web servers with PHP backdoor infections from production networks
2. **BLOCK** known malicious infrastructure at the network perimeter (`45[.]118[.]144[.]151:8081`, `152[.]32[.]191[.]156:8081`)
3. **SCAN** web server directories for PHP backdoors using provided IOCs
4. **AUDIT** cloud service access logs for unauthorized API usage and exfiltration indicators
5. **COLLECT** forensic evidence: web server logs, memory images, and network captures

#### Priority 2: Investigation
1. Reconstruct the exploitation timeline from web server logs
2. Correlate log entries against known malicious infrastructure indicators
3. Audit cloud accounts for unauthorized API access and anomalous data transfers
4. Recover and analyze PHP backdoors and exploit kit components
5. Hunt for lateral movement and additional compromised hosts

#### Priority 3: Remediation
1. Rebuild compromised web servers from verified clean images
2. Apply current patches to all web applications and frameworks
3. Deploy web application firewall rules targeting PHP backdoor patterns
4. Establish baseline monitoring for cloud service API usage

---

## Technical Analysis

### Infrastructure Overview
<table class="professional-table">
  <thead>
    <tr>
      <th>Infrastructure Component</th>
      <th>Value</th>
      <th>Role in Attack Chain</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Primary C2 Server</strong></td>
      <td>45.118.144[.]151:8081</td>
      <td>Initial webshell deployment and backdoor hosting</td>
    </tr>
    <tr>
      <td><strong>Exploitation Server</strong></td>
      <td>152.32.191[.]156:8081</td>
      <td>Exploit kits, payload delivery, and automation</td>
    </tr>
    <tr>
      <td><strong>Content Delivery</strong></td>
      <td>juyu1[.]yifanyi.app</td>
      <td>Malicious content distribution and SEO poisoning</td>
    </tr>
    <tr>
      <td><strong>Command Infrastructure</strong></td>
      <td>shellcp[.]info</td>
      <td>Remote content injection and proxy services</td>
    </tr>
  </tbody>
</table>

---

### Phase 1: Initial Discovery (45.118.144[.]151)

> **Analyst note:** This phase covers the attacker's first-stage implants: a backdoored PHP page that executes only attacker-signed payloads, a general-purpose command shell, and a traffic redirector. Understanding the RSA-keyed execution gate is key — it blocks any third party from reusing these backdoors against the same victims.

**File: pg-politica-de-privacidade.php**  
- Trojanized Privacy Policy page.  
- PHP class `A` with `__wakeup()` method.  
- Hardcoded RSA public key → only attacker‑encrypted payloads execute.  
- Trigger: `$_POST['mxx']`.  
- Obfuscation: dynamically builds function names (`openssl_public_decrypt`, `base64_decode`).  
- Executes decrypted payload via `eval()`.  
- Camouflage: Legitimate Portuguese Privacy Policy appended.  
- **Implication:** Exclusive access backdoor; RSA key is a campaign fingerprint.  
- **Hunting Highlights:**  
  - PHP files with `__wakeup()` + `unserialize()` + `eval()`  
  - POST requests with parameter `mxx`  
  - Embedded RSA public key blocks in PHP code  

**File: upnimix.php**  
- Full‑featured PHP webshell.  
- Capabilities: command execution, file upload/edit/delete/rename, directory listing.  
- **Implication:** Persistence and full remote control.  
- **Hunting Highlights:**  
  - PHP files with `goto` + `exec/system/shell_exec/passthru`  
  - POSTs with parameters like `cmd`, `file_content`, `upload`  
  - PHP spawning OS processes (`/bin/sh`, `cmd.exe`)  

**File: video.php**  
- Remote content injector.  
- Behavior: proxies requests to `shellcp[.]info/api.php`.  
- Cloaks behavior for Googlebot (`?googlebot`).  
- **Implication:** SEO poisoning, phishing, or malware delivery.  
- **Hunting Highlights:**  
  - PHP files with `file_get_contents("http://shellcp.info/...")`  
  - Outbound HTTP requests to `shellcp[.]info`  
  - Cloaking logic tied to "oogle" in User‑Agent  

---

### Phase 2: Pivot & Exploitation (152.32.191[.]156)

> **Analyst note:** This phase covers the exploit kits targeting CloudPanel — a web hosting control panel. The exploit chain forges an authentication cookie to bypass access controls, then creates and uploads a command shell. Attackers also create a persistent OS-level account as a fallback.

**Exploit Kits**  
- Scripts: 测试.py, exploit.py, exploit2.py.  
- Helper: Crypto.php (forged `clp-fm` cookie).  
- Exploit chain: forge cookie → access `/file-manager/` → create file → upload shell → set permissions → verify at `/htdocs/app/files/public/shell.php`.  
- Variants: batch exploitation, version‑specific (CloudPanel 0day Version : 2.0.0 >= 2.3.0).  
- Persistence variant: creates user `zeroday` / password `Etharus@1337`.  

**Webshells**  
- One‑liner (`?cmd=` → system execution, fallback to phpinfo()).  
- `shell.php` uploaded with 0777 permissions.  

**Hunting Highlights**  
- Web logs with cookie header `clp-fm`.  
- Access to `/file-manager/backend/makefile` or `/phpmyadmin/js/`.  
- New privileged accounts (`zeroday`).  
- File creation in `/htdocs/app/files/public/`.  
- Requests with `?cmd=` in query strings.  

---

### Phase 3: Exfiltration & Cloud Abuse

> **Analyst note:** This phase covers the attacker's use of legitimate cloud storage APIs to move stolen data off the victim server. Because outbound traffic reaches real cloud provider endpoints (Dropbox, AWS), standard perimeter blocks are ineffective — detection depends on behavioral anomalies in the traffic volume and destination.

**Modules**  
- **Dropbox:** Client.php, AccessCodeValidator.php → API abuse for stealthy uploads.  
- **Rclone:** Rclone.php, TarCreator.php → bulk data theft, retries, throttling.  
- **AWS:** Ami.php, Instance.php, Regions.php → S3 exfiltration, destructive actions possible.  

**Hunting Highlights**  
- Outbound traffic to `api.dropboxapi.com`.  
- Rclone process execution (`rclone`, `rclone.exe`).  
- Unexpected S3 PutObject/DeleteObject events in CloudTrail.  
- Large outbound transfers to cloud storage from servers without backup roles.  

---

### Phase 4: Infrastructure Automation

> **Analyst note:** This phase covers the attacker's toolkit for scaling compromised infrastructure — installing new web applications, standing up reverse proxies, and automating domain provisioning. This automation capability indicates the operator treats compromised servers as reusable attack nodes, not one-time footholds.

**Site Builder Framework (Site/ directory)**  
- Installers: WordPressInstaller.php, PhpSite.php, NodejsSite.php, PythonSite.php.  
- Reverse Proxy: ReverseProxySite.php → traffic redirection.  
- Domain Automation: DomainName.php.  
- Scaling: VarnishCache/Creator.php.  

**Hunting Highlights**  
- Automated WordPress installs from non‑admin sources.  
- Sudden creation of reverse proxy configs in Nginx/Apache.  
- Varnish cache deployments on non‑web infra.  
- Suspicious PHP files named WordPressInstaller.php, ReverseProxySite.php.  

---

## Attack Chain Analysis

### Campaign Structure Summary
<table class="professional-table">
  <thead>
    <tr>
      <th>Attack Phase</th>
      <th>Primary Techniques</th>
      <th>Infrastructure Used</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Initial Access</strong></td>
      <td>CloudPanel 0-day exploit kits, PHP backdoors</td>
      <td>45.118.144[.]151:8081</td>
      <td class="high">CRITICAL - Server compromise</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>Webshells, backdoor accounts, RSA-encrypted payloads</td>
      <td>Multiple compromised servers</td>
      <td class="high">HIGH - Long-term access</td>
    </tr>
    <tr>
      <td><strong>Exfiltration</strong></td>
      <td>Dropbox API abuse, Rclone, AWS S3 exploitation</td>
      <td>Legitimate cloud services</td>
      <td class="high">HIGH - Data theft</td>
    </tr>
    <tr>
      <td><strong>Infrastructure Scaling</strong></td>
      <td>Automated site builder framework, reverse proxies</td>
      <td>Compromised web infrastructure</td>
      <td class="medium">MEDIUM - Attack expansion</td>
    </tr>
  </tbody>
</table>

### Attribution Fingerprints
<table class="professional-table">
  <thead>
    <tr>
      <th>Fingerprint Type</th>
      <th>Value</th>
      <th>Confidence Level</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>RSA Public Key</strong></td>
      <td>Reused across multiple IPs and backdoors</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Cookie Names</strong></td>
      <td>clp-fm (consistent across exploit kits)</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>File Paths</strong></td>
      <td>/htdocs/app/files/public/shell.php</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Account Patterns</strong></td>
      <td>zeroday/Etharus@1337 (consistent credentials)</td>
      <td class="likely">MODERATE</td>
    </tr>
  </tbody>
</table>

---

### Operational Impact Assessment

### Impact Scenarios
<table class="professional-table">
  <thead>
    <tr>
      <th>Impact Category</th>
      <th>Severity Level</th>
      <th>Recovery Time</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Data Compromise</strong></td>
      <td class="high">HIGH</td>
      <td>extended period</td>
    </tr>
    <tr>
      <td><strong>System Compromise</strong></td>
      <td class="high">HIGH</td>
      <td>several weeks</td>
    </tr>
    <tr>
      <td><strong>Cloud Service Abuse</strong></td>
      <td class="medium">MEDIUM</td>
      <td>several weeks</td>
    </tr>
    <tr>
      <td><strong>Operational Disruption</strong></td>
      <td class="high">HIGH</td>
      <td>several weeks</td>
    </tr>
  </tbody>
</table>

### Operational Impact Timeline
- **Immediate Response:** Web server isolation, service disruption, emergency response
- **Investigation Phase:** System rebuilding, security hardening, enhanced monitoring
- **Recovery Phase:** Process improvements, cloud security implementation
- **Long-term Phase:** Security architecture review, compliance activities

---

### Frequently Asked Questions

### Technical Questions
**Q: What makes the RSA encryption backdoor particularly dangerous?**  
A: It ensures exclusive attacker access — only payloads encrypted with the corresponding private key will execute, preventing other actors or security tools from reusing the backdoor.

**Q: How does cloud service abuse work in this campaign?**  
A: Attackers abuse legitimate cloud APIs (Dropbox, AWS S3) for data exfiltration and infrastructure, making detection difficult because traffic reaches real cloud provider endpoints.

**Q: What are the key hunting indicators for this campaign?**  
A: PHP files with `__wakeup()` methods, POST requests with `mxx` parameter, embedded RSA keys, and access to `/file-manager/` endpoints with forged cookies.

### Business Questions
**Q: What are the regulatory implications of cloud service abuse?**  
A: Unauthorized cloud access can trigger data breach notification obligations and potential liability for customer data exposure, depending on applicable regulations.

**Q: Should compromised web servers be rebuilt or patched?**  
A: Rebuilding from a verified clean image is the safer path given the depth of backdoor access and the possibility of additional hidden compromise mechanisms.

**Q: How can similar cloud abuse be prevented?**  
A: Cloud access monitoring, API security controls, regular access reviews, and least-privilege enforcement on cloud service accounts each reduce the attack surface for this technique.

---

### IOCs
- [From Webshells to The Cloud IOCs]({{ "/ioc-feeds/webshells-to-the-cloud.json" | relative_url }})

### Detections
- [From Webshells to The Cloud Detections]({{ "/hunting-detections/webshells-to-the-cloud/" | relative_url }})

---

## License

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
