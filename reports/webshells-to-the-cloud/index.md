---
title: From Webshells to the Cloud - A Modular Intrusion Chain
date: '2025-10-20'
layout: page
permalink: /reports/webshells-to-the-cloud/
hide: true
---

## Executive Summary
This campaign demonstrates a modular intrusion chain leveraging PHP backdoors, exploit kits, and cloud abuse. Attackers pivot from initial webshell deployment to exploitation, persistence, exfiltration, and infrastructure automation. The reuse of RSA keys, cookie names, and file paths provides strong attribution fingerprints.

---

## Technical Details

### Infrastructure Overview
- **IP 1:** hxxp://45.118.144[.]151:8081  
- **IP 2:** hxxp://152.32.191[.]156:8081  
- **Domains:** juyu1[.]yifanyi.app, shellcp[.]info  
- **Role:** Dedicated malicious infrastructure hosting PHP backdoors, exploit kits, and Cobalt Strike C2.

---

### Phase 1: Initial Discovery (45.118.144[.]151)

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
  - Cloaking logic tied to “oogle” in User‑Agent  

---

### Phase 2: Pivot & Exploitation (152.32.191[.]156)

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

## Final Takeaway
This campaign is modular, layered, and resilient:  
- **Initial Access:** CloudPanel 0‑day exploit kits.  
- **Persistence:** Webshells, backdoor accounts.  
- **Exfiltration:** Dropbox, Rclone, AWS S3.  
- **Infrastructure Scaling:** Automated site builder framework.  
- **Attribution Fingerprint:** RSA public key reuse across multiple IPs.  

---

## IOCs
- [From Webshells to The Cloud IOCs]({{ "/ioc-feeds/webshells-to-the-cloud.json" | relative_url }})

## Detections
- [From Webshells to The Cloud Detections]({{ "/hunting-detections/webshells-to-the-cloud/" | relative_url }})
