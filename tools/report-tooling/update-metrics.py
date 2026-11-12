#!/usr/bin/env python
"""
update-metrics.py — recompute The Hunter's Ledger home-page headline metrics
from the actual published files and write them to _data/metrics.yml.

Run from anywhere: the repo root is found from this file's own location
(<repo>/tools/report-tooling/update-metrics.py), so a worktree or a move needs no
edit. Re-run before each publish commit so the home creds-strip stays current.
GitHub Pages can't run a counting plugin (safe mode), so this is a local pre-commit
step; the generated _data/metrics.yml is committed and the home reads
site.data.metrics.*.

Counts:
  detection_rules = YARA (^rule X) + Sigma (^logsource: or ^correlation:) + Suricata (rule lines with sid:) across
                    every hunting-detections/*.md
  iocs            = individual indicator/artifact entries across every
                    ioc-feeds/*.json, counting ONLY the indicator/artifact keys in
                    IOC_KEYS below (hashes, network endpoints, host artifacts like
                    registry keys / mutexes / file paths, certs, handles, wallets,
                    generic indicator arrays). Deliberately EXCLUDES TTPs, MITRE
                    techniques, capabilities, tags, detection rules, remediation
                    steps, timeframes, notes, and other narrative content.

detection_rules is NOT the detection manifest's total, and the two must not be
"reconciled". At site 9e6b063 (2026-11-12) this script wrote detection_rules: 754
while _data/detection_manifests.yml held 711 entries. This counter counts rule
DOCUMENTS: every YARA `rule` line, every Sigma document keyed `logsource:` or
`correlation:`, every Suricata signature line carrying a `sid:` (245 + 379 + 130).
The manifest (tools/report-tooling/generate-detection-manifests.js, through
lib/parse-detections.js) counts HEADINGS: one entry per `####` heading that carries
a Tier line (245 YARA + 341 Sigma + 125 Suricata). A heading whose single fence
bundles several rules is one manifest entry and several counted rules: 38 Sigma
documents and 5 Suricata signatures sit inside such bundles, which is the whole
43-rule gap. The home tile reads detection_rules; no page publishes the site-wide
manifest total (each detection page shows its own entry count).
"""
import json, glob, os, re, sys

sys.stdout.reconfigure(encoding="utf-8")

# <repo>/tools/report-tooling/update-metrics.py -> <repo>
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DET_DIR = REPO + "/hunting-detections"
IOC_DIR = REPO + "/ioc-feeds"
OUT = REPO + "/_data/metrics.yml"

# --- IOC / artifact key whitelist (lowercased) -----------------------------
# Things a defender can hunt, block, or detect on as a concrete indicator.
IOC_KEYS = {
    # file hashes
    "sha256", "sha1", "md5", "imphash", "imphashes", "hashes",
    # IP / network endpoints
    "ipv4", "ipv6", "ips", "cidr_ranges", "infrastructure", "c2_infrastructure",
    "loopback_c2", "reverse_dns", "asn", "asns",
    # domains
    "domains", "onion_addresses", "nameservers", "subdomain_patterns",
    # urls / http
    "urls", "exploitendpoints", "url_patterns", "user_agents", "http_headers",
    "custom_http_headers",
    # certificates / fingerprints
    "ssl_certificates", "certificates", "tls_fingerprints", "tls_fingerprint",
    "tls_indicators", "pgp_fingerprints",
    # host-based artifacts
    "registry_keys", "registry", "target_registry_keys", "vm_detection_registry",
    "mutexes", "mutex_names", "mutex_thread", "named_pipes", "rpc_interfaces",
    "file_paths", "filenames", "file_names", "filename_patterns",
    "suspicious_filenames", "unc_paths", "suspicious_locations", "locations",
    "dropped_files", "files", "associated_files", "scheduled_tasks",
    "scheduled_task_objects", "service_names", "machine_ids", "appid_guid",
    "section_names",
    # identity / contact / wallets
    "email_addresses", "cryptocurrency_wallets", "telegram_handles",
    "named_handles", "messaging_handles", "contact_handles", "operator_pseudonyms",
    "operator_panel_identifiers",
    # generic indicator collections
    "indicators", "high_confidence_indicators", "high_fidelity_indicators",
    "critical_indicators", "behavioral_indicators", "string_indicators",
    "fraudulent_indicators", "detection_indicators", "memory_indicators",
    "vm_indicators", "telegram_indicators", "iocs", "network", "payloads",
    "common_payloads", "related_samples", "samples", "affected_samples",
}

def is_unlisted(path):
    """True when a page carries `unlisted: true` in its front matter.

    Preview-mode pages are live only at their exact URL and are deliberately absent
    from every public surface. The Suricata feed generator already skips them; this
    check keeps the home-page counts consistent with what a visitor can actually
    reach. Without it, publishing any campaign silently folds every in-flight
    preview's rule and IOC totals into the public metrics, which both inflates the
    numbers and discloses that unpublished work exists.
    """
    try:
        head = open(path, encoding="utf-8", errors="replace").read(2000)
    except OSError:
        return False
    if not head.startswith("---"):
        return False
    end = head.find("\n---", 3)
    front = head[:end] if end != -1 else head
    return re.search(r"(?m)^unlisted:\s*true\s*$", front) is not None


def count_detection_rules():
    yara = sigma = suri = 0
    files = [f for f in glob.glob(DET_DIR + "/*.md")
             if os.path.basename(f) != "index.md" and not is_unlisted(f)]
    skipped = [f for f in glob.glob(DET_DIR + "/*.md")
               if os.path.basename(f) != "index.md" and is_unlisted(f)]
    for f in skipped:
        print("  (skipped unlisted/preview: %s)" % os.path.basename(f))
    for f in files:
        t = open(f, encoding="utf-8", errors="replace").read()
        yara += len(re.findall(r"(?m)^\s*rule\s+[A-Za-z_]\w*\s*[:{]", t))
        # Both Sigma document forms. A correlation rule is keyed on `correlation:` and
        # carries no `logsource:` of its own, since it references other rules rather than
        # a log source, so a logsource-only count silently dropped 24 of 360 documents.
        # The two keys never co-occur in one document, verified corpus-wide against the
        # `title:` and `id:` counts that every Sigma document carries exactly once.
        sigma += len(re.findall(r"(?m)^\s*(?:logsource|correlation):", t))
        # Anchored to the rule line, not to the sid token. A bare `sid:\d+` search
        # also matches every cross-reference a rule makes to its flowbits partner,
        # both in prose and inside msg:, and it matches sids named in retirement
        # notes for rules that no longer exist. That inflated the public home-page
        # count by 20 across the corpus (118 counted, 98 real). Verified corpus-wide
        # that no rule line lacks an inline sid:, so same-line matching loses nothing.
        suri += len(re.findall(r"(?m)^\s*(?:alert|drop|reject|pass)\s+\S+.*?\bsid:\s*\d+", t))
    return yara, sigma, suri, len(files)

def catalog_status():
    """Authoritative publication status per feed, from the site's own module.

    Delegated to tools/report-tooling/lib/catalog-status.js rather than reimplemented,
    because that module is the one place the rule lives: a campaign counts as published
    only when BOTH signals agree (its catalog entry uncommented AND `unlisted:` gone
    from the report front matter), and a disagreement between them is a FAILURE rather
    than something to resolve.

    This replaced a local proxy that inferred preview status from whether the campaign's
    DETECTION file was marked unlisted. On 2026-08-19 that proxy silently counted an
    embargoed campaign into the public home-page totals: MultiVector's catalog entry was
    commented out and its report carried `unlisted: true`, but its detection file had
    only `hide: true`, so the proxy saw nothing and 22 indicators plus its detection
    rules went into the published counts. Two definitions of "preview" drifting apart is
    exactly the failure catalog-status.js exists to prevent, so there is no second
    definition here any more.

    Returns {feed_filename: 'published'|'embargoed'|'unknown'}, or None when the module
    could not be run, which the caller must treat as NOT CHECKED rather than as clean.
    """
    import subprocess
    tooling = REPO + "/tools/report-tooling"
    script = (
        "var CS=require('./lib/catalog-status.js');"
        "var G=require('./generate-ioc-index.js');"
        "var fs=require('fs'),path=require('path');"
        "var root=path.join(__dirname,'..','..');"
        "var r=CS.resolve(fs.readFileSync(path.join(root,'_data','catalog.yml'),'utf8'),"
        "G.readUnlisted(path.join(root,'reports')));"
        "process.stdout.write(JSON.stringify({status:r.status,conflicts:r.conflicts||[]}));"
    )
    try:
        p = subprocess.run(["node", "-e", script], capture_output=True,
                           cwd=tooling, timeout=90)
        if p.returncode != 0:
            return None
        doc = json.loads(p.stdout.decode("utf-8"))
    except Exception:
        return None
    if doc.get("conflicts"):
        print("  PUBLICATION SIGNALS DISAGREE - refusing to write metrics:")
        for c in doc["conflicts"]:
            print("     %s: catalog says %s, front matter says %s"
                  % (c.get("feed"), c.get("catalog"), c.get("front_matter")))
        sys.exit(1)
    return doc.get("status") or None


STATUS = None       # populated in main()


def slug_of(name):
    return re.sub(r"-iocs\.json$|-detections\.md$|\.json$|\.md$", "",
                  os.path.basename(name))


def status_for_slug(slug):
    """Published status for a campaign slug, via its IOC feed entry."""
    if not STATUS:
        return None
    for feed, st in STATUS.items():
        if slug_of(feed) == slug:
            return st
    return None


def feed_is_preview(feed_path):
    """True when an IOC feed belongs to a campaign still in preview.

    IOC feeds are raw JSON with no front matter, so they cannot carry `unlisted`
    themselves - they stay private by having no catalog `ioc_url`. The reliable
    proxy is the campaign's own detection page: if that is unlisted, the whole
    campaign is unpublished and its indicators must not reach the public counts.
    """
    slug = slug_of(feed_path)

    # The authority, when it could be reached.
    st = status_for_slug(slug)
    if st is not None:
        return st != "published"

    # Fallback only when catalog-status.js could not run at all.
    for cand in (slug + "-detections.md", slug + ".md"):
        p = os.path.join(DET_DIR, cand)
        if os.path.exists(p) and is_unlisted(p):
            return True
    return False


def count_iocs():
    total = 0
    feeds = [f for f in glob.glob(IOC_DIR + "/*.json") if not feed_is_preview(f)]
    for f in glob.glob(IOC_DIR + "/*.json"):
        if feed_is_preview(f):
            print("  (skipped unlisted/preview feed: %s)" % os.path.basename(f))
    failed = []
    def walk(x):
        nonlocal total
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(v, list) and k.lower() in IOC_KEYS:
                    total += len(v)
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)
    for f in feeds:
        try:
            walk(json.load(open(f, encoding="utf-8")))
        except Exception as e:
            failed.append((os.path.basename(f), str(e)[:60]))
    return total, len(feeds), failed

def main():
    global STATUS
    STATUS = catalog_status()
    if STATUS is None:
        print("  NOT CHECKED: catalog-status.js could not be run, so publication")
        print("  status fell back to the detection-file proxy. Counts may include an")
        print("  embargoed campaign. Run `npm ci` in tools/report-tooling.")
    else:
        n = sum(1 for v in STATUS.values() if v != "published")
        print("  publication status from catalog-status.js: %d of %d feed(s) withheld"
              % (n, len(STATUS)))

    yara, sigma, suri, ndet = count_detection_rules()
    rules = yara + sigma + suri
    iocs, nfeeds, failed = count_iocs()

    yml = (
        "# Auto-generated by tools/report-tooling/update-metrics.py\n"
        "# Do NOT edit by hand — re-run the script to refresh.\n"
        "# Powers the home-page creds-strip (site.data.metrics.*).\n"
        "detection_rules: %d\n"
        "yara: %d\n"
        "sigma: %d\n"
        "suricata: %d\n"
        "iocs: %d\n"
    ) % (rules, yara, sigma, suri, iocs)
    open(OUT, "w", encoding="utf-8", newline="\n").write(yml)

    print("Detection rules: %d  (YARA %d + Sigma %d + Suricata %d)  across %d files"
          % (rules, yara, sigma, suri, ndet))
    print("IOCs / artifacts: %d  across %d feeds" % (iocs, nfeeds))
    if failed:
        print("WARNING — feeds that failed to parse (excluded):")
        for n, e in failed:
            print("  ", n, e)
    else:
        print("All feeds parsed cleanly.")
    print("Wrote", OUT)

if __name__ == "__main__":
    main()
