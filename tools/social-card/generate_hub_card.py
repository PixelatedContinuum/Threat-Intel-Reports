#!/usr/bin/env python3
"""Generate social cards for listing / hub / landing pages.

These pages have no per-report front matter, so their cards are defined here by
a small spec table and rendered with cardlib.render_hub_card. Mirrors
generate_card.py for the per-report path.

    python tools/social-card/generate_hub_card.py            # all
    python tools/social-card/generate_hub_card.py stix       # one or more

Each card is wired to its page via a `thumbnail:` line (landing pages) or a
Jekyll `defaults` rule in _config.yml (the detection corpus); head.liquid turns
page.thumbnail into og:image / twitter:image — same mechanism as report cards.
`accent` matches each page's header --ph-accent so the card and page agree.
"""
import os
import sys
import cardlib

REPO = os.path.abspath(os.path.join(cardlib.HERE, "..", ".."))
CARDS = os.path.join(REPO, "assets", "images", "cards")

CC = "CC BY-NC 4.0"

# slug -> card spec. `accent` colors the spine + pill (matches each page's
# --ph-accent); pill/kicker/title/subtitle mirror the page's header block.
HUBS = {
    "stix": dict(
        accent="#22d3ee", pill="STIX 2.1", kicker="THREAT INTELLIGENCE",
        title="STIX Bundles",
        subtitle="Per-campaign STIX 2.1 bundles — import into OpenCTI, MISP, "
                 "or any STIX-aware platform.",
        footer_left=CC),
    "reports": dict(
        accent="#a371f7", pill="REPORTS", kicker="ORIGINAL RESEARCH",
        title="Threat Intelligence Reports",
        subtitle="Original malware analysis and reverse engineering — every "
                 "report ships with detection rules and IOCs.",
        footer_left=""),
    "ioc-feeds": dict(
        accent="#f87171", pill="IOC FEEDS", kicker="MACHINE-READABLE",
        title="Indicators of Compromise",
        subtitle="Structured feeds ready for your SIEM, EDR, or CTI platform.",
        footer_left=CC),
    "hunting-detections": dict(
        accent="#4ade80", pill="DETECTIONS", kicker="DETECTION ENGINEERING",
        title="Sigma, YARA & Suricata Rules",
        subtitle="Detection logic from original research, mapped to MITRE ATT&CK.",
        footer_left=CC),
    "about": dict(
        accent="#60a5fa", pill="ABOUT", kicker="ABOUT THE AUTHOR",
        title="Joseph Harrison",
        subtitle="SOC Operations Lead & Threat Intelligence Researcher.",
        footer_left=""),
    "consulting": dict(
        accent="#b8902f", pill="CONSULTING", kicker="CONSULTING & ADVISORY",
        title="Threat Intelligence That Works for Your Team",
        subtitle="The depth behind this site, applied directly to your environment.",
        footer_left=""),
    "subscribe": dict(
        accent="#3b82f6", pill="SUBSCRIBE", kicker="STAY INFORMED",
        title="Subscribe to The Hunter's Ledger",
        subtitle="New reports, detections, and IOC feeds — the moment they publish.",
        footer_left=""),
    "support": dict(
        accent="#f472b6", pill="SUPPORT", kicker="SUPPORT THE WORK",
        title="Keep This Research Independent",
        subtitle="Run by a single researcher. No corporate backing, "
                 "no paywalls, no ads.",
        footer_left=""),
    "sponsor": dict(
        accent="#f59e0b", pill="SPONSOR", kicker="SPONSORSHIP",
        title="Reach Defenders Who Build, Buy, and Use Detection",
        subtitle="Place your brand alongside technical research working "
                 "defenders actually use.",
        footer_left=""),
    "behind-the-reports": dict(
        accent="#f97316", pill="PROCESS", kicker="BEHIND THE REPORTS",
        title="How the Intelligence Is Produced",
        subtitle="The systems, the design decisions, and why they were built.",
        footer_left=""),
}


def main(argv):
    names = argv or list(HUBS)
    for name in names:
        if name not in HUBS:
            raise SystemExit(f"unknown hub '{name}' (known: {', '.join(HUBS)})")
        spec = dict(HUBS[name])
        accent = spec.pop("accent")
        out = os.path.join(CARDS, f"{name}.png")
        cardlib.render_hub_card(spec, out, accent=accent)
        print("wrote", out)


if __name__ == "__main__":
    main(sys.argv[1:])
