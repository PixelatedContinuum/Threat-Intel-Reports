#!/usr/bin/env python
"""Sponsor threat brief: the distilled, shareable version of a published report.

What this is
-------------
A Report Sponsor gets the report they sponsored packaged as a short, designed
brief they can forward. It is NOT a PDF export of the report. It is a derivative
intelligence product: the key points, what to do now, the detections and
indicators worth acting on today, and a technical breakdown of only the parts
that actually stand out.

That distinction is the whole product. The report is public and CC BY 4.0, so a
sponsor could already make a PDF of it. What they cannot do is decide what
matters, and that judgement is what they are being given.

How it works, and why it is a two-step
---------------------------------------
Everything mechanical generates: severity, ATT&CK coverage, the detections worth
acting on, the indicators safe to block. Everything that takes judgement is
written, and `--init` hands you a stub with the generated half already filled and
the written half pre-seeded from the report's own description, so it is an edit
rather than a blank page. Same shape as quarterly_update_gen.py.

    python3 docs/report-brief-gen.py --slug <slug> --init     # writes docs/briefs/<slug>.yml
    ...edit that file...
    python3 docs/report-brief-gen.py --slug <slug>             # renders the PDF

THE SAFETY RULE THAT MATTERS MOST
----------------------------------
A brief that says "block these now" goes from a sponsor's inbox to their SOC. An
August 2026 audit found 63 hosts across 21 published feeds that would harm a
bystander if blocked: api.telegram.org, pastebin.com, github.com, Cloudflare
nameservers, and fifteen victim-side values. Those live in each feed's
`hunt_only_never_block` bucket.

So: nothing from that bucket ever reaches the blockable section. It is rendered
separately and labelled watch, never block. The exclusion is applied BY VALUE, so
a value appearing in both buckets is still excluded.

`action: "HUNT"` is NOT a safety signal here. It is detection-TIER vocabulary, and
treating it as "do not block" previously matched 169 entries including operator
IPs and SHA256 hashes. This reads the bucket, never an action field.

Requires: reportlab, PyYAML.
"""
import argparse
import glob
import json
import os
import sys

import yaml
from xml.sax.saxutils import escape as xesc
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hl_doc_theme import (  # noqa: E402
    INK, PANEL, PANEL_EDGE, GOLD, BLUE, GREEN, RED, PAPER, DIM, FAINT, SEV,
    PAGE, MARGIN, S, rule, bullets, scaled, panel, stat_strip, dark_table,
    paint_cover, make_interior_painter, LOGO_ON_DARK, style)

DATA = os.path.join(REPO, "_data")
BRIEFS = os.path.join(REPO, "docs", "briefs")
OUTDIR = os.path.join(REPO, "docs", "briefs", "out")
CONTENT_W = PAGE[0] - MARGIN["leftMargin"] - MARGIN["rightMargin"]


def _yaml(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def report_front_matter(slug):
    p = os.path.join(REPO, "reports", slug, "index.md")
    if not os.path.exists(p):
        return {}
    with open(p, encoding="utf-8") as fh:
        text = fh.read()
    if not text.startswith("---"):
        return {}
    try:
        return yaml.safe_load(text.split("---", 2)[1]) or {}
    except yaml.YAMLError:
        return {}


def catalog_entry(slug):
    cat = _yaml("catalog.yml")
    entries = cat if isinstance(cat, list) else (cat.get("reports") or list(cat.values())[0])
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("slug") == slug or (e.get("report_url") or "").strip("/").endswith(slug):
            return e
    return {}


# ---------------------------------------------------------------- indicators
# Phrases in which the ANALYST has said, in their own words, do not block this.
# They appear in `false_positive_risk` / `false_positive_notes` prose rather than in
# the hunt_only_never_block bucket, so nothing currently reads them: measured
# 2026-09-13, values carrying these phrases sit in blockable buckets across the
# published feeds today. The August 2026 audit's own conclusion was that "the
# author's own marking catches what no list can"; this reads that marking wherever
# the author put it.
#
# Deliberately narrow. It does NOT trigger on "legitimate" alone, nor on a high
# false_positive_risk alone, because the same audit warns against over-correcting:
# a tenant hostname under a shared provider stays blockable, a path-bearing URL is
# a precise indicator, and mining pools stay blockable by decision.
NEVER_BLOCK_PHRASES = (
    "do not block", "don't block", "never block", "not for blocking",
    "do not use for blocking", "do not blocklist", "do not preemptively block",
    "notify victim before blocking", "victim-side", "not a malicious destination",
)


def _says_never_block(node):
    if not isinstance(node, dict):
        return ""
    for key in ("false_positive_risk", "false_positive_notes", "context", "role", "note"):
        v = str(node.get(key) or "").lower()
        for phrase in NEVER_BLOCK_PHRASES:
            if phrase in v:
                return phrase
    return ""


def _harvest(node, out, flagged=None):
    """Collect indicator values from ANY nesting. Measured across the 57 published
    feeds, leaves are 565 dicts, 127 scalar strings, 25 bare strings in lists, plus
    Nones and ints. A walker that assumed one shape would silently drop whole
    categories and report a short list as though it were the whole feed."""
    if node is None:
        return
    if isinstance(node, dict):
        if "value" in node and isinstance(node["value"], (str, int)):
            rec = {"value": str(node["value"]),
                   "context": node.get("context") or node.get("role")
                   or node.get("category") or node.get("note") or ""}
            phrase = _says_never_block(node)
            if phrase and flagged is not None:
                rec["why"] = phrase
                flagged.append(rec)
                return
            out.append(rec)
            return
        for v in node.values():
            _harvest(v, out, flagged)
    elif isinstance(node, list):
        for v in node:
            _harvest(v, out, flagged)
    elif isinstance(node, str) and node.strip():
        out.append({"value": node.strip(), "context": ""})


def load_feed(slug, entry):
    """Returns (blockable, hunt_only, feed_path). Both feed schemas are handled:
    the flat one keyed network_indicators/file_hashes/host_indicators, and the
    nested `IOCs: {Group: [...]}` one."""
    fn = (entry.get("ioc_url") or "").strip("/").split("/")[-1]
    cands = [os.path.join(REPO, "ioc-feeds", fn)] if fn else []
    cands += glob.glob(os.path.join(REPO, "ioc-feeds", f"{slug}*.json"))
    path = next((c for c in cands if c and os.path.exists(c)), None)
    if not path:
        return [], [], None, []
    with open(path, encoding="utf-8") as fh:
        feed = json.load(fh)

    hunt = []
    _harvest(feed.get("hunt_only_never_block"), hunt)
    hunt_values = {h["value"] for h in hunt}

    block, flagged = [], []
    for key in ("network_indicators", "host_indicators", "file_hashes", "IOCs"):
        _harvest(feed.get(key), block, flagged)
    # Anything the analyst marked never-block, wherever they marked it, joins the
    # watch list rather than the blockable one. Reported loudly, never silently.
    for f in flagged:
        if f["value"] not in {h["value"] for h in hunt}:
            hunt.append(f)
        hunt_values.add(f["value"])
    # Exclude BY VALUE, so a value present in both buckets is still excluded.
    seen, keep = set(), []
    for b in block:
        if b["value"] in hunt_values or b["value"] in seen:
            continue
        seen.add(b["value"])
        keep.append(b)
    return keep, hunt, os.path.basename(path), flagged


def act_now_rules(slug):
    """Detection-tier rules, ranked by robustness.

    NOT 'Detection tier at robustness 3': measured 2026-09-13, that filter is empty
    for 15 of 58 reports, so a brief built on it renders 'nothing to act on' for a
    quarter of the corpus. Detection tier at any robustness is empty for 4, and
    those 4 fall back to the best Hunting rules, labelled honestly."""
    man = _yaml("detection_manifests.yml")
    key = next((k for k in man if k.startswith(slug)), None)
    if not key:
        return [], False
    rules = man[key]
    det = [r for r in rules if r.get("tier") == "Detection"]
    fell_back = False
    if not det:
        det = [r for r in rules if r.get("tier") == "Hunting"]
        fell_back = True
    det.sort(key=lambda r: (-(r.get("robustness") or 0), r.get("name") or ""))
    return det, fell_back


def attack_rows(slug):
    a = _yaml("detection_attack.yml")
    key = next((k for k in a if k.startswith(slug)), None)
    return (a.get(key) or {}) if key else {}


# ---------------------------------------------------------------- stub
STUB_HELP = """# Sponsor threat brief content for {slug}.
#
# The generated half (severity, ATT&CK, detections, indicators) is NOT in this
# file. It is read live from _data/ and the IOC feed at render time, so it can
# never drift from what the site publishes.
#
# What is here is the half that takes judgement. Most of it can be lifted from
# the report itself and tightened; that is the intended workflow, not writing
# from scratch.
#
# Render with:  python3 docs/report-brief-gen.py --slug {slug}
"""


def init_stub(slug, entry, fm):
    os.makedirs(BRIEFS, exist_ok=True)
    path = os.path.join(BRIEFS, f"{slug}.yml")
    if os.path.exists(path):
        print(f"refusing to overwrite existing {os.path.relpath(path, REPO)}")
        return 1
    doc = {
        "slug": slug,
        "title": entry.get("title") or fm.get("title") or slug,
        # Seeded from the report's own description, present in 42 of 42 reports.
        "summary": fm.get("description", ""),
        "what_it_means": "",
        "do_now": ["", "", ""],
        "standout": [{"heading": "", "body": ""}],
    }
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(STUB_HELP.format(slug=slug))
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=88)
    print(f"wrote {os.path.relpath(path, REPO)}")
    print("  seeded 'summary' from the report's own description; fill the rest and re-run")
    return 0


# ---------------------------------------------------------------- render
def render(slug, content, entry, fm, sponsors):
    det, fell_back = act_now_rules(slug)
    block, hunt, feed_name, flagged = load_feed(slug, entry)
    atk = attack_rows(slug)
    sev = str(entry.get("severity") or "").lower()
    sev_col = SEV.get(sev, GOLD)

    sponsor = None
    sid = fm.get("sponsored_by")
    if sid:
        sid = sid[0] if isinstance(sid, list) else sid
        sponsor = sponsors.get(sid)

    story = [Spacer(1, 1.9 * inch)]
    lg = scaled(LOGO_ON_DARK, 3.2 * inch, 1.05 * inch)
    if lg:
        lg.hAlign = "CENTER"
        story.append(lg)
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("THREAT BRIEF", S["cover_eyebrow"]))
    story.append(Paragraph(xesc(content["title"]), S["cover_title"]))
    if entry.get("date"):
        story.append(Paragraph(str(entry["date"]), S["cover_body"]))
    story.append(Spacer(1, 1.5 * inch))
    if sponsor:
        story.append(Paragraph("PREPARED FOR", S["cover_eyebrow"]))
        story.append(Paragraph(xesc(sponsor.get("name", sid)), S["cover_body"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("Independent threat intelligence research<br/>"
                           "the-hunters-ledger.com", S["cover_body"]))
    story.append(PageBreak())

    # -------- executive brief
    story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
    story.append(Paragraph("The Brief", S["title"]))
    story.append(rule(sev_col))
    if content.get("summary"):
        story.append(Paragraph(xesc(content["summary"]), S["body"]))
    story.append(Spacer(1, 4))
    story.append(stat_strip([
        (sev.upper() or "N/A", "severity"),
        (str(atk.get("total", 0)), "ATT&amp;CK techniques"),
        (str(len(det)), "detections to deploy"),
        (str(len(block)), "indicators to block"),
    ], width=CONTENT_W))
    if content.get("what_it_means"):
        story.append(Spacer(1, 9))
        story.append(Paragraph("What this means", S["h2"]))
        story.append(Paragraph(xesc(content["what_it_means"]), S["body"]))
    do = [d for d in (content.get("do_now") or []) if str(d).strip()]
    if do:
        story.append(Paragraph("What to do now", S["h2"]))
        story.append(panel(bullets([xesc(d) for d in do]), accent=sev_col, width=CONTENT_W))
    story.append(PageBreak())

    # -------- act now
    story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
    story.append(Paragraph("Act On This Now", S["title"]))
    story.append(rule(sev_col))
    if det:
        if fell_back:
            story.append(Paragraph(
                "This campaign produced no alerting-grade rule. The rules below are "
                "hunting-grade: run them as hunts and triage the results, do not alert on them.",
                S["small"]))
            story.append(Spacer(1, 4))
        rows = [[Paragraph("Detection", S["cell_h"]), Paragraph("Engine", S["cell_h"]),
                 Paragraph("Robustness", S["cell_h"]), Paragraph("ATT&amp;CK", S["cell_h"])]]
        for r in det[:14]:
            rows.append([Paragraph(xesc(r.get("name", "")), S["cell"]),
                         Paragraph(xesc(str(r.get("engine", "")).upper()), S["cell"]),
                         Paragraph("&#9679;" * (r.get("robustness") or 0), S["cell"]),
                         Paragraph(xesc(", ".join(r.get("attack") or [])), S["cell"])])
        story.append(dark_table(rows, [CONTENT_W * .42, CONTENT_W * .13,
                                       CONTENT_W * .15, CONTENT_W * .30],
                                header_fill=sev_col))
        if len(det) > 14:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"Showing 14 of {len(det)}. The full set ships in the published detection "
                "package.", S["small"]))
    else:
        story.append(Paragraph("No detection rules were published for this campaign.",
                               S["body"]))

    story.append(Paragraph("Indicators safe to block", S["h2"]))
    if block:
        story.append(Paragraph(
            f"{len(block)} indicator(s) whose only cost to block is to the operator.",
            S["small"]))
        story.append(Spacer(1, 4))
        rows = [[Paragraph("Indicator", S["cell_h"]), Paragraph("Context", S["cell_h"])]]
        for b in block[:22]:
            rows.append([Paragraph(xesc(b["value"]), S["mono"]),
                         Paragraph(xesc(b["context"])[:120], S["cell"])])
        story.append(dark_table(rows, [CONTENT_W * .46, CONTENT_W * .54], header_fill=BLUE))
        if len(block) > 22:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"Showing 22 of {len(block)}. The full feed is published "
                                   "as machine-readable JSON.", S["small"]))
    else:
        story.append(Paragraph("No blockable indicators in the published feed.", S["body"]))

    if hunt:
        story.append(Paragraph("Watch, do not block", S["h2"]))
        story.append(panel([
            Paragraph(
                "These are genuinely used by the operator, which is why they are recorded. "
                "Blocking any of them harms bystanders rather than the operator. Hunt on them; "
                "never put them in a blocklist.", S["body"]),
            Paragraph(" &nbsp;&middot;&nbsp; ".join(
                xesc(h["value"]) for h in hunt[:14]), S["mono"]),
        ], accent=RED, width=CONTENT_W))

    # -------- standout
    standout = [s for s in (content.get("standout") or [])
                if str(s.get("heading", "")).strip() or str(s.get("body", "")).strip()]
    if standout:
        story.append(PageBreak())
        story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
        story.append(Paragraph("What Stands Out", S["title"]))
        story.append(rule(sev_col))
        story.append(Paragraph(
            "The parts of this campaign worth a technical reader's time. Routine tradecraft is "
            "left in the full report.", S["subtitle"]))
        for s in standout:
            if s.get("heading"):
                story.append(Paragraph(xesc(s["heading"]), S["h2"]))
            if s.get("body"):
                for para in str(s["body"]).split("\n\n"):
                    if para.strip():
                        story.append(Paragraph(xesc(para.strip()), S["body"]))

    story.append(Spacer(1, 14))
    story.append(rule(PANEL_EDGE, 0.7, 2, 6))
    url = (entry.get("report_url") or "").strip()
    story.append(Paragraph(
        f"Full report, detection package and machine-readable IOC feed: "
        f"<font color='#58A6FF'>the-hunters-ledger.com{xesc(url)}</font>", S["body"]))
    story.append(Paragraph(
        "I researched, wrote and published this independently. Sponsorship buys placement, never "
        "influence: the sponsor did not see it before it went live, and had no say in its "
        "findings, its attribution or its conclusions.", S["small"]))

    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, f"HuntersLedger-Brief-{slug}.pdf")
    doc = SimpleDocTemplate(out, pagesize=PAGE, **MARGIN,
                            title=f"Threat Brief: {content['title']}",
                            author="The Hunters Ledger")
    doc.build(story, onFirstPage=paint_cover,
              onLaterPages=make_interior_painter("the-hunters-ledger.com"))
    print(f"wrote {os.path.relpath(out, REPO)}")
    print(f"  severity {sev or 'N/A'} | ATT&CK {atk.get('total', 0)} | "
          f"detections {len(det)}{' (HUNTING fallback)' if fell_back else ''} | "
          f"blockable {len(block)} | hunt-only excluded {len(hunt)} | feed {feed_name}")
    if flagged:
        print(f"  WARNING: {len(flagged)} indicator(s) sat in a BLOCKABLE bucket in the")
        print("  published feed while carrying the analyst's own do-not-block marking.")
        print("  Moved to the watch list here. The FEED still needs fixing:")
        for f in flagged:
            print(f"    {f['value']}  (matched: \"{f['why']}\")")
    return 0


def selftest():
    """Prove the extractors fire before any empty section is believed."""
    ok = True
    man = _yaml("detection_manifests.yml")
    print(f"control: detection manifests: {len(man)}")
    feeds = glob.glob(os.path.join(REPO, "ioc-feeds", "*.json"))
    print(f"control: IOC feeds on disk: {len(feeds)}")

    # Both feed schemas must yield indicators, or one shape is being silently dropped.
    flat = nested = 0
    for f in feeds:
        d = json.load(open(f, encoding="utf-8"))
        got = []
        for k in ("network_indicators", "host_indicators", "file_hashes", "IOCs"):
            _harvest(d.get(k), got)
        if got:
            if "IOCs" in d:
                nested += 1
            else:
                flat += 1
    print(f"control: feeds yielding indicators: flat-schema {flat}, nested-schema {nested}")
    if flat == 0 or nested == 0:
        print("  FAIL: one feed schema yielded nothing, so it is being silently dropped.")
        ok = False

    hunts = 0
    for f in feeds:
        d = json.load(open(f, encoding="utf-8"))
        h = []
        _harvest(d.get("hunt_only_never_block"), h)
        if h:
            hunts += 1
    print(f"control: feeds with a populated hunt_only_never_block: {hunts}")
    if hunts == 0:
        print("  FAIL: expected ~15; the never-block exclusion is not being read at all.")
        ok = False

    empties = [k for k in man if not [r for r in man[k] if r.get("tier") == "Detection"]]
    print(f"control: manifests with no Detection-tier rule (fall back to Hunting): "
          f"{len(empties)} of {len(man)}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slug")
    ap.add_argument("--init", action="store_true", help="write an editable content stub")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.slug:
        ap.print_help()
        return 0
    entry, fm = catalog_entry(a.slug), report_front_matter(a.slug)
    if not fm:
        print(f"FAIL: no report at reports/{a.slug}/index.md", file=sys.stderr)
        return 1
    if a.init:
        return init_stub(a.slug, entry, fm)
    path = os.path.join(BRIEFS, f"{a.slug}.yml")
    if not os.path.exists(path):
        print(f"FAIL: no content file. Run with --init first.", file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as fh:
        content = yaml.safe_load(fh)
    sponsors = {s["id"]: s for s in (_yaml("sponsors.yml").get("sponsors") or [])}
    return render(a.slug, content, entry, fm, sponsors)


if __name__ == "__main__":
    sys.exit(main())
