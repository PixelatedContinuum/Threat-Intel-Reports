#!/usr/bin/env python
"""
Generates The Hunter's Ledger sponsorship pricing sheet PDF.
Source of record for assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf.
Re-run after any offer change:  python3 docs/sponsorship-pricing-sheet-gen.py

TIER NAMES, PRICES, BILLING NOTES AND BENEFIT BULLETS ARE READ FROM
_data/sponsors.yml. They are not duplicated here, deliberately.

The version before this hardcoded all of it and carried a comment asking whoever
edited one to remember the other. That is a hope rather than a mechanism, and it
failed on 2026-09-13: the offer was reworked, the page updated, and the
downloadable sheet went on advertising a sponsor badge, a newsletter logo, a
quarterly spotlight post and a peak-month view count that had all been removed.
A prospect would have taken the stale sheet into a procurement conversation.

Look and palette come from docs/hl_doc_theme.py, shared with every other document
that leaves here so the brand cannot drift between them.

Requires: reportlab (5.0.1 verified), PyYAML. Run with python3 on Linux.
"""
import os
import sys

import yaml
from xml.sax.saxutils import escape as xesc
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(_REPO, "assets", "files", "Hunters-Ledger-Sponsorship-Pricing.pdf")
DATA = os.path.join(_REPO, "_data", "sponsors.yml")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hl_doc_theme import (  # noqa: E402
    INK, PANEL, PANEL_EDGE, GOLD, BLUE, PAPER, DIM, FAINT, PAGE, MARGIN, S,
    rule, bullets, scaled, panel, stat_strip, dark_table, paint_cover,
    make_interior_painter, LOGO_ON_DARK)

with open(DATA, encoding="utf-8") as fh:
    SPONSORS = yaml.safe_load(fh)
TIERS = {t["id"]: t for t in SPONSORS["tiers"]}
MONTHLY, REPORT = TIERS["monthly"], TIERS["report"]

CONTENT_W = PAGE[0] - MARGIN["leftMargin"] - MARGIN["rightMargin"]
story = []

# ---------------------------------------------------------------- cover
story.append(Spacer(1, 2.15 * inch))
_logo = scaled(LOGO_ON_DARK, 3.5 * inch, 1.15 * inch)
if _logo:
    _logo.hAlign = "CENTER"
    story.append(_logo)
story.append(Spacer(1, 0.62 * inch))
story.append(Paragraph("Sponsorship", S["cover_title"]))
story.append(Paragraph("Pricing and Packages", S["cover_sub"]))
story.append(Paragraph(
    "Independent threat intelligence research.<br/>"
    "Every report ships with working YARA, Sigma and Suricata detections,<br/>"
    "validated IOC feeds, and evidence-tied attribution.", S["cover_body"]))
story.append(Spacer(1, 2.3 * inch))
story.append(Paragraph("THE HUNTER'S LEDGER", S["cover_eyebrow"]))
story.append(Paragraph("the-hunters-ledger.com", S["cover_body"]))
story.append(PageBreak())

# ---------------------------------------------------------------- audience
story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
story.append(Paragraph("Sponsorship: Pricing and Packages", S["title"]))
story.append(Paragraph(
    "Independent threat intelligence research. Every report ships with working YARA, Sigma, and "
    "Suricata detections, validated IOC feeds, and evidence-tied attribution, alongside research "
    "working defenders actively integrate.", S["subtitle"]))
story.append(rule())

story.append(Paragraph("The Audience", S["h2"]))
story.append(Paragraph(
    "A focused, <b>technical security audience</b>, concentrated where security buying decisions "
    "get made: the people who evaluate, recommend, deploy, and buy detection and tooling "
    "(detection engineers, threat-intel analysts, SOC analysts, and security leadership).",
    S["body"]))
story.append(Spacer(1, 3))
# Figures a reader can check, rather than analytics nobody can audit.
story.append(stat_strip([("3,500+", "on LinkedIn"), ("112", "Suricata rules live"),
                         ("57", "IOC feeds"), ("41", "STIX bundles")], width=CONTENT_W))
story.append(Spacer(1, 7))
story.append(Paragraph(
    "The Suricata rules ship in a consolidated feed registered for suricata-update, running in "
    "stacks whose operators have never opened the site. The IOC feeds and STIX bundles are public "
    "and ready to pull straight into a detection stack or an OpenCTI instance.", S["small"]))

# ---------------------------------------------------------------- tiers
# Their own page. The cards are tall enough that any heading placed before them
# on the audience page gets orphaned at its foot with the cards pushed over.
story.append(PageBreak())
story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
story.append(Paragraph("Sponsorship Tiers", S["title"]))
story.append(Paragraph(
    "These are starting points, not limits. Bundle reports in any size, mix new and catalog, "
    "sponsor monthly, or build something custom.", S["subtitle"]))
story.append(rule())


def tier_card(tier, accent, flagship=False):
    """Built from _data/sponsors.yml. Nothing here restates the offer."""
    name = style_para(tier["name"], size=13.5, color=PAPER, bold=True)
    head = [name]
    if flagship:
        head.append(style_para("FLAGSHIP", size=7, color=accent, bold=True, space=4))
    price = style_para(
        f"{xesc(tier['price'])} <font size=9 color='#8B949E'>/ "
        f"{xesc(tier['price_note']).lower()}</font>", size=16, color=accent, bold=True)
    out = head + [price]
    if tier.get("annual_price"):
        # The site renders annual_price and annual_note as separate spans, so the
        # note is written to sit beside the figure rather than run on from it.
        ann = f"Or {xesc(tier['annual_price'])}"
        if tier.get("annual_note"):
            ann += f" <font size=7.5 color='#8B949E'>{xesc(tier['annual_note'])}</font>"
        out.append(style_para(ann, size=9.5, color=accent, bold=True))
    if tier.get("annual_saving"):
        out.append(style_para(xesc(tier["annual_saving"]), size=8, color=DIM, space=5))
    extra = []
    if tier.get("catalog_price"):
        extra.append(f"{xesc(tier['catalog_price'])} {xesc(tier['catalog_price_note'])}")
    if tier.get("intro_price"):
        extra.append(xesc(tier["intro_price"]))
    if extra:
        out.append(style_para(" &nbsp;&middot;&nbsp; ".join(extra), size=8.4,
                              color=accent, bold=True, space=6))
    out.append(style_para(xesc(tier["description"]), size=8.5, color=DIM, space=7,
                          italic=True))
    return out + bullets([xesc(b) for b in tier["benefits"]])


def style_para(text, size, color, bold=False, italic=False, space=2):
    from reportlab.lib.styles import ParagraphStyle
    fn = "Helvetica-Bold" if bold else ("Helvetica-Oblique" if italic else "Helvetica")
    return Paragraph(text, ParagraphStyle(
        f"p{size}{color}{bold}{italic}", fontName=fn, fontSize=size, textColor=color,
        leading=size * 1.28, spaceAfter=space))


col = (CONTENT_W - 10) / 2
cards = Table([[tier_card(MONTHLY, GOLD, flagship=True), tier_card(REPORT, BLUE)]],
              colWidths=[col, col])
cards.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("BACKGROUND", (0, 0), (-1, 0), PANEL),
    ("LINEABOVE", (0, 0), (0, 0), 2.5, GOLD),
    ("LINEABOVE", (1, 0), (1, 0), 2.5, BLUE),
    ("BOX", (0, 0), (0, 0), 0.6, PANEL_EDGE),
    ("BOX", (1, 0), (1, 0), 0.6, PANEL_EDGE),
    ("LEFTPADDING", (0, 0), (-1, -1), 13), ("RIGHTPADDING", (0, 0), (-1, -1), 13),
    ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
]))
story.append(cards)
story.append(Spacer(1, 7))
story.append(Paragraph(
    "<b>First-time sponsor?</b> Your first run is discounted. First new report $100 (vs $150), or "
    "your first 3 months of Monthly at $300/mo (vs $500). Going annual from the start keeps the "
    "same discount: a first full year at $4,400.", S["small"]))

story.append(PageBreak())

# ---------------------------------------------------------------- pay table
story.append(Paragraph("THE HUNTER'S LEDGER", S["eyebrow"]))
story.append(Paragraph("Monthly or Annual", S["title"]))
story.append(rule())
story.append(Paragraph(
    "Both work, and either is equally welcome. Take whichever suits your budget cycle. Annual "
    "prepay is cheaper because planning a year ahead is worth something to me, so that saving is "
    "passed straight back rather than held as a negotiating chip. An annual term also "
    "<b>locks your rate for its full length</b>, so a published price rise cannot reach you mid "
    "term, and the lock holds through renewal: keep sponsoring without a break and you keep the "
    "rate you started at. Monthly stays flexible and can be stopped at the end of any billing "
    "month. The placements, the benefits, and the editorial independence are identical either "
    "way.", S["body"]))

H, C, B = S["cell_h"], S["cell"], S["cell_b"]
pay = [[Paragraph("How you pay", H), Paragraph("Monthly Sponsor", H),
        Paragraph("Report Sponsor", H)],
       [Paragraph("As you go", B), Paragraph("$500 per month", C),
        Paragraph("$150 per new report, or $100 from the catalog", C)],
       [Paragraph("Bundled", B), Paragraph("Not applicable", C),
        Paragraph("3 new reports $335 (26% off) &nbsp;&middot;&nbsp; 6 for $630 (30% off)", C)],
       [Paragraph("Annual", B),
        Paragraph("<b>$5,000 per year.</b> Two months free, a $1,000 saving, 17% off", C),
        Paragraph("<b>$1,170 for 12 new reports.</b> A $630 saving, 35% off", C)],
       [Paragraph("First time", B),
        Paragraph("First 3 months at $300, or a first year at $4,400", C),
        Paragraph("First new report $100", C)]]
story.append(dark_table(pay, [1.2 * inch, CONTENT_W * 0.40, CONTENT_W * 0.42]))

# ---------------------------------------------------------------- the rest
story.append(Paragraph("Optional Add-Ons", S["h2"]))
story += bullets([
    "Newsletter mention, $50, one-off sponsored mention in a subscriber email send",
    "Extra LinkedIn or X post, $50, a single dedicated sponsored post",
])

story.append(Paragraph("Commissioned Research", S["h2"]))
story.append(panel([
    Paragraph(
        "Name a threat your organization needs intelligence on and I will go and get it: original "
        "investigation, full technical analysis, working detections, and a published report, held "
        "to the same evidence standards and the same editorial independence as everything else.",
        S["body"]),
    Paragraph(
        "<b>Priced on scope</b>, because scope varies enormously. A single host or one open "
        "directory is a very different piece of work from a fifty-address infrastructure cluster "
        "with a malware family behind it. Tell me what you want to know and I will come back with "
        "a defined scope and a fixed price before any work starts.", S["body"]),
], accent=BLUE, width=CONTENT_W))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "<b>Flexible and custom:</b> bundles of any size, catalog mixes, multi-month, co-marketing, or "
    "something not listed. Tell me what you are trying to achieve and I will shape a package "
    "around it.", S["body"]))

story.append(Paragraph("Editorial Independence", S["h2"]))
story.append(panel([Paragraph(
    "Sponsorship buys placement and brand association, not content control. Sponsors do not review "
    "reports before publication, do not influence findings or attribution, and are never named as "
    "contributors. Placement is always disclosed. This is not native advertising.", S["body"])],
    accent=GOLD, width=CONTENT_W))

story.append(Spacer(1, 14))
story.append(rule(PANEL_EDGE, 0.7, 2, 6))
story.append(Paragraph(
    "Get in touch &nbsp;&middot;&nbsp; <font color='#58A6FF'><b>intel@the-hunters-ledger.com</b>"
    "</font> &nbsp;&middot;&nbsp; linkedin.com/in/josephrharrison &nbsp;&middot;&nbsp; "
    "the-hunters-ledger.com/sponsor/", S["body"]))
story.append(Paragraph(
    "&#169; 2026 The Hunter's Ledger. Pricing is a starting point and subject to change; custom "
    "arrangements welcome.", S["small"]))

doc = SimpleDocTemplate(OUT, pagesize=PAGE, **MARGIN,
                        title="The Hunter's Ledger, Sponsorship Pricing and Packages",
                        author="The Hunters Ledger")
doc.build(story, onFirstPage=paint_cover,
          onLaterPages=make_interior_painter("the-hunters-ledger.com/sponsor/"))
print(f"wrote {OUT}")
print(f"  tiers from {os.path.relpath(DATA, _REPO)}: "
      f"{MONTHLY['name']} ({len(MONTHLY['benefits'])} benefits), "
      f"{REPORT['name']} ({len(REPORT['benefits'])} benefits)")
