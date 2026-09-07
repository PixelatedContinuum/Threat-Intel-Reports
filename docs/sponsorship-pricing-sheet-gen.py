#!/usr/bin/env python
"""
Generates The Hunter's Ledger sponsorship pricing sheet PDF.
Source of record for assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf.
Re-run after any pricing/model change:  python3 sponsorship-pricing-sheet-gen.py
Reflects the 2-tier model (Monthly + Report + bundle), the annual option and its
discount, the first-time discount, add-ons, and the accepted payment routes.

Keep this in step with _data/sponsors.yml. That file drives the /sponsor/ page and
this script drives the downloadable sheet; a price changed in one and not the other
is the failure mode this comment exists to prevent.

Requires: reportlab (5.0.1 verified).  Run with python3 on Linux.
"""
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, KeepTogether)

# Resolved from this script's own location, so it works from any working directory.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(_REPO, "assets", "files", "Hunters-Ledger-Sponsorship-Pricing.pdf")

GOLD   = colors.HexColor("#B8902F")
NAVY   = colors.HexColor("#14213D")
TEXT   = colors.HexColor("#2B2B2B")
MUTED  = colors.HexColor("#6B7280")
BLUE   = colors.HexColor("#2563EB")
GOLDBG = colors.HexColor("#FBF6EA")
GRAYBG = colors.HexColor("#F5F7FA")
LINE   = colors.HexColor("#E2E2E2")

base = getSampleStyleSheet()["Normal"]
def st(name, **kw):
    return ParagraphStyle(name, parent=base, **kw)

eyebrow   = st("eyebrow", fontName="Helvetica-Bold", fontSize=8, textColor=GOLD, leading=10, spaceAfter=1)
title     = st("title", fontName="Helvetica-Bold", fontSize=21, textColor=NAVY, leading=24, spaceAfter=3)
subtitle  = st("subtitle", fontName="Helvetica", fontSize=10.5, textColor=MUTED, leading=14, spaceAfter=2)
h2        = st("h2", fontName="Helvetica-Bold", fontSize=12.5, textColor=NAVY, leading=15, spaceBefore=7, spaceAfter=3)
body      = st("body", fontName="Helvetica", fontSize=9.5, textColor=TEXT, leading=13, spaceAfter=2)
small     = st("small", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=11)
tname     = st("tname", fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, leading=15, spaceAfter=2)
tprice    = st("tprice", fontName="Helvetica-Bold", fontSize=15, textColor=GOLD, leading=17, spaceAfter=1)
tpriceb   = st("tpriceb", fontName="Helvetica-Bold", fontSize=15, textColor=BLUE, leading=17, spaceAfter=1)
tsub      = st("tsub", fontName="Helvetica-Oblique", fontSize=8.5, textColor=MUTED, leading=11, spaceAfter=6)
tnote     = st("tnote", fontName="Helvetica-Bold", fontSize=8.5, textColor=GOLD, leading=11, spaceAfter=6)
tnoteb    = st("tnoteb", fontName="Helvetica-Bold", fontSize=8.5, textColor=BLUE, leading=11, spaceAfter=6)
tann      = st("tann", fontName="Helvetica-Bold", fontSize=9.5, textColor=GOLD, leading=12, spaceAfter=1)
tannb     = st("tannb", fontName="Helvetica-Bold", fontSize=9.5, textColor=BLUE, leading=12, spaceAfter=1)
tannsub   = st("tannsub", fontName="Helvetica", fontSize=8, textColor=TEXT, leading=10, spaceAfter=5)
cellh     = st("cellh", fontName="Helvetica-Bold", fontSize=8.2, textColor=NAVY, leading=10.5)
cell      = st("cell", fontName="Helvetica", fontSize=8.2, textColor=TEXT, leading=10.5)
cellb     = st("cellb", fontName="Helvetica-Bold", fontSize=8.2, textColor=TEXT, leading=10.5)
bullet    = st("bullet", fontName="Helvetica", fontSize=8.7, textColor=TEXT, leading=11.5, leftIndent=11, bulletIndent=1, spaceAfter=2)

def rule(color=GOLD, w=1.2, sb=2, sa=5):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=sb, spaceAfter=sa, lineCap="round")

def bullets(items, accent=GOLD):
    sty = ParagraphStyle("b", parent=bullet)
    return [Paragraph(t, sty, bulletText="•") for t in items]

story = []

# ---- Header ----
story.append(Paragraph("THE HUNTER'S LEDGER", eyebrow))
story.append(Paragraph("Sponsorship: Pricing &amp; Packages", title))
story.append(Paragraph("Independent threat intelligence research. Every report ships with working YARA, Sigma, and Suricata detections, validated IOC feeds, and evidence-tied attribution, alongside research working defenders actively integrate.", subtitle))
story.append(rule())

# ---- Audience ----
story.append(Paragraph("The Audience", h2))
story.append(Paragraph("A focused, <b>technical security audience</b>, concentrated where security buying decisions get made: the people who evaluate, recommend, deploy, and buy detection and tooling (detection engineers, threat-intel analysts, SOC analysts, and security leadership).", body))
story += bullets([
    "<b>10K+</b> site views in a peak month, and climbing",
    "<b>3,500+</b> LinkedIn followers: detection engineers, TI analysts, and security leaders",
    "<b>~400</b> LinkedIn profile views per day, where every report is posted and discussed",
    "Every detection rule is published to the public <b>Sigma and YARA repositories</b> the community pulls from, deployed in SOCs, labs, and hunt platforms worldwide, beyond direct readers",
])

# ---- Tiers (two cards side by side) ----
story.append(Paragraph("Sponsorship Tiers", h2))

monthly = [
    Paragraph("Monthly Sponsor &nbsp;<font size=7 color='#B8902F'><b>FLAGSHIP</b></font>", tname),
    Paragraph("$500 <font size=9 color='#6B7280'>/ month</font>", tprice),
    Paragraph("Or $5,000 / year", tann),
    Paragraph("Two months free, a $1,000 saving (17% off), and your rate is locked for the term.", tannsub),
    Paragraph("New sponsors: first 3 months $300/mo", tnote),
    Paragraph("Always-on, site-wide brand presence, the strongest value per dollar.", tsub),
] + bullets([
    "Logo + tagline in the left-margin Sponsors panel on every page and report",
    "Logo + dofollow link in the site footer, across every page",
    "Featured in the Sponsors section of the site",
    "Early access to upcoming reports, plus first option to sponsor any one exclusively before anyone else",
    "A welcome announcement post + a monthly sponsor spotlight post",
    "A one-time feature in a single report during your first month",
    "Your logo in the subscriber email newsletter",
    "One sponsor-suggested research topic per year: a threat relevant to your space, researched and published",
])

report = [
    Paragraph("Report Sponsor", tname),
    Paragraph("$150 <font size=9 color='#6B7280'>/ new report</font>", tpriceb),
    Paragraph("Or $1,300 / year", tannb),
    Paragraph("A full year of 12 new reports, a $500 saving (28% off the new-report rate).", tannsub),
    Paragraph("$115 from the catalog (23% off) &nbsp;&middot;&nbsp; new sponsors: first report $100", tnoteb),
    Paragraph("Exclusive placement on a specific report, one sponsor per report.", tsub),
] + bullets([
    "Sole Sponsored-by banner at the top of the report, no competing logos",
    "Logo + dofollow link to your site or chosen landing page",
    "Permanent for the report's life. Never expires, keeps surfacing in search and hunts",
    "The report's launch post credits you (LinkedIn, X, and subscriber email)",
    "Early access to your report before it goes public",
    "Topic alignment, choose a report on a threat relevant to you",
    "<b>Bundle &amp; save on new reports:</b> 3 for $375 &middot; 6 for $675 &middot; 12 for $1,300 across a year. Catalog reports stay $115 each, bundled or not",
])

tiers = Table([[monthly, report]], colWidths=[3.55*inch, 3.55*inch])
tiers.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("BACKGROUND", (0,0), (0,0), GOLDBG),
    ("BACKGROUND", (1,0), (1,0), GRAYBG),
    ("LINEABOVE", (0,0), (0,0), 2.4, GOLD),
    ("LINEABOVE", (1,0), (1,0), 2.4, BLUE),
    ("BOX", (0,0), (0,0), 0.5, LINE),
    ("BOX", (1,0), (1,0), 0.5, LINE),
    ("LEFTPADDING", (0,0), (-1,-1), 13),
    ("RIGHTPADDING", (0,0), (-1,-1), 13),
    ("TOPPADDING", (0,0), (-1,-1), 10),
    ("BOTTOMPADDING", (0,0), (-1,-1), 10),
]))
story.append(tiers)
story.append(Spacer(1, 2))
story.append(Paragraph("<b>First-time sponsor?</b> Your first run is discounted. First report $100 (vs $150), or your first 3 months of Monthly at $300/mo (vs $500). A low-risk way to try before committing.", small))

# ---- Monthly or annual ----
story.append(Paragraph("Monthly or Annual", h2))
story.append(Paragraph("Both work, and either is equally welcome. Take whichever suits your budget cycle. Annual prepay is cheaper because planning a year ahead is worth something to me, so that saving is passed straight back rather than held as a negotiating chip. An annual term also <b>locks your rate for its full length</b>, so a published price rise cannot reach you mid term, and it carries first right of renewal at the locked rate. Monthly stays flexible and can be stopped at the end of any billing month. The placements, the benefits, and the editorial independence are identical either way.", body))

def _c(t, sty=cell):
    return Paragraph(t, sty)

pay_rows = [
    [_c("How you pay", cellh), _c("Monthly Sponsor", cellh), _c("Report Sponsor", cellh)],
    [_c("As you go", cellb), _c("$500 per month"), _c("$150 per new report, or $115 from the catalog")],
    [_c("Bundled", cellb), _c("Not applicable"), _c("3 new reports $375 (17% off) &nbsp;&middot;&nbsp; 6 for $675 (25% off)")],
    [_c("Annual", cellb),
     _c("<b>$5,000 per year.</b> Two months free, a $1,000 saving, 17% off"),
     _c("<b>$1,300 for 12 new reports.</b> A $500 saving, 28% off")],
    [_c("First time", cellb), _c("First 3 months at $300 per month"), _c("First report $100")],
]
# repeatRows=1 so the header follows the table across a page break. Without it the
# Annual and First-time rows landed on page 2 with no column labels at all, in a PDF
# whose whole purpose is being forwarded into somebody's procurement process.
pay = Table(pay_rows, colWidths=[1.05*inch, 2.85*inch, 3.2*inch], repeatRows=1)
pay.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("BACKGROUND", (0,0), (-1,0), GRAYBG),
    ("BACKGROUND", (0,3), (-1,3), GOLDBG),
    ("LINEBELOW", (0,0), (-1,0), 0.8, GOLD),
    ("GRID", (0,0), (-1,-1), 0.4, LINE),
    ("LEFTPADDING", (0,0), (-1,-1), 6),
    ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ("TOPPADDING", (0,0), (-1,-1), 5),
    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
]))
story.append(pay)
story.append(Spacer(1, 4))

# ---- Add-ons + Flexible ----
story.append(Paragraph("Optional Add-Ons", h2))
story += bullets([
    "<b>Newsletter mention</b>, $50, one-off sponsored mention in a subscriber email send",
    "<b>Extra LinkedIn or X post</b>, $50, a single dedicated sponsored post",
])
story.append(Spacer(1, 3))
story.append(Paragraph("Commissioned Research", h2))
story.append(Paragraph("Name a threat your organization needs intelligence on and I will go and get it: original investigation, full technical analysis, working detections, and a published report, held to the same evidence standards and the same editorial independence as everything else. <b>Priced on scope</b>, because scope varies enormously. A single host or one open directory is a very different piece of work from a fifty-address infrastructure cluster with a malware family behind it. Tell me what you want to know and I will come back with a defined scope and a fixed price before any work starts.", body))
story.append(Spacer(1, 3))
story.append(Paragraph("<b>Flexible &amp; custom:</b> bundles of any size, catalog mixes, multi-month, co-marketing, or something not listed. Tell me what you're trying to achieve and I'll shape a package around it.", body))

# ---- Editorial independence ----
story.append(Paragraph("Editorial Independence", h2))
story.append(Paragraph("Sponsorship buys placement and brand association, not content control. Sponsors don't review reports pre-publication, influence findings or attribution, or get named as contributors; placement is always disclosed. Not native advertising.", body))

# ---- Contact ----
story.append(rule(color=LINE, w=0.8, sb=7, sa=5))
story.append(Paragraph("Get in touch &nbsp;&middot;&nbsp; <b>intel@the-hunters-ledger.com</b> &nbsp;&middot;&nbsp; linkedin.com/in/josephrharrison &nbsp;&middot;&nbsp; the-hunters-ledger.com/sponsor/", body))
story.append(Spacer(1, 2))
story.append(Paragraph("&copy; 2026 The Hunter's Ledger. Pricing is a starting point and subject to change; custom arrangements welcome.", small))

doc = SimpleDocTemplate(OUT, pagesize=letter,
                        leftMargin=0.62*inch, rightMargin=0.62*inch,
                        topMargin=0.4*inch, bottomMargin=0.35*inch,
                        title="The Hunter's Ledger: Sponsorship Pricing",
                        author="The Hunter's Ledger")
doc.build(story)
print("wrote", OUT)
