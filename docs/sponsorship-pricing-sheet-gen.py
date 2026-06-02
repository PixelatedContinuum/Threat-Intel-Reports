#!/usr/bin/env python
"""
Generates The Hunter's Ledger sponsorship pricing sheet PDF.
Source of record for assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf.
Re-run after any pricing/model change:  python sponsorship-pricing-sheet-gen.py
Reflects the 2-tier model (Monthly + Report + bundle), first-time discount, value-adds.
Requires: reportlab.  Run with Windows `python` (not python3).
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, KeepTogether)

OUT = r"C:\Users\josep\Documents\GitHub\Threat-Intel-Reports\assets\files\Hunters-Ledger-Sponsorship-Pricing.pdf"

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
h2        = st("h2", fontName="Helvetica-Bold", fontSize=12.5, textColor=NAVY, leading=15, spaceBefore=15, spaceAfter=4)
body      = st("body", fontName="Helvetica", fontSize=9.5, textColor=TEXT, leading=13.5, spaceAfter=3)
small     = st("small", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=11)
tname     = st("tname", fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, leading=15, spaceAfter=2)
tprice    = st("tprice", fontName="Helvetica-Bold", fontSize=15, textColor=GOLD, leading=17, spaceAfter=1)
tpriceb   = st("tpriceb", fontName="Helvetica-Bold", fontSize=15, textColor=BLUE, leading=17, spaceAfter=1)
tsub      = st("tsub", fontName="Helvetica-Oblique", fontSize=8.5, textColor=MUTED, leading=11, spaceAfter=6)
tnote     = st("tnote", fontName="Helvetica-Bold", fontSize=8.5, textColor=GOLD, leading=11, spaceAfter=6)
tnoteb    = st("tnoteb", fontName="Helvetica-Bold", fontSize=8.5, textColor=BLUE, leading=11, spaceAfter=6)
bullet    = st("bullet", fontName="Helvetica", fontSize=8.7, textColor=TEXT, leading=12, leftIndent=11, bulletIndent=1, spaceAfter=2.5)

def rule(color=GOLD, w=1.2, sb=2, sa=8):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=sb, spaceAfter=sa, lineCap="round")

def bullets(items, accent=GOLD):
    sty = ParagraphStyle("b", parent=bullet)
    return [Paragraph(t, sty, bulletText="•") for t in items]

story = []

# ---- Header ----
story.append(Paragraph("THE HUNTER'S LEDGER", eyebrow))
story.append(Paragraph("Sponsorship &mdash; Pricing &amp; Packages", title))
story.append(Paragraph("Independent threat intelligence research. Every report ships with working YARA, Sigma, and Suricata detections, validated IOC feeds, and evidence-tied attribution &mdash; placement alongside research that working defenders actively consume and integrate.", subtitle))
story.append(rule())

# ---- Audience ----
story.append(Paragraph("The Audience", h2))
story.append(Paragraph("A focused, <b>technical security audience</b> &mdash; concentrated where security buying decisions get made: the people who evaluate, recommend, deploy, and buy detection and tooling (detection engineers, threat-intel analysts, SOC analysts, and security leadership).", body))
story += bullets([
    "<b>10K+</b> site views in a peak month, and climbing",
    "<b>3,500+</b> LinkedIn followers &mdash; detection engineers, TI analysts, and security leaders",
    "<b>~400</b> LinkedIn profile views per day, where every report is posted and discussed",
    "Every detection rule is submitted to the public <b>Sigma and YARA rule repositories</b> the community pulls from &mdash; so the research is deployed in SOCs, labs, and hunt platforms worldwide, well beyond direct readers",
])

# ---- Tiers (two cards side by side) ----
story.append(Paragraph("Sponsorship Tiers", h2))

monthly = [
    Paragraph("Monthly Sponsor &nbsp;<font size=7 color='#B8902F'><b>FLAGSHIP</b></font>", tname),
    Paragraph("$500 <font size=9 color='#6B7280'>/ month</font>", tprice),
    Paragraph("New sponsors: first 3 months $300/mo &nbsp;&middot;&nbsp; or $5,000 / year", tnote),
    Paragraph("Always-on, site-wide brand presence &mdash; the strongest value per dollar.", tsub),
] + bullets([
    "Logo + tagline in the left-margin Sponsors panel on every page and report",
    "Logo + dofollow link in the site footer, across every page",
    "Featured in the Sponsors section of the site",
    "Early access to new reports before they go public",
    "A welcome announcement post + a monthly sponsor spotlight post",
    "A one-time feature in a single report during your first month",
    "Your logo in the subscriber email newsletter",
])

report = [
    Paragraph("Report Sponsor", tname),
    Paragraph("$150 <font size=9 color='#6B7280'>/ new report</font>", tpriceb),
    Paragraph("$115 from the catalog (25% off) &nbsp;&middot;&nbsp; new sponsors: first report $100", tnoteb),
    Paragraph("Exclusive placement on a specific report &mdash; one sponsor per report.", tsub),
] + bullets([
    "Sole Sponsored-by banner at the top of the report &mdash; no competing logos",
    "Logo + dofollow link to your site or chosen landing page",
    "Permanent for the report's life &mdash; never expires; keeps surfacing in search and hunts",
    "The report's launch post credits you (LinkedIn, X, and subscriber email)",
    "Early access to your report before it goes public",
    "Topic alignment &mdash; choose a report on a threat relevant to you",
    "<b>Bundle &amp; save:</b> 3 reports $375 &middot; 6 reports $675 (any mix)",
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
    ("TOPPADDING", (0,0), (-1,-1), 13),
    ("BOTTOMPADDING", (0,0), (-1,-1), 13),
]))
story.append(tiers)
story.append(Spacer(1, 4))
story.append(Paragraph("<b>First-time sponsor?</b> Your first run is discounted &mdash; first report $100 (standard $150), or your first 3 months of Monthly at $300/mo (standard $500). A low-risk way to try it before committing to more. Available to any sponsor's first engagement.", small))

# ---- Add-ons + Flexible ----
story.append(Paragraph("Optional Add-Ons", h2))
story += bullets([
    "<b>Newsletter mention</b> &mdash; $50 &mdash; one-off sponsored mention in a subscriber email send",
    "<b>Extra LinkedIn or X post</b> &mdash; $50 &mdash; a single dedicated sponsored post",
    "<b>Sponsor-suggested research topic</b> &mdash; $500+ &mdash; choose a topic your organization needs intel about and I'll do the rest: original research and a published report on it (editorial independence preserved)",
])
story.append(Spacer(1, 3))
story.append(Paragraph("<b>Flexible &amp; custom:</b> bundles of any size, catalog mixes, multi-month, co-marketing, or something not listed &mdash; tell me what you're trying to achieve and I'll shape a package around it.", body))

# ---- Editorial independence ----
story.append(Paragraph("Editorial Independence", h2))
story.append(Paragraph("Sponsorship buys placement and brand association &mdash; not content control. Sponsors do not review reports before publication, do not influence findings or attribution, are never named as analysts or contributors, and sponsored placement is always clearly disclosed. This is not native advertising.", body))

# ---- Contact ----
story.append(rule(color=LINE, w=0.8, sb=12, sa=8))
story.append(Paragraph("Get in touch &nbsp;&mdash;&nbsp; <b>intel@the-hunters-ledger.com</b> &nbsp;&middot;&nbsp; linkedin.com/in/josephrharrison &nbsp;&middot;&nbsp; the-hunters-ledger.com/sponsor/", body))
story.append(Spacer(1, 2))
story.append(Paragraph("&copy; 2026 The Hunter's Ledger. Pricing is a starting point and subject to change; custom arrangements welcome.", small))

doc = SimpleDocTemplate(OUT, pagesize=letter,
                        leftMargin=0.62*inch, rightMargin=0.62*inch,
                        topMargin=0.6*inch, bottomMargin=0.55*inch,
                        title="The Hunter's Ledger — Sponsorship Pricing",
                        author="The Hunter's Ledger")
doc.build(story)
print("wrote", OUT)
