#!/usr/bin/env python
"""
Generates The Hunter's Ledger sponsorship pricing sheet PDF.
Source of record for assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf.
Re-run after any offer change:  python3 docs/sponsorship-pricing-sheet-gen.py

TIER NAMES, PRICES, BILLING NOTES AND BENEFIT BULLETS ARE READ FROM
_data/sponsors.yml. They are not duplicated here, deliberately.

The previous version hardcoded all of it and carried a comment asking whoever
edited one to remember the other. That is a hope rather than a mechanism, and it
failed on 2026-09-13: the offer was reworked, the page updated, and the
downloadable sheet went on advertising a sponsor badge, a newsletter logo, a
quarterly spotlight post and a peak-month view count that had all been removed.
A prospect would have taken the stale sheet into a procurement conversation.

So the only things written below are presentation and the prose sections that
have no home in the data file. If a number appears in both, the data file wins.

Look: the site is dark chrome with gold and blue accents and Space Grotesk as its
display face. The cover carries that directly. Interior pages stay light, because
these get printed for procurement and a fully dark document is both expensive to
print and harder to read on paper.

Requires: reportlab (5.0.1 verified), PyYAML. Run with python3 on Linux.
"""
import os
import yaml
from xml.sax.saxutils import escape as xesc
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, KeepTogether, PageBreak,
                                Image as RLImage)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(_REPO, "assets", "files", "Hunters-Ledger-Sponsorship-Pricing.pdf")
DATA = os.path.join(_REPO, "_data", "sponsors.yml")
LOGO_ON_DARK = os.path.join(_REPO, "assets", "brand", "logo-lockup",
                            "logo-horizontal-on-dark-bg.png")
SG_TTF = os.path.join(_REPO, "tools", "social-card", "SpaceGrotesk.ttf")

# ---------------------------------------------------------------- brand tokens
# Mirrors assets/css/custom.css. Read that file, not this comment, if they drift.
INK     = colors.HexColor("#0D1117")   # cover ground. NOT --hl-bg-page (#111111): it is
                                       # matched to logo-horizontal-on-dark-bg.png, which is
                                       # OPAQUE on #0D1117. Mismatch renders the logo as a
                                       # visible plate floating on the page. Checked, not assumed.
PANEL   = colors.HexColor("#1A1A1A")   # --hl-bg-card
GOLD    = colors.HexColor("#B8902F")   # --hl-accent-gold
BLUE    = colors.HexColor("#58A6FF")   # --hl-accent-blue
GREEN   = colors.HexColor("#4ADE80")   # --hl-accent-green
PAPER   = colors.HexColor("#EEEEEE")   # --hl-text-primary, used ON dark
NAVY    = colors.HexColor("#14213D")
TEXT    = colors.HexColor("#2B2B2B")
MUTED   = colors.HexColor("#6B7280")
DIM     = colors.HexColor("#888888")   # --hl-text-dim
GOLDBG  = colors.HexColor("#FBF6EA")
BLUEBG  = colors.HexColor("#F4F8FD")
LINE    = colors.HexColor("#E2E2E2")

# Space Grotesk is the site's display face. The vendored TTF is the Light weight,
# which reads as deliberate at cover size and too thin below it, so it is used for
# the cover only and interior headings stay on Helvetica-Bold.
DISPLAY = "Helvetica-Bold"
try:
    pdfmetrics.registerFont(TTFont("SpaceGrotesk", SG_TTF))
    DISPLAY = "SpaceGrotesk"
except Exception as exc:                                    # pragma: no cover
    print(f"  note: Space Grotesk unavailable ({exc}); cover falls back to Helvetica")

# ---------------------------------------------------------------- data
with open(DATA, encoding="utf-8") as fh:
    SPONSORS = yaml.safe_load(fh)
TIERS = {t["id"]: t for t in SPONSORS["tiers"]}
MONTHLY, REPORT = TIERS["monthly"], TIERS["report"]

base = getSampleStyleSheet()["Normal"]
def st(name, **kw):
    return ParagraphStyle(name, parent=base, **kw)

# cover, on dark
cv_title  = st("cv_title", fontName=DISPLAY, fontSize=34, textColor=PAPER, leading=38,
               alignment=1, spaceAfter=4)
cv_sub    = st("cv_sub", fontName=DISPLAY, fontSize=17, textColor=GOLD, leading=21,
               alignment=1, spaceAfter=14)
cv_body   = st("cv_body", fontName="Helvetica", fontSize=10.5, textColor=DIM, leading=15,
               alignment=1)
cv_eyebrow= st("cv_eyebrow", fontName="Helvetica-Bold", fontSize=8, textColor=GOLD,
               leading=11, alignment=1, spaceAfter=6)

# interior, on paper
eyebrow  = st("eyebrow", fontName="Helvetica-Bold", fontSize=8, textColor=GOLD, leading=10, spaceAfter=1)
title    = st("title", fontName="Helvetica-Bold", fontSize=21, textColor=NAVY, leading=24, spaceAfter=3)
subtitle = st("subtitle", fontName="Helvetica", fontSize=10.5, textColor=MUTED, leading=14, spaceAfter=2)
h2       = st("h2", fontName="Helvetica-Bold", fontSize=12.5, textColor=NAVY, leading=15, spaceBefore=9, spaceAfter=4)
body     = st("body", fontName="Helvetica", fontSize=9.5, textColor=TEXT, leading=13.5, spaceAfter=4)
small    = st("small", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=11)
tname    = st("tname", fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, leading=15, spaceAfter=2)
tprice   = st("tprice", fontName="Helvetica-Bold", fontSize=15, textColor=GOLD, leading=17, spaceAfter=1)
tpriceb  = st("tpriceb", fontName="Helvetica-Bold", fontSize=15, textColor=NAVY, leading=17, spaceAfter=1)
tsub     = st("tsub", fontName="Helvetica-Oblique", fontSize=8.5, textColor=MUTED, leading=11, spaceAfter=6)
tnote    = st("tnote", fontName="Helvetica-Bold", fontSize=8.5, textColor=GOLD, leading=11, spaceAfter=6)
tnoteb   = st("tnoteb", fontName="Helvetica-Bold", fontSize=8.5, textColor=NAVY, leading=11, spaceAfter=6)
tann     = st("tann", fontName="Helvetica-Bold", fontSize=9.5, textColor=GOLD, leading=12, spaceAfter=1)
tannb    = st("tannb", fontName="Helvetica-Bold", fontSize=9.5, textColor=NAVY, leading=12, spaceAfter=1)
tannsub  = st("tannsub", fontName="Helvetica", fontSize=8, textColor=TEXT, leading=10, spaceAfter=5)
cellh    = st("cellh", fontName="Helvetica-Bold", fontSize=8.2, textColor=NAVY, leading=10.5)
cell     = st("cell", fontName="Helvetica", fontSize=8.2, textColor=TEXT, leading=10.5)
cellb    = st("cellb", fontName="Helvetica-Bold", fontSize=8.2, textColor=TEXT, leading=10.5)
bullet   = st("bullet", fontName="Helvetica", fontSize=8.7, textColor=TEXT, leading=11.5,
              leftIndent=11, bulletIndent=1, spaceAfter=2)

def rule(color=GOLD, w=1.2, sb=2, sa=5):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=sb, spaceAfter=sa,
                      lineCap="round")

def bullets(items):
    return [Paragraph(xesc(t), bullet, bulletText="•") for t in items]

def scaled(path, max_w, max_h):
    """Fit an image inside a box, preserving aspect. Returns None if it is missing,
    so a missing asset degrades to no logo rather than crashing a document that has
    to ship."""
    if not os.path.exists(path):
        print(f"  note: asset missing, skipping: {path}")
        return None
    iw, ih = ImageReader(path).getSize()
    s = min(max_w / iw, max_h / ih)
    return RLImage(path, iw * s, ih * s)

# ---------------------------------------------------------------- page painting
def cover_page(canvas, doc):
    """Full-bleed dark cover. This is the one page that carries the site's own
    chrome; everything after it is light so the sheet survives being printed."""
    canvas.saveState()
    w, h = letter
    canvas.setFillColor(INK)
    canvas.rect(0, 0, w, h, stroke=0, fill=1)
    # accent bar down the left edge, the site's per-section accent, as punctuation
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, 5, h, stroke=0, fill=1)
    canvas.setFillColor(BLUE)
    canvas.rect(0, 0, 5, h * 0.18, stroke=0, fill=1)
    canvas.restoreState()

def interior_page(canvas, doc):
    canvas.saveState()
    w, _ = letter
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, w, 3.5, stroke=0, fill=1)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(w - 0.62 * inch, 0.42 * inch, f"{doc.page}")
    canvas.drawString(0.62 * inch, 0.42 * inch, "the-hunters-ledger.com")
    canvas.restoreState()

story = []

# ---------------------------------------------------------------- cover
story.append(Spacer(1, 2.15 * inch))
_logo = scaled(LOGO_ON_DARK, 3.5 * inch, 1.15 * inch)
if _logo:
    _logo.hAlign = "CENTER"
    story.append(_logo)
story.append(Spacer(1, 0.62 * inch))
story.append(Paragraph("Sponsorship", cv_title))
story.append(Paragraph("Pricing and Packages", cv_sub))
story.append(Paragraph(
    "Independent threat intelligence research.<br/>"
    "Every report ships with working YARA, Sigma and Suricata detections,<br/>"
    "validated IOC feeds, and evidence-tied attribution.", cv_body))
story.append(Spacer(1, 2.4 * inch))
story.append(Paragraph("THE HUNTER'S LEDGER", cv_eyebrow))
story.append(Paragraph("the-hunters-ledger.com", cv_body))
story.append(PageBreak())

# ---------------------------------------------------------------- audience
story.append(Paragraph("THE HUNTER'S LEDGER", eyebrow))
story.append(Paragraph("Sponsorship: Pricing and Packages", title))
story.append(Paragraph(
    "Independent threat intelligence research. Every report ships with working YARA, Sigma, and "
    "Suricata detections, validated IOC feeds, and evidence-tied attribution, alongside research "
    "working defenders actively integrate.", subtitle))
story.append(rule())

story.append(Paragraph("The Audience", h2))
story.append(Paragraph(
    "A focused, <b>technical security audience</b>, concentrated where security buying decisions "
    "get made: the people who evaluate, recommend, deploy, and buy detection and tooling "
    "(detection engineers, threat-intel analysts, SOC analysts, and security leadership).", body))
story += bullets([
    "3,500+ LinkedIn followers: detection engineers, TI analysts, and security leaders",
    "~400 LinkedIn profile views per day, where every report is posted and discussed",
    "112 Suricata rules across 35 campaigns in a consolidated feed registered for "
    "suricata-update, running in stacks whose operators have never opened the site",
    "Every campaign also ships as machine-readable intelligence: 57 IOC feeds in JSON and 41 "
    "STIX bundles for OpenCTI and MISP, all public and ready to pull straight into a detection "
    "stack",
])

# ---------------------------------------------------------------- tiers
story.append(Paragraph("Sponsorship Tiers", h2))

def tier_card(tier, accent_price, accent_note, accent_ann, flagship=False):
    """Built from _data/sponsors.yml. Nothing here restates the offer."""
    head = xesc(tier["name"])
    if flagship:
        head += " &nbsp;<font size=7 color='#B8902F'><b>FLAGSHIP</b></font>"
    out = [Paragraph(head, tname),
           Paragraph(f"{xesc(tier['price'])} <font size=9 color='#6B7280'>/ "
                     f"{xesc(tier['price_note']).lower()}</font>", accent_price)]
    if tier.get("annual_price"):
        # The site renders annual_price and annual_note as separate spans, so the
        # note is written to sit beside the figure rather than to run on from it.
        # Concatenating them flat gives "Or $1,170 Year of Reports, 12 new reports".
        ann = f"Or {xesc(tier['annual_price'])}"
        if tier.get("annual_note"):
            ann += f" <font size=8 color='#6B7280'>{xesc(tier['annual_note'])}</font>"
        out.append(Paragraph(ann, accent_ann))
    if tier.get("annual_saving"):
        out.append(Paragraph(xesc(tier["annual_saving"]), tannsub))
    extra = []
    if tier.get("catalog_price"):
        extra.append(f"{xesc(tier['catalog_price'])} {xesc(tier['catalog_price_note'])}")
    if tier.get("intro_price"):
        extra.append(xesc(tier["intro_price"]))
    if extra:
        out.append(Paragraph(" &nbsp;&middot;&nbsp; ".join(extra), accent_note))
    out.append(Paragraph(xesc(tier["description"]), tsub))
    return out + bullets(tier["benefits"])

cards = Table(
    [[tier_card(MONTHLY, tprice, tnote, tann, flagship=True),
      tier_card(REPORT, tpriceb, tnoteb, tannb)]],
    colWidths=[3.52 * inch, 3.52 * inch])
cards.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("BACKGROUND", (0, 0), (0, 0), GOLDBG),
    ("BACKGROUND", (1, 0), (1, 0), BLUEBG),
    ("LINEABOVE", (0, 0), (0, 0), 2.2, GOLD),
    ("LINEABOVE", (1, 0), (1, 0), 2.2, BLUE),
    ("BOX", (0, 0), (0, 0), 0.5, LINE),
    ("BOX", (1, 0), (1, 0), 0.5, LINE),
    ("LEFTPADDING", (0, 0), (-1, -1), 11),
    ("RIGHTPADDING", (0, 0), (-1, -1), 11),
    ("TOPPADDING", (0, 0), (-1, -1), 10),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
]))
story.append(cards)
story.append(Spacer(1, 5))
story.append(Paragraph(
    "<b>First-time sponsor?</b> Your first run is discounted. First new report $100 (vs $150), or "
    "your first 3 months of Monthly at $300/mo (vs $500). Going annual from the start keeps the "
    "same discount: a first full year at $4,400.", small))

# ---------------------------------------------------------------- pay table
story.append(Paragraph("Monthly or Annual", h2))
story.append(Paragraph(
    "Both work, and either is equally welcome. Take whichever suits your budget cycle. Annual "
    "prepay is cheaper because planning a year ahead is worth something to me, so that saving is "
    "passed straight back rather than held as a negotiating chip. An annual term also "
    "<b>locks your rate for its full length</b>, so a published price rise cannot reach you mid "
    "term, and the lock holds through renewal: keep sponsoring without a break and you keep the "
    "rate you started at. Monthly stays flexible and can be stopped at the end of any billing "
    "month. The placements, the benefits, and the editorial independence are identical either "
    "way.", body))

cellhw = st("cellhw", fontName="Helvetica-Bold", fontSize=8.2, textColor=colors.white,
            leading=10.5)
pay = [[Paragraph("How you pay", cellhw), Paragraph("Monthly Sponsor", cellhw),
        Paragraph("Report Sponsor", cellhw)],
       [Paragraph("As you go", cellb), Paragraph("$500 per month", cell),
        Paragraph("$150 per new report, or $100 from the catalog", cell)],
       [Paragraph("Bundled", cellb), Paragraph("Not applicable", cell),
        Paragraph("3 new reports $335 (26% off) &nbsp;&middot;&nbsp; 6 for $630 (30% off)", cell)],
       [Paragraph("Annual", cellb),
        Paragraph("<b>$5,000 per year.</b> Two months free, a $1,000 saving, 17% off", cell),
        Paragraph("<b>$1,170 for 12 new reports.</b> A $630 saving, 35% off", cell)],
       [Paragraph("First time", cellb),
        Paragraph("First 3 months at $300, or a first year at $4,400", cell),
        Paragraph("First new report $100", cell)]]
pt = Table(pay, colWidths=[1.15 * inch, 2.72 * inch, 3.17 * inch])
pt.setStyle(TableStyle([
    ("GRID", (0, 0), (-1, -1), 0.4, LINE),
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("BACKGROUND", (0, 3), (-1, 3), GOLDBG),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story.append(pt)

# ---------------------------------------------------------------- the rest
story.append(Paragraph("Optional Add-Ons", h2))
story += bullets([
    "Newsletter mention, $50, one-off sponsored mention in a subscriber email send",
    "Extra LinkedIn or X post, $50, a single dedicated sponsored post",
])

story.append(Paragraph("Commissioned Research", h2))
story.append(Paragraph(
    "Name a threat your organization needs intelligence on and I will go and get it: original "
    "investigation, full technical analysis, working detections, and a published report, held to "
    "the same evidence standards and the same editorial independence as everything else. "
    "<b>Priced on scope</b>, because scope varies enormously. A single host or one open directory "
    "is a very different piece of work from a fifty-address infrastructure cluster with a malware "
    "family behind it. Tell me what you want to know and I will come back with a defined scope and "
    "a fixed price before any work starts.", body))
story.append(Paragraph(
    "<b>Flexible and custom:</b> bundles of any size, catalog mixes, multi-month, co-marketing, or "
    "something not listed. Tell me what you are trying to achieve and I will shape a package "
    "around it.", body))

story.append(Paragraph("Editorial Independence", h2))
story.append(Paragraph(
    "Sponsorship buys placement and brand association, not content control. Sponsors do not review "
    "reports before publication, do not influence findings or attribution, and are never named as "
    "contributors. Placement is always disclosed. This is not native advertising.", body))

story.append(Spacer(1, 8))
story.append(rule(LINE, 0.6, 2, 4))
story.append(Paragraph(
    "Get in touch &nbsp;&middot;&nbsp; <font color='#14213D'><b>intel@the-hunters-ledger.com</b>"
    "</font> &nbsp;&middot;&nbsp; linkedin.com/in/josephrharrison &nbsp;&middot;&nbsp; "
    "the-hunters-ledger.com/sponsor/", body))
story.append(Paragraph(
    "&#169; 2026 The Hunter's Ledger. Pricing is a starting point and subject to change; custom "
    "arrangements welcome.", small))

doc = SimpleDocTemplate(OUT, pagesize=letter,
                        leftMargin=0.62 * inch, rightMargin=0.62 * inch,
                        topMargin=0.55 * inch, bottomMargin=0.58 * inch,
                        title="The Hunter's Ledger, Sponsorship Pricing and Packages",
                        author="The Hunters Ledger")
doc.build(story, onFirstPage=cover_page, onLaterPages=interior_page)
print(f"wrote {OUT}")
print(f"  tiers from {os.path.relpath(DATA, _REPO)}: "
      f"{MONTHLY['name']} ({len(MONTHLY['benefits'])} benefits), "
      f"{REPORT['name']} ({len(REPORT['benefits'])} benefits)")
