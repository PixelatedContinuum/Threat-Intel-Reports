"""The Hunter's Ledger document theme, shared by every PDF that leaves here.

Why this is a module and not three copies of the same constants
----------------------------------------------------------------
As of 2026-09-13 there were three generators with three private copies of the
palette: the pricing sheet, the quarterly sponsor brief, and whatever came next.
Two already disagreed. A brand kept as duplicated literals drifts silently, and
the drift only shows up when two documents land on the same desk.

So the tokens live here once, mirrored from assets/css/custom.css, and the page
furniture lives here as functions rather than as instructions in a comment.

The look
--------
Dark throughout. The site is dark chrome and these documents are read on screens
and forwarded as attachments, not printed, so the usual argument for a light
interior does not apply here. Joseph's call, 2026-09-13: "people are not likely
to print it out and are way more likely to download it and email it or share it
electronically."

Requires: reportlab (5.0.1 verified).
"""
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, Image as RLImage, Paragraph, Table, TableStyle

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- tokens
# Mirrors assets/css/custom.css. If they ever disagree, that file is right.
INK        = colors.HexColor("#0D1117")  # page ground. See LOGO_ON_DARK note below.
PANEL      = colors.HexColor("#161B22")  # raised surface, one step off the ground
PANEL_EDGE = colors.HexColor("#2A2A2A")  # --hl-border-card
GOLD       = colors.HexColor("#B8902F")  # --hl-accent-gold
BLUE       = colors.HexColor("#58A6FF")  # --hl-accent-blue
GREEN      = colors.HexColor("#4ADE80")  # --hl-accent-green
RED        = colors.HexColor("#F87171")  # --hl-accent-red
PAPER      = colors.HexColor("#EEEEEE")  # --hl-text-primary
DIM        = colors.HexColor("#8B949E")  # readable secondary on INK
FAINT      = colors.HexColor("#6E7681")  # captions, page furniture

# Severity, for anything ranked. Mirrors --hl-sev-*.
SEV = {"critical": colors.HexColor("#DC2626"), "high": colors.HexColor("#F97316"),
       "medium": colors.HexColor("#EAB308"), "med": colors.HexColor("#EAB308"),
       "low": colors.HexColor("#3B82F6")}

# LOGO_ON_DARK is OPAQUE on #0D1117, which is why INK is that value and not the
# site's #111111. Any other ground renders the lockup as a visible plate floating
# on the page. Checked pixel by pixel on 2026-09-13, not assumed from the filename.
LOGO_ON_DARK = os.path.join(REPO, "assets", "brand", "logo-lockup",
                            "logo-horizontal-on-dark-bg.png")
SG_TTF = os.path.join(REPO, "tools", "social-card", "SpaceGrotesk.ttf")

# Space Grotesk is the site's display face. The vendored TTF is the LIGHT weight:
# deliberate at cover size, too thin for headings, so DISPLAY is used large only.
DISPLAY = "Helvetica-Bold"
MONO = "Courier"
try:
    pdfmetrics.registerFont(TTFont("SpaceGrotesk", SG_TTF))
    DISPLAY = "SpaceGrotesk"
except Exception as exc:                                        # pragma: no cover
    print(f"  note: Space Grotesk unavailable ({exc}); display falls back to Helvetica")

PAGE = letter
MARGIN = dict(leftMargin=0.68 * inch, rightMargin=0.68 * inch,
              topMargin=0.62 * inch, bottomMargin=0.7 * inch)

_base = getSampleStyleSheet()["Normal"]


def style(name, **kw):
    return ParagraphStyle(name, parent=_base, **kw)


# ---------------------------------------------------------------- type scale
S = {
    "cover_title":   style("cover_title", fontName=DISPLAY, fontSize=34, textColor=PAPER,
                           leading=39, alignment=1, spaceAfter=4),
    "cover_sub":     style("cover_sub", fontName=DISPLAY, fontSize=17, textColor=GOLD,
                           leading=22, alignment=1, spaceAfter=16),
    "cover_body":    style("cover_body", fontName="Helvetica", fontSize=10.5, textColor=DIM,
                           leading=16, alignment=1),
    "cover_eyebrow": style("cover_eyebrow", fontName="Helvetica-Bold", fontSize=8,
                           textColor=GOLD, leading=11, alignment=1, spaceAfter=7),
    "eyebrow":       style("eyebrow", fontName="Helvetica-Bold", fontSize=8, textColor=GOLD,
                           leading=11, spaceAfter=2),
    "title":         style("title", fontName=DISPLAY, fontSize=23, textColor=PAPER,
                           leading=27, spaceAfter=4),
    "subtitle":      style("subtitle", fontName="Helvetica", fontSize=10.5, textColor=DIM,
                           leading=15, spaceAfter=3),
    "h2":            style("h2", fontName="Helvetica-Bold", fontSize=13, textColor=PAPER,
                           leading=16, spaceBefore=13, spaceAfter=5),
    "h3":            style("h3", fontName="Helvetica-Bold", fontSize=10.5, textColor=GOLD,
                           leading=13.5, spaceBefore=9, spaceAfter=3),
    "body":          style("body", fontName="Helvetica", fontSize=9.5, textColor=PAPER,
                           leading=14.5, spaceAfter=5),
    "small":         style("small", fontName="Helvetica", fontSize=8, textColor=FAINT,
                           leading=11.5),
    "bullet":        style("bullet", fontName="Helvetica", fontSize=8.8, textColor=PAPER,
                           leading=13, leftIndent=12, bulletIndent=1, spaceAfter=3),
    "cell":          style("cell", fontName="Helvetica", fontSize=8.4, textColor=PAPER,
                           leading=11.5),
    "cell_b":        style("cell_b", fontName="Helvetica-Bold", fontSize=8.4, textColor=PAPER,
                           leading=11.5),
    "cell_h":        style("cell_h", fontName="Helvetica-Bold", fontSize=8.4, textColor=INK,
                           leading=11.5),
    "mono":          style("mono", fontName=MONO, fontSize=8, textColor=BLUE, leading=11.5),
    "stat_fig":      style("stat_fig", fontName=DISPLAY, fontSize=19, textColor=GOLD,
                           leading=22, alignment=1, spaceAfter=1),
    "stat_lbl":      style("stat_lbl", fontName="Helvetica", fontSize=7.4, textColor=DIM,
                           leading=9.5, alignment=1),
}


# ---------------------------------------------------------------- components
def rule(color=GOLD, w=1.2, sb=3, sa=7):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=sb, spaceAfter=sa,
                      lineCap="round")


def bullets(items, style_key="bullet"):
    return [Paragraph(t, S[style_key], bulletText="•") for t in items]


def scaled(path, max_w, max_h):
    """Fit an image in a box, preserving aspect. Returns None when the file is
    absent, so a missing asset degrades to no image rather than crashing a
    document that has to ship."""
    if not os.path.exists(path):
        print(f"  note: asset missing, skipping: {path}")
        return None
    iw, ih = ImageReader(path).getSize()
    s = min(max_w / iw, max_h / ih)
    return RLImage(path, iw * s, ih * s)


def panel(flowables, accent=GOLD, width=None):
    """A raised surface with an accent bar down its left edge. This is the site's
    hl-panel, which is the single component that makes these documents read as the
    site rather than as a generic report."""
    inner = Table([[f] for f in flowables], colWidths=[(width or 6.6 * inch) - 16])
    inner.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    t = Table([["", inner]], colWidths=[3, (width or 6.6 * inch) - 3])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), accent),
        ("BACKGROUND", (1, 0), (1, 0), PANEL),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("TOPPADDING", (0, 0), (0, 0), 0), ("BOTTOMPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 13), ("RIGHTPADDING", (1, 0), (1, 0), 13),
        ("TOPPADDING", (1, 0), (1, 0), 11), ("BOTTOMPADDING", (1, 0), (1, 0), 11),
    ]))
    return t


def stat_strip(pairs, width=6.6 * inch):
    """Figure-over-label cells in a row, the site's creds strip. Reads as an
    instrument panel, which is most of why the site feels like a tool."""
    cells = [[Paragraph(str(fig), S["stat_fig"]), Paragraph(lbl, S["stat_lbl"])]
             for fig, lbl in pairs]
    col = width / len(cells)
    t = Table([[Table([[c[0]], [c[1]]], colWidths=[col - 12]) for c in cells]],
              colWidths=[col] * len(cells))
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.6, PANEL_EDGE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, PANEL_EDGE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))
    return t


def dark_table(rows, col_widths, header_fill=GOLD, zebra=True):
    """Header band in an accent, body on the panel surface. Grid lines are the
    panel edge rather than white, because a bright grid on a dark ground fights
    the text for attention."""
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), header_fill),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.5, PANEL_EDGE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    if zebra:
        for i in range(2, len(rows), 2):
            cmds.append(("BACKGROUND", (0, i), (-1, i), INK))
    t.setStyle(TableStyle(cmds))
    return t


# ---------------------------------------------------------------- page painters
def paint_cover(canvas, doc):
    """Full-bleed ground with the gold-over-blue accent spine down the left edge.
    The spine is the site's per-section accent rail, reduced to punctuation."""
    canvas.saveState()
    w, h = PAGE
    canvas.setFillColor(INK)
    canvas.rect(0, 0, w, h, stroke=0, fill=1)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, 5, h, stroke=0, fill=1)
    canvas.setFillColor(BLUE)
    canvas.rect(0, 0, 5, h * 0.18, stroke=0, fill=1)
    canvas.restoreState()


def make_interior_painter(footer_left="the-hunters-ledger.com"):
    """Interior pages carry the same ground, a hairline accent at the head and a
    quiet footer. Returned as a closure so each document names itself."""
    def paint(canvas, doc):
        canvas.saveState()
        w, h = PAGE
        canvas.setFillColor(INK)
        canvas.rect(0, 0, w, h, stroke=0, fill=1)
        canvas.setFillColor(GOLD)
        canvas.rect(0, h - 3.5, w, 3.5, stroke=0, fill=1)
        canvas.setFont("Helvetica", 7.4)
        canvas.setFillColor(FAINT)
        canvas.drawString(0.68 * inch, 0.45 * inch, footer_left)
        canvas.drawRightString(w - 0.68 * inch, 0.45 * inch, str(doc.page))
        canvas.restoreState()
    return paint
