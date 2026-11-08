"""The Hunter's Ledger document theme for reportlab PDFs, on the concept 3 base.

T-0563 w2a. This module no longer keeps a palette or a font list of its own. Every colour, font,
size ratio and the lockup come from `docs/brand/hl_brand.py`, which reads `docs/brand/tokens.json`,
which `docs/brand/gen_tokens.py` derives from the site stylesheet (`assets/css/custom.scss`).
What lives here is only what a PDF needs that a web page does not: paragraph styles in points,
platypus components (section head, panel, stat strip, table), page painters, and a light variant.

One theme, every reportlab document that leaves here (pricing sheet, sponsor brief, quarterly
update, invoice) consumes it, so they cannot drift from each other or from the site.

The look (site rules, inventory Part 1)
---------------------------------------
Ground #111111, ink #eeeeee, accent blue for rules, links and section marks. Gold means sponsor and
nothing else: `GOLD` here is the site's `--hl-gold-bright`, and a generic rule, h3 or numeral does
not use it. Source Serif 4 for titles, section titles and big numerals, IBM Plex Sans for body,
IBM Plex Mono for data only (ids, dates, counts, hashes, IOCs), Space Grotesk only inside the lockup.
A section head is a square in the section colour, a serif title, and a 2px rule under it.

Dark is the default. `theme("light")` gives the same fonts and layout on a white page for the
documents that keep a light option (quarterly update, invoice). Light mode uses blue and gold only
for rules and marks, never for small text, because #58a6ff is 2.4:1 on white.

Glyph gap (BASE, reported to the lead): the site's Latin subset has no U+2192 (arrow) or U+25CF
(black circle). `sym()` sets those two in a system TrueType that has them (embedded as a subset by
reportlab) and the module prints a note if none is found, so nothing falls back silently.

Requires: reportlab (the gates venv, .venv-gates/bin/python3).
"""
import os
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (HRFlowable, Flowable, Image as RLImage, Paragraph, Table,
                                TableStyle)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand"))
import hl_brand as hl  # noqa: E402

hl.register_fonts()

# ---------------------------------------------------------------- tokens (re-exported, never re-typed)
GROUND, CARD, ROW = hl.GROUND, hl.CARD, hl.ROW
BORDER, BORDER_ROW, HAIRLINE = hl.BORDER, hl.BORDER_ROW, hl.HAIRLINE
INK, MUTED = hl.INK, hl.MUTED
BLUE, GREEN, RED = hl.BLUE, hl.GREEN, hl.RED
GOLD = hl.GOLD_BRIGHT            # sponsor and nothing else (custom.scss:46)
SEV = hl.SEV_BAR                 # severity bars, keys critical/high/med/low
SEC = hl.SEC
CODE_TEXT = hl.CODE_TEXT
FONT = hl.FONT
px = hl.px

PAGE = hl.PAGE
MARGIN = dict(leftMargin=0.68 * inch, rightMargin=0.68 * inch,
              topMargin=0.82 * inch, bottomMargin=0.7 * inch)
SITE_URL = "the-hunters-ledger.com"

# ---------------------------------------------------------------- glyph fallback (see module docstring)
SYM = None
for _p in ("/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
           "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
           "/usr/share/fonts/TTF/DejaVuSans.ttf"):
    if os.path.isfile(_p):
        try:
            pdfmetrics.registerFont(TTFont("HLSymbols", _p))
            SYM = _p
            break
        except Exception:                                           # pragma: no cover
            continue
if SYM is None:                                                     # pragma: no cover
    print("  note: no system font with U+2192 / U+25CF found; those two glyphs will not render")


def sym(text):
    """Wrap the two glyphs the site subset lacks (arrow, black circle) in the fallback font."""
    if SYM is None:
        return text
    for ch in ("→", "●", "&#9679;", "&#8594;"):
        text = text.replace(ch, f"<font name='HLSymbols'>{ch}</font>")
    return text


# ---------------------------------------------------------------- themes
def _blend(a, b, t):
    """a + (b - a) * t, per channel; for the light variant's derived greys."""
    return colors.Color(a.red + (b.red - a.red) * t, a.green + (b.green - a.green) * t,
                        a.blue + (b.blue - a.blue) * t)


class Theme:
    """One document mode: ground, ink and the grey steps, plus its paragraph styles in `S`."""

    def __init__(self, name, ground, ink, muted, card, row, edge, hairline):
        self.name, self.dark = name, name == "dark"
        self.ground, self.ink, self.muted = ground, ink, muted
        self.card, self.row, self.edge, self.hairline = card, row, edge, hairline
        self.S = self._styles()

    def _styles(self):
        ink, muted = self.ink, self.muted

        def st(name, font, size, lead, color=ink, **kw):
            return ParagraphStyle(name + "_" + self.name, fontName=FONT[font], fontSize=size,
                                  leading=lead, textColor=color, alignment=kw.pop("alignment", TA_LEFT), **kw)

        return {
            "cover_title": st("cover_title", "serif_semibold", 34, 39, alignment=TA_CENTER, spaceAfter=4),
            "cover_sub": st("cover_sub", "serif", 17, 22, alignment=TA_CENTER, spaceAfter=16),
            "cover_body": st("cover_body", "sans", 10.5, 16, muted, alignment=TA_CENTER),
            "cover_eyebrow": st("cover_eyebrow", "mono_medium", 8, 11, muted, alignment=TA_CENTER, spaceAfter=7),
            "eyebrow": st("eyebrow", "mono_medium", 8, 11, muted, spaceAfter=3),
            "title": st("title", "serif_semibold", 24, 28, spaceAfter=4),
            "subtitle": st("subtitle", "sans", 10.5, 15, muted, spaceAfter=3),
            "h2": st("h2", "serif_semibold", 14.5, 18, spaceBefore=13, spaceAfter=5),
            "h3": st("h3", "sans_semibold", 10.5, 13.5, spaceBefore=9, spaceAfter=3),
            "body": st("body", "sans", 9.5, 14.5, spaceAfter=5),
            "small": st("small", "sans", 8, 11.5, muted),
            "bullet": st("bullet", "sans", 8.8, 13, leftIndent=12, bulletIndent=1, spaceAfter=3),
            "cell": st("cell", "sans", 8.4, 11.5),
            "cell_b": st("cell_b", "sans_semibold", 8.4, 11.5),
            "cell_h": st("cell_h", "sans_semibold", 8.4, 11.5),
            "data": st("data", "mono", 8.4, 11.5),
            "mono": st("mono", "mono", 8, 11.5, CODE_TEXT if self.dark else ink),
            "stat_fig": st("stat_fig", "serif_semibold", 20, 23, alignment=TA_CENTER, spaceAfter=1),
            "stat_lbl": st("stat_lbl", "sans", 7.4, 9.5, muted, alignment=TA_CENTER),
        }


DARK = Theme("dark", GROUND, INK, MUTED, CARD, ROW, BORDER, HAIRLINE)
_W = colors.white
LIGHT = Theme("light", _W, GROUND, _blend(_W, GROUND, 0.62), _blend(_W, GROUND, 0.04),
              _blend(_W, GROUND, 0.02), _blend(_W, GROUND, 0.16), _blend(_W, GROUND, 0.10))
S = DARK.S


def theme(mode="dark"):
    if mode == "dark":
        return DARK
    if mode == "light":
        return LIGHT
    raise ValueError("theme mode must be 'dark' or 'light'")


def hexs(c):
    """'#rrggbb' for a reportlab colour, for <font color=...> inside a Paragraph (so a token is never retyped)."""
    return "#%02x%02x%02x" % (round(c.red * 255), round(c.green * 255), round(c.blue * 255))


def style(name, parent=None, **kw):
    """A ParagraphStyle on the dark body style, for one-off styles in a generator."""
    return ParagraphStyle(name, parent=parent or S["body"], **kw)


# ---------------------------------------------------------------- flowables
class DocSection(Flowable):
    """Section head: a 14px square in the section colour, a serif title, a 2px rule across the width.
    The geometry is the site's (tokens.json section_head); only the title size is a document choice."""

    def __init__(self, title, width, color=None, t=DARK, size=14.5, sub=False):
        super().__init__()
        g = hl.TOKENS["section_head"]
        self.title, self.width, self.t = title, width, t
        self.color = color or BLUE
        self.size = size
        self.sq = px(g["sub_square" if sub else "square"])
        self.gap = px(g["sub_square_margin_right" if sub else "square_margin_right"])
        self.rule = px(g["sub_rule" if sub else "rule"])
        self.height = size * 1.15 + px(8) + self.rule
        self.spaceBefore, self.spaceAfter, self.keepWithNext = 9, 6, 1

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        base = self.height - self.size * 0.95
        c.setFillColor(self.color)
        c.rect(0, base + (self.size * 0.72 - self.sq) / 2, self.sq, self.sq, stroke=0, fill=1)
        c.setFillColor(self.t.ink)
        c.setFont(FONT["serif_semibold"], self.size)
        c.drawString(self.sq + self.gap, base, self.title)
        c.setFillColor(self.color)
        c.rect(0, 0, self.width, self.rule, stroke=0, fill=1)


def section(title, width, color=None, t=DARK, sub=False):
    return DocSection(title, width, color=color, t=t, sub=sub)


class Lockup(Flowable):
    """The site lockup, drawn as vectors, centred. On the light theme it sits on a ground-coloured plate,
    because the wordmark is light ink."""

    def __init__(self, scale=1.4, t=DARK, which="masthead", align="CENTER"):
        super().__init__()
        self.scale, self.t, self.which, self.hAlign = scale, t, which, align
        self.w, self.h = hl.lockup_size(scale, which)
        self.pad = 0 if t.dark else 16
        self.width, self.height = self.w + 2 * self.pad, self.h + 2 * self.pad

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        if not self.t.dark:
            c.setFillColor(GROUND)
            c.roundRect(0, 0, self.width, self.height, 3, stroke=0, fill=1)
        hl.draw_lockup(c, self.pad, self.pad, self.scale, self.which)


# ---------------------------------------------------------------- components
def rule(color=None, w=None, sb=3, sa=7, t=DARK):
    """A full-width rule. Default is the site's 2px blue; pass a hairline colour and 0.5 for a divider."""
    return HRFlowable(width="100%", thickness=w if w is not None else px(2),
                      color=color or BLUE, spaceBefore=sb, spaceAfter=sa, lineCap="butt")


def bullets(items, style_key="bullet", t=DARK):
    return [Paragraph(sym(x), t.S[style_key], bulletText="•") for x in items]


def scaled(path, max_w, max_h):
    """Fit an image in a box, preserving aspect. Returns None when the file is absent, so a missing
    asset degrades to no image rather than crashing a document that has to ship."""
    if not path or not os.path.exists(path):
        print(f"  note: asset missing, skipping: {path}")
        return None
    iw, ih = ImageReader(path).getSize()
    s = min(max_w / iw, max_h / ih)
    return RLImage(path, iw * s, ih * s)


def panel(flowables, accent=None, width=None, t=DARK):
    """The site's plate: a card ground, a 1px border and a 3px edge in the accent colour."""
    accent = accent or BLUE
    wd = width or 6.6 * inch
    inner = Table([[f] for f in flowables], colWidths=[wd - 3 - 26])
    inner.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    tb = Table([["", inner]], colWidths=[3, wd - 3])
    tb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), accent),
        ("BACKGROUND", (1, 0), (1, 0), t.card),
        ("BOX", (0, 0), (-1, -1), 0.75, t.edge),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("TOPPADDING", (0, 0), (0, 0), 0), ("BOTTOMPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 13), ("RIGHTPADDING", (1, 0), (1, 0), 13),
        ("TOPPADDING", (1, 0), (1, 0), 9), ("BOTTOMPADDING", (1, 0), (1, 0), 9),
    ]))
    return tb


def stat_strip(pairs, width=6.6 * inch, t=DARK):
    """Serif figure over a sans label, in a row of cells on the card ground (the site's creds strip)."""
    cells = [[Paragraph(str(fig), t.S["stat_fig"]), Paragraph(lbl, t.S["stat_lbl"])] for fig, lbl in pairs]
    col = width / len(cells)
    tb = Table([[Table([[c[0]], [c[1]]], colWidths=[col - 12]) for c in cells]], colWidths=[col] * len(cells))
    tb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), t.card),
        ("BOX", (0, 0), (-1, -1), 0.75, t.edge),
        ("INNERGRID", (0, 0), (-1, -1), 0.75, t.edge),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))
    return tb


def dark_table(rows, col_widths, header_fill=None, zebra=True, t=DARK):
    """Header row on the card ground with a 2px rule in `header_fill` (the section or severity colour)
    under it, body rows on the row ground with hairlines. `header_fill` keeps its old name so callers
    that pass a severity colour read the same; it is now the rule colour, not a fill."""
    header_fill = header_fill or BLUE
    tb = Table(rows, colWidths=col_widths, repeatRows=1)
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), t.card),
        ("BACKGROUND", (0, 1), (-1, -1), t.row),
        ("LINEBELOW", (0, 0), (-1, 0), px(2), header_fill),
        ("LINEBELOW", (0, 1), (-1, -1), 0.5, t.edge),
        ("BOX", (0, 0), (-1, -1), 0.5, t.edge),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if zebra:
        for i in range(2, len(rows), 2):
            cmds.append(("BACKGROUND", (0, i), (-1, i), t.card))
    tb.setStyle(TableStyle(cmds))
    return tb


# ---------------------------------------------------------------- page painters
def paint_ground(canvas, t=DARK, grid=False):
    """Fill the whole page with the theme ground (for generators with their own page chrome)."""
    _ground(canvas, t, grid)


def _ground(canvas, t, grid):
    w, h = PAGE
    if t.dark:
        hl.draw_ground(canvas, w, h, grid=grid)
    else:
        canvas.saveState()
        canvas.setFillColor(t.ground)
        canvas.rect(0, 0, w, h, stroke=0, fill=1)
        canvas.restoreState()


def make_cover_painter(t=DARK):
    def paint(canvas, doc):
        _ground(canvas, t, grid=True)
    return paint


paint_cover = make_cover_painter(DARK)


def make_interior_painter(footer_left=SITE_URL, t=DARK):
    """Interior pages: the ground, the bar-size lockup top left over a hairline (dark only; the light
    page gets the mono name), and a mono footer on a hairline."""
    def paint(canvas, doc):
        _ground(canvas, t, grid=False)
        w, h = PAGE
        lm, rm = MARGIN["leftMargin"], w - MARGIN["rightMargin"]
        canvas.saveState()
        top = h - 0.34 * inch
        if t.dark:
            lh = hl.lockup_size(0.62, "bar")[1]
            hl.draw_lockup(canvas, lm, top - lh / 2, 0.62, "bar")
        else:
            canvas.setFont(FONT["mono_medium"], 7.4)
            canvas.setFillColor(t.muted)
            canvas.drawString(lm, top - 3, "THE HUNTER'S LEDGER")
        canvas.setStrokeColor(t.edge)
        canvas.setLineWidth(0.5)
        canvas.line(lm, h - 0.58 * inch, rm, h - 0.58 * inch)
        canvas.line(lm, 0.62 * inch, rm, 0.62 * inch)
        canvas.setFont(FONT["mono"], 7.4)
        canvas.setFillColor(t.muted)
        canvas.drawString(lm, 0.44 * inch, footer_left)
        canvas.drawRightString(rm, 0.44 * inch, str(doc.page))
        canvas.restoreState()
    return paint
