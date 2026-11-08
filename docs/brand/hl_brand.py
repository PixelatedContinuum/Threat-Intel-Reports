"""The Hunter's Ledger brand for reportlab documents: tokens, fonts, page ground, lockup, section head.

T-0563 w1. Every value here is read from `tokens.json`, which `gen_tokens.py` derives from the site
stylesheet (`assets/css/custom.scss`, concept 3). Nothing is hand-copied: if the site changes,
`gen_tokens.py --check` fails and a re-run of `gen_tokens.py` updates this module's values.

Use (from any generator; this directory is not a package, add it to sys.path):

    import sys; sys.path.insert(0, "<TIR>/docs/brand")          # repos/Threat-Intel-Reports/docs/brand
    import hl_brand as hl
    hl.register_fonts()                                         # idempotent
    c = canvas.Canvas("x.pdf", pagesize=hl.PAGE)
    hl.draw_ground(c, *hl.PAGE)                                 # #111111 page, optional faint grid
    hl.draw_lockup(c, x, y, scale=1.0)                          # vector lockup, no PNG needed
    hl.draw_section_head(c, x, y, "Title", width, color=hl.SEC["Reports"])
    # platypus: hl.SectionHead("Title", width, color), hl.styles()["body"], hl.styles()["h2"] ...

Fonts: registered under the names in FONT (HLSerif, HLSerif-SemiBold, HLSerif-Bold, HLSerif-Italic,
HLSans, HLSans-SemiBold, HLMono, HLMono-Medium, SpaceGrotesk-Medium, SpaceGrotesk-Bold). The HLSerif,
HLSans and HLMono families are registered as reportlab families so `<b>` and `<i>` in a Paragraph
resolve (bold is the site's 600 / 500, not 700). The glyph set is the site's Latin subset.

Requires reportlab (the gates venv: .venv-gates/bin/python3).
"""
import json
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Flowable

HERE = os.path.dirname(os.path.abspath(__file__))
TOKENS = json.load(open(os.path.join(HERE, "tokens.json"), encoding="utf-8"))["tokens"]
FONT_DIR = os.path.join(HERE, "fonts", "ttf")
LOGO_DIR = os.path.join(HERE, "logos")

_c = TOKENS["colors"]
HC = colors.HexColor

# ---- colours (names follow tokens.json "colors")
GROUND, CARD, ROW = HC(_c["ground"]), HC(_c["card"]), HC(_c["row"])
BORDER, BORDER_ROW = HC(_c["border_card"]), HC(_c["border_row"])
INK, MUTED = HC(_c["ink"]), HC(_c["muted"])
BLUE, PURPLE, TEAL = HC(_c["blue"]), HC(_c["purple"]), HC(_c["teal"])
GREEN, RED = HC(_c["green"]), HC(_c["red"])
GOLD, GOLD_LIGHT, GOLD_BRIGHT, STEEL = HC(_c["gold"]), HC(_c["gold_light"]), HC(_c["gold_bright"]), HC(_c["steel"])
FIELD, FIELD_LINE, HAIRLINE = HC(_c["field"]), HC(_c["field_line"]), HC(_c["hairline"])
SEV_BAR = {k: HC(v["bar"]) for k, v in TOKENS["severity"].items()}
SEV_LABEL = {k: HC(v["label"]) for k, v in TOKENS["severity"].items()}
SEC = {k: HC(v) for k, v in TOKENS["section_hues"].items()}      # nav hue per section
SEC_DEFAULT = HC(TOKENS["section_head"]["default_color"])         # blue

# ---- colour rule hues (T-0563 round 2): rotation, kind map and light-ground variants, all derived
# by gen_tokens.py (tokens.json "hues"). 1-based index, wraps past 7, so hue(i) never raises.
_H = TOKENS["hues"]
HUES = [HC(r["dark"]) for r in _H["rotation"]]               # Wire, Reports, Detections, Techniques, STIX, Actors, IOC
HUES_LIGHT = [HC(r["light"]) for r in _H["rotation"]]
_KIND = {k: v for k, v in _H["kinds"].items()}


def hue(i):
    """The i-th hue (1-based, wraps) of the fixed rotation on the dark ground (#111111)."""
    return HUES[(int(i) - 1) % len(HUES)]


def hue_light(i):
    """Same, darkened to pass 4.5:1 on #ffffff and #f6f8fa."""
    return HUES_LIGHT[(int(i) - 1) % len(HUES_LIGHT)]


def hue_for(kind):
    """Hue of a kind: reports, detections, iocs, stix, wire, actors, techniques (KeyError otherwise)."""
    return HC(_KIND[kind]["dark"])


def hue_for_light(kind):
    return HC(_KIND[kind]["light"])

CODE_TEXT, CODE_INLINE_BG, CODE_BLOCK_BG = (HC(TOKENS["code"][k]) for k in ("text", "inline_bg", "block_bg"))
RADIUS = TOKENS["radius_px"]
SCALE_PX = TOKENS["type_scale_px"]            # meta 15, small 16, body 18, card 20, section 26 (CSS px)

PAGE = letter
MARGIN = 0.75 * inch

# ---- fonts
FONT = {
    "serif": "HLSerif", "serif_semibold": "HLSerif-SemiBold", "serif_bold": "HLSerif-Bold", "serif_italic": "HLSerif-Italic",
    "sans": "HLSans", "sans_semibold": "HLSans-SemiBold",
    "mono": "HLMono", "mono_medium": "HLMono-Medium",
    "wordmark_medium": "SpaceGrotesk-Medium", "wordmark_bold": "SpaceGrotesk-Bold",
}
_FILES = {
    "HLSerif": "HLSerif-Regular", "HLSerif-SemiBold": "HLSerif-SemiBold", "HLSerif-Bold": "HLSerif-Bold",
    "HLSerif-Italic": "HLSerif-Italic", "HLSans": "HLSans-Regular", "HLSans-SemiBold": "HLSans-SemiBold",
    "HLMono": "HLMono-Regular", "HLMono-Medium": "HLMono-Medium",
    "SpaceGrotesk-Medium": "SpaceGrotesk-Medium", "SpaceGrotesk-Bold": "SpaceGrotesk-Bold",
}
_registered = False


def register_fonts():
    """Register the static TTF instances with reportlab. Raises if a file is missing (no silent fallback)."""
    global _registered
    if _registered:
        return
    for rl_name, stem in _FILES.items():
        path = os.path.join(FONT_DIR, stem + ".ttf")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{path} missing: run .venv-gates/bin/python3 docs/brand/make_fonts.py")
        pdfmetrics.registerFont(TTFont(rl_name, path))
    pdfmetrics.registerFontFamily("HLSerif", normal="HLSerif", bold="HLSerif-SemiBold", italic="HLSerif-Italic", boldItalic="HLSerif-Italic")
    pdfmetrics.registerFontFamily("HLSans", normal="HLSans", bold="HLSans-SemiBold", italic="HLSans", boldItalic="HLSans-SemiBold")
    pdfmetrics.registerFontFamily("HLMono", normal="HLMono", bold="HLMono-Medium", italic="HLMono", boldItalic="HLMono-Medium")
    _registered = True


def px(css_px):
    """CSS px to PDF points at the browser's 96 dpi (1px = 0.75pt). Document sizes are chosen in pt; use this to
    keep a site proportion (for example the 14px section square or the 2px rule)."""
    return css_px * 0.75


# ---- page ground
def draw_ground(c, w, h, grid=False):
    """Fill the page with the site ground (#111111). grid=True adds the site's faint 24px blue grid (3% alpha);
    the grid is drawn over the ground, so a raster logo must be the TRANSPARENT one on a gridded page."""
    c.saveState()
    c.setFillColor(GROUND)
    c.rect(0, 0, w, h, stroke=0, fill=1)
    if grid:
        step = px(TOKENS["page"]["grid_px"])
        r, g, b, a = TOKENS["page"]["grid_rgba"]
        c.setStrokeColor(colors.Color(r / 255, g / 255, b / 255, alpha=a))
        c.setLineWidth(px(1))
        x = 0
        while x <= w:
            c.line(x, 0, x, h)
            x += step
        y = h
        while y >= 0:
            c.line(0, y, w, y)
            y -= step
    c.restoreState()


# ---- lockup (vector, from the site's own geometry)
def _icon(c, x, y, size):
    """The HL mark: 64x64 viewBox, rounded square #161b22 with a #30363d border and blue strokes (navbar.liquid)."""
    k = size / 64.0
    c.saveState()
    c.translate(x, y)
    c.scale(k, k)                               # y up; the SVG is y down, so flip inside a 64 box
    c.translate(0, 64)
    c.scale(1, -1)
    c.setFillColor(HC("#161b22"))
    c.roundRect(0, 0, 64, 64, 14, stroke=0, fill=1)
    c.setStrokeColor(HC("#30363d"))
    c.setLineWidth(1.5)
    c.roundRect(1, 1, 62, 62, 13, stroke=1, fill=0)
    c.setStrokeColor(BLUE)
    c.setLineWidth(4)
    c.setLineCap(1)
    c.setLineJoin(1)
    for pts in (((19, 16), (19, 48)), ((35, 16), (35, 48)), ((19, 32), (35, 32)), ((35, 48), (50, 48))):
        c.line(*pts[0], *pts[1])
    c.restoreState()


def lockup_size(scale=1.0, which="masthead"):
    """(width, height) in points of draw_lockup at `scale` (1.0 = the page masthead's CSS px, as points x0.75)."""
    g = TOKENS["brand"][which]
    s = px(1) * scale
    top_w = pdfmetrics.stringWidth(TOKENS["brand"]["top"]["text"], FONT["wordmark_medium"], g["top_size"]) + \
        TOKENS["brand"]["top"]["tracking_em"] * g["top_size"] * (len(TOKENS["brand"]["top"]["text"]) - 1)
    main_w = pdfmetrics.stringWidth(TOKENS["brand"]["main"]["text"], FONT["wordmark_bold"], g["main_size"]) + \
        TOKENS["brand"]["main"]["tracking_em"] * g["main_size"] * len(TOKENS["brand"]["main"]["text"]) + g["dot_margin_left"] + g["dot"]
    return (g["icon"] + g["gap"] + g["rule_w"] + g["gap"] + max(top_w, main_w)) * s, g["icon"] * s


def draw_lockup(c, x, y, scale=1.0, which="masthead"):
    """Draw the site lockup with its lower-left at (x, y): icon, blue rule, THE HUNTER'S over LEDGER, square dot.
    `which` is "masthead" (the big one on the page) or "bar" (the nav-bar size). scale 1.0 = CSS px x 0.75pt."""
    register_fonts()
    B = TOKENS["brand"]
    g = B[which]
    s = px(1) * scale
    h = g["icon"] * s
    c.saveState()                               # char spacing (Tc) is graphics state and would leak into later text
    _icon(c, x, y, h)
    cx = x + (g["icon"] + g["gap"]) * s
    c.setFillColor(HC(B["rule_color"]))
    rh = g["rule_h"] * s
    c.roundRect(cx, y + (h - rh) / 2, g["rule_w"] * s, rh, g["rule_radius"] * s, stroke=0, fill=1)
    tx = cx + (g["rule_w"] + g["gap"]) * s
    # stack: top line over main line, centred on the icon's mid line (flex align-items:center, line-height 1)
    top_sz, main_sz = g["top_size"] * s, g["main_size"] * s
    stack_h = top_sz + g["stack_gap"] * s + main_sz
    base_top = y + h / 2 + stack_h / 2 - top_sz * 0.78
    base_main = y + h / 2 - stack_h / 2 + main_sz * 0.22
    c.setFillColor(HC(B["top"]["color"]))
    t = c.beginText(tx, base_top)
    t.setFont(FONT["wordmark_medium"], top_sz)
    t.setCharSpace(B["top"]["tracking_em"] * top_sz)
    t.textOut(B["top"]["text"])
    c.drawText(t)
    c.setFillColor(HC(B["main"]["color"]))
    t = c.beginText(tx, base_main)
    t.setFont(FONT["wordmark_bold"], main_sz)
    t.setCharSpace(B["main"]["tracking_em"] * main_sz)
    t.textOut(B["main"]["text"])
    c.drawText(t)
    main_w = pdfmetrics.stringWidth(B["main"]["text"], FONT["wordmark_bold"], main_sz) + \
        B["main"]["tracking_em"] * main_sz * len(B["main"]["text"])
    c.setFillColor(HC(B["dot_color"]))
    d = g["dot"] * s
    c.roundRect(tx + main_w + g["dot_margin_left"] * s, base_main, d, d, g["dot_radius"] * s, stroke=0, fill=1)
    c.restoreState()


# ---- section head (concept 3): a square in the section colour, a serif title, a rule under the whole head
def draw_section_head(c, x, y, title, width, color=None, sub=False, size_pt=None):
    """Draw a section head with its title baseline at y. Returns the y of the rule (bottom of the head).
    Square 14px (11px if sub), 12px (10px) gap, title Source Serif 4 SemiBold ink, 2px rule in `color` across `width`."""
    register_fonts()
    S = TOKENS["section_head"]
    color = color or SEC_DEFAULT
    sq = px(S["sub_square" if sub else "square"])
    gap = px(S["sub_square_margin_right" if sub else "square_margin_right"])
    size = size_pt or px(S["title_size"])
    c.saveState()
    c.setFillColor(color)
    c.rect(x, y + (size * 0.72 - sq) / 2, sq, sq, stroke=0, fill=1)    # square centred on the cap height
    c.setFillColor(INK)
    c.setFont(FONT["serif_semibold"], size)
    c.drawString(x + sq + gap, y, title)
    rule = px(S["sub_rule" if sub else "rule"])
    ry = y - size * 0.3 - px(8)
    c.setFillColor(color)
    c.rect(x, ry - rule, width, rule, stroke=0, fill=1)
    c.restoreState()
    return ry - rule


class SectionHead(Flowable):
    """Platypus flowable for draw_section_head."""
    def __init__(self, title, width, color=None, sub=False):
        super().__init__()
        self.title, self.width, self.color, self.sub = title, width, color, sub
        self.size = px(TOKENS["section_head"]["title_size"])
        self.height = self.size + px(8) + self.size * 0.3 + px(TOKENS["section_head"]["rule"]) + px(6)

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        draw_section_head(self.canv, 0, self.height - self.size, self.title, self.width, self.color, self.sub)


# ---- paragraph styles (sizes in pt: the site's px x 0.75 is too small for print, so these are the
# conventional document sizes, with the site's families, weights, colours and leading ratios)
def styles(ink=None):
    register_fonts()
    ink = ink or INK
    base = dict(textColor=ink, alignment=TA_LEFT)
    return {
        "body": ParagraphStyle("hl_body", fontName=FONT["sans"], fontSize=10.5, leading=15.5, **base),
        "prose": ParagraphStyle("hl_prose", fontName=FONT["serif"], fontSize=11, leading=16, **base),
        "small": ParagraphStyle("hl_small", fontName=FONT["sans"], fontSize=9, leading=13, **base),
        "muted": ParagraphStyle("hl_muted", fontName=FONT["sans"], fontSize=9, leading=13, textColor=MUTED, alignment=TA_LEFT),
        "h1": ParagraphStyle("hl_h1", fontName=FONT["serif_semibold"], fontSize=26, leading=31, spaceAfter=8, **base),
        "h2": ParagraphStyle("hl_h2", fontName=FONT["serif_semibold"], fontSize=18, leading=22, spaceBefore=14, spaceAfter=6, **base),
        "h3": ParagraphStyle("hl_h3", fontName=FONT["sans_semibold"], fontSize=11, leading=15, spaceBefore=8, spaceAfter=3, **base),
        "kicker": ParagraphStyle("hl_kicker", fontName=FONT["mono_medium"], fontSize=9, leading=12, textColor=MUTED, alignment=TA_LEFT),
        "mono": ParagraphStyle("hl_mono", fontName=FONT["mono"], fontSize=9, leading=13, **base),
        "code": ParagraphStyle("hl_code", fontName=FONT["mono"], fontSize=9, leading=13, textColor=CODE_TEXT, alignment=TA_LEFT),
    }
