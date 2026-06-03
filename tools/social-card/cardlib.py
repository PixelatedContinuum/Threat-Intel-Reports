"""Social-card generation library for The Hunter's Ledger.

Pure data helpers + front-matter/catalog parsing + 1200x630 card rendering +
idempotent thumbnail front-matter insertion. See design spec / plan in
AIAgents_Workflows/Projects/hunters-ledger-site/preview-mockups/.
"""
import os
import re
import datetime
import calendar
import glob
import yaml
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
SG_PATH = os.path.join(HERE, "SpaceGrotesk.ttf")
DOMAIN = "the-hunters-ledger.com"


# ---------------------------------------------------------------- pure helpers
def format_card_date(value):
    if isinstance(value, (datetime.date, datetime.datetime)):
        dt = value
    else:
        dt = datetime.datetime.strptime(str(value).strip(), "%Y-%m-%d")
    return f"{calendar.month_abbr[dt.month]} {dt.day}, {dt.year}"


_SEV = {"critical": "CRITICAL", "high": "HIGH", "med": "MEDIUM",
        "medium": "MEDIUM", "low": "LOW"}


def severity_label(value):
    return _SEV.get(str(value).strip().lower(), "HIGH")


def derive_kicker(category, tags):
    if category:
        return str(category).upper()
    if tags:
        return str(tags[0]).upper()
    return "THREAT INTELLIGENCE"


# ------------------------------------------------------ front matter + catalog
def load_front_matter(index_md_path):
    with open(index_md_path, encoding="utf-8") as fh:
        text = fh.read()
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        raise ValueError(f"No front matter in {index_md_path}")
    return yaml.safe_load(m.group(1)) or {}


def slug_of(index_md_path):
    """Canonical URL slug = last segment of the report's permalink."""
    fm = load_front_matter(index_md_path)
    return fm.get("permalink", "").strip("/").split("/")[-1]


def _catalog_entry(repo_root, slug):
    with open(os.path.join(repo_root, "_data/catalog.yml"), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    target = f"/reports/{slug}/"
    for e in data.get("entries", []):
        if e.get("report_url") == target:
            return e
    return None


def severity_for_slug(repo_root, slug):
    entry = _catalog_entry(repo_root, slug)
    if entry and entry.get("severity"):
        return severity_label(entry["severity"])
    return "HIGH"  # conservative fallback (warned in generate_card)


def _report_dir_for_slug(repo_root, slug):
    for idx in glob.glob(os.path.join(repo_root, "reports", "*", "index.md")):
        if slug_of(idx) == slug:
            return idx
    raise FileNotFoundError(f"No report with permalink slug '{slug}'")


def card_fields(repo_root, slug):
    idx = _report_dir_for_slug(repo_root, slug)
    fm = load_front_matter(idx)
    entry = _catalog_entry(repo_root, slug)
    tags = (entry or {}).get("tags", [])
    return {
        "slug": slug,
        "title": fm["title"],
        "kicker": derive_kicker(fm.get("category"), tags),
        "severity": severity_for_slug(repo_root, slug),
        "date": format_card_date(fm["date"]),
        "subtitle": (fm.get("description") or "").strip(),
    }


# ---------------------------------------------------------------- rendering
W, H, SS = 1200, 630, 2
BW, BH = W * SS, H * SS


def _s(v):
    return int(v * SS)


BG = "#111111"
GRID = "#1a1a1d"
BLUE = "#58a6ff"
GOLD = "#b8902f"
TXT = "#eeeeee"
MUTED = "#8a8a8a"
DIV = "#2a2a2a"
SEV = {"CRITICAL": ("#dc2626", "#ef4444", "#ffffff"),
       "HIGH": ("#f97316", "#fb923c", "#160a02"),
       "MEDIUM": ("#eab308", "#facc15", "#160f02"),
       "LOW": ("#3b82f6", "#60a5fa", "#ffffff")}


def _font(size, weight=500):
    f = ImageFont.truetype(SG_PATH, int(size * SS))
    try:
        f.set_variation_by_axes([weight])
    except Exception:
        pass
    return f


_scratch = ImageDraw.Draw(Image.new("RGB", (4, 4)))


def _tracked(d, pos, text, font, fill, track):
    x, y = pos
    for ch in text:
        d.text((x, y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + track


def _background():
    im = Image.new("RGB", (BW, BH), BG)
    d = ImageDraw.Draw(im)
    step = _s(48)
    for x in range(0, BW, step):
        d.line([(x, 0), (x, BH)], fill=GRID, width=_s(1))
    for y in range(0, BH, step):
        d.line([(0, y), (BW, y)], fill=GRID, width=_s(1))
    gl = Image.new("RGBA", (BW, BH), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gl)
    r, g, b = tuple(int(BLUE[i:i + 2], 16) for i in (1, 3, 5))
    gw = _s(170)
    for x in range(gw):
        gd.line([(x, 0), (x, BH)], fill=(r, g, b, int(40 * (1 - x / gw))))
    return Image.alpha_composite(im.convert("RGBA"), gl).convert("RGB")


def _fit_title(title, max_w, max_lines=3, start=62, lo=34):
    size = start
    lines = [title]
    while size >= lo:
        f = _font(size, 700)
        words = title.split()
        lines, cur, ok = [], "", True
        for w in words:
            cand = w if not cur else cur + " " + w
            if _scratch.textlength(cand, font=f) <= max_w:
                cur = cand
            else:
                if cur:
                    lines.append(cur)
                cur = w
                if _scratch.textlength(cur, font=f) > max_w:
                    ok = False
        if cur:
            lines.append(cur)
        if ok and len(lines) <= max_lines:
            return f, lines
        size -= 2
    return _font(lo, 700), lines[:max_lines]


def _ellipsize(text, font, max_w):
    if _scratch.textlength(text, font=font) <= max_w:
        return text
    while text and _scratch.textlength(text + "…", font=font) > max_w:
        text = text[:-1]
    text = text.rstrip()
    if " " in text:                       # back off to the last whole word
        text = text[:text.rfind(" ")].rstrip()
    return text + "…"


def render_card(fields, out_path):
    bd, lt, ptx = SEV.get(fields["severity"], SEV["HIGH"])
    im = _background()
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, _s(8), BH], fill=bd)                       # severity spine
    ml, mr, top = _s(72), _s(72), _s(60)
    d.rounded_rectangle([ml, top, ml + _s(5), top + _s(30)], radius=_s(2), fill=BLUE)
    _tracked(d, (ml + _s(15), top + _s(4)), "THE HUNTER'S LEDGER",
             _font(18, 600), TXT, _s(2.2))
    fp = _font(19, 700)
    pt = fields["severity"]
    tw = _scratch.textlength(pt, font=fp)
    pw, ph = tw + _s(34), _s(40)
    px0 = BW - mr - pw
    d.rounded_rectangle([px0, top - _s(4), px0 + pw, top - _s(4) + ph],
                        radius=_s(20), fill=bd)
    d.text((px0 + _s(17), top + _s(5)), pt, font=fp, fill=ptx)
    _tracked(d, (ml, _s(206)), fields["kicker"], _font(19, 600), GOLD, _s(3))
    f, lines = _fit_title(fields["title"], BW - ml - mr, 3, 62, 34)
    lh = int(f.size * 1.12)
    y = _s(244)
    for ln in lines:
        d.text((ml, y), ln, font=f, fill=TXT)
        y += lh
    if fields.get("subtitle"):
        fs = _font(21, 400)
        d.text((ml, y + _s(14)),
               _ellipsize(fields["subtitle"], fs, BW - ml - mr),
               font=fs, fill=MUTED)
    d.line([(ml, _s(H - 96)), (BW - mr, _s(H - 96))], fill=DIV, width=_s(1))
    fm = _font(19, 500)
    ym = _s(H - 76)
    d.text((ml, ym), fields["date"], font=fm, fill=MUTED)
    fd = _font(19, 600)
    twd = _scratch.textlength(DOMAIN, font=fd)
    xr = BW - mr - twd
    d.rounded_rectangle([xr - _s(20), ym + _s(5), xr - _s(20) + _s(11), ym + _s(5) + _s(11)],
                        radius=_s(2), fill=BLUE)
    d.text((xr, ym), DOMAIN, font=fd, fill="#b8b8b8")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    im.resize((W, H), Image.LANCZOS).save(out_path, optimize=True)


# -------------------------------------------------- thumbnail front matter
def ensure_thumbnail_line(text, slug):
    """Insert a `thumbnail:` line into the front-matter block if absent.

    Returns (new_text, changed). Idempotent.
    """
    m = re.match(r"^(---\s*\n)(.*?)(\n---\s*\n)", text, re.DOTALL)
    if not m:
        raise ValueError("No front matter")
    head, body, tail = m.groups()
    if re.search(r"^thumbnail:", body, re.MULTILINE):
        return text, False
    line = f"thumbnail: /assets/images/cards/{slug}.png"
    lines = body.split("\n")
    insert_at = None
    for key in ("permalink:", "layout:", "date:"):
        for i, ln in enumerate(lines):
            if ln.startswith(key):
                insert_at = i + 1
                break
        if insert_at is not None:
            break
    if insert_at is None:
        insert_at = len(lines)
    lines.insert(insert_at, line)
    new_block = head + "\n".join(lines) + tail
    return text[:m.start()] + new_block + text[m.end():], True
