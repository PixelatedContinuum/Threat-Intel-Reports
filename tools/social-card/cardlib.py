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
# Brand tokens and static fonts are the shared base (T-0563 w1): docs/brand/.
BRAND = os.path.join(HERE, "..", "..", "docs", "brand")
FONT_DIR = os.path.join(BRAND, "fonts", "ttf")
LOCKUP_PATH = os.path.join(BRAND, "logos", "hl-lockup-transparent.png")
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


def _report_url_for_slug(repo_root, slug):
    """The report's own permalink (the catalog's report_url), not /reports/<slug>/.

    A nested permalink such as /reports/arsenal-237/nethost-dll/ has slug nethost-dll, so
    rebuilding the URL from the slug misses its catalog entry. Falls back to the flat form
    when no report carries the slug.
    """
    try:
        perm = load_front_matter(_report_dir_for_slug(repo_root, slug)).get("permalink", "")
    except FileNotFoundError:
        perm = ""
    return perm.strip() or f"/reports/{slug}/"


def _catalog_entry(repo_root, slug):
    with open(os.path.join(repo_root, "_data/catalog.yml"), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    target = _report_url_for_slug(repo_root, slug)
    for e in data.get("entries", []):
        if e.get("report_url") == target:
            return e
    return None


def _parked_catalog_entry(repo_root, slug):
    """The catalog entry a preview keeps for go-live: a commented-out block in catalog.yml.

    Preview mode parks the entry as a comment block (hunters-ledger-publish,
    references/preview-and-go-live.md, Step 4), so yaml.safe_load sees no entry for the
    slug. Read the comment blocks, drop the banner lines, and parse what is left as
    catalog entries.
    """
    with open(os.path.join(repo_root, "_data/catalog.yml"), encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    blocks, cur = [], []
    for raw in lines:
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            cur.append(stripped[1:])
        elif cur:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    target = _report_url_for_slug(repo_root, slug)
    for block in blocks:
        body = "\n".join(ln for ln in block if not ln.strip().startswith("====="))
        try:
            data = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if isinstance(data, dict):
            if "report_url" in data:          # a single entry parked without its list dash
                data = [data]
            else:
                data = data.get("entries")
        if not isinstance(data, list):
            continue
        for e in data:
            if isinstance(e, dict) and e.get("report_url") == target:
                return e
    return None


def _report_dir_for_slug(repo_root, slug):
    for idx in glob.glob(os.path.join(repo_root, "reports", "*", "index.md")):
        if slug_of(idx) == slug:
            return idx
    raise FileNotFoundError(f"No report with permalink slug '{slug}'")


def _front_matter_severity(repo_root, slug):
    """The severity the report itself declares in its front matter, if any."""
    try:
        idx = _report_dir_for_slug(repo_root, slug)
    except FileNotFoundError:
        return None
    fm = load_front_matter(idx)
    for key in ("severity", "threat_level"):
        if fm.get(key):
            return fm[key]
    return None


def severity_with_source(repo_root, slug):
    """(label, source) for a report's card severity.

    Source is "catalog" (the live entry), "catalog-parked" (the commented block a preview
    keeps for go-live), "front-matter" (the report's own declaration) or "fallback".
    The catalog wins because it is the site's single source of truth for severity; a
    parked entry is the catalog entry the preview gets at go-live.
    """
    entry = _catalog_entry(repo_root, slug)
    if entry and entry.get("severity"):
        return severity_label(entry["severity"]), "catalog"
    parked = _parked_catalog_entry(repo_root, slug)
    if parked and parked.get("severity"):
        return severity_label(parked["severity"]), "catalog-parked"
    declared = _front_matter_severity(repo_root, slug)
    if declared:
        return severity_label(declared), "front-matter"
    return "HIGH", "fallback"  # conservative fallback (warned in generate_card)


def severity_for_slug(repo_root, slug):
    return severity_with_source(repo_root, slug)[0]


def card_fields(repo_root, slug):
    idx = _report_dir_for_slug(repo_root, slug)
    fm = load_front_matter(idx)
    entry = _catalog_entry(repo_root, slug)
    tags = (entry or {}).get("tags", [])
    severity, severity_source = severity_with_source(repo_root, slug)
    return {
        "slug": slug,
        "title": fm["title"],
        "kicker": derive_kicker(fm.get("category"), tags),
        "severity": severity,
        "severity_source": severity_source,
        "date": format_card_date(fm["date"]),
        "subtitle": (fm.get("description") or "").strip(),
    }


# ---------------------------------------------------------------- rendering
W, H, SS = 1200, 630, 2
BW, BH = W * SS, H * SS


def _s(v):
    return int(v * SS)


def _load_tokens():
    import json
    with open(os.path.join(BRAND, "tokens.json"), encoding="utf-8") as fh:
        return json.load(fh)["tokens"]


_T = _load_tokens()
_C = _T["colors"]
BG = _C["ground"]
TXT = _C["ink"]
MUTED = _C["muted"]            # kicker and secondary text on the site
DIV = _C["border_card"]
BLUE = _C["blue"]
STEEL = _C["steel"]           # consulting (the page header, drawer link and hub card)
GOLD = _C["gold_bright"]       # sponsor only (custom.scss): the sponsor hub card
HUE = _T["hues"]["kinds"]      # section hues (r2-base): a kind's colour, from the token file
REPORT_HUE = HUE["reports"]["dark"]   # the kicker of a per-report card names its kind
RADIUS = _T["radius_px"]       # 3 px, every box and pill
# faint site grid: 24 px step, blue at 3% alpha (tokens page.grid_*)
_GRID_PX = _T["page"]["grid_px"]
_GRID_RGBA = tuple(_T["page"]["grid_rgba"])
SEV = {k.upper() if k != "med" else "MEDIUM": (v["bar"], v["label"], p)
       for (k, v), p in zip(_T["severity"].items(),
                            ("#ffffff", "#160a02", "#160f02", "#ffffff"))}

_FACES = {"serif-semibold": "HLSerif-SemiBold.ttf", "serif-bold": "HLSerif-Bold.ttf",
          "sans": "HLSans-Regular.ttf", "sans-semibold": "HLSans-SemiBold.ttf",
          "mono": "HLMono-Regular.ttf", "mono-medium": "HLMono-Medium.ttf"}


def _font(face, size):
    """Static TTF from the shared brand fonts (no variable-font axes)."""
    return ImageFont.truetype(os.path.join(FONT_DIR, _FACES[face]), int(size * SS))


_scratch = ImageDraw.Draw(Image.new("RGB", (4, 4)))


def _tracked(d, pos, text, font, fill, track):  # per-glyph; no kerning, fine for caps labels
    x, y = pos
    for ch in text:
        d.text((x, y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + track


def _background():
    im = Image.new("RGB", (BW, BH), BG).convert("RGBA")
    gl = Image.new("RGBA", (BW, BH), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gl)
    step = _s(_GRID_PX)
    r, g, b, a = _GRID_RGBA
    col = (int(r), int(g), int(b), int(round(a * 255)))
    for x in range(0, BW, step):
        gd.line([(x, 0), (x, BH)], fill=col, width=_s(1))
    for y in range(0, BH, step):
        gd.line([(0, y), (BW, y)], fill=col, width=_s(1))
    return Image.alpha_composite(im, gl).convert("RGB")


def _lockup(im, x, y, height):
    """Paste the live-site lockup (transparent PNG from docs/brand) at a CSS-px height."""
    lk = Image.open(LOCKUP_PATH).convert("RGBA")
    h = _s(height)
    w = int(lk.width * h / lk.height)
    lk = lk.resize((w, h), Image.LANCZOS)
    im.paste(lk, (x, y), lk)
    return w


def _fit_title(title, max_w, max_lines=3, start=62, lo=34):
    size = start
    lines = [title]
    while size >= lo:
        f = _font("serif-semibold", size)
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
    return _font("serif-semibold", lo), lines[:max_lines]


def _ellipsize(text, font, max_w):
    if _scratch.textlength(text, font=font) <= max_w:
        return text
    while text and _scratch.textlength(text + "…", font=font) > max_w:
        text = text[:-1]
    text = text.rstrip()
    if " " in text:                       # back off to the last whole word
        text = text[:text.rfind(" ")].rstrip()
    return text + "…"


def _header(im, d, spine, pill_text, pill_fill, pill_ink):
    """Spine, lockup (top left) and the pill (top right), shared by both card kinds."""
    d.rectangle([0, 0, _s(8), BH], fill=spine)
    ml, mr, top = _s(72), _s(72), _s(52)
    _lockup(im, ml, top, 50)
    fp = _font("sans-semibold", 19)
    tw = _scratch.textlength(pill_text, font=fp)
    pw, ph = tw + _s(34), _s(40)
    px0 = BW - mr - pw
    d.rounded_rectangle([px0, top + _s(2), px0 + pw, top + _s(2) + ph],
                        radius=_s(RADIUS), fill=pill_fill)
    d.text((px0 + _s(17), top + _s(2) + (ph - fp.size) // 2 - _s(1)), pill_text,
           font=fp, fill=pill_ink)


def _footer(d, left_text, mark=BLUE):
    ml, mr = _s(72), _s(72)
    d.line([(ml, _s(H - 96)), (BW - mr, _s(H - 96))], fill=DIV, width=_s(1))
    fm = _font("mono", 19)
    ym = _s(H - 76)
    d.text((ml, ym), left_text, font=fm, fill=MUTED)
    fd = _font("mono-medium", 19)
    twd = _scratch.textlength(DOMAIN, font=fd)
    xr = BW - mr - twd
    d.rectangle([xr - _s(22), ym + _s(6), xr - _s(22) + _s(11), ym + _s(6) + _s(11)],
                fill=mark)                       # section-mark square, radius 0
    d.text((xr, ym), DOMAIN, font=fd, fill=TXT)


def render_card(fields, out_path):
    bd, lt, ptx = SEV.get(fields["severity"], SEV["HIGH"])
    im = _background()
    d = ImageDraw.Draw(im)
    _header(im, d, bd, fields["severity"], bd, ptx)
    ml, mr = _s(72), _s(72)
    _tracked(d, (ml, _s(206)), fields["kicker"], _font("sans-semibold", 19), REPORT_HUE, _s(3))
    f, lines = _fit_title(fields["title"], BW - ml - mr, 3, 62, 34)
    lh = int(f.size * 1.14)
    y = _s(244)
    for ln in lines:
        d.text((ml, y), ln, font=f, fill=TXT)
        y += lh
    if fields.get("subtitle"):
        fs = _font("sans", 21)
        d.text((ml, y + _s(22)),
               _ellipsize(fields["subtitle"], fs, BW - ml - mr),
               font=fs, fill=MUTED)
    _footer(d, fields["date"])
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


# -------------------------------------------------- hub / listing-page cards
HUB_ACCENT = HUE["stix"]["dark"]   # cyan, the STIX section hue (token file)


def _wrap(text, font, max_w, max_lines):
    """Greedy word-wrap to at most max_lines; ellipsize the last if it spills."""
    words, cur, lines = text.split(), "", []
    for w in words:
        cand = w if not cur else cur + " " + w
        if _scratch.textlength(cand, font=font) <= max_w:
            cur = cand
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        keep = lines[:max_lines]
        keep[-1] = _ellipsize(" ".join(lines[max_lines - 1:]), font, max_w)
        lines = keep
    return lines


def render_hub_card(fields, out_path, accent=HUB_ACCENT, kicker_color=None):
    """Render a 1200x630 social card for a listing / hub page (e.g. /stix/).

    Unlike render_card (per-report) there is no severity or date; `accent`
    colors the left spine + the top-right pill, while the grid background,
    lockup, kicker and domain footer match the report cards so hub
    cards sit in the same visual family.

    fields keys: pill, kicker, title, subtitle, footer_left.
    """
    kicker_color = kicker_color or accent      # r2d: the kicker and footer square take the page's hue
    im = _background()
    d = ImageDraw.Draw(im)
    _header(im, d, accent, fields["pill"], accent, BG)     # ground-coloured ink on the hue
    ml, mr = _s(72), _s(72)
    _tracked(d, (ml, _s(206)), fields["kicker"], _font("sans-semibold", 19), kicker_color, _s(3))
    f, lines = _fit_title(fields["title"], BW - ml - mr, 3, 76, 40)
    lh = int(f.size * 1.12)
    y = _s(238)
    for ln in lines:
        d.text((ml, y), ln, font=f, fill=TXT)
        y += lh
    if fields.get("subtitle"):
        fs = _font("sans", 21)
        sy = y + _s(22)
        for ln in _wrap(fields["subtitle"], fs, BW - ml - mr, 2):
            d.text((ml, sy), ln, font=fs, fill=MUTED)
            sy += int(fs.size * 1.18)
    _footer(d, fields.get("footer_left", ""), mark=accent)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    im.resize((W, H), Image.LANCZOS).save(out_path, optimize=True)
