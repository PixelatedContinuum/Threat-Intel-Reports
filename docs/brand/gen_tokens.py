#!/usr/bin/env python3
"""Derive the document brand tokens from the site stylesheet, and check they have not drifted.

T-0563 w1. The Hunter's Ledger site (concept 3, T-0556) is defined by
`assets/css/custom.scss`. Every outbound document (PDF, email, image) must look like it.
This script reads that stylesheet (and the masthead markup in `_includes/default/navbar.liquid`)
and writes two files beside it, which every document generator then reads instead of keeping
its own hex literals:

    tokens.json   machine-readable: colours, font stacks and font files, type scale, radius,
                  the logo-lockup geometry, the section-head geometry, code-block colours
    tokens.css    the same values as CSS custom properties (:root), for the HTML/Brave path

Usage (run from anywhere; stdlib only, so /usr/bin/python3 works):

    python3 gen_tokens.py            # (re)write tokens.json and tokens.css
    python3 gen_tokens.py --check    # exit 1 if either file no longer matches the stylesheet
    python3 gen_tokens.py --check --scss PATH   # check against another copy of the stylesheet
    python3 gen_tokens.py --print    # print the derived tokens to stdout, write nothing

How it fails safe
-----------------
Every value is looked up by selector or custom-property name. A lookup that finds nothing
raises, so a restyle of the site that renames a rule stops this script instead of silently
yielding a stale token. The denominator is printed: the number of declarations found in the
stylesheet's first `:root` block by the parser, against an independent line-regex count of the
same block. They must agree. `provenance` (file and line locators) is informational and is not
compared by --check, so an unrelated edit higher in the stylesheet does not fail the check.

What it cannot see: a site change that keeps a selector and its names but moves where a
document should use them (for example a new accent for a new section), and anything the
stylesheet does with JavaScript or per-page inline styles. Section colours are therefore read
from the navbar markup (`--sc:` on each section link), which is where the site sets them.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.dirname(os.path.dirname(HERE))          # repos/Threat-Intel-Reports
DEFAULT_SCSS = os.path.join(SITE, "assets", "css", "custom.scss")
NAVBAR = os.path.join(SITE, "_includes", "default", "navbar.liquid")
TOKENS_JSON = os.path.join(HERE, "tokens.json")
TOKENS_CSS = os.path.join(HERE, "tokens.css")


# ------------------------------------------------------------------ stylesheet parsing

def _clean(text):
    """Drop Jekyll front matter, the Liquid comment block, and CSS comments."""
    text = re.sub(r"\{%-?\s*comment\s*-?%\}.*?\{%-?\s*endcomment\s*-?%\}", "", text, flags=re.S)
    text = re.sub(r"(?m)^---\s*$", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _split_top(s, sep):
    """Split on `sep` outside parentheses and quotes."""
    out, buf, depth, quote = [], [], 0, None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def parse_rules(text, media=None):
    """Return [(selector, body, media)] for every rule, descending into @media."""
    rules, i, n = [], 0, len(text)
    while i < n:
        j = text.find("{", i)
        if j < 0:
            break
        prelude = text[i:j].strip()
        depth, k, quote = 1, j + 1, None
        while k < n and depth:
            ch = text[k]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            k += 1
        body = text[j + 1:k - 1]
        if prelude.startswith("@") and not prelude.startswith("@font-face"):
            rules.extend(parse_rules(body, media=re.sub(r"\s+", " ", prelude)))
        else:
            rules.append((re.sub(r"\s+", " ", prelude), body, media))
        i = k
    return rules


def parse_decls(body):
    d = {}
    for part in _split_top(body, ";"):
        if ":" not in part:
            continue
        prop, val = part.split(":", 1)
        prop = prop.strip()
        if prop:
            d[prop] = re.sub(r"\s+", " ", val.strip().replace("!important", "")).strip()
    return d


class Sheet:
    def __init__(self, raw):
        self.raw = raw
        self.text = _clean(raw)
        self.rules = parse_rules(self.text)
        roots = [(s, b, m) for s, b, m in self.rules if s == ":root" and m is None]
        if not roots:
            raise SystemExit("no top-level :root block found in the stylesheet")
        self.root_body = roots[0][1]
        self.root = parse_decls(self.root_body)
        self.root_independent = len(re.findall(r"(?m)^\s*(--[\w-]+)\s*:", self.root_body))

    def decls(self, selector, media=None):
        """Merged declarations (later rules win) of every rule whose selector list holds `selector`."""
        want = re.sub(r"\s+", " ", selector.strip())
        merged, hit = {}, 0
        for sel, body, m in self.rules:
            if m != media:
                continue
            if want in [re.sub(r"\s+", " ", s.strip()) for s in _split_top(sel, ",")]:
                merged.update(parse_decls(body))
                hit += 1
        if not hit:
            raise SystemExit(f"selector not found in the stylesheet: {selector!r} (media={media!r})")
        return merged

    def media_root(self, media_contains):
        out = {}
        for sel, body, m in self.rules:
            if sel == ":root" and m and media_contains in m:
                out.update(parse_decls(body))
        if not out:
            raise SystemExit(f"no :root inside a media rule containing {media_contains!r}")
        return out

    def font_faces(self):
        faces = []
        for sel, body, m in self.rules:
            if sel == "@font-face":
                d = parse_decls(body)
                url = re.search(r"url\(['\"]?([^'\")]+)", d["src"]).group(1)
                faces.append({
                    "family": d["font-family"].strip("'\""),
                    "style": d.get("font-style", "normal"),
                    "weight": d["font-weight"],
                    "file": os.path.basename(url),
                })
        if not faces:
            raise SystemExit("no @font-face rules found")
        return faces

    def lineno(self, needle, nth=1):
        """1-based line of the nth raw occurrence of `needle` (informational locator)."""
        pos = -1
        for _ in range(nth):
            pos = self.raw.find(needle, pos + 1)
            if pos < 0:
                return None
        return self.raw.count("\n", 0, pos) + 1


def resolve(value, root, depth=0):
    """Replace var(--x) with its :root value, recursively."""
    if depth > 8:
        raise SystemExit(f"var() chain too deep: {value}")
    def sub(m):
        name = m.group(1)
        if name not in root:
            raise SystemExit(f"var({name}) is not defined in :root")
        return resolve(root[name], root, depth + 1)
    return re.sub(r"var\((--[\w-]+)\)", sub, value)


def px(value):
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)px", value.strip())
    if not m:
        raise SystemExit(f"expected a px value, got {value!r}")
    f = float(m.group(1))
    return int(f) if f == int(f) else f


def hexv(value):
    v = value.strip().lower()
    if not re.fullmatch(r"#[0-9a-f]{6}", v):
        raise SystemExit(f"expected a 6-digit hex colour, got {value!r}")
    return v


# ------------------------------------------------------------------ token derivation

def derive(scss_path=DEFAULT_SCSS, navbar_path=NAVBAR):
    raw = open(scss_path, encoding="utf-8").read()
    sh = Sheet(raw)
    R = sh.root

    def rv(name):
        if name not in R:
            raise SystemExit(f"custom property {name} missing from :root")
        return resolve(R[name], R)

    colors = {
        "ground": hexv(rv("--hl-bg-page")),
        "card": hexv(rv("--hl-bg-card")),
        "row": hexv(rv("--hl-bg-row")),
        "border_card": hexv(rv("--hl-border-card")),
        "border_row": hexv(rv("--hl-border-row")),
        "ink": hexv(rv("--hl-text-primary")),
        "ink_secondary": hexv(rv("--hl-text-secondary")),
        "muted": hexv(rv("--hl-text-muted")),
        "muted_d": hexv(rv("--hl-muted-d")),
        "blue": hexv(rv("--hl-accent-blue")),
        "purple": hexv(rv("--hl-accent-purple")),
        "teal": hexv(rv("--hl-accent-teal")),
        "green": hexv(rv("--hl-accent-green")),
        "red": hexv(rv("--hl-accent-red")),
        "gold": hexv(rv("--hl-accent-gold")),
        "gold_light": hexv(rv("--hl-accent-gold-light")),
        "gold_bright": hexv(rv("--hl-gold-bright")),
        "steel": hexv(rv("--hl-accent-steel")),
        "field": hexv(rv("--hl-field")),
        "field_line": hexv(rv("--hl-field-line")),
    }
    severity = {}
    for key, tok in (("critical", "critical"), ("high", "high"), ("med", "med"), ("low", "low")):
        severity[key] = {"bar": hexv(rv(f"--hl-sev-{tok}")), "label": hexv(rv(f"--hl-sev-{tok}-lbl"))}

    # Nav hairlines: the 1px rules above and below the bar (.hl-nav::before / ::after).
    nav = sh.decls(".hl-nav::before, .hl-nav::after".split(",")[0])
    colors["hairline"] = hexv(nav["background"])
    mast_top = sh.decls(".hl-mast__top")
    m = re.fullmatch(r"(\d+)px solid (.+)", resolve(mast_top["border-bottom"], R))
    masthead_rule = {"weight": int(m.group(1)), "color": hexv(m.group(2))}

    # Code (report body): inline and block.
    code_i = sh.decls(".hl-post-content code")
    code_b = sh.decls(".hl-post-content pre")
    bl = re.fullmatch(r"(\d+)px solid (#[0-9a-fA-F]{6})", code_b["border-left"])
    code = {
        "text": hexv(code_i["color"]),
        "inline_bg": hexv(code_i["background"]),
        "block_bg": hexv(code_b["background"]),
        "block_border": hexv(re.fullmatch(r"\d+px solid (#[0-9a-fA-F]{6})", code_b["border"]).group(1)),
        "block_left_weight": int(bl.group(1)),
        "block_left_color": hexv(bl.group(2)),
    }

    # Fonts.
    fonts = {
        "serif": resolve(R["--hl-font-serif"], R),
        "sans": resolve(R["--hl-font-sans"], R),
        "mono": resolve(R["--hl-font-mono"], R),
    }
    top = sh.decls(".hl-brand__top")
    main = sh.decls(".hl-brand__main")
    fonts["wordmark"] = top["font-family"]
    if top["font-family"] != main["font-family"]:
        raise SystemExit("wordmark stacks differ between .hl-brand__top and .hl-brand__main")
    faces = sh.font_faces()

    # Type scale and radius.
    scale = {k[len("--hl-fs-"):]: px(R[k]) for k in R if k.startswith("--hl-fs-")}
    scale_phone = {k[len("--hl-fs-"):]: px(v) for k, v in sh.media_root("max-width: 699px").items() if k.startswith("--hl-fs-")}
    radius = px(R["--hl-radius"])

    # Logo lockup: base (bar) geometry and the masthead multiple used on the page.
    rule = sh.decls(".hl-brand__rule")
    dot = sh.decls(".hl-brand__dot")
    stack = sh.decls(".hl-brand__stack")
    mrule = sh.decls(".hl-mast__brand .hl-brand__rule")
    mdot = sh.decls(".hl-mast__brand .hl-brand__dot")
    micon = sh.decls(".hl-mast__brand .hl-brand__icon")
    mtop = sh.decls(".hl-mast__brand .hl-brand__top")
    mmain = sh.decls(".hl-mast__brand .hl-brand__main")
    mstack = sh.decls(".hl-mast__brand .hl-brand__stack")
    mbrand = sh.decls(".hl-mast__brand, .hl-mast__brand:visited".split(",")[0])
    icon_bar = sh.decls(".hl-brand__icon")

    def lockup(icon, rl, stk_gap, top_size, main_size, dot_size, dot_margin, brand_gap, r_w, r_h, r_rad, d_rad):
        return {
            "icon": icon, "rule_w": r_w, "rule_h": r_h, "rule_radius": r_rad,
            "stack_gap": stk_gap, "top_size": top_size, "main_size": main_size,
            "dot": dot_size, "dot_radius": d_rad, "dot_margin_left": dot_margin, "gap": brand_gap,
        }

    bar = lockup(px(icon_bar["width"]), None, px(stack["gap"]), px(top["font-size"]), px(main["font-size"]),
                 px(dot["width"]), px(dot["margin-left"]), 10,
                 px(rule["width"]), px(rule["height"]), px(rule["border-radius"]), px(dot["border-radius"]))
    nav_brand = sh.decls(".hl-nav__brand")
    bar["gap"] = px(nav_brand["gap"]) if "gap" in nav_brand else bar["gap"]
    mast = lockup(px(micon["width"]), None, px(mstack["gap"]), px(mtop["font-size"]), px(mmain["font-size"]),
                  px(mdot["width"]), px(mdot["margin-left"]), px(mbrand["gap"]),
                  px(mrule["width"]), px(mrule["height"]), px(mrule["border-radius"]), px(mdot["border-radius"]))
    brand = {
        "rule_color": hexv(resolve(rule["background"], R)),
        "dot_color": hexv(resolve(dot["background"], R)),
        "top": {"weight": int(top["font-weight"]), "tracking_em": float(top["letter-spacing"].rstrip("em")),
                "color": hexv(top["color"]), "text": "THE HUNTER’S"},
        "main": {"weight": int(main["font-weight"]), "tracking_em": float(main["letter-spacing"].rstrip("em")),
                 "color": hexv(main["color"]), "text": "LEDGER"},
        "bar": bar,
        "masthead": mast,
    }
    # Markup facts: the icon SVG and the tagline, and the section hues.
    nav_html = open(navbar_path, encoding="utf-8").read()
    svg = re.search(r'<svg class="hl-brand__icon"[^>]*>.*?</svg>', nav_html, flags=re.S)
    tag = re.search(r'<p class="hl-mast__tag">(.*?)</p>', nav_html, flags=re.S)
    if not svg or not tag:
        raise SystemExit("navbar.liquid: lockup SVG or tagline not found")
    brand["icon_svg"] = svg.group(0)
    brand["tagline"] = re.sub(r"\s+", " ", tag.group(1)).strip()
    hues = re.findall(r'<a href="[^"]*"\s+style="--sc:(#[0-9a-fA-F]{6})"[^>]*>([^<]+)</a>', nav_html)
    if not hues:
        raise SystemExit("navbar.liquid: no section hues (--sc) found")
    section_hues = {name.strip(): hexv(h) for h, name in hues}

    # Section head (concept 3, "w5c"): square before a serif title, 2px rule under the head.
    h2 = sh.decls(".c3-sec h2")
    before = sh.decls(".c3-sec h2::before, .c3-cols h3::before, .c3-about h2::before".split(",")[0])
    before_sub = sh.decls(".c3-cols h3::before")
    sec_rule = sh.decls(".c3-sec")
    sec_sub_rule = sh.decls(".c3-cols h3")
    about = sh.decls(".c3-about")
    base = sh.decls(".c3-sec, .c3-cols > div, .c3-about".split(",")[0])
    fm = re.fullmatch(r"(\d+) (var\(--hl-fs-section\))/([\d.]+) (var\(--hl-font-serif\))", h2["font"])
    if not fm:
        raise SystemExit(f"unexpected .c3-sec h2 font shorthand: {h2['font']!r}")
    rule_decl = lambda d, k: re.fullmatch(r"(\d+)px solid var\(--sec\)", d[k]).group(1)
    section_head = {
        "square": px(before["width"]), "square_margin_right": px(before["margin-right"]),
        "sub_square": px(before_sub["width"]), "sub_square_margin_right": px(before_sub["margin-right"]),
        "rule": int(rule_decl(sec_rule, "border-bottom")),
        "sub_rule": int(rule_decl(sec_sub_rule, "border-bottom")),
        "about_top_rule": int(rule_decl(about, "border-top")),
        "title_weight": int(fm.group(1)), "title_size": scale["section"], "title_size_phone": scale_phone["section"],
        "title_line_height": float(fm.group(3)), "title_color": colors["ink"],
        "default_color": hexv(resolve(base["--sec"], R)),
        "square_radius": 0,
    }
    if "radius" in before or "border-radius" in before:
        raise SystemExit("section square now has a radius: update section_head.square_radius")
    kick = sh.decls(".c3-kick")
    km = re.fullmatch(r"(\d+) var\(--hl-fs-meta\)/([\d.]+) var\(--hl-font-mono\)", kick["font"])
    kicker = {"weight": int(km.group(1)), "size": scale["meta"], "tracking_em": float(kick["letter-spacing"].rstrip("em")),
              "color": colors["muted_d"]}

    page_grid = sh.decls("body")
    gm = re.findall(r"rgba\((\d+),(\d+),(\d+),([\d.]+)\)", page_grid["background-image"])
    page = {"grid_px": px(page_grid["background-size"].split()[0]),
            "grid_rgba": [int(gm[0][0]), int(gm[0][1]), int(gm[0][2]), float(gm[0][3])]}

    tokens = {
        "colors": colors,
        "severity": severity,
        "code": code,
        "fonts": fonts,
        "font_faces": faces,
        "type_scale_px": scale,
        "type_scale_phone_px": scale_phone,
        "radius_px": radius,
        "masthead_rule": masthead_rule,
        "page": page,
        "brand": brand,
        "section_head": section_head,
        "kicker": kicker,
        "section_hues": section_hues,
        "css_root": {k: R[k] for k in R},
    }
    provenance = {
        "source": "assets/css/custom.scss",
        "root_declarations_parsed": len(R),
        "root_declarations_independent_count": sh.root_independent,
        "root_first_line": sh.lineno(":root {"),
        "locators_informational": {
            "tokens": sh.lineno("--hl-bg-page:"),
            "font_faces": sh.lineno("@font-face"),
            "brand_lockup": sh.lineno(".hl-brand__rule {"),
            "section_head_w5c": sh.lineno("T-0556 w5c"),
            "masthead_w2": sh.lineno("T-0556 w2: masthead"),
        },
    }
    if len(R) != sh.root_independent:
        raise SystemExit(f"DENOMINATOR MISMATCH: parser found {len(R)} root declarations, line regex found {sh.root_independent}")
    return tokens, provenance


# Known values, verified by reading custom.scss by hand (T-0563 lead, 2026-11-08). If the generator
# reads something else the generator is suspect; if the site was changed on purpose, edit this table.
CONTROL = {"ground": "#111111", "ink": "#eeeeee", "blue": "#58a6ff", "gold_bright": "#d4a73a"}


def control_problems(tokens):
    return [f"CONTROL {k}: derived {tokens['colors'][k]}, known {v}" for k, v in CONTROL.items() if tokens["colors"][k] != v]


def render_css(tokens):
    """tokens.css: the :root custom properties for documents, from tokens.json values only."""
    c, f, b, s = tokens["colors"], tokens["fonts"], tokens["brand"], tokens["section_head"]
    lines = ["/* GENERATED by gen_tokens.py from assets/css/custom.scss (T-0563 w1). Do not edit; run gen_tokens.py. */", ":root {"]
    for k, v in tokens["css_root"].items():
        if k.startswith("--hl-fs-") or k.startswith(("--hl-nav", "--hl-col", "--hl-rail", "--hl-card-", "--hl-gold-glow")):
            continue                                   # page-layout tokens a document does not use
        lines.append(f"  {k}: {v};")
    for k, v in tokens["type_scale_px"].items():
        lines.append(f"  --hl-fs-{k}: {v}px;")
    lines += [
        f"  --hl-font-wordmark: {f['wordmark']};",
        f"  --hl-hairline: {c['hairline']};",
        f"  --hl-code-text: {tokens['code']['text']};",
        f"  --hl-code-inline-bg: {tokens['code']['inline_bg']};",
        f"  --hl-code-block-bg: {tokens['code']['block_bg']};",
        f"  --hl-code-block-border: {tokens['code']['block_border']};",
        f"  --hl-grid-size: {tokens['page']['grid_px']}px;",
        f"  --hl-grid-line: rgba({tokens['page']['grid_rgba'][0]},{tokens['page']['grid_rgba'][1]},{tokens['page']['grid_rgba'][2]},{tokens['page']['grid_rgba'][3]});",
        f"  --hl-sec: {s['default_color']};",
        f"  --hl-sec-square: {s['square']}px;",
        f"  --hl-sec-sub-square: {s['sub_square']}px;",
        f"  --hl-sec-rule: {s['rule']}px;",
        f"  --hl-sec-title-weight: {s['title_weight']};",
        f"  --hl-sec-title-lh: {s['title_line_height']};",
    ]
    for k, v in tokens["severity"].items():
        lines.append(f"  --hl-sev-{k}-bar: {v['bar']};")
    for name, hexv_ in tokens["section_hues"].items():
        lines.append(f"  --hl-hue-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}: {hexv_};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_json(tokens, provenance):
    doc = {"_generated_by": "docs/brand/gen_tokens.py", "_do_not_edit": True, "tokens": tokens, "provenance": provenance}
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def check(scss_path, tokens_json=TOKENS_JSON, tokens_css=TOKENS_CSS):
    tokens, prov = derive(scss_path)
    problems = []
    try:
        on_disk = json.load(open(tokens_json, encoding="utf-8"))
    except FileNotFoundError:
        problems.append(f"{tokens_json} is missing")
        on_disk = None
    if on_disk is not None:
        disk_tokens, disk_prov = on_disk["tokens"], on_disk["provenance"]
        if disk_tokens != tokens:
            for k in tokens:
                if disk_tokens.get(k) != tokens[k]:
                    a, b = disk_tokens.get(k), tokens[k]
                    if isinstance(a, dict) and isinstance(b, dict):
                        for kk in sorted(set(a) | set(b)):
                            if a.get(kk) != b.get(kk):
                                problems.append(f"tokens.json {k}.{kk}: file has {a.get(kk)!r}, stylesheet gives {b.get(kk)!r}")
                    else:
                        problems.append(f"tokens.json {k} differs")
        for key in ("source", "root_declarations_parsed", "root_declarations_independent_count"):
            if disk_prov.get(key) != prov.get(key):
                problems.append(f"provenance.{key}: file has {disk_prov.get(key)!r}, stylesheet gives {prov.get(key)!r}")
    try:
        if open(tokens_css, encoding="utf-8").read() != render_css(tokens):
            problems.append("tokens.css differs from what the stylesheet generates")
    except FileNotFoundError:
        problems.append(f"{tokens_css} is missing")
    problems += control_problems(tokens)
    return tokens, prov, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--print", action="store_true")
    ap.add_argument("--scss", default=DEFAULT_SCSS)
    a = ap.parse_args()
    if a.check:
        tokens, prov, problems = check(a.scss)
        print(f"checked against {a.scss}")
        print(f"denominator: {prov['root_declarations_parsed']} root declarations parsed, "
              f"{prov['root_declarations_independent_count']} by independent line count; "
              f"{len(tokens['colors'])} colours, {len(tokens['font_faces'])} font faces, {len(tokens['section_hues'])} section hues")
        if problems:
            print("FAIL: token files no longer match the stylesheet:")
            for p in problems:
                print("  -", p)
            print("Run: python3 docs/brand/gen_tokens.py")
            return 1
        print(f"PASS: tokens.json and tokens.css match the stylesheet (ground {tokens['colors']['ground']}, ink {tokens['colors']['ink']}, "
              f"blue {tokens['colors']['blue']}, gold_bright {tokens['colors']['gold_bright']})")
        return 0
    tokens, prov = derive(a.scss)
    ctl = control_problems(tokens)
    if ctl:
        print("refusing to write: the derived tokens fail the control:", *ctl, sep="\n  ")
        return 2
    if a.print:
        print(render_json(tokens, prov))
        return 0
    open(TOKENS_JSON, "w", encoding="utf-8", newline="\n").write(render_json(tokens, prov))
    open(TOKENS_CSS, "w", encoding="utf-8", newline="\n").write(render_css(tokens))
    print(f"wrote {TOKENS_JSON} and {TOKENS_CSS}")
    print(f"denominator: {prov['root_declarations_parsed']} root declarations parsed = "
          f"{prov['root_declarations_independent_count']} independent count; {len(tokens['colors'])} colours, "
          f"{len(tokens['font_faces'])} font faces, {len(tokens['section_hues'])} section hues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
