"""Build the shared <head>, masthead and section markup for Hunter's Ledger HTML documents (Brave to PDF).

T-0563 w1. Reads tokens.json / tokens.css / hl-doc-base.css and the site's own woff2 fonts; writes
nothing. The fonts load locally, never from Google Fonts: by default inlined as base64 from
repos/Threat-Intel-Reports/assets/fonts, so the HTML is one self-contained file (`fonts="base64"`, about
0.3 MB). `fonts="file"` writes file:// URLs instead; on this machine headless Brave did NOT load
those (tested 2026-11-08, with and without --allow-file-access-from-files: it fell back to Liberation
and JetBrains Mono), so do not use it for a PDF without checking `pdffonts`.

    import sys; sys.path.insert(0, "<TIR>/docs/brand")
    import hl_doc_html as hd
    html = hd.page(title="...", body=hd.masthead(kicker="Feedback", right="2026-11-08")
                                    + hd.section("What worked", hue="Detections") + "<p>...</p>")
    # render: brave --headless --disable-gpu --no-sandbox --hide-scrollbars --virtual-time-budget=20000 \\
    #   --run-all-compositor-stages-before-draw --no-pdf-header-footer --print-to-pdf=/tmp/x.pdf file:///...html
    # (Brave cannot write into the repo: render to /tmp or the scratchpad and copy.)

Stdlib only.
"""
import base64
import html as _html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.dirname(os.path.dirname(HERE))
FONT_DIR = os.path.join(SITE, "assets", "fonts")
TOKENS = json.load(open(os.path.join(HERE, "tokens.json"), encoding="utf-8"))["tokens"]


def _read(name):
    return open(os.path.join(HERE, name), encoding="utf-8").read()


def font_face_css(mode="file"):
    """@font-face rules for the six faces the stylesheet declares (tokens.json font_faces)."""
    if mode not in ("file", "base64"):
        raise ValueError("mode must be 'file' or 'base64'")
    out = []
    for f in TOKENS["font_faces"]:
        path = os.path.join(FONT_DIR, f["file"])
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        if mode == "file":
            src = "file://" + path.replace(" ", "%20")
        else:
            src = "data:font/woff2;base64," + base64.b64encode(open(path, "rb").read()).decode("ascii")
        # display=block so a print never captures the fallback face
        out.append(f"@font-face{{font-family:'{f['family']}';font-style:{f['style']};font-weight:{f['weight']};"
                   f"font-display:block;src:url('{src}') format('woff2');}}")
    return "\n".join(out)


def head(title, fonts="base64", extra_css=""):
    """Return the <head> element: charset, title, tokens.css, local @font-face, hl-doc-base.css, then extra_css."""
    return ("<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{_html.escape(title)}</title>\n<style>\n{_read('tokens.css')}\n{font_face_css(fonts)}\n{_read('hl-doc-base.css')}\n{extra_css}\n</style>\n</head>")


def lockup_html(scale=None):
    """The site lockup as markup (icon SVG from the navbar, rule, two-line wordmark, square dot). `scale` sets --lk."""
    B = TOKENS["brand"]
    svg = B["icon_svg"].replace(' aria-hidden="true" focusable="false"', ' aria-hidden="true" focusable="false"')
    style = f' style="--lk:{scale}"' if scale else ""
    return (f'<div class="hl-brand"{style} role="img" aria-label="The Hunter’s Ledger">{svg}'
            f'<span class="hl-brand__rule"></span><span class="hl-brand__stack"><span class="hl-brand__top">{_html.escape(B["top"]["text"])}</span>'
            f'<span class="hl-brand__main">{B["main"]["text"]}<span class="hl-brand__dot"></span></span></span></div>')


def masthead(kicker="", right="", tagline=True, scale=None):
    """The concept 3 masthead: a mono top row (left text, right text) over a hairline, then lockup and tagline."""
    tag = f'<p class="hl-mast__tag">{_html.escape(TOKENS["brand"]["tagline"])}</p>' if tagline else ""
    return (f'<div class="hl-mast"><div class="hl-mast__top"><span>{_html.escape(kicker)}</span><span>{_html.escape(right)}</span></div>'
            f'<div class="hl-mast__main">{lockup_html(scale)}{tag}</div></div>')


def section(title, hue=None, sub=False, level=2):
    """A section head. `hue` is a section name from tokens.json section_hues (Reports, Detections, ...) or a hex; default blue."""
    colour = TOKENS["section_hues"].get(hue, hue) if hue else TOKENS["section_head"]["default_color"]
    cls = "hl-sec hl-sec--sub" if sub else "hl-sec"
    return f'<div class="{cls}" style="--sec:{colour}"><h{level}>{_html.escape(title)}</h{level}></div>'


def page(title, body, fonts="base64", extra_css="", body_class=""):
    """A complete document: head + <body><div class="hl-doc">body</div></body>."""
    cls = f' class="{body_class}"' if body_class else ""
    return f"<!doctype html>\n<html lang=\"en\">\n{head(title, fonts, extra_css)}\n<body{cls}><div class=\"hl-doc\">\n{body}\n</div></body>\n</html>\n"
