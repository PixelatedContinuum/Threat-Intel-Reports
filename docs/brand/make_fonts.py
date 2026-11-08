#!/usr/bin/env python3
"""Build static TrueType instances of the site's fonts for the PDF (reportlab) path.

T-0563 w1. reportlab cannot read woff2 or variable fonts. The site's own font files
(assets/fonts/*.woff2, SIL OFL 1.1) are turned into static TTFs locally with fontTools' instancer;
nothing is downloaded. Run with the gates interpreter (fontTools + brotli live there):

    .venv-gates/bin/python3 docs/brand/make_fonts.py

Writes docs/brand/fonts/ttf/*.ttf and docs/brand/fonts/MANIFEST.json (source file, axes pinned,
sha256, glyph count per instance) and copies OFL.txt beside them.

Naming (a decision, see the w1 report): the OFL reserves the names "Source" (Source Serif) and
"Plex" (IBM Plex). A static instance is a Modified Version, so the Source and Plex instances are
renamed inside the font (family "HL Serif", "HL Sans", "HL Mono"). Space Grotesk has no reserved
name and keeps it. The HTML/Brave path loads the site's woff2 files unmodified, with their own names.

The woff2 files are Latin subsets (about 230 glyphs); a character outside the subset is missing
from the TTF too. specimen.py prints which punctuation the instances cover.
"""
import hashlib
import json
import os
import shutil
import sys

from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(SITE, "assets", "fonts")
OUT = os.path.join(HERE, "fonts", "ttf")

# (output stem, family shown to reportlab/PDF, style, source woff2, axes to pin, weight class, italic, renamed?)
SPECS = [
    ("HLSerif-Regular",  "HL Serif", "Regular",  "source-serif-4-var.woff2",        {"wght": 400, "opsz": 20}, 400, False, True),
    ("HLSerif-SemiBold", "HL Serif", "SemiBold", "source-serif-4-var.woff2",        {"wght": 600, "opsz": 20}, 600, False, True),
    ("HLSerif-Bold",     "HL Serif", "Bold",     "source-serif-4-var.woff2",        {"wght": 700, "opsz": 20}, 700, False, True),
    ("HLSerif-Italic",   "HL Serif", "Italic",   "source-serif-4-var-italic.woff2", {"wght": 400},             400, True,  True),
    ("HLSans-Regular",   "HL Sans",  "Regular",  "ibm-plex-sans-var.woff2",         {"wght": 400},             400, False, True),
    ("HLSans-SemiBold",  "HL Sans",  "SemiBold", "ibm-plex-sans-var.woff2",         {"wght": 600},             600, False, True),
    ("HLMono-Regular",   "HL Mono",  "Regular",  "ibm-plex-mono-400.woff2",         None,                      400, False, True),
    ("HLMono-Medium",    "HL Mono",  "Medium",   "ibm-plex-mono-500.woff2",         None,                      500, False, True),
    ("SpaceGrotesk-Medium", "Space Grotesk", "Medium", "space-grotesk.woff2",       {"wght": 500},             500, False, False),
    ("SpaceGrotesk-Bold",   "Space Grotesk", "Bold",   "space-grotesk.woff2",       {"wght": 700},             700, False, False),
]


def set_names(font, family, style, ps_name, weight, italic, rename):
    name = font["name"]
    ribbi = style in ("Regular", "Bold", "Italic", "Bold Italic")
    full = family if style == "Regular" else f"{family} {style}"
    nid1 = family if ribbi else f"{family} {style}"
    nid2 = style if ribbi else "Regular"
    # drop every existing name record we replace (and the variable-font PS prefix, id 25)
    for nid in (1, 2, 3, 4, 6, 16, 17, 21, 22, 25):
        name.removeNames(nameID=nid)
    for plat, enc, lang in ((3, 1, 0x409), (1, 0, 0)):
        for nid, val in ((1, nid1), (2, nid2), (3, f"{ps_name};T-0563-w1-static-instance"), (4, full), (6, ps_name)):
            name.setName(val, nid, plat, enc, lang)
        if not ribbi or nid1 != family:
            name.setName(family, 16, plat, enc, lang)
            name.setName(style, 17, plat, enc, lang)
    os2 = font["OS/2"]
    os2.usWeightClass = weight
    sel = os2.fsSelection & ~(0b1100001)            # clear ITALIC(0), BOLD(5), REGULAR(6)
    if italic:
        sel |= 1
    if style == "Bold":
        sel |= 1 << 5
    if style in ("Regular", "SemiBold", "Medium") and not italic:
        sel |= 1 << 6
    os2.fsSelection = sel
    head = font["head"]
    head.macStyle = (1 if style == "Bold" else 0) | (2 if italic else 0)
    if os2.fsType != 0:
        raise SystemExit(f"{ps_name}: fsType {os2.fsType} restricts embedding")


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = []
    for stem, family, style, src, axes, weight, italic, rename in SPECS:
        path = os.path.join(SRC, src)
        font = TTFont(path)
        font.flavor = None
        if axes:
            if "fvar" not in font:
                raise SystemExit(f"{src}: expected a variable font")
            font = instancer.instantiateVariableFont(font, axes, inplace=False)
        elif "fvar" in font:
            raise SystemExit(f"{src}: is variable but no axes given")
        set_names(font, family, style, stem, weight, italic, rename)
        for tag in ("STAT", "avar", "fvar", "gvar", "HVAR", "MVAR"):
            if tag in font:
                del font[tag]
        dest = os.path.join(OUT, stem + ".ttf")
        font.save(dest)
        chk = TTFont(dest)
        manifest.append({
            "file": f"ttf/{stem}.ttf", "reportlab_name": stem, "family": family, "style": style,
            "source": f"assets/fonts/{src}", "axes_pinned": axes, "glyphs": len(chk.getGlyphOrder()),
            "cmap_codepoints": len(chk.getBestCmap()), "static": "fvar" not in chk,
            "sha256": hashlib.sha256(open(dest, "rb").read()).hexdigest(),
            "bytes": os.path.getsize(dest),
        })
        print(f"{stem:22s} {axes!s:32s} glyphs={manifest[-1]['glyphs']:4d} bytes={manifest[-1]['bytes']}")
    shutil.copyfile(os.path.join(SRC, "OFL.txt"), os.path.join(HERE, "fonts", "OFL.txt"))
    with open(os.path.join(HERE, "fonts", "MANIFEST.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"_generated_by": "docs/brand/make_fonts.py", "instances": manifest}, fh, indent=2)
        fh.write("\n")
    print(f"{len(manifest)} instances of {len(SPECS)} listed")
    return 0 if len(manifest) == len(SPECS) else 1


if __name__ == "__main__":
    sys.exit(main())
