#!/usr/bin/env python3
"""Render the site's live logo lockup to PNG for documents that need a raster logo on the #111111 ground.

T-0563 w1. The existing brand-kit lockup (assets/brand/logo-lockup/logo-horizontal-on-dark-bg.png) is opaque
on #0d1117, which shows as a visible box on the site ground #111111. These files are drawn by Brave from
the same markup and CSS the site uses (the navbar's icon SVG, the .hl-brand__* rules, Space Grotesk), then
cropped. Nothing under assets/brand/ is touched; the outputs go to docs/brand/logos/ (docs/ is excluded from
the site build, so these are not published).

    .venv-gates/bin/python3 docs/brand/make_logos.py

Outputs (4x pixel density, masthead size = icon 78 css px, so 312 px tall icon):
    logos/hl-lockup-transparent.png   transparent background (use on a gridded ground or any dark surface)
    logos/hl-lockup-on-111111.png     the same pixels composited on #111111 (the document ground)
Needs: brave on PATH, Pillow. Brave cannot write into the repo, so it writes to a temp dir first.
"""
import os
import subprocess
import sys
import tempfile

from PIL import Image

import hl_doc_html as hd

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "logos")
DSF = 4
PAD_CSS = 10            # css px of breathing room kept around the lockup


def render(html_path, png_path, w, h):
    subprocess.run(["brave", "--headless", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
                    f"--force-device-scale-factor={DSF}", f"--window-size={w},{h}", "--default-background-color=00000000",
                    "--virtual-time-budget=10000", f"--screenshot={png_path}", "file://" + html_path],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    os.makedirs(OUT, exist_ok=True)
    ground = tuple(int(hd.TOKENS["colors"]["ground"][i:i + 2], 16) for i in (1, 3, 5))
    body = '<div style="padding:40px">' + hd.lockup_html(scale=1) + "</div>"
    page = hd.page("lockup", body, extra_css="html,body{background:transparent !important}.hl-doc{margin:0;max-width:none}")
    tmp = tempfile.mkdtemp(prefix="hl-logo-")
    html_path = os.path.join(tmp, "lockup.html")
    open(html_path, "w", encoding="utf-8").write(page)
    raw = os.path.join(tmp, "raw.png")
    render(html_path, raw, 800, 200)
    im = Image.open(raw).convert("RGBA")
    bbox = im.getchannel("A").getbbox()
    if not bbox:
        raise SystemExit("render came back fully transparent (no lockup drawn)")
    pad = PAD_CSS * DSF
    box = (max(bbox[0] - pad, 0), max(bbox[1] - pad, 0), min(bbox[2] + pad, im.width), min(bbox[3] + pad, im.height))
    if bbox[2] >= im.width - 2 or bbox[3] >= im.height - 2:
        raise SystemExit("lockup touches the screenshot edge: the window is too small")
    crop = im.crop(box)
    crop.save(os.path.join(OUT, "hl-lockup-transparent.png"), optimize=True)
    flat = Image.new("RGBA", crop.size, ground + (255,))
    flat.alpha_composite(crop)
    flat.convert("RGB").save(os.path.join(OUT, "hl-lockup-on-111111.png"), optimize=True)
    print(f"transparent {crop.size}, on-ground {crop.size}, ground {ground}; bbox of drawn pixels {bbox}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
