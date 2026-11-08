#!/usr/bin/env python3
"""One-page specimen of the colour-rule hues (T-0563 round 2): the seven hues on the dark grounds and
their light-ground variants on #ffffff and #f6f8fa, each with its measured contrast ratio.

    .venv-gates/bin/python3 docs/brand/hue_specimen.py OUT.pdf

Every number printed on the page is read from tokens.json ("hues"), which gen_tokens.py computes.
"""
import sys

from reportlab.lib import colors
from reportlab.pdfgen import canvas

import hl_brand as hl

HC = colors.HexColor


def main(out):
    hl.register_fonts()
    w, h = hl.PAGE
    m = hl.MARGIN
    H = hl.TOKENS["hues"]
    c = canvas.Canvas(out, pagesize=hl.PAGE)
    c.setTitle("Hunters Ledger hue specimen (T-0563 round 2)")
    hl.draw_ground(c, w, h)
    y = h - m
    c.setFillColor(hl.INK); c.setFont(hl.FONT["serif_semibold"], 20)
    c.drawString(m, y - 16, "Colour rule hues: dark and light grounds")
    c.setFillColor(hl.MUTED); c.setFont(hl.FONT["mono"], 8)
    c.drawString(m, y - 32, "rotation order = hue(1..7); kind map = hue_for(kind); light = OKLab darkened to >= 4.5:1 on both light grounds")
    y -= 56

    def block(y0, title, grounds, key_hex, key_ratio, first_hue_kind):
        # a panel for each ground side by side
        pw = (w - 2 * m - 12) / 2
        rows = H["rotation"]
        ph = 14 + len(rows) * 40 + 12
        for gi, g in enumerate(grounds):
            x0 = m + gi * (pw + 12)
            c.setFillColor(HC(g)); c.setStrokeColor(hl.BORDER); c.rect(x0, y0 - ph, pw, ph, stroke=1, fill=1)
            on_dark = g in H["dark_grounds"]
            ink = hl.INK if on_dark else HC("#0d1117")
            mut = hl.MUTED if on_dark else HC("#57606a")
            c.setFillColor(mut); c.setFont(hl.FONT["mono"], 7.5)
            c.drawString(x0 + 10, y0 - 12, f"{title} on {g}")
            yy = y0 - 14
            for r in rows:
                col = HC(r[key_hex])
                yy -= 40
                c.setFillColor(col); c.rect(x0 + 10, yy + 14, 14, 14, stroke=0, fill=1)
                c.setFont(hl.FONT["serif_semibold"], 13)
                c.drawString(x0 + 32, yy + 15, f"{r['index']}  {r['section']}")
                kinds = [k for k, v in H["kinds"].items() if v["section"] == r["section"]]
                c.setFillColor(ink); c.setFont(hl.FONT["serif"], 10)
                c.drawString(x0 + 32, yy + 2, "Prose stays ink")
                c.setFillColor(col); c.setFont(hl.FONT["mono"], 7.5)
                c.drawRightString(x0 + pw - 10, yy + 18, f"{r[key_hex]}  {r[key_ratio][g]}:1")
                c.setFillColor(mut)
                c.drawRightString(x0 + pw - 10, yy + 6, f"kind: {kinds[0]}")
                c.setStrokeColor(col); c.setLineWidth(2); c.line(x0 + 10, yy - 4, x0 + pw - 10, yy - 4)
        return y0 - ph - 18

    y = block(y, "dark hue", H["dark_grounds"], "dark", "ratio_dark", None)
    # light: two panels, each ground, variants
    y = block(y, "light variant", H["light_grounds"], "light", "ratio_light", None)
    c.setFillColor(hl.MUTED); c.setFont(hl.FONT["mono"], 7.5)
    c.drawString(m, y, f"minimum {H['min_ratio']}:1 (WCAG AA, normal text). control: hue_for('detections') = {"#" + hl.hue_for("detections").hexval()[2:]}")
    c.showPage(); c.save()
    print("wrote", out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
