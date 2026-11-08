#!/usr/bin/env python3
"""One-page reportlab specimen of the brand foundation: every static font instance, the vector lockup,
a section head, and the concept 3 palette on the #111111 ground.

    .venv-gates/bin/python3 docs/brand/specimen_pdf.py OUT.pdf

Proof that each TTF registers and embeds (check with `pdffonts OUT.pdf`). T-0563 w1.
"""
import sys

from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics

import hl_brand as hl

TEXT = "The quick brown fox: 0123456789 ’quotes” § • · × © SHA256 a1b2c3 107.189.19.107"


def main(out):
    hl.register_fonts()
    w, h = hl.PAGE
    c = canvas.Canvas(out, pagesize=hl.PAGE)
    c.setTitle("Hunters Ledger brand foundation specimen (T-0563 w1)")
    hl.draw_ground(c, w, h, grid=True)
    m = hl.MARGIN
    y = h - m
    lw, lh = hl.lockup_size(0.9)
    hl.draw_lockup(c, m, y - lh, scale=0.9)
    y -= lh + 26
    y = hl.draw_section_head(c, m, y - 14, "Static font instances", w - 2 * m, hl.SEC["The Wire"]) - 22
    rows = [
        ("serif", "HLSerif", 15), ("serif_semibold", "HLSerif-SemiBold", 15), ("serif_bold", "HLSerif-Bold", 15), ("serif_italic", "HLSerif-Italic", 15),
        ("sans", "HLSans", 12), ("sans_semibold", "HLSans-SemiBold", 12),
        ("mono", "HLMono", 10.5), ("mono_medium", "HLMono-Medium", 10.5),
        ("wordmark_medium", "SpaceGrotesk-Medium", 13), ("wordmark_bold", "SpaceGrotesk-Bold", 13),
    ]
    for key, label, size in rows:
        face = hl.FONT[key]
        c.setFillColor(hl.MUTED)
        c.setFont(hl.FONT["mono"], 8)
        c.drawString(m, y, label)
        c.setFillColor(hl.INK)
        c.setFont(face, size)
        c.drawString(m + 128, y, TEXT[:54])
        # prove every character of TEXT has a glyph in this face
        face_obj = pdfmetrics.getFont(face)
        missing = [ch for ch in TEXT if ord(ch) not in face_obj.face.charToGlyph]
        if missing:
            raise SystemExit(f"{label}: missing glyphs {missing}")
        y -= size + 9
    y -= 6
    y = hl.draw_section_head(c, m, y - 14, "Section colours", w - 2 * m, hl.SEC["Reports"]) - 20
    x = m
    for name, col in hl.SEC.items():
        c.setFillColor(col)
        c.rect(x, y - 14, 14, 14, stroke=0, fill=1)
        c.setFillColor(hl.INK)
        c.setFont(hl.FONT["sans"], 8)
        c.drawString(x + 19, y - 11, name)
        x += 79
    y -= 34
    x = m
    for name, col in (("ground", hl.GROUND), ("card", hl.CARD), ("ink", hl.INK), ("muted", hl.MUTED), ("blue", hl.BLUE), ("gold bright (sponsor only)", hl.GOLD_BRIGHT)):
        c.setFillColor(col)
        c.setStrokeColor(hl.BORDER)
        c.rect(x, y - 14, 14, 14, stroke=1, fill=1)
        c.setFillColor(hl.INK)
        c.setFont(hl.FONT["mono"], 8)
        c.drawString(x + 19, y - 11, name)
        x += 19 + pdfmetrics.stringWidth(name, hl.FONT["mono"], 8) + 16
    y -= 32
    y = hl.draw_section_head(c, m, y - 12, "Sub-column head", (w - 2 * m) / 2, hl.SEC["Detections"], sub=True) - 14
    c.setFillColor(hl.CODE_BLOCK_BG)
    c.rect(m, y - 34, w - 2 * m, 30, stroke=0, fill=1)
    c.setFillColor(hl.CODE_TEXT)
    c.setFont(hl.FONT["mono"], 9)
    c.drawString(m + 10, y - 22, "rule SHA256 3f2a... | 107.189.19.107:8443 | 2026-11-08")
    c.setFillColor(hl.BLUE)
    c.rect(m, y - 34, 3, 30, stroke=0, fill=1)
    c.showPage()
    c.save()
    print("wrote", out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
