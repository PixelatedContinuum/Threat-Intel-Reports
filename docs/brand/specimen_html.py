#!/usr/bin/env python3
"""Write a one-page HTML specimen of the shared document head, masthead and section heads.

    /usr/bin/python3 docs/brand/specimen_html.py OUT.html [--fonts base64|file]

Render with Brave (see hl_doc_html.py); `pdffonts` on the PDF should list Source Serif 4, IBM Plex Sans,
IBM Plex Mono and Space Grotesk, not a system fallback. T-0563 w1.
"""
import argparse
import sys

import hl_doc_html as hd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--fonts", default="base64", choices=["file", "base64"])
    a = ap.parse_args()
    body = (
        hd.masthead(kicker="SPECIMEN · shared document foundation", right="2026-11-08")
        + '<span class="hl-kicker" style="margin-top:20px">T-0563 W1 · TOKENS FROM custom.scss</span>'
        + '<h1 class="hl-title">One look for every document the site sends out</h1>'
        + '<p class="hl-standfirst">Headings in Source Serif 4, running text in IBM Plex Sans, data in IBM Plex Mono, the wordmark in Space Grotesk. Blue is the default accent; gold means sponsor and nothing else.</p>'
        + hd.section("Section head, default blue")
        + "<p>Body text is <strong>IBM Plex Sans</strong> at the document size, with a <a href=\"#\">link in the site blue</a> and a hash <code>3f2a9c1e5b7d</code> in IBM Plex Mono.</p>"
        + "<ul><li>List markers take the site blue.</li><li>An address such as <code>107.189.19.107:8443</code> stays on one line.</li></ul>"
        + hd.section("Detections hue", hue="Detections")
        + '<div class="hl-plate" style="--edge:var(--hl-hue-detections)"><dl><dt>RECORD</dt><dd>Specimen plate with a coloured edge</dd><dt>DATE</dt><dd>2026-11-08</dd><dt>STATUS</dt><dd><span class="hl-chip hl-chip--high">HIGH</span> <span class="hl-chip hl-chip--low">LOW</span></dd></dl></div>'
        + hd.section("Sub-column head", hue="Reports", sub=True)
        + '<table class="hl-table"><tr><th>FIELD</th><th>VALUE</th></tr><tr><td>Ground</td><td><code>#111111</code></td></tr><tr><td>Rule</td><td>2px, in the section colour</td></tr></table>'
        + "<pre><code>sigma check rule.yml\nyarac -w rule.yar /dev/null</code></pre>"
        + '<div class="hl-foot">The Hunter’s Ledger · specimen page, not a deliverable</div>'
    )
    open(a.out, "w", encoding="utf-8", newline="\n").write(hd.page("HL document foundation specimen", body, fonts=a.fonts))
    print("wrote", a.out)


if __name__ == "__main__":
    sys.exit(main())
