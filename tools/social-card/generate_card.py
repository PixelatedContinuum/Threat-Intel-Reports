"""Render Hunter's Ledger social cards.

Usage:
  python tools/social-card/generate_card.py <report-dir-name>   # one report
  python tools/social-card/generate_card.py --all               # every report

Writes assets/images/cards/<slug>.png (slug = the report's permalink segment).
Does NOT edit any .md file — see ensure_thumbnail.py for the front-matter line.
"""
import os
import sys
import glob
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cardlib as c

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def render_slug(slug):
    fields = c.card_fields(REPO, slug)
    out = os.path.join(REPO, "assets", "images", "cards", f"{slug}.png")
    c.render_card(fields, out)
    print(f"  {slug}.png  [{fields['severity']}]")
    return out


def main():
    ap = argparse.ArgumentParser(description="Render social cards.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("report", nargs="?", help="report directory name under reports/")
    g.add_argument("--all", action="store_true", help="render a card for every report")
    a = ap.parse_args()
    if a.all:
        slugs = sorted(c.slug_of(p) for p in
                       glob.glob(os.path.join(REPO, "reports", "*", "index.md")))
        print(f"Rendering {len(slugs)} cards:")
        for s in slugs:
            render_slug(s)
    else:
        idx = os.path.join(REPO, "reports", a.report, "index.md")
        if not os.path.exists(idx):
            sys.exit(f"No such report: reports/{a.report}/index.md")
        render_slug(c.slug_of(idx))


if __name__ == "__main__":
    main()
