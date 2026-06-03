"""Idempotently insert a `thumbnail:` line into report front matter.

Usage:
  python tools/social-card/ensure_thumbnail.py <report-dir-name>   # one report
  python tools/social-card/ensure_thumbnail.py --all               # every report

Preserves the file's existing line endings so the diff is exactly +1 line.
"""
import os
import sys
import glob
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cardlib as c

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def process(index_md):
    slug = c.slug_of(index_md)
    with open(index_md, "r", encoding="utf-8", newline="") as fh:
        raw = fh.read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    text = raw.replace("\r\n", "\n")               # normalize for processing
    out, changed = c.ensure_thumbnail_line(text, slug)
    if changed:
        if nl == "\r\n":
            out = out.replace("\n", "\r\n")        # restore original endings
        with open(index_md, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
    print(("  set  " if changed else "  ok   ") + slug)


def main():
    ap = argparse.ArgumentParser(description="Insert thumbnail front matter.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("report", nargs="?", help="report directory name under reports/")
    g.add_argument("--all", action="store_true", help="process every report")
    a = ap.parse_args()
    if a.all:
        paths = sorted(glob.glob(os.path.join(REPO, "reports", "*", "index.md")))
    else:
        idx = os.path.join(REPO, "reports", a.report, "index.md")
        if not os.path.exists(idx):
            sys.exit(f"No such report: reports/{a.report}/index.md")
        paths = [idx]
    for p in paths:
        process(p)


if __name__ == "__main__":
    main()
