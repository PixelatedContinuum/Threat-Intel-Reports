#!/usr/bin/env python
"""Regenerate data/misp-galaxy-attack-pattern.tsv from MISP's own ATT&CK galaxy.

WHY THE MISP GALAXY AND NOT THE ATT&CK CATALOG
----------------------------------------------
A MISP instance attaches a `misp-galaxy:mitre-attack-pattern="..."` tag to a
galaxy cluster only when the quoted value equals a cluster value exactly. The
cluster values are MISP's spelling ("Malware - T1587.001", "Remote Access
Tools - T1219"), not the report's wording and not always the ATT&CK name of the
day. The first real pull of the feed (2026-10-09, T-0201) showed 247 of 1,035
tags missing their cluster because they were built from the report's text. So
the feed takes the tag value from the same file MISP resolves against.

WHY A COMMITTED TSV AND NOT A LIVE LOOKUP
-----------------------------------------
Same reason as data/attack-techniques.tsv: the generator is Node and offline,
and a galaxy update should show up as a diff a person reads.

WHEN TO RUN
-----------
When the MISP galaxy moves (a new ATT&CK release lands in MISP/misp-galaxy), or
when check-misp-feed.js reports a technique with no galaxy value. Then commit
the diff.

    python tools/report-tooling/generate-misp-galaxy-names.py [URL or local path]

Exit codes: 0 wrote the file, 2 could not run (source unreadable).
"""
import json
import os
import re
import sys
import urllib.request

SOURCE = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json'
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'data', 'misp-galaxy-attack-pattern.tsv')
ID = re.compile(r' - (T\d{4}(?:\.\d{3})?)$')


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else SOURCE
    try:
        if re.match(r'^https?://', src):
            with urllib.request.urlopen(src, timeout=60) as r:
                doc = json.load(r)
        else:
            with open(src, encoding='utf-8') as f:
                doc = json.load(f)
    except Exception as e:  # noqa: BLE001 - any failure means nothing was written
        print('NOT CHECKED  could not read the MISP galaxy from %s: %s' % (src, e))
        return 2
    rows = {}
    for v in doc.get('values', []):
        m = ID.search(v.get('value', ''))
        if m:
            rows[m.group(1)] = v['value']
    if not rows:
        print('NOT CHECKED  the galaxy at %s has no "Name - Txxxx" values' % src)
        return 2
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# MISP ATT&CK galaxy cluster values. GENERATED - do not edit by hand.\n')
        f.write('# Source: %s\n' % src)
        f.write('# Galaxy version: %s\n' % doc.get('version', 'unknown'))
        f.write('# Regenerate: python tools/report-tooling/generate-misp-galaxy-names.py\n')
        f.write('# id\tvalue\n')
        for k in sorted(rows, key=lambda t: [int(x) for x in t[1:].split('.')]):
            f.write('%s\t%s\n' % (k, rows[k]))
    print('wrote %s, %d techniques' % (os.path.relpath(OUT), len(rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
