#!/usr/bin/env python3
"""Validates feeds/misp/ with PyMISP, the reference implementation of the format.

Every event file is loaded through MISPEvent.from_dict, which rejects an unknown
attribute type or a category the type does not allow; the manifest entry is
compared with what PyMISP would write for the same event; and hashes.csv is
recomputed with PyMISP's own hash_values and compared line for line.

Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED (PyMISP missing or feed absent).
"""
import json, os, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
FEED = os.path.join(ROOT, 'feeds', 'misp')

try:
    from pymisp import MISPEvent
except Exception as e:  # noqa: BLE001
    print('NOT CHECKED  PyMISP is not importable (%s); pip install pymisp' % e)
    sys.exit(2)

try:
    manifest = json.load(open(os.path.join(FEED, 'manifest.json')))
    hashes = set(l.strip() for l in open(os.path.join(FEED, 'hashes.csv')) if l.strip())
except OSError as e:
    print('NOT CHECKED  feed is absent: %s' % e)
    sys.exit(2)

problems, events, attrs, lines = [], 0, 0, set()
for uuid, entry in manifest.items():
    p = os.path.join(FEED, uuid + '.json')
    try:
        raw = json.load(open(p))
    except OSError:
        problems.append('%s: event file missing' % uuid); continue
    ev = MISPEvent()
    try:
        ev.from_dict(**raw)
    except Exception as e:  # noqa: BLE001
        problems.append('%s: PyMISP rejects the event: %s' % (uuid, e)); continue
    events += 1
    if ev.uuid != uuid:
        problems.append('%s: event uuid differs from its manifest key (%s)' % (uuid, ev.uuid))
    for k in ('info', 'date', 'analysis', 'threat_level_id', 'timestamp'):
        theirs = ev.manifest[ev.uuid][k]
        if str(theirs) != str(entry[k]):
            problems.append('%s: manifest %s is %r, PyMISP would write %r' % (uuid, k, entry[k], theirs))
    mine = [t['name'] for t in entry.get('Tag', [])]
    theirs = [t['name'] for t in ev.manifest[ev.uuid]['Tag']]
    if mine != theirs:
        problems.append('%s: manifest tags differ from the event tags' % uuid)
    if not ev.attributes:
        problems.append('%s: no attributes' % uuid)
    for a in ev.attributes:
        attrs += 1
        for h in a.hash_values('md5'):
            lines.add('%s,%s' % (h, uuid))
        # a rule attribute must carry the whole rule, never a truncated one
        if a.type in ('yara', 'sigma', 'snort') and len(a.value) < 20:
            problems.append('%s: %s attribute suspiciously short' % (uuid, a.type))

if lines != hashes:
    problems.append('hashes.csv differs from PyMISP hash_values: %d lines on disk, %d recomputed, %d only on disk, %d only recomputed'
                    % (len(hashes), len(lines), len(hashes - lines), len(lines - hashes)))
files = [f for f in os.listdir(FEED) if f.endswith('.json') and f not in ('manifest.json', '_state.json')]
if len(files) != len(manifest):
    problems.append('%d event files on disk, %d manifest entries' % (len(files), len(manifest)))

if problems:
    print('FAIL  feeds/misp/')
    for p in problems: print('   FAIL  ' + p)
    sys.exit(1)
print('PASS  feeds/misp/  %d events, %d attributes loaded by PyMISP %s; manifest and hashes.csv agree with PyMISP'
      % (events, attrs, __import__('pymisp').__version__))
