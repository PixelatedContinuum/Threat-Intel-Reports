#!/usr/bin/env python
"""Regenerate data/attack-techniques.tsv from pySigma's installed ATT&CK data.

WHY pySigma AND NOT A HAND LIST
-------------------------------
`sigma check` validates every Sigma rule in hunting-detections/ against exactly
this dataset. Deriving the catalog from anywhere else would give the site a
second opinion on what a technique is called and which tactic owns it, and the
two would drift silently. This is the codebase's signature failure mode, so the
catalog is CARRIED from the same source the rules are already gated against.

WHY A COMMITTED TSV AND NOT A LIVE LOOKUP
-----------------------------------------
The generator and gate that consume it are Node, and pySigma is Python. A
committed file is the handoff. It is also the reviewable artifact: an ATT&CK
version bump shows up as a diff a person reads, not as silently different
output on the next build.

WHEN TO RUN
-----------
On an ATT&CK version bump (after `pip install -U pysigma`), or when
check-detection-attack.js reports a technique it cannot resolve. Then commit
the diff.

    python tools/report-tooling/generate-attack-catalog.py

Exit codes: 0 wrote the file, 2 could not run (pySigma missing).
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "attack-techniques.tsv")

# ATT&CK tactic slug -> the display name the site renders, in kill-chain order.
# The order here IS the strip's bar order, so it must match TACTIC_ORDER in
# assets/js/attack-coverage.js. check-detection-attack.js asserts that.
TACTIC_DISPLAY = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("stealth", "Stealth"),
    ("defense-impairment", "Defense Impairment"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
DISPLAY = dict(TACTIC_DISPLAY)


def die(reason):
    print("NOT CHECKED  attack catalog not regenerated: " + reason)
    print("             Run `pip install --user pysigma` and retry.")
    sys.exit(2)


try:
    from sigma.data import mitre_attack as mitre
except Exception as exc:  # noqa: BLE001 - any import failure is the same outcome
    die("pySigma did not import (%s)" % exc)

data = mitre._load_mitre_attack_data()
version = data["mitre_attack_version"]
names = data["mitre_attack_techniques"]
mapping = data["mitre_attack_techniques_tactics_mapping"]

unknown_tactics = sorted(
    {t for tactics in mapping.values() for t in tactics} - set(DISPLAY)
)
if unknown_tactics:
    # A new tactic means the strip has no bar for it. Fail rather than drop the
    # techniques that live there, which would understate coverage silently.
    print("FAIL  ATT&CK %s introduced tactic(s) this catalog cannot place: %s"
          % (version, ", ".join(unknown_tactics)))
    print("      Add them to TACTIC_DISPLAY here AND to TACTIC_ORDER in")
    print("      assets/js/attack-coverage.js, then re-run.")
    sys.exit(1)


def sort_key(tid):
    base, _, sub = tid.partition(".")
    return (int(base[1:]), int(sub or 0))


rows = []
for tid in sorted(names, key=sort_key):
    tactics = mapping.get(tid) or []
    if not tactics:
        continue
    # PRIMARY TACTIC = the first ATT&CK lists. CLAUDE.md requires one tactic in
    # column 1 for a dual-tactic technique, and picking ATT&CK's own first entry
    # is the only choice that does not depend on how often some report happened
    # to write it. Every tactic is still recorded in the `all` column so nothing
    # is lost.
    rows.append((tid, DISPLAY[tactics[0]], names[tid],
                 ",".join(DISPLAY[t] for t in tactics)))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("# ATT&CK technique catalog. GENERATED - do not edit by hand.\n")
    fh.write("# Source: pySigma mitre_attack data, the same dataset `sigma check`\n")
    fh.write("# validates hunting-detections/ against.\n")
    fh.write("# Regenerate: python tools/report-tooling/generate-attack-catalog.py\n")
    fh.write("# attack_version\t%s\n" % version)
    fh.write("# id\tprimary_tactic\tname\tall_tactics\n")
    for row in rows:
        fh.write("\t".join(row) + "\n")

print("PASS  wrote %s" % OUT)
print("   note  ATT&CK %s, %d techniques, %d tactics"
      % (version, len(rows), len(TACTIC_DISPLAY)))
