#!/usr/bin/env python3
"""Benign false-positive budget: how often does each PEVAD finding fire on clean images?

Usage: baseline_prevalence.py PEVAD_JSON [PEVAD_JSON ...]   (outputs of `vol -r json windows.pevad.Pevad`
on images known to be free of the behaviour under test). Prints per-finding prevalence and tier counts.
Small corpora give wide uncertainty: read the counts, not just the percentages."""
import json
import sys
from collections import Counter

tiers, per_key, procs = Counter(), Counter(), 0
for path in sys.argv[1:]:
    rows = json.load(open(path))
    for r in rows:
        procs += 1
        tiers[r["Tier"]] += 1
        for key in {c["Finding"].split()[1] for c in r.get("__children", [])}:
            per_key[key] += 1
print(f"{procs} processes from {len(sys.argv) - 1} image(s)")
print("tiers: " + ", ".join(f"{t} {n}" for t, n in tiers.most_common()))
print(f"{'finding':28} {'processes':>9} {'share':>7}")
for key, n in per_key.most_common():
    print(f"{key:28} {n:>9} {n / procs:>7.1%}")
