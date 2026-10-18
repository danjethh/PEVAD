#!/usr/bin/env python3
"""Compare PEVAD JSON output on a synthetic tampered image with the generator's manifest.
Usage: check_tamper.py MANIFEST.json PEVAD_TAMPERED.json [PEVAD_PRISTINE.json]
Exit status 1 if any planted modification is missed or any untouched process changed tier."""
import json
import sys

manifest = json.load(open(sys.argv[1]))
rows = json.load(open(sys.argv[2]))
pristine = {r["PID"]: r for r in json.load(open(sys.argv[3]))} if len(sys.argv) > 3 else {}
by_pid = {r["PID"]: r for r in rows}
touched = {op["pid"] for op in manifest["operations"]}
bad = 0
print(f"{'op':15} {'pid':>5} {'process':16} {'tier':11} expected -> found")
for op in manifest["operations"]:
    r = by_pid[op["pid"]]
    found = [c["Finding"].split()[0] for c in r.get("__children", [])]
    tags = {t for c in r.get("__children", []) for t in c["Corroboration"].split(",") if t}
    ok = all(e in found for e in op["expect"]) and set(op.get("expect_tags", [])) <= tags
    bad += not ok
    print(f"{op['op']:15} {op['pid']:>5} {r['Process']:16} {r['Tier']:11} {','.join(op['expect'])} -> "
          f"{'OK ' if ok else 'MISS'} {sorted(set(found))}{' tags=' + ','.join(sorted(tags)) if tags else ''}")
changed = [(p, pristine[p]["Tier"], by_pid[p]["Tier"]) for p in pristine
           if p in by_pid and p not in touched and pristine[p]["Tier"] != by_pid[p]["Tier"]]
print(f"\nuntouched processes whose tier changed: {len(changed)}", changed[:10])
sys.exit(1 if bad or changed else 0)
