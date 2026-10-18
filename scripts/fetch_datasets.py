#!/usr/bin/env python3
"""Fetch and checksum-verify the PEVAD evaluation datasets.

Memory images are NEVER committed: data/ is git-ignored.

  python scripts/fetch_datasets.py fetch      # download the Volatility test-corpus images and symbol
                                              # packs from the volatility3-test-data GitHub release,
                                              # verify each against the published SHA-256, gunzip images
  python scripts/fetch_datasets.py verify     # re-hash everything present against the manifest
  python scripts/fetch_datasets.py status     # what is present, what is manual-only
  python scripts/fetch_datasets.py record NAME FILE   # trust-on-first-use for a manually obtained image
  python scripts/fetch_datasets.py synthetic  # build the synthetic tampered Win10 image + manifest

The published checksums below are those of github.com/volatilityfoundation/volatility3-test-data
(images/SHA256SUMS, symbols/SHA256SUMS) at the time of writing. Hashes of the decompressed images are
computed locally and stored in data/checksums.json.
"""
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
IMAGES = DATA / "images"
SYMBOLS = DATA / "symbols"
MANIFEST = DATA / "checksums.json"
RELEASE = "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/"

# name -> (published asset name, published sha256, destination dir, decompress)
PUBLISHED = {
    "win10_19041_image": ("win-10_19041-2025_03.dmp.gz",
                          "b377ecd13bf40c90f59a8c41ffc8bc81166462627a7800ec82a67a73520c7f9d", IMAGES, True),
    "winxp_2005_image": ("win-xp-laptop-2005-06-25.img.gz",
                         "4cbdd5725adbb9505c8b3f4a51f0f042bac8dd53bf1dcc4b3bb7c71a6c8a74cd", IMAGES, True),
    "win10_19041_symbols": ("symbols_win-10_19041-2025_03.zip",
                            "abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e", SYMBOLS, False),
    "windows_symbols": ("windows.zip",
                        "231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e", SYMBOLS, False),
}

# Images with real malicious samples that the build sandbox could not reach. Download manually,
# place under data/images/, then `record`. Not part of any claim in this repository until recorded.
MANUAL = {
    "memlabs_lab3": "MemLabs Lab 3 (Mega link in stuxnet999/MemLabs README)",
    "memlabs_lab6": "MemLabs Lab 6 (Mega link in stuxnet999/MemLabs README)",
    "dfrws2022": "DFRWS 2022 USA memory forensics challenge (source not confirmed)",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def load():
    return json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}


def save(m):
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


def fetch():
    manifest = load()
    for name, (asset, published, dest, unzip) in PUBLISHED.items():
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / asset
        if not target.exists():
            print(f"downloading {asset} ...")
            urllib.request.urlretrieve(RELEASE + asset, target)
        digest = sha256(target)
        if digest != published:
            sys.exit(f"CHECKSUM MISMATCH for {asset}: {digest} != published {published}")
        rec = {"file": str(target.relative_to(DATA)), "sha256": digest, "size": target.stat().st_size,
               "source": RELEASE + asset, "checksum_origin": "published (volatility3-test-data SHA256SUMS)",
               "malware": False}
        if unzip:
            raw = target.with_suffix("")
            if not raw.exists():
                with gzip.open(target, "rb") as src, raw.open("wb") as out:
                    shutil.copyfileobj(src, out)
            rec["decompressed_file"] = str(raw.relative_to(DATA))
            rec["decompressed_sha256"] = sha256(raw)
        manifest[name] = rec
        print(f"OK {name}: {digest}")
    save(manifest)


def verify():
    manifest, bad = load(), 0
    for name, rec in manifest.items():
        for key, hkey in (("file", "sha256"), ("decompressed_file", "decompressed_sha256")):
            if key not in rec:
                continue
            p = DATA / rec[key]
            if not p.exists():
                print(f"MISSING  {name}: {rec[key]}")
                bad += 1
            elif sha256(p) != rec[hkey]:
                print(f"MISMATCH {name}: {rec[key]}")
                bad += 1
            else:
                print(f"OK       {name}: {rec[key]}")
    sys.exit(1 if bad else 0)


def status():
    manifest = load()
    for name in list(PUBLISHED) + list(MANUAL):
        state = "recorded" if name in manifest else ("auto-fetch" if name in PUBLISHED else "MANUAL, not present")
        print(f"{name:22s} {state:22s} {MANUAL.get(name, PUBLISHED.get(name, ('',))[0])}")


def record(name, filename):
    p = IMAGES / filename
    if not p.exists():
        sys.exit(f"{p} not found")
    manifest = load()
    manifest[name] = {"file": str(p.relative_to(DATA)), "sha256": sha256(p), "size": p.stat().st_size,
                      "checksum_origin": "trust-on-first-use (no published checksum)"}
    save(manifest)
    print(f"recorded {name}: {manifest[name]['sha256']}")


def synthetic():
    src = IMAGES / "win-10_19041-2025_03.dmp"
    if not src.exists():
        sys.exit("run `fetch` first")
    out = DATA / "synthetic"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.check_call([sys.executable, "-I", str(ROOT / "scripts" / "make_tampered_image.py"),
                           str(src), str(out / "win10_tampered.dmp"), str(out / "win10_tampered_manifest.json")])


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "record":
        record(sys.argv[2], sys.argv[3])
    else:
        {"fetch": fetch, "verify": verify, "status": status, "synthetic": synthetic}[cmd]()
