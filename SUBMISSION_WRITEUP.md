# PEVAD — Volatility Foundation 14th Annual Plugin Contest Submission

## What it is

PEVAD (PEB/VAD Cross-Structural Validation) is a Volatility 3 plugin
(`windows.pevad.Pevad`) that detects memory-resident malware by checking
whether what a process *claims about itself* (PEB, loader lists,
user-writable structures) agrees with what the kernel *recorded independently*
(VAD tree, `EPROCESS.SectionBaseAddress`, `SeAuditProcessCreationInfo`, VAD
file objects). Based on "Deterministic Memory-Resident Malware Detection via
PEB-VAD Cross-Structural Validation" (Addai et al., QRS 2026); this
submission (v2) replaces the paper's weighted score with rule-based evidence
tiers (Clean / Info / Suspicious / High) graded by cross-structural
contradiction (Class I), anomalous state (Class II), or context only (Class
III), plus an experimental `--deep` mode that reads the PFN database to catch
inline hooks and patched code pages.

## How it's used

    vol -p ./plugin -f image.dmp windows.pevad.Pevad [--pid N ...] \
        [--min-tier clean|info|suspicious|high] [--dump] [--deep]

Output is the standard Volatility 3 `TreeGrid`: one row per process (tier,
score, hypothesis, coverage) and one child row per finding (evidence class,
MITRE ATT&CK technique, memory range, protection, content corroboration,
confidence). `-r json` gives the machine-readable form used for all
evaluation in this submission. Full usage, the finding catalogue, and the
tier rules are in the repository README.

## Why it should win

1. **It cross-validates structures, not single heuristics.** Where
   `malfind` looks at one VAD's protection flags and `ldrmodules` compares
   loader lists alone, PEVAD checks four independent kernel-vs-userland
   agreements at once and only escalates to High on corroborated or
   multi-family evidence — fewer things for an examiner to triage, by
   design, not by threshold tuning.

2. **It doesn't silently skip processes with a damaged PEB.** A real bug
   found and fixed during this submission's evaluation (see below) meant
   orphan-memory/WX checks were gated behind a readable PEB even though they
   only need the kernel VAD tree. Fixing it surfaced a real detection miss
   on a real image (`taskhostw.exe`, WinDump sample) and — independently,
   discovered afterward — turned out to be exactly the condition present in
   the RedLine ground-truth case below (`oneetx.exe`'s PEB was unreadable).

3. **It's verified against two independently documented, real-world
   malware cases, not just synthetic tests:**
   - **CyberDefenders "BlackEnergy" lab** (Windows XP SP3 x86, captured
     2023-02-13): PEVAD flags `svchost.exe` PID 880 as the only High-tier
     finding in a 19-process image — a 36 KB RWX private region with no
     owning PEB module, content-corroborated. This is the exact process and
     PID documented as the BlackEnergy v2 code-injection point by two
     independent public writeups.
   - **CyberDefenders "RedLine" lab** (Windows 10 19041 x64, captured
     2023-05-21): PEVAD flags `oneetx.exe` PID 5896 as High — a 224 KB RWX
     private region at the process image base. This is the exact process
     and PID documented as the RedLine Stealer dropper in a public writeup,
     and its PEB was unreadable in this image, directly exercising the fix
     in point 2.

   Both are true positives against ground truth PEVAD's authors did not
   write, on malware PEVAD's authors did not build. The README documents
   both in full, with citations.

4. **Honest reporting of what doesn't work yet.** The README's "Known open
   issues" section names two unresolved High-tier findings (one on a
   benign-looking real image with incomplete VAD-tree coverage, one on a
   CTF image with no ground truth for this detection domain) and states
   plainly that real-malware ground truth is currently two confirmed cases,
   not a benchmark corpus. Nothing in the evaluation was retuned to chase a
   better number; findings here are reported as observed, including a case
   where a plugin fix was driven by investigating a real cross-check miss
   against `malfind`, not by score-chasing.

5. **PEB-independence and JIT-host noise suppression are both load-bearing
   design decisions**, not afterthoughts: the former is what caught the
   RedLine case above; the latter (downgrading private-executable findings
   in known JIT/managed-runtime hosts absent strong content corroboration)
   keeps browser and CLR processes from drowning the High tier in noise,
   verified on real WinDump data (four `clrjit.dll`-hosting processes
   correctly downgraded).

## Demonstration sample

Rather than redistribute a ~2GB memory-image binary, this submission ships the generator:
`scripts/make_tampered_image.py` builds a synthetic positive control deterministically from
the pristine, public Volatility test-corpus Windows 10 19041 x64 image. It plants six
structurally distinct techniques (PEB path spoof, PEB image-base spoof, loader-list unlink,
main-image retype, a reflective-injection-like region, and a W+X-only region) at known PIDs.
`data/synthetic/win10_tampered_manifest.json` is committed and records the exact PIDs and
expected PEVAD finding IDs from the run that produced the results below, so a judge can
regenerate the identical sample and check PEVAD's output against it directly:

    python scripts/fetch_datasets.py fetch
    python scripts/fetch_datasets.py synthetic
    vol -r json -p ./plugin -f data/synthetic/win10_tampered.dmp windows.pevad.Pevad > out.json
    python scripts/check_tamper.py data/synthetic/win10_tampered_manifest.json out.json out.json

The two real-malware ground-truth cases (BlackEnergy, RedLine) use
third-party CyberDefenders lab images under their own distribution terms and
are not redistributed here; the README gives exact sources and how to obtain
them for independent verification.

## Repository

https://github.com/danjethh/PEVAD — source, 402 passing unit tests,
full evaluation writeup, and comparison data against
malfind/ldrmodules/hollowprocesses/pebmasquerade/processghosting.

## License

Not yet finalized — PEVAD's license will be determined pending the outcome
of this contest, per the repository README.
