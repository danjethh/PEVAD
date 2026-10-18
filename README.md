# PEVAD 2.0 - PEB/VAD Cross-Structural Validation (Volatility 3 plugin)

Entry for the Volatility Foundation 14th Annual Plugin Contest (deadline 2026-12-31).
Based on "Deterministic Memory-Resident Malware Detection via PEB-VAD Cross-Structural Validation"
(Addai et al., QRS 2026). v2 drops the paper's weighted score in favour of rule-based evidence tiers.
The paper-faithful v1 is kept in `reference/pevad_v1_paper.py`.

## What it does

For every process it asks whether what the process *claims* (PEB, loader lists, user-writable) agrees with what
the kernel *recorded* (VAD tree, `EPROCESS.SectionBaseAddress`, `SeAuditProcessCreationInfo`, VAD file objects).

    vol -p ./plugin -f image.dmp windows.pevad.Pevad [--pid N ...] [--min-tier clean|info|suspicious|high] [--dump] [--deep]

Output is a tree: one row per process (tier, ordinal score, hypothesis, coverage) and one child row per finding
(ID, evidence class, ATT&CK technique, range, protection, backing file, evidence text, content corroboration,
confidence, JSON detail). `-r json` is the machine-readable form.

### Reading it at the terminal
Like any Volatility 3 plugin, `vol` renders the `TreeGrid` above as a plain-text table in the default CLI
renderer: one header line, then one line per row, process rows first and each process's finding rows indented
under it with a leading `*` per tree depth (standard `vol` behaviour, not specific to this plugin). A clean
process still prints a row (`Tier` Clean, no children) so the output accounts for every PID scanned. Example,
truncated to fit:

```
PID    Process         Tier        Score  Finding              EvClass   Technique     ... Evidence
7252   taskhostw.exe   Suspicious  34     3 finding(s)
* 7252 taskhostw.exe   Suspicious  34     PEVAD-II01 EXEC...    Class II  T1055; T1620  ... 0x7ff66ccf0000: 4 KiB ...
* 7252 taskhostw.exe   Suspicious  34     PEVAD-II02 WX_PRI...  Class II  T1055         ... 0x7ff66ccf0000: 4 KiB ...
```

The `Evidence`, `Coverage` and `Details` columns are wide (`Details` is a full JSON blob of the finding) and the
default renderer does not wrap — a narrow terminal truncates them silently. For anything beyond a quick look,
pipe to `-r json` or `-r csv` or use `--dump` for the per-finding JSON (`Details`), which has everything the
printed row cuts off. `--min-tier` filters which process rows print at all (their finding rows always print in
full once the process row clears the floor).

### Findings
- **Class I - contradiction between structures:** I01 PEB image base != kernel section base; I02 main image not an
  IMAGE VAD; I03 main image file != audit path; I04 PEB path != kernel path; I05 module name != VAD file;
  I06 listed module not backed; I07 mapped image in no loader list (hidden).
- **Class II - anomalous state:** II01 executable private memory with no image; II02 private W+X; II03 W+X image;
  II04 image coverage deficit; II05 header anomaly; II06 module directory mismatch; II07 loader lists
  inconsistent; II08 executable image pages are private copies (`--deep`).
- **Class III - context only:** III01 module from risky directory; III02 unlisted image, unverified; III03 header
  not PE; III04 module/VAD unverified (VAD tree incomplete).

### Tier rules (no probabilities, no weights)
Clean / Info / Suspicious / High, plus **Unevaluated** when no check could run. High needs one of: a Class I finding
rated confirmed or probable; a Class II finding with strong content corroboration (PE header or shellcode-stager
bytes in the region); or Class II findings from at least two independent families (private_exec, image_state,
module_integrity). The `Score` column is ordinal ordering inside a tier, not a probability.
Every check is tri-state; unreadable or unknown data is never counted as pass or fail, and the `Coverage` column says
what was and was not evaluated. Loader-list completeness and VAD-tree completeness (`VadCount`) gate the
"hidden image" and "module without VAD" findings.

### `--deep` (experimental)
Reads the PFN database to find executable pages of image mappings that are private copies (inline hooks, patched
code). Hook trampolines (`mov rax,imm64; jmp rax`) are masked before comparing, and a patch identical in at least
two other processes of the same program is downgraded to Info (product behaviour). Skipped: NGEN images and CLR
modules in CLR hosts. Pages whose frame no longer belongs to the mapping (a dump artefact) are treated as unknown.
64-bit Windows only; elsewhere it warns and is ignored. About 3x slower (107 s vs 36 s on the Win10 image).

## Trust model - read this
The PEB is a claim a process can rewrite. The VAD tree, section base, audit path and VAD file object are treated as
kernel ground truth. **A rootkit that edits those kernel structures consistently (or alters what the memory image
shows) defeats PEVAD.** It detects inconsistency between the user-writable and kernel-owned views, not every form
of malware. Code that keeps all structures consistent is only seen through content or `--deep` evidence.

## Evaluation (what was actually run)
Pinned: Volatility 3 framework 2.28.3 at commit `77ff0b19...` (`PINS.txt`). Unit tests: 402 passing
(`python -m pytest tests -q`), including the sweep-line join against brute force and the tier table.

| Image | Processes | Clean | Info | Suspicious | High |
|---|---|---|---|---|---|
| Win10 19041 x64 (benign, Volatility test corpus) | 114 | 105 | 7 | 2 | 0 |
| same, `--deep` | 114 | 94 | 16 | 4 | 0 |
| WinXP SP2 x86 2005 (benign, corpus) | 42 | 37 | 2 | 3 | 0 |
| Win10 synthetic tampered, `--deep` | 114 | 88 | 16 | 5 | 5 |
| Windows Server 2008 (real-world, CrowdStrike-style IR capture, no ground truth) | 44 | 36 | 5 | 3 | 0 |
| WinDump (real-world, 13Cubed sample, no ground truth) | 134 | 100 | 27 | 6 | 1 |
| MemLabs Lab 1-6 (real-world CTF images, 2018-19 era, no ground truth for this detection domain) | 48/54/41/41/54/53 | - | - | 7/4/4/5/9/1 | 0/0/0/0/1/0 |
| **CyberDefenders BlackEnergy (real-world, ground-truth confirmed)** | 19 | 17 | 0 | 1 | **1** |

### Ground truth validation (real malware)
The three rows above (Server 2008, WinDump, MemLabs) are **false-positive/stability corpora**: real-world images
that exercise PEVAD against realistic process populations and show it doesn't drown an examiner in noise, but none
of them carry documented ground truth for process-injection/hollowing/hidden-module detection - this was verified,
not assumed (MemLabs' own writeups confirm its "flags" are unrelated artifacts, e.g. deleted-file recovery).

**BlackEnergy is the one case with independently published ground truth in PEVAD's actual detection domain.**
CyberDefenders' "BlackEnergy" lab (`cyberdefenders.org/blueteam-ctf-challenges/blackenergy/`, Volatility-tagged,
scenario: BlackEnergy v2 code injection) ships a real memory image (Windows XP SP3 x86, captured 2023-02-13,
19 processes). Two independent public writeups (not mine, found via web search, cross-checked against each other)
document code injection in `svchost.exe`, PID 880, confirmed in the original writeups via `malfind` + a VirusTotal
check on the extracted region.

Running PEVAD against this image, unmodified, no retuning:

    vol -r json -p ./plugin -f CYBERDEF-567078-20230213-171333.raw windows.pevad.Pevad

**Result: PID 880 (svchost.exe) is the only High-tier finding in the image (1/19 processes)** - exactly the
process the published ground truth names, nothing else. Findings: `EXEC_PRIVATE_ORPHAN` and `WX_PRIVATE`, a
36 KB RWX private region at `0x980000-0x989000` with no owning PEB module, content-corroborated (`pe_header`,
`peb_access`). This is a true positive against independently documented ground truth, not a synthetic or
self-constructed test, and it is the strongest evaluation evidence in this README - the synthetic positive
control (below) tests PEVAD's own model of each technique; this tests it against someone else's malware and
someone else's documented finding.

*Benign Suspicious, no ground truth:* SearchApp and smartscreen (RWX private regions with zero or unreadable
content); XP winlogon, svchost, explorer (16 KB RWX private regions, cause unknown, possibly shim thunks). With
`--deep`, two msedge processes (3952, 3876) have private ntdll syscall-stub pages carrying inline hooks whose
hook sets are not shared by two peers; the other eight msedge processes are downgraded to Info. These are real
modifications, very probably Chromium sandbox interception, but that is an inference. The trampoline masking was
added after seeing this output, so the Win10 `--deep` row is not a blind result.

*Synthetic positive control* (`scripts/make_tampered_image.py`, edits a COPY; originals never modified): six
planted operations (PEB path, PEB image base, loader-list unlink, main image retyped, reflective-injection-like
region, W+X-only region) - 6/6 detected against the current build, re-verified after every logic change in this
round, 0 untouched processes changed tier versus the pristine run except a browser-JIT family (see next
paragraph), both confirmed by rerunning `scripts/check_tamper.py` against the current plugin, not quoted from an
earlier run. This tests the plumbing and rules against the author's model of each technique. It is not recall on
real malware. `--deep` has no synthetic positive control; its logic is covered by unit tests only.

*Existing plugins on the same synthetic image* (`results/compare/`): none of malfind, ldrmodules, hollowprocesses,
pebmasquerade, processghosting flagged the PEB-path edit; malfind caught the two planted RWX regions; ldrmodules
reported the unlink and the main-image retype but also shows "unlinked" rows for 61 benign processes on the
pristine image. Runtimes on the pristine Win10 image: pebmasquerade 3 s, ldrmodules 18 s, processghosting 21 s,
PEVAD 36 s, hollowprocesses 74 s, malfind 92 s. This shows a gap on one synthetic edit, not that PEVAD finds more
real malware.

*Cross-check against `malfind` on WinDump* (same real image, both tools, independent heuristics): of 5 malfind
hits picked at random (SearchUI.exe, MOM.exe, CCC.exe, taskhostw.exe, two ngentask.exe instances), PEVAD agreed
on 4/5 at first pass. The one miss (taskhostw.exe PID 7252, reported Clean) was a real bug, not a detection
limit: PEVAD's orphan-executable-memory check was wrongly gated behind a readable PEB, so any process with an
unreadable PEB skipped that check entirely even though it only needs the kernel VAD tree. Fixed; taskhostw.exe
now reports Suspicious with the same RWX regions malfind flagged. Re-running the full WinDump image afterward
surfaced two more processes with the same previously-invisible class (svchost.exe, smartscreen.ex) and zero new
High-tier findings; Server 2008 was unaffected (0 tier changes), confirming the fix is scoped to processes with
genuinely unreadable PEBs, not a general loosening.

*JIT-host downgrade was inconsistent across checks.* `EXEC_PRIVATE_ORPHAN`/`WX_PRIVATE` already downgraded to
Info for known JIT/managed-runtime hosts (browsers, CLR, etc.) absent strong content corroboration - `IMAGE_CODE_MODIFIED`
(`--deep`) did not, so any Chromium- or CLR-hosted process with self-modifying JIT code pages reads as a latent
false positive under `--deep`. Fixed to use the same rule. Verified on real WinDump data: MOM.exe, CCC.exe and
ngentask.exe (both instances) all load `clrjit.dll` and all show `IMAGE_CODE_MODIFIED`; all four now correctly
downgrade to Info instead of Suspicious.

## Known open issues (not fixed, not retuned to hide)
- **WinDump: 1 unresolved High** tied to `ShellExperienceHost.exe` and VAD-tree-completeness (28
  `MODULE_VAD_UNVERIFIED` findings for ordinary DLLs on the same image). Not investigated yet - flagged, not
  chased, pending a decision on priority before the contest deadline.
- **MemLabs Lab 5: 1 unresolved High** on `explorer.exe` PID 1580. MemLabs ships no ground truth for
  process-injection/hollowing/hidden-module detection (verified against two independent public writeups for this
  lab) - its actual intended "flag" is a different process and mechanism entirely (deleted-file recovery via
  `mftparser`). This finding is neither confirmed nor refuted; it is exactly the kind of case PEVAD is built to
  surface, with no way to check it against this dataset.
- **Real-malware ground truth is now one confirmed case, not a corpus.** BlackEnergy (above) is the only
  real-world image with independently published ground truth in this detection domain, and PEVAD correctly
  isolated it (1/19 processes, matching the documented PID). Server 2008, WinDump, and MemLabs 1-6 remain
  ground-truth-free stability corpora. CIC-MalMem2022 turned out to be pre-extracted CSV features, not raw memory
  images, so it cannot be run through this plugin. No broader public, verified, downloadable ground-truth dataset
  for this detection domain was found despite searching DFRWS, Black Hat, and researcher-hosted sources. The
  synthetic positive control (6/6, above) still covers techniques BlackEnergy doesn't exercise (PEB-path/image-base
  spoofing, loader-list unlinking).

## Limitations
- See "Known open issues" above for the two specific unresolved findings and the ground-truth gap.
- Tested on Windows 10 19041 x64, Windows XP x86, Windows Server 2008, and whatever builds the WinDump/MemLabs
  images happen to be (2018-19 era, Win7/early-Win10).
- JIT/engine hosts (browsers, .NET, Java, Electron) get private-executable and modified-image-page findings
  downgraded to Info unless content corroboration is strong - an evasion surface for injection into such a host.
- Dumps contain stale or non-resident pages; those are reported as unknown, which can hide real tampering.
- `--deep` peer consistency can hide an attack that patches identical bytes in many processes of one program.
- 8.3 short names in paths are undecidable and treated as unknown.

## Reproduce
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    python -m pytest tests -q
    vol -r json -p ./plugin -f <image.dmp> windows.pevad.Pevad > out.json

**Demonstration sample:** a self-contained synthetic positive control (six planted techniques: PEB path spoof,
PEB image-base spoof, loader-list unlink, main-image retype, reflective-injection-like region, W+X-only region
- built by `scripts/make_tampered_image.py` from a pristine, redistributable Volatility test-corpus Win10 19041
x64 image) is attached to the GitHub Release for this repository, alongside its tamper manifest, since it is too
large for this repository's git history. Verify PEVAD against it with:

    vol -r json -p ./plugin -f win10_tampered.dmp windows.pevad.Pevad > out.json
    python scripts/check_tamper.py win10_tampered_manifest.json <(cat out.json) out.json

Real-world evaluation (Server 2008, WinDump, MemLabs, and the two ground-truth cases below, BlackEnergy and
RedLine) used third-party memory images under their own distribution terms and are not redistributed in this
repository or its release; see the Evaluation section for exact sources, citations, and how to obtain them.

Memory images are git-ignored and must never be committed to this repository.

## License
Volatility is under VSL 1.0. Its copyleft clause treats software that executes Volatility and parses its results
as an "Addition" that must be published if distributed. The plugin's license is not yet chosen.
