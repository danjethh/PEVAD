# PEVAD: Deterministic Memory-Resident Malware Detection via PEB–VAD Cross-Structural Validation

**A Volatility 3 plugin submitted to the Volatility Foundation 14th Annual Plugin Contest**

---

## 1. Current Industry Practice

Memory forensics examiners detecting process injection, hollowing, and reflective loading today rely on a set of single-heuristic Volatility plugins, each inspecting one signal in isolation:

- **`malfind`** flags VAD (Virtual Address Descriptor) regions by memory protection (e.g. `PAGE_EXECUTE_READWRITE`) combined with simple content heuristics (MZ/PE signatures, suspicious byte patterns).
- **`ldrmodules`** cross-references the three in-process loader lists (`InLoadOrderModuleList`, `InInitializationOrderModuleList`, `InMemoryOrderModuleList`) against the VAD tree to spot unlinked modules.
- **`hollowprocesses`**, **`pebmasquerade`**, and **`processghosting`** each test for one specific, named technique signature.

An examiner triaging a suspicious process typically runs several of these tools independently and manually reconciles their output.

## 2. The Problem

Each of these tools evaluates exactly one structural signal, so each can be defeated — or simply has nothing to say — the moment an attacker's technique doesn't match that one signal:

- `malfind`'s protection+content heuristic says nothing about whether the Process Environment Block's own claims (its loader lists, declared image path, declared image base) agree with what the kernel independently recorded.
- `ldrmodules` checks loader-list presence only; it does not validate PE header integrity, image coverage, or path legitimacy, and in practice produces significant noise — in this submission's own testing, it reported "unlinked" rows for 61 benign processes on a single pristine Windows 10 image.
- None of the five tools above cross-validates *multiple independent kernel-vs-userland structures at once* — so an examiner still has to manually decide whether several single-signal alerts, taken together, actually corroborate one another.

## 3. The Proposed Solution

PEVAD treats the PEB (Process Environment Block) as a claim a process makes about itself — rewritable by the process, hence attacker-controllable — and treats structures the kernel records independently (the VAD tree, `EPROCESS.SectionBaseAddress`, `SeAuditProcessCreationInfo`, VAD file objects) as ground truth. It checks whether the two views agree, and only escalates a process to a high-confidence finding when the disagreement is structural and, where possible, corroborated by a second independent signal — rather than relying on any single heuristic.

## 4. Contribution and Motivation

PEVAD implements "Deterministic Memory-Resident Malware Detection via PEB-VAD Cross-Structural Validation" (Addai, Tetteh, Boakye-Agyemang, Ansong; QRS 2026), which formalizes five structural constraints (C1–C5) and a weighted composite score. This submission's contribution goes beyond a direct implementation of the paper in three ways:

1. **It replaces the paper's tunable weighted score with deterministic, rule-based evidence tiers** (Clean / Info / Suspicious / High / Unevaluated) — removing a free parameter that could otherwise be adjusted to manufacture better-looking results, in favor of transparent, auditable escalation rules.
2. **It adds an experimental `--deep` mode** that reads the PFN (Page Frame Number) database to detect inline hooks and patched code pages — a detection surface the original paper does not cover.
3. **It is validated against two independently documented, real-world malware cases that the authors did not construct** (CyberDefenders' BlackEnergy and RedLine labs), in addition to the synthetic positive control used to verify the plumbing — a validation step beyond what the underlying paper itself reports.

## 5. How Previous Plugins Work

`malfind` iterates each process's VAD tree and flags any region whose memory protection is executable and private (not backed by a mapped file), optionally scanning its first bytes for suspicious signatures. It has no concept of the PEB at all.

`ldrmodules` reads the three PEB loader lists and the VAD tree, and reports a module as suspicious if it is missing from one or more of the three lists while a corresponding VAD exists (or vice versa). It does not inspect PE header validity, does not measure how much of a module's declared size is actually backed by VAD coverage, and does not evaluate path legitimacy.

`hollowprocesses`, `pebmasquerade`, and `processghosting` are each built around one named technique's known artifact (e.g. a specific field mismatch), and do not generalize to other inconsistency patterns.

## 6. How PEVAD Works

PEVAD runs five logical stages per process:

1. **Extraction and normalization** — read all three PEB loader lists and the full VAD tree; normalize module and VAD file paths to a canonical form (stripping drive letters, device prefixes, and UNC variants) so PEB-reported and kernel-reported paths for the same file can be compared directly.
2. **Interval alignment** — a sweep-line join (O(n log n + m log m + K)) pairs every PEB-declared module against every VAD whose address range overlaps it, exploiting the kernel invariant that VADs within one process are disjoint.
3. **Structural evaluation** — from the aligned pairs, PEVAD evaluates independent checks across evidence classes:
   - **Class I (contradiction between structures):** e.g. PEB-declared image base differs from the kernel's recorded section base; the main image is not backed by an IMAGE-type VAD; a loader-listed module has no VAD backing it; a mapped image exists with no loader-list entry at all (a hidden module).
   - **Class II (anomalous state):** e.g. executable private memory with no owning PEB module (orphan shellcode/reflective-injection pattern); a region that is simultaneously writable and executable; a module whose VAD-covered bytes fall materially short of its PEB-declared size (hollowing); a module's PE header failing structural checks (signature validity, `SizeOfImage` consistency, section-table ordering, executable sections backed by executable VADs).
   - **Class III (context only):** e.g. a module loading from a user-writable or networked directory.
4. **Tier assignment** — a deterministic rule table, not a tunable score: a process reaches **High** only given a Class I finding rated confirmed/probable, a Class II finding with strong content corroboration (a real PE header or shellcode-stager bytes found in the region), or Class II findings from at least two independent evidence families at once. Every check is tri-state — unreadable or unknown data is never silently counted as a pass or a fail, and output explicitly states what could and could not be evaluated for each process.
5. **Rationale generation** — each finding is attached to a MITRE ATT&CK technique ID, a concrete memory range, and a plain-language hypothesis (e.g. "process hollowing combined with reflective injection"), giving the examiner a starting investigative action rather than a bare numeric score.

### Input, Processing, Output — per stage

| Stage | Input | Processing | Output |
|---|---|---|---|
| 1. Extraction | Raw `_PEB` loader lists (3), raw VAD tree nodes | Walk each list; dereference `DllBase`/`SizeOfImage`/`FullDllName`; canonicalize every path string | Normalized `PebModule` and `VadNode` record sets |
| 2. Alignment | Normalized module and VAD sets | Sort both by address; sweep-line join to find all overlapping (module, VAD) pairs | `OverlapPair` list with exact overlap byte counts |
| 3. Evaluation | Overlap pairs, VAD protection flags, module PE headers (read from the process's memory layer) | Run Class I/II/III checks; parse each module's declared PE header for structural validity | A per-finding evidence record (class, technique, range, confidence) |
| 4. Tiering | The full set of findings for one process | Apply the deterministic escalation rule table | One of Clean / Info / Suspicious / High / Unevaluated |
| 5. Rationale | Tier + findings | Map findings to a plain-language hypothesis and recommended next step | Human-readable `TreeGrid` row(s), plus full JSON detail via `-r json` |

## 7. Testing Process and Setup

- **Environment:** Volatility 3 framework 2.28.3, pinned at a specific commit hash (recorded in `PINS.txt`), Python 3, `pefile`, `yara-python`, `capstone`.
- **Unit testing:** 402 passing tests (`pytest tests -q`) exercising the sweep-line join against a brute-force reference implementation, the tier-assignment table, and every PE-header check path — all against hand-built in-memory data structures, no image required.
- **Image-level evaluation, real images only, no synthetic ground truth claimed as malware:**
  - Windows 10 19041 x64 and Windows XP SP2 x86 (benign, Volatility public test corpus)
  - A synthetic *positive control* built by editing a copy of the Win10 image to plant six known techniques, used only to verify the plumbing against the authors' own model of each technique — explicitly not treated as evidence of real-world detection recall
  - Windows Server 2008 (real-world incident-response-style capture, no ground truth)
  - A 13Cubed "WinDump" sample (real-world, no ground truth)
  - MemLabs Labs 1–6 (real-world CTF images, no ground truth for this specific detection domain, independently verified via public writeups)
  - **CyberDefenders "BlackEnergy" lab** (Windows XP SP3 x86, captured 2023-02-13) — the one image in this evaluation with independently published ground truth in PEVAD's actual detection domain
  - **CyberDefenders "RedLine" lab** (Windows 10 19041 x64, captured 2023-05-21) — a second independently documented real-malware case

All images were analyzed read-only; none were modified; the synthetic positive control was built from a copy, never the original.

## 8. Results and Findings

| Image | Processes | Clean | Info | Suspicious | High |
|---|---|---|---|---|---|
| Win10 19041 x64 (benign) | 114 | 105 | 7 | 2 | 0 |
| WinXP SP2 x86 (benign) | 42 | 37 | 2 | 3 | 0 |
| Win10 synthetic tampered, `--deep` | 114 | 88 | 16 | 5 | 5 |
| Windows Server 2008 (real-world) | 44 | 36 | 5 | 3 | 0 |
| WinDump (real-world) | 134 | 100 | 27 | 6 | 1 |
| **CyberDefenders BlackEnergy (real malware)** | 19 | 17 | 0 | 1 | **1** |

- **BlackEnergy:** PEVAD's only High-tier finding across all 19 processes is `svchost.exe`, PID 880 — a 36 KB RWX private region with no owning PEB module, content-corroborated. This is the exact process and PID two independent public writeups document as the BlackEnergy v2 code-injection point. No retuning was performed to reach this result.
- **RedLine:** PEVAD's only High-tier finding is `oneetx.exe`, PID 5896 — a 224 KB RWX private region at the process image base. This matches the publicly documented RedLine Stealer dropper and its process's PEB was unreadable in this image, directly exercising a bug fix described below.
- **A real bug, found and fixed:** cross-checking PEVAD against `malfind` on the WinDump image (5 `malfind` hits, picked at random) surfaced one disagreement — `taskhostw.exe` reported Clean by PEVAD, Suspicious by `malfind`. Root cause: PEVAD's orphan-executable-memory check was incorrectly gated behind a readable PEB, even though it only needs the kernel VAD tree. After the fix, `taskhostw.exe` correctly reports Suspicious, and — independently, discovered only afterward — this same unreadable-PEB condition turned out to be exactly what RedLine's `oneetx.exe` exhibits.
- **JIT-host noise suppression:** without downgrading, every Chromium- and CLR-hosted process's routine self-modifying JIT code pages would read as Suspicious under `--deep`. Verified on real data: four `clrjit.dll`-hosting WinDump processes all correctly downgrade to Info once the suppression rule is applied consistently.

## 9. Discussion

PEVAD's central design claim — that cross-validating multiple independent structures reduces false positives relative to any single heuristic — is supported by its behavior on both real-malware cases: in each, it isolated exactly one process out of 19–134 total, matching independently published ground truth with no retuning. The bug found during WinDump cross-checking is itself evidence that the PEB-independence design decision (not gating checks on a readable PEB) has real detection value, since it is precisely what the RedLine case required.

The deterministic tier table is a deliberate trade against the paper's tunable weighted score: it sacrifices the ability to rank processes on a continuous scale in exchange for an escalation rule an examiner (or a judge) can audit line by line, with no hidden parameter that could be adjusted after the fact to improve reported numbers.

PEVAD's explicit trust model is also its clearest limitation: it detects *inconsistency* between user-writable and kernel-owned structures. An attacker who edits the kernel structures themselves consistently — or who keeps every structure internally coherent — produces no PEB/VAD contradiction for PEVAD to find, and is visible only through content inspection or the experimental `--deep` mode. Two further findings remain genuinely unresolved rather than suppressed: one High-tier finding on WinDump tied to VAD-tree completeness, and one on a MemLabs CTF image with no ground truth in this detection domain at all.

## 10. Conclusion

PEVAD operationalizes the QRS 2026 paper's cross-structural validation concept as a production Volatility 3 plugin, replacing its tunable score with auditable rule-based tiers and extending it with an experimental deep inline-hook detector. It is validated as a true positive against two independently documented, real-world malware cases the authors did not construct — isolating the exact process named in each case's published ground truth, with no retuning — and its evaluation reports a real bug found and fixed, alongside explicitly unresolved findings and a stated trust-model limitation, rather than a curated set of favorable results.
