# PEVAD: Process Environment Block - Virtual Address Descriptor cross-structural validation.
#
# A Volatility 3 plugin implementing "Deterministic Memory-Resident Malware Detection via
# PEB-VAD Cross-Structural Validation" (Addai, Tetteh, Boakye-Agyemang, Ansong; QRS 2026):
#   Stage 1  extraction + normalisation   (PEB loader lists, VAD tree)
#   Stage 2  interval alignment           (Algorithm 1, sweep-line join)
#   Stage 3  constraints C1-C5            (Eqs 2-9, Algorithm 2)
#   Stage 4  weighted composite score     (Eq 10, Table 1 weights)
#   Stage 5  tier + rationale             (Algorithm 3, Table 3, Listing 1)
#
# All thresholds and weights are the paper's published values and are intentionally constants.
# Implementation choices where the paper is silent are marked "ASSUMPTION" and are reported in
# each process's rationale where they affect the result.

import bisect
import json
import logging
import re
import struct
from typing import Dict, FrozenSet, Generator, List, NamedTuple, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

PEVAD_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Published parameters (paper Table 1, Sect. 3.3-3.5, 5.2). Do not tune.
# --------------------------------------------------------------------------- #
WEIGHTS = {"C1": 0.30, "C2": 0.08, "C3": 0.28, "C4": 0.14, "C5": 0.20}
TAU1 = 0.05             # C1 normalisation threshold
TAU2 = 0.02             # C2 normalisation threshold
THETA_4B = 0.40         # C4 directory-risk threshold
SIGMA_SUSPICIOUS = 0.20
SIGMA_HIGH = 0.50
F1_SEVERE = 0.90        # f1-hat >= 0.90 alone is Suspicious
HEADER_SIZE_TOLERANCE = 0.20   # C5 check 2

# Denominator S_p for C1/C2. The paper defines S_p as "total mapped bytes" (sum of all VAD sizes).
# On Windows 10/11 x64 every process carries a 2 TB Control Flow Guard mapping, so that sum is
# ~2 TB for every process and f1/f2 can never leave zero (a 340 KB orphan -> f1 ~ 1.6e-7 against
# tau1 = 0.05). The paper's Case 1 (340 KB orphan in notepad.exe -> f1-hat = 1.00) is only
# reachable if S_p is private *committed* memory (notepad.exe: ~5.2 MB). "committed" is therefore
# the default; "all" is the literal reading and is kept for comparison.
S_BASES = ("committed", "all")

CLEAN, SUSPICIOUS, HIGH, UNEVALUATED = "Clean", "Suspicious", "High Confidence", "Unevaluated"
TIER_ORDER = {UNEVALUATED: -1, CLEAN: 0, SUSPICIOUS: 1, HIGH: 2}

VAD_IMAGE_MAP = 2       # MI_VAD_TYPE.VadImageMap
IMAGE_SCN_MEM_EXECUTE = 0x20000000


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #

class PebModule(NamedTuple):
    base: int
    size: int
    full_name: str
    base_name: str
    in_load: bool
    in_init: bool
    in_mem: bool


class VadNode(NamedTuple):
    start: int
    end: int
    protection: str
    vad_type: str            # "IMAGE" | "PRIVATE" | "MAPPED"
    file_path: Optional[str]
    commit: Optional[int] = None   # committed bytes (CommitCharge * page size); None = unknown


class OverlapPair(NamedTuple):
    module: PebModule
    vad: VadNode
    overlap_bytes: int


# --------------------------------------------------------------------------- #
# Stage 1 helpers: protection, path canonicalisation, directory risk
# --------------------------------------------------------------------------- #

_PROT_MAP = {
    "PAGE_NOACCESS": frozenset(),
    "PAGE_READONLY": frozenset("R"),
    "PAGE_READWRITE": frozenset("RW"),
    "PAGE_WRITECOPY": frozenset("RC"),
    "PAGE_EXECUTE": frozenset("X"),
    "PAGE_EXECUTE_READ": frozenset("RX"),
    "PAGE_EXECUTE_READWRITE": frozenset("RWX"),
    "PAGE_EXECUTE_WRITECOPY": frozenset("RCX"),
}


def parse_protection(protection: str) -> FrozenSet[str]:
    """Map Windows protection names to the paper's canonical set {R, W, X, C}.

    Copy-on-write is C, not W, so an image mapped PAGE_EXECUTE_WRITECOPY is not a WX region."""
    flags = set()
    for token in (protection or "").upper().replace(" ", "").split("|"):
        flags |= _PROT_MAP.get(token, frozenset())
    return frozenset(flags)


def canon_path(path: Optional[str]) -> str:
    """Canonical form used to compare PEB and VAD paths (Sect. 4.3 step ii).

    ASSUMPTION: VAD file names carry no drive letter (e.g. \\Windows\\System32\\ntdll.dll) while PEB
    names do (C:\\Windows\\...), so the drive letter / device prefix is dropped on both sides."""
    if not path:
        return ""
    p = path.strip().replace("/", "\\").lower()
    p = p.replace("%systemroot%", "\\windows").replace("%windir%", "\\windows")
    p = re.sub(r"^\\\?\?\\", "", p)
    p = re.sub(r"^\\\\\?\\", "", p)
    p = re.sub(r"^\\systemroot\\", "\\\\windows\\\\", p)
    if p.startswith("\\device\\mup\\"):
        p = "\\\\" + p[len("\\device\\mup\\"):]
    p = re.sub(r"^\\device\\harddiskvolume\d+", "", p)
    p = re.sub(r"^unc\\", "\\\\\\\\", p)
    p = re.sub(r"^[a-z]:", "", p)
    unc = p.startswith("\\\\")
    p = re.sub(r"\\{2,}", "\\\\", p)
    return ("\\" + p) if unc else p


_TRUSTED_PREFIXES = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\program files\\",
                     "\\program files (x86)\\")
_USER_WRITABLE = ("\\users\\", "\\programdata\\", "\\windows\\tasks\\", "\\windows\\debug\\",
                  "\\$recycle.bin\\", "\\perflogs\\")


def dir_risk(canon: str) -> float:
    """Directory risk score rho (Sect. 3.3, C4). ASSUMPTION: the 'user-writable' set in (c) is
    the list above; the paper does not enumerate it."""
    if not canon:
        return 0.3
    p = canon if canon.endswith("\\") else canon + "\\"
    if "\\temp\\" in p or "\\downloads\\" in p or "\\appdata\\local\\temp" in p:
        return 1.0
    if canon.startswith("\\\\"):
        return 0.8
    if p.startswith(_TRUSTED_PREFIXES):
        return 0.0
    if p.startswith(_USER_WRITABLE):
        return 0.6
    return 0.3


# --------------------------------------------------------------------------- #
# Stage 2: Algorithm 1 (sweep-line interval join)
# --------------------------------------------------------------------------- #

def sweep_line_join(modules: List[PebModule], vads: List[VadNode]) -> List[OverlapPair]:
    """All (module, VAD) pairs with non-empty overlap. O(n log n + m log m + K).
    VADs are disjoint (kernel invariant), so the lower fence is monotone."""
    pairs: List[OverlapPair] = []
    mods = sorted(modules, key=lambda m: m.base)
    vs = sorted(vads, key=lambda v: v.start)
    j_lo = 0
    for m in mods:
        m_start, m_end = m.base, m.base + m.size
        while j_lo < len(vs) and vs[j_lo].end <= m_start:
            j_lo += 1
        j = j_lo
        while j < len(vs) and vs[j].start < m_end:
            ov = max(0, min(m_end, vs[j].end) - max(m_start, vs[j].start))
            if ov > 0:
                pairs.append(OverlapPair(m, vs[j], ov))
            j += 1
    return pairs


# --------------------------------------------------------------------------- #
# Stage 3 helpers: C5 header checks
# --------------------------------------------------------------------------- #

def find_vad(sorted_vads: List[VadNode], starts: List[int], addr: int) -> Optional[VadNode]:
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and sorted_vads[i].start <= addr < sorted_vads[i].end:
        return sorted_vads[i]
    return None


def check_pe_header(
    header: bytes, peb_size: int, base: int, sorted_vads: List[VadNode], starts: List[int]
) -> Tuple[int, List[str]]:
    """Run the four C5 checks on the bytes at a module's declared base.
    Returns (number of failed checks 0-4, human-readable failure notes)."""
    fails, notes = 0, []

    # (1) MZ and PE signatures
    pe_off = None
    if len(header) >= 0x40 and header[:2] == b"MZ":
        (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
        if 0 < e_lfanew <= len(header) - 24 and header[e_lfanew:e_lfanew + 4] == b"PE\0\0":
            pe_off = e_lfanew
    if pe_off is None:
        return 4, ["no valid MZ/PE signature at declared base"]  # nothing else can be evaluated

    num_sections, = struct.unpack_from("<H", header, pe_off + 6)
    opt_size, = struct.unpack_from("<H", header, pe_off + 20)
    opt_off = pe_off + 24
    if opt_off + 60 > len(header):
        return 1, ["truncated optional header"]
    size_of_image, = struct.unpack_from("<I", header, opt_off + 56)

    # (2) SizeOfImage within 20% of the PEB-declared size
    if peb_size > 0 and abs(size_of_image - peb_size) > HEADER_SIZE_TOLERANCE * peb_size:
        fails += 1
        notes.append(f"SizeOfImage 0x{size_of_image:x} differs >20% from PEB size 0x{peb_size:x}")

    # (3) section VAs monotonically ordered and inside the image
    sec_off = opt_off + opt_size
    sections = []
    if num_sections > 96 or sec_off + 40 * num_sections > len(header):
        fails += 1
        notes.append(f"implausible section table ({num_sections} sections)")
    else:
        for i in range(num_sections):
            vsize, va = struct.unpack_from("<II", header, sec_off + 40 * i + 8)
            chars, = struct.unpack_from("<I", header, sec_off + 40 * i + 36)
            sections.append((va, vsize, chars))
        ordered = all(sections[i][0] < sections[i + 1][0] for i in range(len(sections) - 1))
        bounded = all(va + vsize <= size_of_image + 0xFFF for va, vsize, _ in sections)
        if not (ordered and bounded):
            fails += 1
            notes.append("section virtual addresses not monotonic or outside SizeOfImage")

    # (4) executable sections must lie in a VAD that permits execution
    # ASSUMPTION: the paper does not define 'consistent'; an executable section in a
    # non-executable (or absent) VAD is the unambiguous inconsistency.
    bad = False
    for va, _vsize, chars in sections:
        if chars & IMAGE_SCN_MEM_EXECUTE:
            v = find_vad(sorted_vads, starts, base + va)
            if v is None or "X" not in parse_protection(v.protection):
                bad = True
                break
    if bad:
        fails += 1
        notes.append("executable section not backed by an executable VAD")
    return fails, notes


# --------------------------------------------------------------------------- #
# Stage 3: constraints (Algorithm 2) / Stage 4: score / Stage 5: tier
# --------------------------------------------------------------------------- #

class Evaluation(NamedTuple):
    f: Dict[str, float]            # normalised f-hat per constraint
    raw: Dict[str, float]
    evidence: Dict[str, List[str]]
    notes: List[str]


def _kb(n: int) -> str:
    return f"{n // 1024} KB"


def evaluate_constraints(
    modules: List[PebModule],
    vads: List[VadNode],
    pairs: List[OverlapPair],
    c5_results: Optional[Dict[int, Tuple[int, List[str]]]] = None,
    s_basis: str = "committed",
) -> Evaluation:
    """c5_results maps module base -> (failed checks, notes) for modules whose header was
    readable. Unreadable headers are simply absent (ASSUMPTION: excluded from f5)."""
    evidence = {k: [] for k in WEIGHTS}
    notes: List[str] = []
    def span(v: VadNode) -> int:
        """Bytes a VAD contributes to S_p and to the C1/C2 numerators under the chosen basis."""
        if s_basis == "all":
            return v.end - v.start
        if v.vad_type != "PRIVATE":
            return 0                                   # committed basis counts private memory only
        return v.commit if v.commit is not None else v.end - v.start

    s_p = sum(span(v) for v in vads) or 1

    # C1 - orphan executable PRIVATE regions
    overlapped = {id(p.vad) for p in pairs}
    orphans = [v for v in vads if v.vad_type == "PRIVATE" and "X" in parse_protection(v.protection)
               and id(v) not in overlapped]
    f1 = sum(span(v) for v in orphans) / s_p
    f1h = min(1.0, f1 / TAU1)
    for v in sorted(orphans, key=lambda v: -(v.end - v.start))[:5]:
        flags = "".join(sorted(parse_protection(v.protection) - {"C"}))
        evidence["C1"].append(
            f"0x{v.start:x}-0x{v.end:x}: {_kb(v.end - v.start)}, {flags}, PRIVATE, no PEB entry")

    # C2 - WX / RWX regions
    wx = [v for v in vads if {"W", "X"} <= parse_protection(v.protection)]
    f2 = sum(span(v) for v in wx) / s_p
    f2h = min(1.0, f2 / TAU2)
    for v in sorted(wx, key=lambda v: -(v.end - v.start))[:5]:
        evidence["C2"].append(f"0x{v.start:x}-0x{v.end:x}: {_kb(v.end - v.start)}, WX, {v.vad_type}")

    # C3 - worst-case IMAGE coverage deficit over M_img
    cover: Dict[int, int] = {}
    for p in pairs:
        if p.vad.vad_type == "IMAGE":
            cover[p.module.base] = cover.get(p.module.base, 0) + p.overlap_bytes
    m_img = [m for m in modules if m.base in cover and m.size > 0]
    deficits = [(1 - min(1.0, cover[m.base] / m.size), m) for m in m_img]
    f3h = max((d for d, _ in deficits), default=0.0)
    for d, m in sorted(deficits, key=lambda x: -x[0])[:5]:
        if d > 0:
            evidence["C3"].append(
                f"{m.base_name or hex(m.base)} @0x{m.base:x}: PEB size {_kb(m.size)}, "
                f"IMAGE coverage {_kb(cover[m.base])} ({d:.0%} deficit)")

    # C4 - path mismatch rate and directory risk over P_img
    p_img = [p for p in pairs if p.vad.vad_type == "IMAGE"]
    mism, risk_sum, unresolved = [], 0.0, 0
    for p in p_img:
        risk_sum += dir_risk(canon_path(p.vad.file_path))
        a, b = canon_path(p.module.full_name), canon_path(p.vad.file_path)
        if not a or not b:
            unresolved += 1      # ASSUMPTION: unresolvable paths are not counted as mismatches
        elif a != b:
            mism.append(p)
    f4a = len(mism) / len(p_img) if p_img else 0.0
    f4b = risk_sum / len(p_img) if p_img else 0.0
    f4h = max(f4a, 1.0 if f4b > THETA_4B else 0.0)
    for p in mism[:5]:
        evidence["C4"].append(
            f"{p.module.base_name or hex(p.module.base)}: PEB '{p.module.full_name}' "
            f"vs VAD '{p.vad.file_path}'")
    if f4b > THETA_4B:
        evidence["C4"].append(f"mean directory risk {f4b:.2f} exceeds {THETA_4B}")
    if unresolved:
        notes.append(f"{unresolved} IMAGE overlap(s) had an unresolved path and were not path-checked")

    # C5 - fraction of M_img modules with any header anomaly
    f5, fails_n, evaluable = 0.0, 0, 0
    if c5_results is not None:
        for _, m in deficits:
            r = c5_results.get(m.base)
            if r is None:
                continue
            evaluable += 1
            if r[0] > 0:
                fails_n += 1
                if len(evidence["C5"]) < 5:
                    evidence["C5"].append(f"{m.base_name or hex(m.base)} @0x{m.base:x}: " + "; ".join(r[1]))
        f5 = fails_n / evaluable if evaluable else 0.0
        skipped = len(m_img) - evaluable
        if skipped:
            notes.append(f"{skipped} module header(s) unreadable (paged out) and excluded from C5")

    f = {"C1": f1h, "C2": f2h, "C3": f3h, "C4": f4h, "C5": f5}
    raw = {"C1": f1, "C2": f2, "C3": f3h, "C4a": f4a, "C4b": f4b, "C5": f5,
           "S_p": s_p, "s_basis": s_basis, "C1_bytes": sum(span(v) for v in orphans),
           "C2_bytes": sum(span(v) for v in wx),
           "C5_evaluable": evaluable if c5_results is not None else 0}
    return Evaluation(f, raw, evidence, notes)


def composite_score(f: Dict[str, float]) -> float:
    """Eq. 10."""
    return sum(WEIGHTS[k] * f[k] for k in WEIGHTS)


def assign_tier(sigma: float, f: Dict[str, float]) -> str:
    """Algorithm 3 / Table 3."""
    f1, f3, f5 = f["C1"], f["C3"], f["C5"]
    if (f1 >= 0.6 and f3 >= 0.6) or (f1 >= 0.6 and f5 >= 0.6) or (f3 >= 0.8 and f5 >= 0.6):
        return HIGH
    if sigma >= SIGMA_HIGH:
        return HIGH
    if sigma >= SIGMA_SUSPICIOUS or f1 >= F1_SEVERE:
        return SUSPICIOUS
    return CLEAN


def primary_hypothesis(f: Dict[str, float]) -> Optional[str]:
    f1, f2, f3, f4, f5 = (f[k] for k in ("C1", "C2", "C3", "C4", "C5"))
    if f1 >= 0.6 and f3 >= 0.6:
        return "Process hollowing combined with reflective injection"
    if f3 >= 0.6:
        return "Process hollowing (IMAGE coverage deficit beneath PEB-declared size)"
    if f1 >= 0.6 and f5 >= 0.6:
        return "Reflective DLL injection / manual mapping with malformed PE headers"
    if f1 >= 0.6:
        return "Reflective DLL injection or shellcode staging (orphan executable private memory)"
    if f5 >= 0.6:
        return "Module stomping or manual mapping (PE header anomalies)"
    if f4 >= 0.5:
        return "DLL hijacking or load from a high-risk directory"
    if f2 > 0 and max(f1, f3, f4, f5) == 0:
        return "Active staging or packer (WX protections); corroborating evidence only"
    if max(f1, f2, f3, f4, f5) > 0:
        return "Weak structural inconsistency; consistent with benign behaviour such as JIT"
    return None


def build_rationale(pid: int, name: str, tier: str, sigma: float, ev: Evaluation) -> Dict[str, object]:
    evidence = [line for k in WEIGHTS for line in ev.evidence[k]]
    recs = []
    if ev.evidence["C1"]:
        first = ev.evidence["C1"][0].split(":")[0]
        recs.append(f"Dump {first} for YARA/signature scan")
    if ev.evidence["C3"] or ev.evidence["C4"] or ev.evidence["C5"]:
        recs.append("Compare the on-disk image hash against the mapped module")
    if tier in (SUSPICIOUS, HIGH):
        recs.append("Inspect parent process creation chain")
    return {
        "process": name, "pid": pid, "tier": tier, "sigma": round(sigma, 4),
        "scores": {k: round(ev.f[k], 2) for k in WEIGHTS},
        "hypothesis": primary_hypothesis(ev.f),
        "raw": {k: (round(v, 6) if isinstance(v, float) else v) for k, v in ev.raw.items()},
        "evidence": evidence, "recommendations": recs, "notes": ev.notes,
        "pevad_version": PEVAD_VERSION,
    }


# --------------------------------------------------------------------------- #
# The plugin
# --------------------------------------------------------------------------- #

class Pevad(interfaces.plugins.PluginInterface):
    """Deterministic memory-resident malware detection via PEB-VAD cross-structural validation."""

    _required_framework_version = (2, 27, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.VersionRequirement(name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)),
            requirements.ListRequirement(
                name="pid", element_type=int, optional=True,
                description="Process IDs to include (all other processes are excluded)"),
            requirements.ChoiceRequirement(
                name="s_basis", optional=True, default="committed", choices=list(S_BASES),
                description="Denominator for C1/C2: 'committed' = private committed bytes (default, "
                            "see S_BASES note); 'all' = sum of all VAD sizes (paper-literal)"),
            requirements.ChoiceRequirement(
                name="min_tier", optional=True, default="clean",
                choices=["clean", "suspicious", "high"],
                description="Only report processes at or above this tier (default: clean = all)"),
        ]

    # -- Stage 1 ----------------------------------------------------------- #

    @staticmethod
    def _get_peb_modules(proc) -> Optional[List[PebModule]]:
        """Normalised module set M_p. Returns None if no PEB list could be read at all."""
        lists = {"load": {}, "init": {}, "mem": {}}
        readers = {"load": proc.load_order_modules, "init": proc.init_order_modules,
                   "mem": proc.mem_order_modules}
        any_read = False
        for key, reader in readers.items():
            try:
                for mod in reader():
                    try:
                        lists[key][int(mod.DllBase)] = mod
                        any_read = True
                    except exceptions.InvalidAddressException:
                        continue
            except (exceptions.InvalidAddressException, AttributeError):
                continue
        if not any_read:
            return None
        modules = []
        for base in set(lists["load"]) | set(lists["init"]) | set(lists["mem"]):
            src = lists["load"].get(base) or lists["init"].get(base) or lists["mem"].get(base)

            def safe(fn, default):
                try:
                    return fn()
                except (AttributeError, exceptions.InvalidAddressException):
                    return default

            size = safe(lambda: int(src.SizeOfImage), 0)
            if base == 0 or size == 0:
                continue
            modules.append(PebModule(
                base, size,
                safe(lambda: src.FullDllName.get_string(), ""),
                safe(lambda: src.BaseDllName.get_string(), ""),
                base in lists["load"], base in lists["init"], base in lists["mem"]))
        return modules

    @staticmethod
    def _vad_type(vad, private: bool, file_path: Optional[str]) -> str:
        if private:
            return "PRIVATE"
        flags = None
        for chain in (("u", "VadFlags"), ("Core", "u", "VadFlags")):
            obj = vad
            try:
                for attr in chain:
                    if not obj.has_member(attr):
                        raise AttributeError(attr)
                    obj = getattr(obj, attr)
                flags = obj
                break
            except AttributeError:
                continue
        if flags is not None and flags.has_member("VadType"):
            return "IMAGE" if int(flags.VadType) == VAD_IMAGE_MAP else "MAPPED"
        # ASSUMPTION (fallback only): without a VadType member, a file-backed non-private VAD is IMAGE.
        return "IMAGE" if file_path else "MAPPED"

    def _get_vad_nodes(self, proc, kernel) -> List[VadNode]:
        protect_values = vadinfo.VadInfo.protect_values(
            self.context, kernel.layer_name, kernel.symbol_table_name)
        nodes = []
        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                start, end = vad.get_start(), vad.get_end() + 1   # inclusive end -> half-open
            except exceptions.InvalidAddressException:
                continue
            try:
                protection = vad.get_protection(protect_values, vadinfo.winnt_protections)
            except Exception:  # noqa: BLE001
                protection = ""
            try:
                fn = vad.get_file_name()
                fn = fn if isinstance(fn, str) else None
            except exceptions.InvalidAddressException:
                fn = None
            try:
                private = bool(vad.get_private_memory())
            except (AttributeError, exceptions.InvalidAddressException):
                private = fn is None
            try:
                commit = int(vad.get_commit_charge()) * 0x1000
            except (AttributeError, exceptions.InvalidAddressException):
                commit = None
            nodes.append(VadNode(start, end, protection, self._vad_type(vad, private, fn), fn, commit))
        return nodes

    def _c5_results(self, proc, modules, pairs, vads) -> Dict[int, Tuple[int, List[str]]]:
        sorted_vads = sorted(vads, key=lambda v: v.start)
        starts = [v.start for v in sorted_vads]
        img_bases = {p.module.base for p in pairs if p.vad.vad_type == "IMAGE"}
        out: Dict[int, Tuple[int, List[str]]] = {}
        try:
            layer = self.context.layers[proc.add_process_layer()]
        except exceptions.InvalidAddressException:
            return out
        for m in modules:
            if m.base not in img_bases:
                continue
            try:
                header = layer.read(m.base, 0x1000, pad=False)
            except exceptions.InvalidAddressException:
                continue                      # unreadable (paged out): not evaluable
            out[m.base] = check_pe_header(header, m.size, m.base, sorted_vads, starts)
        return out

    # -- orchestration ----------------------------------------------------- #

    def _analyse(self, proc, kernel, s_basis="committed"):
        pid = int(proc.UniqueProcessId)
        try:
            name = utility.array_to_string(proc.ImageFileName)
        except (AttributeError, exceptions.InvalidAddressException):
            name = "?"
        modules = self._get_peb_modules(proc)
        vads = self._get_vad_nodes(proc, kernel)
        if modules is None or not vads:
            # Without a readable PEB every executable private region would look orphaned,
            # so the process is reported as not evaluable instead of scored.
            ev = Evaluation({k: 0.0 for k in WEIGHTS}, {}, {k: [] for k in WEIGHTS},
                            ["PEB module lists unreadable or no VADs; process not scored"])
            return pid, name, UNEVALUATED, 0.0, ev, 0, len(vads)
        pairs = sweep_line_join(modules, vads)
        ev = evaluate_constraints(modules, vads, pairs, self._c5_results(proc, modules, pairs, vads), s_basis)
        sigma = composite_score(ev.f)
        return pid, name, assign_tier(sigma, ev.f), sigma, ev, len(modules), len(vads)

    def _generator(self, pids, min_tier, s_basis) -> Generator[Tuple, None, None]:
        kernel = self.context.modules[self.config["kernel"]]
        floor = {"clean": 0, "suspicious": 1, "high": 2}[min_tier]
        for proc in pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(pids),
        ):
            try:
                pid, name, tier, sigma, ev, n_mod, n_vad = self._analyse(proc, kernel, s_basis)
            except exceptions.InvalidAddressException:
                continue
            if TIER_ORDER[tier] < floor:
                continue
            rationale = json.dumps(build_rationale(pid, name, tier, sigma, ev))
            yield (0, (pid, name, tier, round(sigma, 4), n_mod, n_vad,
                       round(ev.f["C1"], 4), round(ev.f["C2"], 4), round(ev.f["C3"], 4),
                       round(ev.f["C4"], 4), round(ev.f["C5"], 4),
                       primary_hypothesis(ev.f) or "", rationale))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Tier", str), ("Sigma", float),
             ("PEB_Modules", int), ("VAD_Nodes", int),
             ("C1", float), ("C2", float), ("C3", float), ("C4", float), ("C5", float),
             ("Hypothesis", str), ("Rationale", str)],
            self._generator(self.config.get("pid", None), self.config.get("min_tier", "clean"), self.config.get("s_basis", "committed")))
