# PEVAD 2: PEB / VAD / kernel cross-structural validation for Volatility 3.
#
# PEVAD compares what a process CLAIMS about its memory (the user-writable PEB loader lists,
# image base and image path) with what the KERNEL records (VAD tree, EPROCESS.SectionBaseAddress,
# SeAuditProcessCreationInfo, the file object behind each image VAD) and with the bytes actually
# present in memory. Every disagreement is reported as an individual, explainable finding.
#
# Design (see README.md):
#   * Findings, not fractions. A small implant cannot be diluted by a large process.
#   * Three evidence classes:
#       I   contradiction  two trust levels disagree in a way the OS loader cannot produce
#       II  anomalous      state the loader does not produce but benign software sometimes does
#       III context        weak signal, only meaningful in combination
#   * Tri-state checks: a check that cannot read its evidence is "unknown" (counted in the
#     coverage figure) - it never counts as pass or as fail.
#   * Tier is decided by explicit rules (classify()), not by a weighted sum.
#   * Content corroboration (PE header / shellcode idioms) is read from the region itself.
#
# Limits that the README repeats: a kernel-level rootkit that rewrites the VAD tree, the
# EPROCESS fields and the page tables consistently defeats these checks; module stomping that
# leaves page protections and metadata untouched needs on-disk comparison (not performed).

import bisect
import hashlib
import json
import logging
import math
import re
import struct
from typing import Callable, Dict, FrozenSet, Generator, List, NamedTuple, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

PEVAD_VERSION = "2.0.0"

# --------------------------------------------------------------------------- #
# Tiers
# --------------------------------------------------------------------------- #
UNEVALUATED, CLEAN, INFO, SUSPICIOUS, HIGH = -1, 0, 1, 2, 3
TIER_NAME = {UNEVALUATED: "Unevaluated", CLEAN: "Clean", INFO: "Info",
             SUSPICIOUS: "Suspicious", HIGH: "High"}
MIN_TIER_CHOICES = {"clean": CLEAN, "info": INFO, "suspicious": SUSPICIOUS, "high": HIGH}

VAD_IMAGE_MAP = 2            # MI_VAD_TYPE.VadImageMap
IMAGE_SCN_MEM_EXECUTE = 0x20000000
HEADER_SIZE_TOLERANCE = 0.20
DEFICIT_MIN_FRACTION = 0.10  # IMAGE coverage deficit reported when >= 10% of the PEB size ...
DEFICIT_MIN_BYTES = 0x2000   # ... and >= 8 KiB
REGION_SAMPLE_BYTES = 0x10000
MAX_REGIONS_SCANNED = 40

# Loaded modules that make a process a plausible JIT / emulation host. A class II private-memory
# finding in such a process is downgraded one level unless the region carries strong content
# corroboration. This is a deliberate, documented evasion surface (README "Threat model").
JIT_HOST_MODULES = frozenset({
    "clrjit.dll", "coreclr.dll", "clr.dll", "mscorwks.dll", "jscript9.dll", "jscript.dll",
    "chakra.dll", "chakracore.dll", "edgehtml.dll", "chrome.dll", "msedge.dll", "libcef.dll",
    "xul.dll", "mozjs.dll", "jvm.dll", "mpengine.dll", "v8.dll", "node.dll", "python3.dll",
})

# --------------------------------------------------------------------------- #
# Finding catalogue
# --------------------------------------------------------------------------- #
# key -> (id, class, title, ATT&CK technique)
CATALOG: Dict[str, Tuple[str, int, str, str]] = {
    "IMAGE_BASE_MISMATCH": ("PEVAD-I01", 1, "PEB image base differs from the kernel's section base", "T1055.012"),
    "MAIN_IMAGE_NOT_IMAGE_VAD": ("PEVAD-I02", 1, "Process image base is not an image-backed VAD", "T1055.012"),
    "MAIN_IMAGE_FILE_MISMATCH": ("PEVAD-I03", 1, "Kernel image identity disagrees with the mapped image file", "T1055.012; T1055.013"),
    "PEB_PATH_MISMATCH": ("PEVAD-I04", 1, "PEB image path differs from the kernel's recorded image path", "T1036.005"),
    "MODULE_NAME_MISMATCH": ("PEVAD-I05", 1, "PEB module name differs from the file mapped at its base", "T1055.001; T1036.005"),
    "LOADED_MODULE_UNBACKED": ("PEVAD-I06", 1, "PEB lists a module where the kernel has no image mapping", "T1620; T1055"),
    "HIDDEN_IMAGE": ("PEVAD-I07", 1, "Image mapping with a valid PE header absent from every PEB loader list", "T1055.001"),
    "EXEC_PRIVATE_ORPHAN": ("PEVAD-II01", 2, "Committed executable private memory with no loaded module", "T1055; T1620"),
    "WX_PRIVATE": ("PEVAD-II02", 2, "Private memory that is both writable and executable", "T1055"),
    "WX_IMAGE": ("PEVAD-II03", 2, "Image mapping that is writable and executable (not copy-on-write)", "T1055"),
    "IMAGE_COVERAGE_DEFICIT": ("PEVAD-II04", 2, "Image mapping smaller than the PEB-declared module size", "T1055.012"),
    "HEADER_ANOMALY": ("PEVAD-II05", 2, "PE header at module base is malformed or inconsistent", "T1055; T1070"),
    "IMAGE_CODE_MODIFIED": ("PEVAD-II08", 2, "Executable pages of an image mapping are private (modified) copies", "T1055; T1562.001"),
    "MODULE_DIR_MISMATCH": ("PEVAD-II06", 2, "PEB module directory differs from the mapped file's directory", "T1574; T1036.005"),
    "LIST_INCONSISTENT": ("PEVAD-II07", 2, "Module present in only one of the InLoad / InMemory lists", "T1055.001"),
    "RISKY_MODULE_PATH": ("PEVAD-III01", 3, "Module loaded from a user-writable or remote location", "T1574"),
    "UNLISTED_IMAGE_UNVERIFIED": ("PEVAD-III02", 3, "Image mapping absent from PEB lists; cannot be verified", "T1055.001"),
    "MODULE_VAD_UNVERIFIED": ("PEVAD-III04", 3, "PEB lists a module with no VAD, but the VAD tree could not be proven complete", "T1620; T1055"),
    "HEADER_NOT_PE": ("PEVAD-III03", 3, "Page at module base is not a PE header (erased header or stale page)", "T1070; T1055"),
}

HYPOTHESIS = {
    "IMAGE_BASE_MISMATCH": "Process hollowing (image re-mapped at a new base, PEB updated)",
    "MAIN_IMAGE_NOT_IMAGE_VAD": "Process hollowing (original image unmapped, private memory at its base)",
    "MAIN_IMAGE_FILE_MISMATCH": "Process hollowing / ghosting / herpaderping (mapped file is not the launched file)",
    "PEB_PATH_MISMATCH": "Process masquerading (PEB image path edited)",
    "MODULE_NAME_MISMATCH": "Module masquerading or DLL substitution",
    "LOADED_MODULE_UNBACKED": "Manual mapping or stomping with a forged loader entry",
    "HIDDEN_IMAGE": "Module unlinked from the PEB loader lists (injected or hidden DLL)",
    "EXEC_PRIVATE_ORPHAN": "Shellcode or reflectively loaded code in private memory",
    "WX_PRIVATE": "Writable+executable private memory (staging, packer, or JIT)",
    "WX_IMAGE": "Writable+executable image mapping (patched or self-modifying module)",
    "IMAGE_COVERAGE_DEFICIT": "Partial image mapping beneath a PEB-declared module (hollowing)",
    "HEADER_ANOMALY": "Malformed or erased PE header (manual mapping, stomping)",
    "IMAGE_CODE_MODIFIED": "Inline hook, patch or stomped code in a file-backed module",
    "MODULE_DIR_MISMATCH": "Possible DLL hijack or path spoof (same name, different directory)",
    "LIST_INCONSISTENT": "Partial PEB loader-list unlink",
    "RISKY_MODULE_PATH": "Module loaded from a high-risk directory",
    "UNLISTED_IMAGE_UNVERIFIED": "Image mapping missing from loader lists (cannot be verified)",
    "HEADER_NOT_PE": "Erased PE header or stale page in a memory dump",
    "MODULE_VAD_UNVERIFIED": "Module without a VAD in an incompletely recovered VAD tree",
}

# A process that hosts the CLR maps IL assemblies as image sections without a loader-list entry.
CLR_HOST_MODULES = frozenset({"clr.dll", "coreclr.dll", "mscorwks.dll", "clrjit.dll"})

STRONG_TAGS = frozenset({"pe_header", "shellcode_stager"})
MIN_PEERS = 2        # identical modified bytes in >= 2 other processes of the same image = deployment-wide

# Class II findings that describe the same phenomenon share a family; independent evidence means
# different families (two RWX regions in one process are not independent of each other).
FAMILY = {
    "EXEC_PRIVATE_ORPHAN": "private_exec", "WX_PRIVATE": "private_exec",
    "WX_IMAGE": "image_state", "IMAGE_CODE_MODIFIED": "image_state",
    "IMAGE_COVERAGE_DEFICIT": "module_integrity", "HEADER_ANOMALY": "module_integrity",
    "MODULE_DIR_MISMATCH": "module_integrity", "LIST_INCONSISTENT": "module_integrity",
}


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
    end: int                       # half-open
    protection: str
    vad_type: str                  # "IMAGE" | "PRIVATE" | "MAPPED"
    file_path: Optional[str]
    commit: Optional[int] = None   # committed bytes; None = unknown


class OverlapPair(NamedTuple):
    module: PebModule
    vad: VadNode
    overlap_bytes: int


class KernelFacts(NamedTuple):
    """What the kernel (and the PEB) say about the process image. None = could not be read."""
    image_name: Optional[str] = None        # EPROCESS.ImageFileName (<= 15 chars)
    audit_path: Optional[str] = None        # SeAuditProcessCreationInfo.ImageFileName
    section_base: Optional[int] = None      # EPROCESS.SectionBaseAddress
    peb_image_base: Optional[int] = None    # PEB.ImageBaseAddress
    peb_image_path: Optional[str] = None    # PEB.ProcessParameters.ImagePathName
    is_wow64: bool = False
    build_number: Optional[int] = None      # Windows build number (e.g. 17134, 9200)


class Finding(NamedTuple):
    fid: str
    key: str
    cls: int
    title: str
    technique: str
    start: Optional[int]
    end: Optional[int]
    protection: str
    backing: str
    evidence: str
    confidence: str                  # "confirmed" | "probable" | "possible"
    subject: Tuple                   # grouping key: same subject => one piece of evidence
    tags: Tuple[str, ...] = ()
    downgraded: bool = False


class ImagePageInfo(NamedTuple):
    """Deep-mode census of one image mapping's executable (sub)sections."""
    start: int
    end: int
    path: str
    resident: int                                  # resident executable pages examined
    shared: int                                    # backed by the image's prototype PTEs (normal)
    stale: int                                     # frame no longer owned by this mapping (dump artefact)
    private: List[Tuple[int, str, Tuple[str, ...]]]   # (page VA, content digest, content tags)
    peers: int = 0                                 # other processes of the same image with identical bytes


class ProcessReport(NamedTuple):
    pid: int
    name: str
    tier: int
    score: int
    findings: List[Finding]
    hypothesis: str
    coverage: Dict[str, object]
    notes: List[str]
    jit_hosts: List[str]


# --------------------------------------------------------------------------- #
# Protection / path helpers
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
    """Windows protection names -> {R, W, X, C}. Copy-on-write is C, not W."""
    flags = set()
    for token in (protection or "").upper().replace(" ", "").split("|"):
        flags |= _PROT_MAP.get(token, frozenset())
    return frozenset(flags)


def canon_path(path: Optional[str]) -> str:
    """Canonical comparison form. VAD file names carry no drive letter; PEB names do."""
    if not path:
        return ""
    p = path.strip().replace("/", "\\").lower()
    p = p.replace("%systemroot%", "\\windows").replace("%windir%", "\\windows")
    p = re.sub(r"^\\\?\?\\", "", p)
    p = re.sub(r"^\\\\\?\\", "", p)
    p = re.sub(r"^\\systemroot\\", "\\\\windows\\\\", p)
    if p.startswith("\\device\\mup\\"):
        p = "\\\\" + p[len("\\device\\mup\\"):]
    p = re.sub(r"^\\device\\[^\\]+(\\dp\(\d+\)[^\\]*)?", "", p)
    p = re.sub(r"^unc\\", "\\\\\\\\", p)
    p = re.sub(r"^[a-z]:", "", p)
    unc = p.startswith("\\\\")
    p = re.sub(r"\\{2,}", "\\\\", p)
    return ("\\" + p) if unc else p


_TRUSTED_PREFIXES = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
                     "\\program files\\", "\\program files (x86)\\")
_USER_WRITABLE = ("\\users\\", "\\programdata\\", "\\windows\\tasks\\", "\\windows\\debug\\",
                  "\\$recycle.bin\\", "\\perflogs\\")


def dir_risk(canon: str) -> float:
    """0.0 trusted .. 1.0 temp/downloads. Unknown = 0.3."""
    if not canon:
        return 0.3
    p = canon if canon.endswith("\\") else canon + "\\"
    if "\\temp\\" in p or "\\downloads\\" in p:
        return 1.0
    if canon.startswith("\\\\"):
        return 0.8
    if p.startswith(_TRUSTED_PREFIXES):
        return 0.0
    if p.startswith(_USER_WRITABLE):
        return 0.6
    return 0.3


def _basename(canon: str) -> str:
    return canon.rsplit("\\", 1)[-1]


def _is_plausible_path(path: Optional[str]) -> bool:
    """Check if a string looks like a plausible Windows file path (not garbled).
    Returns False for strings that are clearly corrupted (random chars, non-printable)."""
    if not path or len(path) < 3:
        return False
    # Common path prefixes
    if not (path.startswith("\\") or path.startswith("C:") or path.startswith("D:") or
            path.lower().startswith("\\device\\") or path.lower().startswith("\\\\?")):
        return False
    # Check for printable characters (allow backslash, colon, hyphen, dot, space)
    for ch in path:
        if ord(ch) < 0x20 and ch not in "\t\n\r":  # non-printable except whitespace
            return False
        # High-byte chars mixed with ASCII often indicate corruption
        if ord(ch) > 0x7f:
            return False
    # Should have at least one dot (file extension) or end with backslash
    if not ("." in path or path.endswith("\\") or path.endswith(")")):
        return False
    return True


def _is_plausible_peb_base(addr: Optional[int]) -> bool:
    """Check if a PEB base address looks plausible (not corrupted).
    Valid image bases are page-aligned and not obviously garbage values."""
    if addr is None or addr == 0:
        return False
    # Common garbage values that appear in corrupted PEB reads
    if addr in (0x30323737, 0xcccccccc, 0xfffffffe, 0xffffffff, 0xdeadbeef, 0xbadf00d):
        return False
    # Image bases are usually page-aligned (0x1000) or larger alignment
    if addr < 0x10000:
        return False
    # On 64-bit Windows, ASLR places images up to ~0x7FFF...FFFF; allow up to 1 PB for safety
    if addr > 0x10000000000000:  # > 1 PB (unrealistic)
        return False
    # Every real PE image base is page-aligned; a non-aligned "base" is a smeared/garbled
    # PEB field, not an image load address
    if addr & 0xFFF:
        return False
    return True


def _fold_wow64(canon: str) -> str:
    """WOW64 file-system redirection: a 32-bit loader records C:\\Windows\\System32\\x.dll for the
    file the kernel maps from \\Windows\\SysWOW64\\x.dll. Only applied to WOW64 processes."""
    return canon.replace("\\windows\\syswow64\\", "\\windows\\system32\\")


def paths_equal(a: Optional[str], b: Optional[str], wow64: bool = False) -> Optional[bool]:
    """Tri-state path comparison. None = cannot decide (missing side or 8.3 short names)."""
    ca, cb = canon_path(a), canon_path(b)
    if not ca or not cb:
        return None
    if ca == cb:
        return True
    if wow64 and _fold_wow64(ca) == _fold_wow64(cb):
        return True
    if re.search(r"~\d", ca) or re.search(r"~\d", cb):
        return None
    return False


# --------------------------------------------------------------------------- #
# Interval join and VAD lookup
# --------------------------------------------------------------------------- #

def sweep_line_join(modules: List[PebModule], vads: List[VadNode]) -> List[OverlapPair]:
    """All (module, VAD) pairs with non-empty overlap in O(n log n + m log m + K)."""
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


def find_vad(sorted_vads: List[VadNode], starts: List[int], addr: int) -> Optional[VadNode]:
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and sorted_vads[i].start <= addr < sorted_vads[i].end:
        return sorted_vads[i]
    return None


# --------------------------------------------------------------------------- #
# PE header and content analysis
# --------------------------------------------------------------------------- #

def has_pe_signature(header: bytes) -> bool:
    if len(header) >= 0x40 and header[:2] == b"MZ":
        (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
        return 0 < e_lfanew <= len(header) - 4 and header[e_lfanew:e_lfanew + 4] == b"PE\0\0"
    return False


def check_pe_header(header: bytes, peb_size: int, base: int, sorted_vads: List[VadNode],
                    starts: List[int]) -> Tuple[int, List[str]]:
    """Four header checks. Returns (failed checks 0-4, notes)."""
    fails, notes = 0, []
    if not has_pe_signature(header):
        return 4, ["no valid MZ/PE signature at declared base"]
    (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
    pe_off = e_lfanew
    num_sections, = struct.unpack_from("<H", header, pe_off + 6)
    opt_size, = struct.unpack_from("<H", header, pe_off + 20)
    opt_off = pe_off + 24
    if opt_off + 60 > len(header):
        return 1, ["truncated optional header"]
    size_of_image, = struct.unpack_from("<I", header, opt_off + 56)
    if peb_size > 0 and abs(size_of_image - peb_size) > HEADER_SIZE_TOLERANCE * peb_size:
        fails += 1
        notes.append(f"SizeOfImage 0x{size_of_image:x} differs >20% from PEB size 0x{peb_size:x}")
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


def pe_is_managed(header: bytes) -> bool:
    """True when the PE carries a CLR (COM descriptor) data directory, i.e. a .NET assembly."""
    if not has_pe_signature(header):
        return False
    (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
    opt_off = e_lfanew + 24
    if opt_off + 2 > len(header):
        return False
    magic, = struct.unpack_from("<H", header, opt_off)
    dd_off = opt_off + {0x10B: 96, 0x20B: 112}.get(magic, -opt_off)
    entry = dd_off + 14 * 8
    if dd_off <= 0 or entry + 8 > len(header):
        return False
    va, size = struct.unpack_from("<II", header, entry)
    return va != 0 and size != 0


# cld; and rsp,-16  |  cld; call +<=255 (rel32 high bytes zero)  |  cld; pushad; mov ebp,esp
_RE_STAGER = re.compile(rb"\xFC\x48\x83\xE4\xF0|\xFC\xE8.\x00\x00\x00|\xFC\x60\x89\xE5", re.S)
_RE_PEB = re.compile(
    rb"\x65\x48\x8B[\x04\x0C\x14\x1C\x24\x2C\x34\x3C]\x25\x60\x00\x00\x00"
    rb"|\x65\x48\x8B[\x40-\x47]\x60"
    rb"|\x64\xA1\x30\x00\x00\x00"
    rb"|\x64\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]\x30\x00\x00\x00"
    rb"|\x64\x8B[\x40-\x47]\x30", re.S)
_RE_ROR13 = re.compile(rb"\xC1[\xC8-\xCF]\x0D")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def scan_runs(runs: List[bytes]) -> List[str]:
    """Content corroboration tags for the readable bytes of a region.
    pe_header / shellcode_stager are strong; peb_access+ror13_hash together are strong;
    the rest are weak."""
    tags: List[str] = []
    for data in runs:
        pos = data.find(b"MZ")
        while pos != -1 and pos < len(data) - 0x40:
            (e_lfanew,) = struct.unpack_from("<I", data, pos + 0x3C)
            if 0x40 <= e_lfanew <= 0x1000 and data[pos + e_lfanew:pos + e_lfanew + 4] == b"PE\0\0":
                tags.append("pe_header")
                break
            pos = data.find(b"MZ", pos + 2)
        if _RE_STAGER.search(data):
            tags.append("shellcode_stager")
        if _RE_PEB.search(data):
            tags.append("peb_access")
        if _RE_ROR13.search(data):
            tags.append("ror13_hash")
    joined = b"".join(runs)
    if len(joined) >= 4096 and _entropy(joined) > 7.2:
        tags.append("high_entropy")
    return sorted(set(tags))


def strong_corroboration(tags) -> bool:
    t = set(tags)
    return bool(t & STRONG_TAGS) or {"peb_access", "ror13_hash"} <= t


Reader = Callable[[int, int], Optional[bytes]]


def sample_region(reader: Reader, start: int, end: int, limit: int = REGION_SAMPLE_BYTES):
    """Read up to `limit` bytes page by page. Returns (runs of contiguous readable bytes,
    pages read, pages unreadable)."""
    runs: List[bytes] = []
    cur = bytearray()
    ok = bad = 0
    pos, stop = start & ~0xFFF, min(end, (start & ~0xFFF) + limit)
    while pos < stop:
        data = reader(pos, min(0x1000, stop - pos))
        if data is None:
            bad += 1
            if cur:
                runs.append(bytes(cur))
                cur = bytearray()
        else:
            ok += 1
            cur += data
        pos += 0x1000
    if cur:
        runs.append(bytes(cur))
    return runs, ok, bad


# --------------------------------------------------------------------------- #
# Process analysis (pure logic: no Volatility objects)
# --------------------------------------------------------------------------- #

def _mk(key, start, end, prot, backing, evidence, confidence, subject, tags=(), downgraded=False):
    fid, cls, title, tech = CATALOG[key]
    return Finding(fid, key, cls, title, tech, start, end, prot, backing, evidence, confidence,
                   subject, tuple(tags), downgraded)


def _kb(n: int) -> str:
    return f"{n // 1024} KB"


def _flags(prot: str) -> str:
    return "".join(sorted(parse_protection(prot) - {"C"})) or "-"


def analyse_process(
    pid: int,
    name: str,
    modules: Optional[List[PebModule]],
    vads: List[VadNode],
    facts: KernelFacts,
    reader: Reader,
    lists_present: Tuple[bool, bool, bool] = (True, True, True),
    lists_complete: bool = True,
    vads_complete: Optional[bool] = True,
    image_pages: Optional[List[ImagePageInfo]] = None,
    is_stale: Callable[[int], bool] = lambda addr: False,
) -> ProcessReport:
    findings: List[Finding] = []
    notes: List[str] = []
    cov: Dict[str, object] = {
        "peb_modules": None if modules is None else len(modules), "vads": len(vads),
        "headers_checked": 0, "headers_unreadable": 0, "paths_unresolved": 0,
        "regions_scanned": 0, "regions_unreadable_pages": 0,
        "kernel_section_base": facts.section_base is not None,
        "kernel_audit_path": facts.audit_path is not None,
        "peb_image_base": facts.peb_image_base is not None,
        "loader_lists_complete": lists_complete,
        "vad_tree_complete": vads_complete,
    }
    sorted_vads = sorted(vads, key=lambda v: v.start)
    starts = [v.start for v in sorted_vads]
    wow64 = facts.is_wow64
    jit_hosts = sorted({m.base_name.lower() for m in (modules or [])} & JIT_HOST_MODULES)
    clr_host = bool({m.base_name.lower() for m in (modules or [])} & CLR_HOST_MODULES)
    checks_run = 0

    # ---- main image: kernel facts against each other and against the PEB ------------------
    main_vad = None
    sb = facts.section_base
    if sb and sorted_vads:
        checks_run += 1
        main_vad = find_vad(sorted_vads, starts, sb)
        if main_vad is None:
            findings.append(_mk(
                "MAIN_IMAGE_NOT_IMAGE_VAD" if vads_complete else "MODULE_VAD_UNVERIFIED",
                sb, sb + 0x1000, "", "",
                f"EPROCESS.SectionBaseAddress 0x{sb:x} lies in no VAD"
                + ("" if vads_complete else " (VAD tree not proven complete)"),
                "probable" if vads_complete else "possible", ("main",)))
        elif main_vad.vad_type != "IMAGE":
            findings.append(_mk(
                "MAIN_IMAGE_NOT_IMAGE_VAD", main_vad.start, main_vad.end, main_vad.protection,
                main_vad.file_path or "",
                f"EPROCESS.SectionBaseAddress 0x{sb:x} is in a {main_vad.vad_type} VAD "
                f"(0x{main_vad.start:x}-0x{main_vad.end:x}, {_flags(main_vad.protection)}), not an image mapping",
                "confirmed", ("main",)))
        else:
            # Validate kernel-side paths before trusting them
            audit_plausible = _is_plausible_path(facts.audit_path)
            mapped_plausible = _is_plausible_path(main_vad.file_path)
            if (facts.audit_path and main_vad.file_path and
                (not audit_plausible or not mapped_plausible)):
                # Garbled strings: treat as unknown, don't report a contradiction
                if not audit_plausible:
                    cov["paths_unresolved"] = cov.get("paths_unresolved", 0) + 1
            else:
                eq = paths_equal(facts.audit_path, main_vad.file_path, wow64)
                if eq is None and facts.audit_path and main_vad.file_path:
                    cov["paths_unresolved"] += 1
                if eq is False:
                    findings.append(_mk(
                        "MAIN_IMAGE_FILE_MISMATCH", main_vad.start, main_vad.end, main_vad.protection,
                        main_vad.file_path or "",
                        f"kernel audit path '{facts.audit_path}' vs file mapped at image base "
                        f"'{main_vad.file_path}'", "confirmed", ("main",)))
            if facts.image_name and main_vad.file_path:
                base = _basename(canon_path(main_vad.file_path))
                short = facts.image_name.lower()
                # EPROCESS.ImageFileName is char[15]: at most 14 visible characters
                name_ok = base == short or (len(short) >= 14 and base.startswith(short))
                if not name_ok and not re.search(r"~\d", base):
                    # Only report if the mapped file path looks valid
                    if _is_plausible_path(main_vad.file_path):
                        findings.append(_mk(
                            "MAIN_IMAGE_FILE_MISMATCH", main_vad.start, main_vad.end,
                            main_vad.protection, main_vad.file_path or "",
                            f"EPROCESS.ImageFileName '{facts.image_name}' vs mapped file '{base}'",
                            "probable", ("main",)))
    if facts.section_base and facts.peb_image_base:
        checks_run += 1
        # Validate PEB base address is plausible
        if not _is_plausible_peb_base(facts.peb_image_base):
            # PEB base looks corrupted; treat as unknown
            cov["paths_unresolved"] = cov.get("paths_unresolved", 0) + 1
        elif facts.section_base != facts.peb_image_base:
            findings.append(_mk(
                "IMAGE_BASE_MISMATCH", facts.peb_image_base, facts.peb_image_base + 0x1000, "", "",
                f"PEB.ImageBaseAddress 0x{facts.peb_image_base:x} != EPROCESS.SectionBaseAddress "
                f"0x{facts.section_base:x}", "confirmed", ("main-peb",)))
    if facts.peb_image_path and facts.audit_path:
        checks_run += 1
        # Validate both paths are plausible before comparing
        peb_plausible = _is_plausible_path(facts.peb_image_path)
        audit_plausible = _is_plausible_path(facts.audit_path)
        if not peb_plausible or not audit_plausible:
            # Garbled path; treat as unknown
            cov["paths_unresolved"] += 1
        else:
            eq = paths_equal(facts.peb_image_path, facts.audit_path, wow64)
            if eq is None:
                cov["paths_unresolved"] += 1
            elif eq is False:
                findings.append(_mk(
                    "PEB_PATH_MISMATCH", None, None, "", "",
                    f"PEB ImagePathName '{facts.peb_image_path}' vs kernel audit path "
                    f"'{facts.audit_path}'", "confirmed", ("main-path",)))

    # ---- module / VAD cross-validation (needs the PEB loader lists) -----------------------
    pairs: List[OverlapPair] = []
    overlapped = set()
    if modules is not None and sorted_vads:
        checks_run += 1
        pairs = sweep_line_join(modules, vads)
        overlapped = {id(p.vad) for p in pairs}
        image_cover: Dict[int, int] = {}
        for p in pairs:
            if p.vad.vad_type == "IMAGE":
                image_cover[p.module.base] = image_cover.get(p.module.base, 0) + p.overlap_bytes
        for m in sorted(modules, key=lambda m: m.base):
            label = m.base_name or hex(m.base)
            # A PEB module record itself can be corrupted (smeared/paged-out buffer): an
            # implausible base/size or an unreadable name means the record cannot be trusted
            # as evidence either way, so these checks are skipped entirely for this module.
            peb_record_plausible = (_is_plausible_peb_base(m.base) and 0 < m.size <= 0x40000000
                                     and _is_plausible_path(m.full_name))
            v0 = find_vad(sorted_vads, starts, m.base)
            if v0 is None or v0.vad_type != "IMAGE":
                if not peb_record_plausible:
                    cov["paths_unresolved"] = cov.get("paths_unresolved", 0) + 1
                    continue
                what = "no VAD" if v0 is None else f"a {v0.vad_type} VAD ({_flags(v0.protection)})"
                key = "LOADED_MODULE_UNBACKED" if (v0 is not None or vads_complete) else "MODULE_VAD_UNVERIFIED"
                findings.append(_mk(
                    key, m.base, m.base + m.size,
                    v0.protection if v0 else "", v0.file_path or "" if v0 else "",
                    f"{label}: PEB lists base 0x{m.base:x} ({_kb(m.size)}) but the kernel has {what} there"
                    + ("" if key == "LOADED_MODULE_UNBACKED" else " (VAD tree not proven complete)"),
                    ("probable" if v0 is None else "confirmed") if key == "LOADED_MODULE_UNBACKED" else "possible",
                    ("mod", m.base)))
                continue

            # path agreement between the PEB claim and the file the kernel mapped.
            # Validate BOTH sides before trusting either as evidence: a garbled PEB-side
            # module name (smeared/paged-out Unicode buffer) looks identical to a masquerade.
            peb_name_plausible = _is_plausible_path(m.full_name)
            kernel_path_plausible = _is_plausible_path(v0.file_path)
            if not peb_name_plausible or not kernel_path_plausible:
                cov["paths_unresolved"] += 1
            else:
                eq = paths_equal(m.full_name, v0.file_path, wow64)
                if eq is None:
                    cov["paths_unresolved"] += 1
                elif eq is False:
                    ca, cb = canon_path(m.full_name), canon_path(v0.file_path)
                    if _basename(ca) != _basename(cb):
                        findings.append(_mk(
                            "MODULE_NAME_MISMATCH", v0.start, v0.end, v0.protection, v0.file_path or "",
                            f"{label}: PEB '{m.full_name}' vs mapped '{v0.file_path}'", "confirmed",
                            ("mod", m.base)))
                    else:
                        findings.append(_mk(
                            "MODULE_DIR_MISMATCH", v0.start, v0.end, v0.protection, v0.file_path or "",
                            f"{label}: PEB '{m.full_name}' vs mapped '{v0.file_path}'", "possible",
                            ("mod", m.base)))
            risk = dir_risk(canon_path(v0.file_path or m.full_name))
            if risk >= 0.8:
                findings.append(_mk(
                    "RISKY_MODULE_PATH", v0.start, v0.end, v0.protection, v0.file_path or "",
                    f"{label} loaded from {v0.file_path or m.full_name} (directory risk {risk:.1f})",
                    "possible", ("mod", m.base)))

            # coverage deficit
            covered = image_cover.get(m.base, 0)
            deficit = m.size - covered
            if deficit >= DEFICIT_MIN_BYTES and deficit / m.size >= DEFICIT_MIN_FRACTION:
                findings.append(_mk(
                    "IMAGE_COVERAGE_DEFICIT", m.base, m.base + m.size, v0.protection,
                    v0.file_path or "",
                    f"{label}: PEB size {_kb(m.size)} but IMAGE mapping covers {_kb(covered)} "
                    f"({deficit / m.size:.0%} deficit)", "probable", ("mod", m.base)))

            # list consistency (only when both lists were readable at all)
            if lists_complete and lists_present[0] and lists_present[2] and m.in_load != m.in_mem:
                where = "InLoad" if m.in_load else "InMemory"
                findings.append(_mk(
                    "LIST_INCONSISTENT", m.base, m.base + m.size, v0.protection, v0.file_path or "",
                    f"{label}: present only in {where} order list", "possible", ("mod", m.base)))

            # header sanity (tri-state)
            header = None if is_stale(m.base) else reader(m.base, 0x1000)
            if is_stale(m.base):
                cov["headers_stale"] = cov.get("headers_stale", 0) + 1
            if header is None or not any(header):
                cov["headers_unreadable"] += 1
            else:
                cov["headers_checked"] += 1
                fails, hnotes = check_pe_header(header, m.size, m.base, sorted_vads, starts)
                if fails > 0:
                    first = header[:16].hex()
                    if not has_pe_signature(header) and header[:2] != b"MZ":
                        # No MZ at all: an erased header and a stale page in a dump look the
                        # same, so this is context only.
                        findings.append(_mk(
                            "HEADER_NOT_PE", m.base, m.base + m.size, v0.protection,
                            v0.file_path or "",
                            f"{label}: no MZ at declared base (first bytes {first})",
                            "possible", ("mod", m.base)))
                    else:
                        findings.append(_mk(
                            "HEADER_ANOMALY", m.base, m.base + m.size, v0.protection,
                            v0.file_path or "",
                            f"{label}: " + "; ".join(hnotes) + f" (first bytes {first})",
                            "probable", ("mod", m.base)))

        # image mappings no loader list knows about. Non-executable image mappings are resource
        # loads (LOAD_LIBRARY_AS_IMAGE_RESOURCE) and are not modules; managed assemblies in a CLR
        # host are mapped by the CLR itself, not by the loader.
        unverified: List[VadNode] = []
        for v in sorted_vads:
            if v.vad_type != "IMAGE" or id(v) in overlapped:
                continue
            if "X" not in parse_protection(v.protection):
                cov["resource_images"] = cov.get("resource_images", 0) + 1
                continue
            header = None if is_stale(v.start) else reader(v.start, 0x1000)
            if header is None or not any(header):
                cov["headers_unreadable"] += 1
                unverified.append(v)
            elif has_pe_signature(header):
                if clr_host and pe_is_managed(header):
                    cov["managed_images"] = cov.get("managed_images", 0) + 1
                    continue
                if not lists_complete:
                    unverified.append(v)       # the loader-list walk was cut short: unprovable
                    continue
                # On pre-Win8 (build < 9200), resource mappings (LOAD_LIBRARY_AS_IMAGE_RESOURCE,
                # e.g. imageres.dll, .mui files) always show EXECUTE_WRITECOPY and have no loader
                # entry, so they look identical to a hidden/injected image. This is a known
                # structural false-positive class on these builds (not a rule we are tuning to
                # the data): downgrade the finding to Info rather than suppress it.
                is_pre_win8 = facts.build_number is not None and facts.build_number < 9200
                findings.append(_mk(
                    "HIDDEN_IMAGE", v.start, v.end, v.protection, v.file_path or "",
                    f"IMAGE VAD 0x{v.start:x}-0x{v.end:x} ({v.file_path or 'no file name'}) has a "
                    f"valid PE header but is in no PEB list" +
                    (" (pre-Win8 build: image VADs loaded as resources have no loader entry and "
                     "are reported here as context, not as a hidden-image finding)"
                     if is_pre_win8 else " (all loader lists walked to their head)"),
                    "probable" if is_pre_win8 else "confirmed", ("vad", v.start),
                    downgraded=is_pre_win8))
        if unverified:
            first = unverified[0]
            names = ", ".join((_basename(canon_path(v.file_path)) or hex(v.start))
                              for v in unverified[:5])
            findings.append(_mk(
                "UNLISTED_IMAGE_UNVERIFIED", first.start, first.end, first.protection,
                first.file_path or "",
                f"{len(unverified)} executable IMAGE VAD(s) in no PEB list that cannot be verified "
                f"({'loader-list walk incomplete' if not lists_complete else 'header unreadable'}; "
                f"e.g. {names})", "possible", ("unlisted",)))

    elif modules is None and sorted_vads:
        notes.append("PEB loader lists unreadable: module and header checks not run "
                     "(orphan-memory/WX checks below need only the kernel VAD tree and still ran)")
    elif modules is None:
        notes.append("PEB loader lists unreadable: module, orphan-memory and header checks not run")

    # ---- private / writable-executable memory (kernel VAD tree only; no PEB needed, so this
    # runs even when the PEB loader lists above were unreadable -- malfind-equivalent coverage
    # must not depend on a readable PEB) --------------------------------------------------
    if sorted_vads:
        checks_run += 1
        candidates = []
        for v in sorted_vads:
            prot = parse_protection(v.protection)
            if v.vad_type == "IMAGE" and {"W", "X"} <= prot:
                findings.append(_mk(
                    "WX_IMAGE", v.start, v.end, v.protection, v.file_path or "",
                    f"IMAGE VAD 0x{v.start:x}-0x{v.end:x} is {_flags(v.protection)}", "probable",
                    ("vad", v.start)))
            elif v.vad_type == "PRIVATE" and "X" in prot and (v.commit is None or v.commit > 0):
                candidates.append(v)
        candidates.sort(key=lambda v: -(v.end - v.start))
        if len(candidates) > MAX_REGIONS_SCANNED:
            notes.append(f"{len(candidates) - MAX_REGIONS_SCANNED} smaller executable private "
                         f"region(s) not content-scanned")
        for idx, v in enumerate(candidates):
            tags: List[str] = []
            if idx < MAX_REGIONS_SCANNED:
                runs, ok, bad = sample_region(reader, v.start, v.end)
                cov["regions_scanned"] += 1
                cov["regions_unreadable_pages"] += bad
                tags = scan_runs(runs) if ok else ["content_unreadable"]
            prot = parse_protection(v.protection)
            size = v.end - v.start
            committed = v.commit if v.commit is not None else size
            tagtxt = f"; content: {', '.join(tags)}" if tags else ""
            downgraded = bool(jit_hosts) and not strong_corroboration(tags)
            if id(v) not in overlapped:
                findings.append(_mk(
                    "EXEC_PRIVATE_ORPHAN", v.start, v.end, v.protection, "",
                    f"0x{v.start:x}-0x{v.end:x}: {_kb(size)} ({_kb(committed)} committed), "
                    f"{_flags(v.protection)}, PRIVATE, no PEB module{tagtxt}",
                    "probable", ("vad", v.start), tags, downgraded))
            if {"W", "X"} <= prot:
                findings.append(_mk(
                    "WX_PRIVATE", v.start, v.end, v.protection, "",
                    f"0x{v.start:x}-0x{v.end:x}: {_kb(size)} private {_flags(v.protection)}{tagtxt}",
                    "probable", ("vad", v.start), tags, downgraded))

    # ---- deep: private (modified) executable pages inside image mappings -----------------
    if image_pages is not None:
        # deliberately not counted in checks_run: deep mode adds evidence, it never turns an
        # otherwise Unevaluated process (no PEB, no section base) into a "Clean" one
        cov["exec_pages_examined"] = sum(ip.resident for ip in image_pages)
        cov["exec_pages_stale"] = sum(ip.stale for ip in image_pages)
        for ip in image_pages:
            if not ip.private:
                continue
            cpath = canon_path(ip.path)
            base_name = _basename(cpath)
            if clr_host and (base_name.endswith((".ni.dll", ".ni.exe")) or "\\assembly\\nativeimages" in cpath
                             or base_name in CLR_HOST_MODULES):
                cov["ngen_images_skipped"] = cov.get("ngen_images_skipped", 0) + 1
                continue
            peer = ip.peers >= MIN_PEERS
            tags = sorted({t for _, _, ts in ip.private for t in ts} | ({"peer_consistent"} if peer else set()))
            first = ", ".join(f"0x{va:x}" for va, _, _ in ip.private[:3])
            # same documented JIT-host downgrade used for EXEC_PRIVATE_ORPHAN/WX_PRIVATE above:
            # a JIT/managed-runtime host (Edge/Chrome/CLR/etc.) legitimately self-modifies its own
            # mapped code pages, which looks identical to a hooked image unless corroborated.
            jit_downgrade = bool(jit_hosts) and not strong_corroboration(tags)
            findings.append(_mk(
                "IMAGE_CODE_MODIFIED", ip.start, ip.end, "", ip.path,
                f"{base_name or hex(ip.start)}: {len(ip.private)} of {ip.resident} resident executable "
                f"page(s) are private copies (e.g. {first})"
                + (f"; identical bytes in {ip.peers} other process(es) of this image: likely a product hook"
                   if peer else "")
                + (" (process hosts a JIT/managed runtime; downgraded absent strong content "
                   "corroboration)" if jit_downgrade and not peer else ""),
                "probable", ("vad", ip.start), tags, peer or jit_downgrade))

    if checks_run == 0:
        return ProcessReport(pid, name, UNEVALUATED, 0, [], "", cov,
                             notes + ["no check could run (no PEB, no section base, no VADs)"], jit_hosts)

    tier, score = classify(findings)
    top = _top_finding(findings)
    return ProcessReport(pid, name, tier, score, findings,
                         HYPOTHESIS[top.key] if top else "", cov, notes, jit_hosts)


_TRAMPOLINE = re.compile(rb"(\x48\xb8|\x49\xbb)(.{8})(\xff\xe0|\x41\xff\xe3)", re.S)


def mask_trampolines(data: bytes) -> bytes:
    """Zero the 64-bit absolute target of `mov rax/r11, imm64; jmp rax/r11` trampolines so that the
    same inline hook installed in two ASLR-different processes hashes identically. The patched
    bytes are still reported; only the peer comparison uses the masked form."""
    return _TRAMPOLINE.sub(lambda m: m.group(1) + b"\0" * 8 + m.group(3), data)


def mark_peers(per_process: List[Tuple[str, List[ImagePageInfo]]]) -> List[List[ImagePageInfo]]:
    """Fill ImagePageInfo.peers. per_process = [(main_image_key, pages)] one entry per process.
    peers = number of OTHER processes with the same main image whose copy of the same module has
    the same page (same offset inside the mapping, same content digest) modified. Deployment-wide
    identical patches (a sandbox's ntdll interceptions, an EDR hook) are product behaviour; an
    intrusion normally touches one process."""
    seen: Dict[Tuple[str, str, int, str], set] = {}
    for idx, (main_key, pages) in enumerate(per_process):
        for ip in pages:
            name = _basename(canon_path(ip.path))
            for va, digest, _tags in ip.private:
                seen.setdefault((main_key, name, va - ip.start, digest), set()).add(idx)
    out = []
    for idx, (main_key, pages) in enumerate(per_process):
        updated = []
        for ip in pages:
            name = _basename(canon_path(ip.path))
            counts = [len(seen[(main_key, name, va - ip.start, digest)]) - 1 for va, digest, _t in ip.private]
            updated.append(ip._replace(peers=min(counts) if counts else 0))
        out.append(updated)
    return out


# --------------------------------------------------------------------------- #
# Tier rules
# --------------------------------------------------------------------------- #

def finding_level(f: Finding) -> int:
    """Effective level of one finding after corroboration / downgrade."""
    if f.cls == 1:
        if f.downgraded:
            return INFO
        return HIGH if f.confidence != "possible" else SUSPICIOUS
    if f.cls == 2:
        if strong_corroboration(f.tags):
            return HIGH
        if f.downgraded:
            return INFO
        return SUSPICIOUS
    return INFO


def classify(findings: List[Finding]) -> Tuple[int, int]:
    """Process tier and ordinal triage score (0-100; for sorting, not a probability).

    High       any confirmed/probable class I finding; any class II finding with strong content
               corroboration; or class II findings from >= 2 different families (independent
               evidence: private executable memory, image state, module integrity).
    Suspicious any class II finding (not JIT-downgraded), or a possible class I finding.
    Info       class III findings or JIT-downgraded class II findings.
    Clean      nothing."""
    if not findings:
        return CLEAN, 0
    levels = [finding_level(f) for f in findings]
    tier = max(levels)
    sus = [f for f, lv in zip(findings, levels) if lv == SUSPICIOUS and f.cls == 2]
    if tier < HIGH and len({FAMILY[f.key] for f in sus}) >= 2:
        tier = HIGH
    base = {HIGH: 85, SUSPICIOUS: 55, INFO: 20, CLEAN: 0}[tier]
    if tier == HIGH and max(levels) == HIGH and any(f.cls == 2 and strong_corroboration(f.tags) for f in findings):
        base = 90
    if any(f.cls == 1 and f.confidence == "confirmed" for f in findings):
        base = 95
    extra = min(10, 3 * (len({f.subject for f in findings if finding_level(f) >= SUSPICIOUS}) - 1))
    return tier, min(100, base + max(0, extra))


def _top_finding(findings: List[Finding]) -> Optional[Finding]:
    if not findings:
        return None
    return min(findings, key=lambda f: (-finding_level(f), f.cls, f.fid))


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #

def finding_to_dict(f: Finding) -> Dict[str, object]:
    return {
        "id": f.fid, "key": f.key, "class": f.cls, "title": f.title, "technique": f.technique,
        "start": None if f.start is None else hex(f.start),
        "end": None if f.end is None else hex(f.end),
        "protection": f.protection, "backing": f.backing, "evidence": f.evidence,
        "confidence": f.confidence, "corroboration": list(f.tags),
        "jit_downgraded": f.downgraded, "level": TIER_NAME[finding_level(f)],
    }


def coverage_text(cov: Dict[str, object]) -> str:
    parts = []
    if cov.get("peb_modules") is None:
        parts.append("PEB unreadable")
    else:
        checked, unread = cov["headers_checked"], cov["headers_unreadable"]
        parts.append(f"modules {cov['peb_modules']}, headers readable {checked}/{checked + unread}")
    kernel_ok = "/".join(n for n, k in (("section", "kernel_section_base"),
                                        ("audit", "kernel_audit_path"),
                                        ("pebbase", "peb_image_base")) if cov.get(k))
    parts.append("kernel facts: " + (kernel_ok or "none"))
    if cov.get("paths_unresolved"):
        parts.append(f"{cov['paths_unresolved']} path(s) undecidable")
    if cov.get("regions_scanned"):
        parts.append(f"{cov['regions_scanned']} region(s) content-scanned")
    return "; ".join(parts)


def report_to_dict(r: ProcessReport) -> Dict[str, object]:
    return {
        "pevad_version": PEVAD_VERSION, "pid": r.pid, "process": r.name, "tier": TIER_NAME[r.tier],
        "score": r.score, "hypothesis": r.hypothesis, "coverage": r.coverage, "notes": r.notes,
        "jit_hosts": r.jit_hosts, "findings": [finding_to_dict(f) for f in r.findings],
    }


# --------------------------------------------------------------------------- #
# The plugin
# --------------------------------------------------------------------------- #

class Pevad(interfaces.plugins.PluginInterface):
    """Cross-validates the PEB, VAD tree and kernel image records of every process and reports
    explainable findings of process hollowing, unlinked/hidden modules, reflective code and
    image masquerading."""

    _required_framework_version = (2, 27, 0)
    _version = (2, 0, 0)

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
                name="min_tier", optional=True, default="clean", choices=list(MIN_TIER_CHOICES),
                description="Only report processes at or above this tier (default: clean = all)"),
            requirements.BooleanRequirement(
                name="dump", optional=True, default=False,
                description="Dump the VAD regions of processes at Suspicious or High tier"),
            requirements.BooleanRequirement(
                name="deep", optional=True, default=False,
                description="EXPERIMENTAL: also compare executable image pages against the PFN database "
                            "(Windows 64-bit) to find private, modified copies of image code"),
        ]

    # -- Stage 1: extraction --------------------------------------------------- #

    _LISTS = {"load": ("InLoadOrderModuleList", "InLoadOrderLinks"),
              "init": ("InInitializationOrderModuleList", "InInitializationOrderLinks"),
              "mem": ("InMemoryOrderModuleList", "InMemoryOrderLinks")}

    @staticmethod
    def _walk_list(head, ldr_type: str, link_member: str):
        """Walk one loader list forwards and backwards. A walk that stops early (unreadable
        entry) is detected by checking whether the last link leads back to the list head.
        Returns ({DllBase: entry}, complete)."""
        entries: Dict[int, object] = {}
        complete = False
        for forward in (True, False):
            last = None
            try:
                for ldr in head.to_list(ldr_type, link_member, forward=forward):
                    last = ldr
                    try:
                        entries.setdefault(int(ldr.DllBase), ldr)
                    except exceptions.InvalidAddressException:
                        continue
            except exceptions.InvalidAddressException:
                pass
            try:
                if last is None:
                    link = head.Flink if forward else head.Blink
                else:
                    node = last.member(link_member)
                    link = node.Flink if forward else node.Blink
                if int(link) == head.vol.offset:
                    complete = True
            except (exceptions.InvalidAddressException, AttributeError):
                pass
        return entries, complete

    def _get_peb_modules(self, proc):
        """Normalised PEB module set from the 64-bit and (WOW64) 32-bit loader lists.
        Returns (modules or None, lists_present, lists_complete)."""
        lists: Dict[str, Dict[int, object]] = {"load": {}, "init": {}, "mem": {}}
        complete = {"load": True, "init": True, "mem": True}
        pebs = []
        for getter in (proc.get_peb, proc.get_peb32):
            try:
                peb = getter()
                if peb:
                    pebs.append(peb)
            except (exceptions.InvalidAddressException, AttributeError, ValueError):
                continue
        any_read = False
        for peb in pebs:
            sym_table = proc.get_symbol_table_name()
            try:
                peb.Ldr
                if peb.Ldr.vol.type_name.split(constants.BANG)[-1] == "unsigned long":
                    sym_table = proc.set_types(peb)
            except (exceptions.InvalidAddressException, AttributeError):
                complete = {k: False for k in complete}
                continue
            ldr_type = f"{sym_table}{constants.BANG}_LDR_DATA_TABLE_ENTRY"
            for key, (list_member, link_member) in self._LISTS.items():
                try:
                    head = peb.Ldr.member(list_member)
                    entries, done = self._walk_list(head, ldr_type, link_member)
                except (exceptions.InvalidAddressException, AttributeError):
                    complete[key] = False
                    continue
                lists[key].update(entries)
                complete[key] = complete[key] and done
                any_read = any_read or bool(entries)
        if not any_read:
            return None, (False, False, False), False
        modules = []

        def safe(fn, default):
            try:
                return fn()
            except (AttributeError, exceptions.InvalidAddressException):
                return default

        for base in set(lists["load"]) | set(lists["init"]) | set(lists["mem"]):
            src = lists["load"].get(base) or lists["init"].get(base) or lists["mem"].get(base)
            size = safe(lambda: int(src.SizeOfImage), 0)
            if base == 0 or size == 0:
                continue
            modules.append(PebModule(
                base, size, safe(lambda: src.FullDllName.get_string(), ""),
                safe(lambda: src.BaseDllName.get_string(), ""),
                base in lists["load"], base in lists["init"], base in lists["mem"]))
        return (modules, (bool(lists["load"]), bool(lists["init"]), bool(lists["mem"])),
                all(complete.values()))

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
        # Fallback for kernels whose VAD flags carry no VadType (XP/2003): a non-private,
        # file-backed VAD is treated as an image mapping.
        return "IMAGE" if file_path else "MAPPED"

    def _get_vad_nodes(self, proc, kernel):
        protect_values = vadinfo.VadInfo.protect_values(
            self.context, kernel.layer_name, kernel.symbol_table_name)
        nodes, objs = [], {}
        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                start, end = vad.get_start(), vad.get_end() + 1
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
            objs[start] = vad
        return nodes, objs

    @staticmethod
    def _expected_vad_count(proc) -> Optional[int]:
        """Number of VAD nodes the kernel says the tree holds (Win10: EPROCESS.VadCount;
        Win7: VadRoot.NumberGenericTableElements). None where the kernel exposes no count."""
        for getter in (lambda: int(proc.VadCount),
                       lambda: int(proc.NumberOfVads),
                       lambda: int(proc.VadRoot.NumberGenericTableElements)):
            try:
                n = getter()
                if n > 0:
                    return n
            except Exception:  # noqa: BLE001
                continue
        return None

    @staticmethod
    def _kernel_facts(proc, kernel=None) -> KernelFacts:
        def attempt(fn):
            try:
                return fn()
            except (AttributeError, exceptions.InvalidAddressException, ValueError):
                return None
            except Exception:  # noqa: BLE001
                return None

        image_name = attempt(lambda: utility.array_to_string(proc.ImageFileName))
        audit = attempt(lambda: proc.SeAuditProcessCreationInfo.ImageFileName.Name.get_string())
        section_base = attempt(lambda: int(proc.SectionBaseAddress)) or None
        peb = attempt(lambda: proc.get_peb())
        peb_base = peb_path = None
        if peb is not None:
            peb_base = attempt(lambda: int(peb.ImageBaseAddress)) or None
            peb_path = attempt(lambda: peb.ProcessParameters.ImagePathName.get_string())
        wow64 = bool(attempt(lambda: proc.get_is_wow64()))
        # Try to get build number from kernel (NtBuildNumber is a ULONG; low 16 bits
        # hold the build number, high bits may carry free/checked-build flags)
        build = None
        if kernel is not None:
            try:
                build_offset = kernel.get_symbol("NtBuildNumber").address
                build = int(kernel.object(object_type="unsigned long", offset=build_offset)) & 0xffff
            except (AttributeError, exceptions.InvalidAddressException, ValueError, TypeError):
                build = None
        return KernelFacts(image_name or None, audit or None, section_base, peb_base,
                           peb_path or None, wow64, build)

    def _make_reader(self, proc) -> Reader:
        try:
            layer = self.context.layers[proc.add_process_layer()]
        except exceptions.InvalidAddressException:
            return lambda addr, n: None

        def read(addr: int, n: int) -> Optional[bytes]:
            try:
                return layer.read(addr, n, pad=False)
            except exceptions.InvalidAddressException:
                return None
            except Exception:  # noqa: BLE001
                return None
        return read

    # -- page ownership (PFN database) ------------------------------------------ #

    def _init_pfn(self, kernel) -> bool:
        """Locate the PFN database. False where this kernel lacks what page checks need
        (non-64-bit, or no MmPfnDatabase / _MMPFN.u4.PrototypePte / PteFrame)."""
        self._pfn = None
        self._pfn_cache: Dict[int, Tuple[int, int]] = {}
        self._pt_cache: Dict[Tuple[int, int], Optional[int]] = {}
        try:
            table = kernel.symbol_table_name
            mmpfn = self.context.symbol_space.get_type(table + constants.BANG + "_MMPFN")
            sym = kernel.get_symbol("MmPfnDatabase")
            db = int(self.context.object(table + constants.BANG + "pointer", kernel.layer_name,
                                         offset=kernel.offset + sym.address))
            if not db:
                return False
            self._pfn = (table, kernel.layer_name, db, mmpfn.size)
            probe = self.context.object(table + constants.BANG + "_MMPFN", kernel.layer_name,
                                        offset=db + mmpfn.size, native_layer_name=kernel.layer_name)
            int(probe.u4.PrototypePte), int(probe.u4.PteFrame)       # fields must exist and be readable
            return True
        except (exceptions.SymbolError, exceptions.InvalidAddressException, AttributeError, KeyError,
                TypeError, ValueError):
            self._pfn = None
            return False

    def _frame_flags(self, pfn: int) -> Optional[Tuple[int, int]]:
        """(PrototypePte, PteFrame) of one physical frame, cached."""
        hit = self._pfn_cache.get(pfn)
        if hit is not None:
            return hit
        table, layer, db, size = self._pfn
        try:
            entry = self.context.object(table + constants.BANG + "_MMPFN", layer,
                                        offset=db + pfn * size, native_layer_name=layer)
            hit = (int(entry.u4.PrototypePte), int(entry.u4.PteFrame))
        except (exceptions.InvalidAddressException, AttributeError):
            hit = (-1, -1)
        self._pfn_cache[pfn] = hit
        return hit

    def _pt_frame(self, layer, dtb: int, va: int, phys_layer: str) -> Optional[int]:
        """Frame number of the page-table page that holds the PTE for `va` (4-level paging)."""
        key = (dtb, va >> 21)
        if key in self._pt_cache:
            return self._pt_cache[key]
        frame = None
        try:
            table = dtb & 0x000FFFFFFFFFF000
            for shift in (39, 30, 21):
                entry = int.from_bytes(
                    self.context.layers[phys_layer].read(table + ((va >> shift) & 0x1FF) * 8, 8), "little")
                if not entry & 1 or (shift != 39 and entry & 0x80):
                    table = None
                    break
                table = entry & 0x000FFFFFFFFFF000
            frame = None if table is None else table >> 12
        except exceptions.InvalidAddressException:
            frame = None
        self._pt_cache[key] = frame
        return frame

    def _page_state(self, proc_layer: str, va: int) -> Optional[str]:
        """'shared' (image prototype page), 'private' (a copy owned by this process's page table),
        'stale' (frame no longer belongs to this mapping: a dump artefact) or None (not resident)."""
        if self._pfn is None:
            return None
        layer = self.context.layers[proc_layer]
        try:
            phys, phys_layer = layer.translate(va)
        except exceptions.InvalidAddressException:
            return None
        proto, pte_frame = self._frame_flags(phys >> 12)
        if proto == 1:
            return "shared"
        if proto != 0:
            return None
        pt = self._pt_frame(layer, layer.config.get("page_map_offset", 0), va, phys_layer)
        return "private" if pt is not None and pt == pte_frame else "stale"

    def _is_stale(self, proc_layer: str):
        def stale(addr: int) -> bool:
            return self._pfn is not None and self._page_state(proc_layer, addr) == "stale"
        return stale

    @staticmethod
    def _walk_subsections(vad):
        """Yield (protection, pages) for each subsection of an image VAD, in address order."""
        try:
            sub = vad.Subsection.dereference()
        except (exceptions.InvalidAddressException, AttributeError):
            return
        for _ in range(512):
            try:
                yield int(sub.u.SubsectionFlags.Protection), int(sub.PtesInSubsection)
                if not int(sub.NextSubsection):
                    return
                sub = sub.NextSubsection.dereference()
            except (exceptions.InvalidAddressException, AttributeError):
                return

    _EXEC_PROTECTIONS = frozenset({2, 3, 6, 7})     # MM_EXECUTE, _READ, _READWRITE, _WRITECOPY

    def _image_pages(self, proc_layer: str, vad_nodes, vad_objs) -> List[ImagePageInfo]:
        """Census of the executable subsections of every image mapping (deep mode)."""
        out = []
        layer = self.context.layers[proc_layer]
        for node in vad_nodes:
            if node.vad_type != "IMAGE" or "X" not in parse_protection(node.protection):
                continue
            vad = vad_objs.get(node.start)
            if vad is None:
                continue
            page = node.start
            resident = shared = stale = 0
            private: List[Tuple[int, str, Tuple[str, ...]]] = []
            for protection, pages in self._walk_subsections(vad):
                if protection in self._EXEC_PROTECTIONS:
                    for i in range(pages):
                        va = page + i * 0x1000
                        state = self._page_state(proc_layer, va)
                        if state is None:
                            continue
                        resident += 1
                        if state == "shared":
                            shared += 1
                        elif state == "stale":
                            stale += 1
                        else:
                            try:
                                data = layer.read(va, 0x1000, pad=False)
                            except exceptions.InvalidAddressException:
                                continue
                            private.append((va, hashlib.blake2b(mask_trampolines(data), digest_size=16).hexdigest(),
                                            tuple(t for t in scan_runs([data]) if t in STRONG_TAGS or t == "peb_access")))
                page += pages * 0x1000
            if resident:
                out.append(ImagePageInfo(node.start, node.end, node.file_path or "", resident, shared,
                                         stale, private))
        return out

    # -- orchestration --------------------------------------------------------- #

    def _analyse(self, proc, kernel, deep: bool = False, image_pages=None, prepared=None):
        pid = int(proc.UniqueProcessId)
        try:
            name = utility.array_to_string(proc.ImageFileName)
        except (AttributeError, exceptions.InvalidAddressException):
            name = "?"
        facts = self._kernel_facts(proc, kernel)
        modules, present, complete = self._get_peb_modules(proc)
        vads, vad_objs = self._get_vad_nodes(proc, kernel)
        expected = self._expected_vad_count(proc)
        vads_complete = None if expected is None else len(vads) >= expected
        is_stale = lambda a: False  # noqa: E731
        if deep and getattr(self, "_pfn", None) is not None:
            layer_name = proc.add_process_layer()
            if image_pages is None:
                image_pages = self._image_pages(layer_name, vads, vad_objs)
            is_stale = self._is_stale(layer_name)
        else:
            image_pages = None
        report = analyse_process(pid, name, modules, vads, facts, self._make_reader(proc), present,
                                 complete, vads_complete, image_pages=image_pages, is_stale=is_stale)
        report.coverage["vad_nodes_expected"] = expected
        report.coverage["deep"] = bool(deep and image_pages is not None)
        return report, vad_objs

    def _dump_findings(self, proc, report, vad_objs) -> Dict[int, str]:
        dumped: Dict[int, str] = {}
        for f in report.findings:
            if f.start is None or f.start in dumped or finding_level(f) < SUSPICIOUS:
                continue
            vad = vad_objs.get(f.start)
            if vad is None:
                continue
            try:
                handle = vadinfo.VadInfo.vad_dump(self.context, proc, vad, self.open)
                handle.close()
                dumped[f.start] = handle.preferred_filename
            except (exceptions.InvalidAddressException, OverflowError, AttributeError) as excp:
                vollog.debug("Unable to dump %s.%x: %s", report.pid, f.start, excp)
        return dumped

    def _deep_pages(self, procs, kernel) -> Dict[int, List[ImagePageInfo]]:
        """Pass 1 of deep mode: census every process, then mark cross-process peers. Peers are
        computed over ALL processes, not only the --pid selection, so filtering cannot change a verdict."""
        pages: Dict[int, List[ImagePageInfo]] = {}
        keys: Dict[int, str] = {}
        for proc in pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"]):
            try:
                vads, vad_objs = self._get_vad_nodes(proc, kernel)
                pid = int(proc.UniqueProcessId)
                pages[pid] = self._image_pages(proc.add_process_layer(), vads, vad_objs)
                keys[pid] = utility.array_to_string(proc.ImageFileName).lower()
            except (exceptions.InvalidAddressException, AttributeError):
                continue
        order = list(pages)
        marked = mark_peers([(keys[pid], pages[pid]) for pid in order])
        return dict(zip(order, marked))

    def _generator(self, pids, min_tier, dump, deep=False) -> Generator[Tuple, None, None]:
        kernel = self.context.modules[self.config["kernel"]]
        floor = MIN_TIER_CHOICES[min_tier]
        na = renderers.NotApplicableValue()
        if deep and not self._init_pfn(kernel):
            vollog.warning("--deep needs a 64-bit Windows kernel with MmPfnDatabase and _MMPFN.u4; "
                           "running without it")
            deep = False
        self._pfn = getattr(self, "_pfn", None)
        if deep:
            all_pages = self._deep_pages(None, kernel)
        for proc in pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(pids),
        ):
            try:
                report, vad_objs = self._analyse(
                    proc, kernel, deep=deep,
                    image_pages=all_pages.get(int(proc.UniqueProcessId), []) if deep else None)
            except exceptions.InvalidAddressException:
                continue
            if report.tier < floor:
                continue
            dumped = self._dump_findings(proc, report, vad_objs) if dump else {}
            summary = report_to_dict(report)
            yield (0, (report.pid, report.name, TIER_NAME[report.tier], report.score,
                       f"{len(report.findings)} finding(s)" if report.findings else "",
                       "", "", na, na, "", "", report.hypothesis, "", "",
                       coverage_text(report.coverage),
                       json.dumps({k: v for k, v in summary.items() if k != "findings"})))
            for f in sorted(report.findings, key=lambda f: (-finding_level(f), f.fid, f.start or 0)):
                detail = finding_to_dict(f)
                if f.start in dumped:
                    detail["dump_file"] = dumped[f.start]
                yield (1, (report.pid, report.name, TIER_NAME[finding_level(f)], report.score,
                           f.fid + " " + f.key, f"Class {'I' * f.cls}" if f.cls < 4 else "",
                           f.technique,
                           format_hints.Hex(f.start) if f.start is not None else na,
                           format_hints.Hex(f.end) if f.end is not None else na,
                           f.protection, f.backing, f.evidence, ",".join(f.tags), f.confidence,
                           "", json.dumps(detail)))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Tier", str), ("Score", int), ("Finding", str),
             ("EvClass", str), ("Technique", str), ("Start", format_hints.Hex),
             ("End", format_hints.Hex), ("Protection", str), ("Backing", str),
             ("Evidence", str), ("Corroboration", str), ("Confidence", str),
             ("Coverage", str), ("Details", str)],
            self._generator(self.config.get("pid", None), self.config.get("min_tier", "clean"),
                            self.config.get("dump", False), self.config.get("deep", False)))
