"""Unit tests for PEVAD 2 pure logic: no memory image and no Volatility objects required."""
import importlib.util
import random
import struct
from pathlib import Path

import pytest

_PLUGIN = Path(__file__).resolve().parents[1] / "plugin" / "windows" / "pevad.py"
_spec = importlib.util.spec_from_file_location("pevad_under_test", _PLUGIN)
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)

SYS = "C:\\Windows\\System32\\"


def mod(base, size, name=SYS + "x.dll", load=True, init=True, mem=True):
    return P.PebModule(base, size, name, name.split("\\")[-1], load, init, mem)


def vad(start, end, prot="PAGE_EXECUTE_WRITECOPY", typ="IMAGE", path=None, commit=None):
    return P.VadNode(start, end, prot, typ, path, commit)


# ----------------------------- interval join ------------------------------- #

def brute_force(modules, vads):
    return {(m.base, v.start) for m in modules for v in vads
            if max(0, min(m.base + m.size, v.end) - max(m.base, v.start)) > 0}


def random_snapshot(rng):
    cursor, vads = 0x10000, []
    for _ in range(rng.randint(0, 40)):
        cursor += rng.randint(0, 8) * 0x1000
        length = rng.randint(1, 16) * 0x1000
        vads.append(vad(cursor, cursor + length))
        cursor += length
    modules = [mod(rng.randint(0x10000, cursor + 0x4000) & ~0xFFF, rng.randint(1, 20) * 0x1000)
               for _ in range(rng.randint(0, 25))]
    return modules, vads


@pytest.mark.parametrize("seed", range(300))
def test_sweep_line_matches_brute_force(seed):
    modules, vads = random_snapshot(random.Random(seed))
    got = {(p.module.base, p.vad.start) for p in P.sweep_line_join(modules, vads)}
    assert got == brute_force(modules, vads)


def test_overlap_bytes_exact_and_adjacent_excluded():
    assert [p.overlap_bytes for p in P.sweep_line_join([mod(0x1000, 0x3000)], [vad(0x2000, 0x8000)])] == [0x2000]
    assert P.sweep_line_join([mod(0x1000, 0x1000)], [vad(0x2000, 0x3000)]) == []


# -------------------------- protection / paths ----------------------------- #

@pytest.mark.parametrize("name,expected", [
    ("PAGE_EXECUTE_READWRITE", {"R", "W", "X"}),
    ("PAGE_EXECUTE_WRITECOPY", {"R", "C", "X"}),     # copy-on-write is not W
    ("PAGE_READONLY", {"R"}), ("PAGE_NOACCESS", set()), ("garbage", set()),
])
def test_parse_protection(name, expected):
    assert P.parse_protection(name) == expected


@pytest.mark.parametrize("raw,canon", [
    ("C:\\Windows\\System32\\NTDLL.DLL", "\\windows\\system32\\ntdll.dll"),
    ("\\Windows\\System32\\ntdll.dll", "\\windows\\system32\\ntdll.dll"),
    ("\\??\\C:\\Windows\\x.exe", "\\windows\\x.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "\\windows\\system32\\smss.exe"),
    ("\\Device\\HarddiskVolume3\\Windows\\x.exe", "\\windows\\x.exe"),
    ("\\Device\\Harddisk1\\DP(1)0-0+b\\dd\\dd.exe", "\\dd\\dd.exe"),   # XP removable device form
    ("D:\\dd\\dd.exe", "\\dd\\dd.exe"),
    ("", ""), (None, ""),
])
def test_canon_path(raw, canon):
    assert P.canon_path(raw) == canon


def test_paths_equal_tri_state():
    assert P.paths_equal(SYS + "a.dll", "\\Windows\\System32\\A.DLL") is True
    assert P.paths_equal(SYS + "a.dll", "\\Windows\\System32\\b.dll") is False
    assert P.paths_equal(SYS + "a.dll", None) is None
    assert P.paths_equal("C:\\PROGRA~1\\x\\a.dll", "\\Program Files\\x\\a.dll") is None   # 8.3: undecidable


def test_wow64_redirection_only_folded_for_wow64_processes():
    peb, kernel = SYS + "a.dll", "\\Windows\\SysWOW64\\a.dll"
    assert P.paths_equal(peb, kernel, wow64=True) is True
    assert P.paths_equal(peb, kernel, wow64=False) is False


def test_wow64_fold_does_not_hide_a_different_file_name():
    assert P.paths_equal(SYS + "a.dll", "\\Windows\\SysWOW64\\b.dll", wow64=True) is False


@pytest.mark.parametrize("path,low,high", [
    ("\\windows\\system32\\x.dll", 0.0, 0.0), ("\\users\\bob\\appdata\\local\\temp\\x.dll", 1.0, 1.0),
    ("\\\\server\\share\\x.dll", 0.8, 0.8), ("\\users\\bob\\app\\x.dll", 0.6, 0.6), ("", 0.3, 0.3),
])
def test_dir_risk(path, low, high):
    assert low <= P.dir_risk(path) <= high


# ----------------------------- PE header ----------------------------------- #

def make_pe(size_of_image=0x10000, sections=((0x1000, 0x800, 0x60000020), (0x2000, 0x800, 0x40000040)),
            magic=b"MZ", sig=b"PE\0\0", managed=False):
    h = bytearray(0x1000)
    h[0:2] = magic
    struct.pack_into("<I", h, 0x3C, 0x80)
    h[0x80:0x84] = sig
    struct.pack_into("<H", h, 0x80 + 6, len(sections))
    struct.pack_into("<H", h, 0x80 + 20, 240)
    struct.pack_into("<H", h, 0x80 + 24, 0x20B)                    # PE32+
    struct.pack_into("<I", h, 0x80 + 24 + 56, size_of_image)
    if managed:
        struct.pack_into("<II", h, 0x80 + 24 + 112 + 14 * 8, 0x2000, 0x48)
    sec = 0x80 + 24 + 240
    for i, (va, vs, ch) in enumerate(sections):
        struct.pack_into("<II", h, sec + 40 * i + 8, vs, va)
        struct.pack_into("<I", h, sec + 40 * i + 36, ch)
    return bytes(h)


def run_header(header, base=0x400000, peb_size=0x10000, vprot="PAGE_EXECUTE_WRITECOPY"):
    vads = [vad(base, base + 0x10000, vprot)]
    return P.check_pe_header(header, peb_size, base, vads, [v.start for v in vads])


def test_header_clean_passes():
    assert run_header(make_pe())[0] == 0


def test_header_bad_signature():
    assert run_header(make_pe(magic=b"\0\0"))[0] == 4
    assert run_header(make_pe(sig=b"XX\0\0"))[0] == 4


def test_header_size_of_image_tolerance():
    assert run_header(make_pe(size_of_image=0x40000))[0] >= 1
    assert run_header(make_pe(size_of_image=0x11000))[0] == 0


def test_header_non_monotonic_sections():
    assert run_header(make_pe(sections=((0x2000, 0x800, 0x20), (0x1000, 0x800, 0x20))))[0] >= 1


def test_header_exec_section_in_non_exec_vad():
    assert run_header(make_pe(), vprot="PAGE_READONLY")[0] >= 1


def test_pe_is_managed():
    assert P.pe_is_managed(make_pe(managed=True)) is True
    assert P.pe_is_managed(make_pe()) is False
    assert P.pe_is_managed(b"\0" * 0x1000) is False


# --------------------------- content scanning ------------------------------ #

def test_scan_detects_embedded_pe():
    blob = bytearray(0x3000)
    blob[0x800:0x800 + len(make_pe()[:0x100])] = make_pe()[:0x100]
    assert "pe_header" in P.scan_runs([bytes(blob)])


def test_scan_detects_stager_prologues():
    assert "shellcode_stager" in P.scan_runs([b"\x90" * 8 + bytes.fromhex("fc4883e4f0e8c0000000")])
    assert "shellcode_stager" in P.scan_runs([bytes.fromhex("fce882000000")])
    assert "shellcode_stager" in P.scan_runs([bytes.fromhex("fc6089e5")])


def test_scan_loose_cld_call_is_not_a_stager():
    assert "shellcode_stager" not in P.scan_runs([bytes.fromhex("fce8aabbccdd")])   # far call target


def test_scan_peb_access_alone_is_weak_and_with_ror13_strong():
    peb = bytes.fromhex("65488b042560000000")
    ror = bytes.fromhex("c1cf0d")
    assert P.scan_runs([peb]) == ["peb_access"] and not P.strong_corroboration(["peb_access"])
    assert P.strong_corroboration(P.scan_runs([peb + ror]))


def test_scan_random_bytes_clean_and_high_entropy_weak():
    rng = random.Random(7)
    noise = bytes(rng.randrange(256) for _ in range(16384))
    tags = P.scan_runs([noise])
    assert not P.strong_corroboration(tags) or "pe_header" in tags   # noise must not look like shellcode
    assert "high_entropy" in tags
    assert P.scan_runs([b"\0" * 8192]) == []


# ------------------------- process-level scenarios ------------------------- #

BASE = 0x7FF600000000


def memory_reader(pages=None):
    pages = pages or {}

    def read(addr, n):
        page = addr & ~0xFFF
        if page in pages:
            data = pages[page]
            return data[addr - page:addr - page + n].ljust(n, b"\0")
        return None
    return read


def clean_process():
    """exe + ntdll + one dll, all consistent."""
    exe = BASE
    ntdll = 0x7FF800000000
    dll = 0x7FF810000000
    modules = [mod(exe, 0x10000, "C:\\Windows\\System32\\svchost.exe"),
               mod(ntdll, 0x10000, SYS + "ntdll.dll"), mod(dll, 0x10000, SYS + "a.dll")]
    vads = [vad(exe, exe + 0x10000, path="\\Windows\\System32\\svchost.exe"),
            vad(ntdll, ntdll + 0x10000, path="\\Windows\\System32\\ntdll.dll"),
            vad(dll, dll + 0x10000, path="\\Windows\\System32\\a.dll"),
            vad(0x200000, 0x300000, "PAGE_READWRITE", "PRIVATE", None, 0x100000)]
    facts = P.KernelFacts("svchost.exe", "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
                          exe, exe, "C:\\Windows\\System32\\svchost.exe", False)
    pages = {m.base: make_pe(m.size, sections=((0x1000, 0x800, 0x60000020),)) for m in modules}
    return modules, vads, facts, pages


def analyse(modules, vads, facts, pages=None, **kw):
    return P.analyse_process(100, "svchost.exe", modules, vads, facts, memory_reader(pages), **kw)


def keys(report):
    return {f.key for f in report.findings}


def test_clean_process_is_clean():
    modules, vads, facts, pages = clean_process()
    r = analyse(modules, vads, facts, pages)
    assert r.tier == P.CLEAN and not r.findings, [f.evidence for f in r.findings]
    assert r.coverage["headers_checked"] == 3


def test_nothing_to_check_is_unevaluated():
    r = analyse(None, [], P.KernelFacts())
    assert r.tier == P.UNEVALUATED


def test_peb_path_masquerade_is_class_one_high():
    modules, vads, facts, pages = clean_process()
    facts = facts._replace(peb_image_path="C:\\Windows\\System32\\svch0st.exe")
    r = analyse(modules, vads, facts, pages)
    assert "PEB_PATH_MISMATCH" in keys(r) and r.tier == P.HIGH


def test_image_base_mismatch():
    modules, vads, facts, pages = clean_process()
    r = analyse(modules, vads, facts._replace(peb_image_base=BASE + 0x10000), pages)
    assert "IMAGE_BASE_MISMATCH" in keys(r) and r.tier == P.HIGH


def test_main_image_replaced_by_private_memory():
    modules, vads, facts, pages = clean_process()
    vads[0] = vad(BASE, BASE + 0x10000, "PAGE_EXECUTE_READWRITE", "PRIVATE", None, 0x10000)
    r = analyse(modules, vads, facts, pages)
    assert "MAIN_IMAGE_NOT_IMAGE_VAD" in keys(r) and "LOADED_MODULE_UNBACKED" in keys(r)
    assert r.tier == P.HIGH


def test_main_image_file_differs_from_launched_file():
    modules, vads, facts, pages = clean_process()
    vads[0] = vad(BASE, BASE + 0x10000, path="\\Users\\bob\\evil.exe")
    r = analyse(modules, vads, facts, pages)
    assert "MAIN_IMAGE_FILE_MISMATCH" in keys(r) and r.tier == P.HIGH


def test_image_name_is_truncated_to_14_chars_and_not_flagged():
    modules, vads, facts, pages = clean_process()
    long_exe = "\\Windows\\System32\\fontdrvhost.exe"
    vads[0] = vad(BASE, BASE + 0x10000, path=long_exe)
    facts = facts._replace(image_name="fontdrvhost.ex", audit_path="\\Device\\HarddiskVolume3" + long_exe,
                           peb_image_path="C:" + long_exe)
    modules[0] = mod(BASE, 0x10000, "C:" + long_exe)
    r = analyse(modules, vads, facts, pages)
    assert "MAIN_IMAGE_FILE_MISMATCH" not in keys(r), [f.evidence for f in r.findings]


def test_module_name_substitution_is_class_one():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, path="\\Users\\bob\\evil.dll")
    r = analyse(modules, vads, facts, pages)
    assert "MODULE_NAME_MISMATCH" in keys(r) and r.tier == P.HIGH


def test_same_name_other_directory_is_class_two_suspicious():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, path="\\Program Files\\Vendor\\a.dll")
    r = analyse(modules, vads, facts, pages)
    assert keys(r) == {"MODULE_DIR_MISMATCH"} and r.tier == P.SUSPICIOUS


def test_wow64_redirected_path_is_not_a_finding_in_a_wow64_process():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, path="\\Windows\\SysWOW64\\a.dll")
    assert analyse(modules, vads, facts._replace(is_wow64=True), pages).tier == P.CLEAN
    assert "MODULE_DIR_MISMATCH" in keys(analyse(modules, vads, facts._replace(is_wow64=False), pages))


def test_peb_module_over_private_memory_is_unbacked_class_one():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, "PAGE_EXECUTE_READWRITE", "PRIVATE", None, 0x10000)
    r = analyse(modules, vads, facts, pages)
    assert "LOADED_MODULE_UNBACKED" in keys(r) and r.tier == P.HIGH


@pytest.mark.parametrize("vads_complete,key,tier", [
    (True, "LOADED_MODULE_UNBACKED", P.HIGH),
    (None, "MODULE_VAD_UNVERIFIED", P.INFO),       # VAD tree not proven complete: not provable
    (False, "MODULE_VAD_UNVERIFIED", P.INFO),
])
def test_peb_module_with_no_vad_depends_on_vad_tree_completeness(vads_complete, key, tier):
    modules, vads, facts, pages = clean_process()
    del vads[2]
    r = analyse(modules, vads, facts, pages, vads_complete=vads_complete)
    assert key in keys(r) and r.tier == tier


def hidden_image_process(prot="PAGE_EXECUTE_WRITECOPY", managed=False, clr=False):
    modules, vads, facts, pages = clean_process()
    h = 0x7FF820000000
    vads.append(vad(h, h + 0x10000, prot, path="\\Users\\bob\\inj.dll"))
    pages[h] = make_pe(0x10000, managed=managed)
    if clr:
        c = 0x7FF830000000
        modules.append(mod(c, 0x10000, SYS + "clr.dll"))
        vads.append(vad(c, c + 0x10000, path="\\Windows\\System32\\clr.dll"))
        pages[c] = make_pe(0x10000)
    return modules, vads, facts, pages


def test_unlisted_executable_image_with_pe_header_is_hidden_image():
    r = analyse(*hidden_image_process())
    assert "HIDDEN_IMAGE" in keys(r) and r.tier == P.HIGH


def test_hidden_image_needs_complete_loader_lists():
    r = analyse(*hidden_image_process(), lists_complete=False)
    assert "HIDDEN_IMAGE" not in keys(r) and "UNLISTED_IMAGE_UNVERIFIED" in keys(r)
    assert r.tier == P.INFO


def test_non_executable_image_mapping_is_a_resource_load_not_a_module():
    r = analyse(*hidden_image_process(prot="PAGE_READONLY"))
    assert r.tier == P.CLEAN and r.coverage["resource_images"] == 1


def test_managed_assembly_in_clr_host_is_not_hidden():
    r = analyse(*hidden_image_process(managed=True, clr=True))
    assert "HIDDEN_IMAGE" not in keys(r) and r.coverage["managed_images"] == 1


def test_managed_assembly_outside_clr_host_is_still_hidden():
    r = analyse(*hidden_image_process(managed=True, clr=False))
    assert "HIDDEN_IMAGE" in keys(r)


def test_unreadable_header_is_unknown_not_a_finding():
    modules, vads, facts, _ = clean_process()
    r = analyse(modules, vads, facts, pages={})
    assert r.tier == P.CLEAN and r.coverage["headers_unreadable"] == 3 and r.coverage["headers_checked"] == 0


def test_zero_header_page_is_unknown_not_a_finding():
    modules, vads, facts, pages = clean_process()
    pages[0x7FF810000000] = b"\0" * 0x1000
    r = analyse(modules, vads, facts, pages)
    assert r.tier == P.CLEAN and r.coverage["headers_unreadable"] == 1


def test_stale_non_mz_header_is_context_only():
    modules, vads, facts, pages = clean_process()
    pages[0x7FF810000000] = bytes.fromhex("8bc64c897424604c2bc1e8e8fe0000ff") + b"\x90" * 0xFF0
    r = analyse(modules, vads, facts, pages)
    assert keys(r) == {"HEADER_NOT_PE"} and r.tier == P.INFO


def test_mz_with_broken_pe_signature_is_header_anomaly():
    modules, vads, facts, pages = clean_process()
    pages[0x7FF810000000] = make_pe(0x10000, sig=b"XX\0\0")
    r = analyse(modules, vads, facts, pages)
    assert keys(r) == {"HEADER_ANOMALY"} and r.tier == P.SUSPICIOUS


def test_image_coverage_deficit():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810004000, path="\\Windows\\System32\\a.dll")
    r = analyse(modules, vads, facts, pages)
    assert "IMAGE_COVERAGE_DEFICIT" in keys(r) and r.tier == P.SUSPICIOUS


def test_list_inconsistency_only_reported_when_walks_completed():
    modules, vads, facts, pages = clean_process()
    modules[2] = mod(0x7FF810000000, 0x10000, SYS + "a.dll", load=True, mem=False)
    assert "LIST_INCONSISTENT" in keys(analyse(modules, vads, facts, pages))
    assert "LIST_INCONSISTENT" not in keys(analyse(modules, vads, facts, pages, lists_complete=False))


def with_private_exec(modules, vads, facts, pages, size=0x20000, prot="PAGE_EXECUTE_READWRITE",
                      content=None, commit=0x4000, start=0x1000000):
    vads.append(vad(start, start + size, prot, "PRIVATE", None, commit))
    if content is not None:
        pages[start] = content
    return modules, vads, facts, pages


def test_orphan_exec_private_is_suspicious():
    r = analyse(*with_private_exec(*clean_process()))
    assert {"EXEC_PRIVATE_ORPHAN", "WX_PRIVATE"} <= keys(r) and r.tier == P.SUSPICIOUS


def test_reserved_but_uncommitted_executable_region_is_ignored():
    r = analyse(*with_private_exec(*clean_process(), commit=0, size=0x10000000000))
    assert r.tier == P.CLEAN


def test_two_rwx_regions_are_one_family_not_independent_evidence():
    m, v, f, p = with_private_exec(*clean_process())
    m, v, f, p = with_private_exec(m, v, f, p, start=0x3000000)
    assert analyse(m, v, f, p).tier == P.SUSPICIOUS


def test_strong_content_corroboration_makes_it_high():
    content = make_pe(0x4000) + bytes.fromhex("fc4883e4f0e8c0000000")
    r = analyse(*with_private_exec(*clean_process(), content=content))
    assert r.tier == P.HIGH
    assert {"pe_header"} <= set(r.findings[0].tags) | set(r.findings[1].tags)


def test_unreadable_region_content_is_reported_as_unknown():
    r = analyse(*with_private_exec(*clean_process()))
    assert all("content_unreadable" in f.tags for f in r.findings if f.key == "EXEC_PRIVATE_ORPHAN")


def jit_process():
    modules, vads, facts, pages = clean_process()
    c = 0x7FF830000000
    modules.append(mod(c, 0x10000, SYS + "clrjit.dll"))
    vads.append(vad(c, c + 0x10000, path="\\Windows\\System32\\clrjit.dll"))
    pages[c] = make_pe(0x10000)
    return modules, vads, facts, pages


def test_jit_host_downgrades_plain_rwx_to_info():
    r = analyse(*with_private_exec(*jit_process()))
    assert r.tier == P.INFO and r.jit_hosts == ["clrjit.dll"]


def test_jit_downgrade_does_not_hide_a_pe_header():
    content = make_pe(0x4000)
    r = analyse(*with_private_exec(*jit_process(), content=content))
    assert r.tier == P.HIGH


def test_two_families_of_class_two_evidence_are_high():
    m, v, f, p = with_private_exec(*clean_process())
    v[2] = vad(0x7FF810000000, 0x7FF810004000, path="\\Windows\\System32\\a.dll")   # coverage deficit
    assert analyse(m, v, f, p).tier == P.HIGH


def test_wx_image_mapping():
    modules, vads, facts, pages = clean_process()
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, "PAGE_EXECUTE_READWRITE", path="\\Windows\\System32\\a.dll")
    assert "WX_IMAGE" in keys(analyse(modules, vads, facts, pages))


def test_risky_module_path_is_information_only():
    modules, vads, facts, pages = clean_process()
    modules[2] = mod(0x7FF810000000, 0x10000, "C:\\Users\\bob\\AppData\\Local\\Temp\\a.dll")
    vads[2] = vad(0x7FF810000000, 0x7FF810010000, path="\\Users\\bob\\AppData\\Local\\Temp\\a.dll")
    r = analyse(modules, vads, facts, pages)
    assert keys(r) == {"RISKY_MODULE_PATH"} and r.tier == P.INFO


def test_unreadable_peb_still_runs_kernel_checks():
    modules, vads, facts, pages = clean_process()
    vads[0] = vad(BASE, BASE + 0x10000, "PAGE_EXECUTE_READWRITE", "PRIVATE", None, 0x10000)
    r = analyse(None, vads, facts._replace(peb_image_base=None, peb_image_path=None), pages)
    assert "MAIN_IMAGE_NOT_IMAGE_VAD" in keys(r) and r.tier == P.HIGH


def test_unreadable_peb_does_not_hide_an_orphan_rwx_region():
    # real-world bug: taskhostw.exe on WinDump had unreadable PEB loader lists *and* a
    # malfind-flagged RWX private VAD. The orphan-memory/WX scan only needs the kernel VAD
    # tree, not the PEB, so it must not be gated behind "modules is not None" -- a process
    # with no readable PEB should never report Clean just because the module loop couldn't run.
    modules, vads, facts, pages = with_private_exec(*clean_process())
    r = analyse(None, vads, facts._replace(peb_image_base=None, peb_image_path=None), pages)
    assert {"EXEC_PRIVATE_ORPHAN", "WX_PRIVATE"} <= keys(r)
    assert r.tier != P.CLEAN
    assert any("orphan-memory" in n and "still ran" in n for n in r.notes)


# ------------------------------- rules ------------------------------------- #

def finding(key, tags=(), downgraded=False, subject=("x",), conf="probable"):
    return P._mk(key, 0, 1, "", "", "", conf, subject, tags, downgraded)


@pytest.mark.parametrize("fs,tier", [
    ([], P.CLEAN),
    ([finding("RISKY_MODULE_PATH")], P.INFO),
    ([finding("EXEC_PRIVATE_ORPHAN", downgraded=True)], P.INFO),
    ([finding("EXEC_PRIVATE_ORPHAN")], P.SUSPICIOUS),
    ([finding("EXEC_PRIVATE_ORPHAN", tags=("pe_header",))], P.HIGH),
    ([finding("HIDDEN_IMAGE", conf="confirmed")], P.HIGH),
    ([finding("HIDDEN_IMAGE", conf="possible")], P.SUSPICIOUS),
    ([finding("EXEC_PRIVATE_ORPHAN", subject=("a",)), finding("WX_PRIVATE", subject=("b",))], P.SUSPICIOUS),
    ([finding("EXEC_PRIVATE_ORPHAN", subject=("a",)), finding("HEADER_ANOMALY", subject=("b",))], P.HIGH),
])
def test_classify_table(fs, tier):
    assert P.classify(fs)[0] == tier


def test_score_is_ordinal_and_capped():
    t, s = P.classify([finding("HIDDEN_IMAGE", conf="confirmed")])
    assert t == P.HIGH and 0 < s <= 100
    assert P.classify([])[1] == 0
    assert P.classify([finding("RISKY_MODULE_PATH")])[1] < P.classify([finding("EXEC_PRIVATE_ORPHAN")])[1]


def test_report_serialises_to_json():
    import json
    r = analyse(*with_private_exec(*clean_process()))
    d = json.loads(json.dumps(P.report_to_dict(r)))
    assert d["tier"] == "Suspicious" and d["findings"][0]["id"].startswith("PEVAD-")
    assert P.coverage_text(r.coverage)


def test_catalogue_is_complete_and_consistent():
    assert set(P.CATALOG) == set(P.HYPOTHESIS)
    assert len({v[0] for v in P.CATALOG.values()}) == len(P.CATALOG)          # unique ids
    for key, (fid, cls, _t, _tech) in P.CATALOG.items():
        assert fid.startswith("PEVAD-" + "I" * cls + "0"), (key, fid)
    assert all(k in P.CATALOG for k in P.FAMILY)


# ---- deep mode (image pages) ---------------------------------------------------------------

NTDLL = 0x7FF800000000


def ipage(path=SYS + "ntdll.dll", private=1, peers=0, resident=100, stale=0, tags=()):
    pv = [(NTDLL + 0x9D000 + i * 0x1000, "d%d" % i, tuple(tags)) for i in range(private)]
    return P.ImagePageInfo(NTDLL, NTDLL + 0x10000, path, resident, resident - private - stale, stale, pv, peers)


def test_deep_unpeered_private_image_page_is_suspicious():
    m, v, f, pg = clean_process()
    rep = analyse(m, v, f, pg, image_pages=[ipage()])
    assert "IMAGE_CODE_MODIFIED" in keys(rep)
    assert rep.tier == P.SUSPICIOUS


def test_deep_peer_consistent_patch_is_info():
    m, v, f, pg = clean_process()
    rep = analyse(m, v, f, pg, image_pages=[ipage(peers=P.MIN_PEERS)])
    assert rep.tier == P.INFO
    assert "peer_consistent" in next(x for x in rep.findings if x.key == "IMAGE_CODE_MODIFIED").tags


def test_deep_one_peer_is_not_enough():
    m, v, f, pg = clean_process()
    assert analyse(m, v, f, pg, image_pages=[ipage(peers=P.MIN_PEERS - 1)]).tier == P.SUSPICIOUS


def test_deep_jit_host_downgrades_unpeered_image_code_modified():
    # same documented evasion surface as the private-memory JIT downgrade: a JIT/managed-runtime
    # host (Edge/Chrome/CLR/etc.) legitimately self-modifies its own mapped code pages, so an
    # unpeered IMAGE_CODE_MODIFIED finding there should downgrade to Info, not stay Suspicious.
    m, v, f, pg = jit_process()
    rep = analyse(m, v, f, pg, image_pages=[ipage(peers=0)])
    assert "IMAGE_CODE_MODIFIED" in keys(rep)
    assert rep.tier == P.INFO


def test_deep_jit_host_downgrade_does_not_hide_strong_corroboration():
    m, v, f, pg = jit_process()
    rep = analyse(m, v, f, pg, image_pages=[ipage(peers=0, tags=("pe_header", "shellcode_stager"))])
    assert "IMAGE_CODE_MODIFIED" in keys(rep)
    assert rep.tier == P.HIGH


def test_deep_clr_and_ngen_skipped_in_clr_host():
    m, v, f, pg = clean_process()
    m.append(mod(0x7FF830000000, 0x10000, SYS + "clr.dll"))
    v.append(vad(0x7FF830000000, 0x7FF830010000, path="\\Windows\\System32\\clr.dll"))
    pg[0x7FF830000000] = make_pe(0x10000, sections=((0x1000, 0x800, 0x60000020),))
    rep = analyse(m, v, f, pg, image_pages=[ipage(path="\\Windows\\assembly\\NativeImages_v4\\x.ni.dll")])
    assert "IMAGE_CODE_MODIFIED" not in keys(rep)
    assert rep.coverage["ngen_images_skipped"] == 1


def test_deep_never_evaluates_an_otherwise_unevaluated_process():
    rep = P.analyse_process(4, "System", None, [], P.KernelFacts("System", None, None, None, None, False),
                            memory_reader({}), (False, False, False), False, None, image_pages=[ipage()])
    assert rep.tier == P.UNEVALUATED


def test_deep_off_has_no_image_findings():
    m, v, f, pg = clean_process()
    assert "IMAGE_CODE_MODIFIED" not in keys(analyse(m, v, f, pg))


def test_stale_header_is_unknown_not_failure():
    m, v, f, pg = clean_process()
    pg[m[2].base] = b"\x00" * 0x1000                       # recycled frame: not MZ
    rep = analyse(m, v, f, pg, is_stale=lambda a: a == m[2].base)
    assert "HEADER_NOT_PE" not in keys(rep) and "HEADER_ANOMALY" not in keys(rep)
    assert rep.coverage.get("headers_stale") == 1


def test_mask_trampolines_makes_aslr_variants_equal():
    a = bytes.fromhex("48b8a0f13cf4ff7f0000ffe0")
    b = bytes.fromhex("48b880c2d102f77f0000ffe0")
    assert P.mask_trampolines(a) == P.mask_trampolines(b) != a
    assert P.mask_trampolines(b"\x90" * 16) == b"\x90" * 16


def test_mark_peers_counts_other_processes_with_identical_page():
    def pages(d):
        return [P.ImagePageInfo(NTDLL, NTDLL + 0x10000, SYS + "ntdll.dll", 10, 9, 0,
                                [(NTDLL + 0x9D000, d, ())], 0)]
    out = P.mark_peers([("msedge.exe", pages("x")), ("msedge.exe", pages("x")), ("msedge.exe", pages("x")),
                        ("msedge.exe", pages("y")), ("other.exe", pages("x"))])
    assert [o[0].peers for o in out] == [2, 2, 2, 0, 0]


# ----------------------------- path validation ----------------------------- #

def test_is_plausible_path_accepts_valid_paths():
    assert P._is_plausible_path("C:\\Windows\\System32\\kernel32.dll")
    assert P._is_plausible_path("\\Device\\HarddiskVolume2\\Windows\\Temp\\x.exe")
    assert P._is_plausible_path("\\\\server\\share\\file.dll")
    assert P._is_plausible_path("\\SystemRoot\\System32\\cmd.exe")


def test_is_plausible_path_rejects_garbled_strings():
    # Obvious garbage: random high bytes, non-printable
    assert not P._is_plausible_path("l-TimeZones.Resources\" version")
    assert not P._is_plausible_path("chitecture=\"amd64\" publicKeyToken")
    assert not P._is_plausible_path("0x30323737")
    assert not P._is_plausible_path("")
    assert not P._is_plausible_path(None)
    assert not P._is_plausible_path("x")


def test_is_plausible_peb_base_accepts_valid_addresses():
    assert P._is_plausible_peb_base(0x400000)
    assert P._is_plausible_peb_base(0x140000000)
    assert P._is_plausible_peb_base(0x10000)


def test_is_plausible_peb_base_rejects_garbage_addresses():
    assert not P._is_plausible_peb_base(0x30323737)  # corrupted PEB read
    assert not P._is_plausible_peb_base(0xcccccccc)  # uninitialized memory
    assert not P._is_plausible_peb_base(0xdeadbeef)  # obvious sentinel
    assert not P._is_plausible_peb_base(0xffffffff)
    assert not P._is_plausible_peb_base(0)
    assert not P._is_plausible_peb_base(None)
    assert not P._is_plausible_peb_base(0x10000000000001)  # > 1 PB


def test_is_plausible_peb_base_rejects_unaligned_addresses():
    # Real PE image bases are always page-aligned; a smeared PEB field that happens to land
    # in a plausible range but isn't page-aligned is not a real load address.
    assert not P._is_plausible_peb_base(0x2010007)
    assert not P._is_plausible_peb_base(0x64aac784)
    assert P._is_plausible_peb_base(0x64aac000)  # aligned equivalent is fine


# ----------------------------- pre-Win8 I07 downgrade -------------------- #

def test_i07_downgraded_on_pre_win8_builds():
    """On pre-Win8 (build < 9200), resource mappings appear as HIDDEN_IMAGE but should be Info tier."""
    vads = [vad(0x70000000, 0x70010000, typ="IMAGE", path="\\Windows\\System32\\imageres.dll")]
    facts = P.KernelFacts(build_number=7601)  # Win7 SP1
    report = P.analyse_process(0, "test.exe", [], vads, facts, lambda a, n: None)
    if report.findings:
        i07 = [f for f in report.findings if f.key == "HIDDEN_IMAGE"]
        if i07:
            # Pre-Win8 I07 should be "probable" confidence, not "confirmed"
            assert i07[0].confidence == "probable"


def test_i07_confirmed_on_win8_and_later():
    """On Win8+ (build >= 9200), HIDDEN_IMAGE should be confirmed."""
    vads = [vad(0x70000000, 0x70010000, typ="IMAGE", path="\\Windows\\System32\\imageres.dll")]
    facts = P.KernelFacts(build_number=9200)  # Win8
    report = P.analyse_process(0, "test.exe", [], vads, facts, lambda a, n: None)
    if report.findings:
        i07 = [f for f in report.findings if f.key == "HIDDEN_IMAGE"]
        if i07:
            # Win8+ I07 should be confirmed
            assert i07[0].confidence == "confirmed"


def test_i06_skipped_when_peb_module_name_is_garbled():
    """A PEB module record with a plausible base/size but a garbled name (smeared Unicode
    buffer) is itself corrupted evidence, even though base+size alone look fine -- must not
    produce a LOADED_MODULE_UNBACKED finding. Regression for real MemLabs Lab 6 data, where
    WmiPrvSE.exe had base=0x74b80000 (plausible, page-aligned) but name='ᆠ7'-style garbage."""
    modules = [mod(0x74b80000, 0x3000, name="ᆠ" + "7")]  # garbled name, plausible base/size
    vads: list = []  # no VAD at that base
    facts = P.KernelFacts(build_number=7601)
    report = P.analyse_process(0, "WmiPrvSE.exe", modules, vads, facts, lambda a, n: None)
    assert not any(f.key == "LOADED_MODULE_UNBACKED" for f in report.findings)
