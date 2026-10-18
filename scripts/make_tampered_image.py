#!/usr/bin/env python3
"""Create a SYNTHETIC tampered copy of a Windows memory image to exercise PEVAD end to end.

This is a positive-control generator, not malware. It copies a clean image and edits kernel and
user-mode structures in the COPY so that the Volatility framework parses them exactly as it
would parse the artefacts left by real tradecraft:

  peb_path        PEB ImagePathName edited (process masquerading)               -> PEVAD-I04
  peb_imagebase   PEB ImageBaseAddress moved (hollowing artefact)               -> PEVAD-I01
  unlink          a module unlinked from all three PEB loader lists             -> PEVAD-I07
  main_not_image  main image VAD re-typed as private memory (hollowed)          -> PEVAD-I02 / I06
  reflective      private RW region made RWX and filled with a PE header and
                  a shellcode-stager prologue (reflective injection)            -> PEVAD-II01/II02 + corroboration
  wx_only         private RW region made RWX, zero content                      -> PEVAD-II01/II02, no corroboration

It proves the detection logic and the parsing path, NOT recall on real malware: the tampering
is shaped by the author's model of the technique. The original image is never modified.

Usage: make_tampered_image.py SRC_IMAGE DST_IMAGE MANIFEST.json  (Windows 10 x64 crash dump/raw)
"""
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import sys
from pathlib import Path

import volatility3
from volatility3 import framework
from volatility3.framework import automagic, constants, contexts, exceptions, interfaces
from volatility3.framework import plugins as fw_plugins
from volatility3.plugins.windows import pslist, vadinfo

PEVAD_PATH = Path(__file__).resolve().parents[1] / "plugin" / "windows" / "pevad.py"


def load_pevad():
    spec = importlib.util.spec_from_file_location("pevad_for_tamper", PEVAD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256(path, chunk=1 << 24):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                return h.hexdigest()
            h.update(b)


class Patcher:
    def __init__(self, ctx, dst):
        self.ctx, self.fh = ctx, open(dst, "r+b")

    def file_offset(self, layer_name, addr):
        name = layer_name
        while True:
            layer = self.ctx.layers[name]
            if isinstance(layer, interfaces.layers.TranslationLayerInterface):
                addr, name = layer.translate(addr)
            else:
                return addr

    def write(self, layer_name, addr, data: bytes):
        pos = 0
        while pos < len(data):
            chunk = min(len(data) - pos, 0x1000 - ((addr + pos) & 0xFFF))
            off = self.file_offset(layer_name, addr + pos)
            self.fh.seek(off)
            self.fh.write(data[pos:pos + chunk])
            pos += chunk

    def set_bits(self, layer_name, bitfield_obj, value: int):
        """Rewrite one bit field inside its containing integer."""
        vol = bitfield_obj.vol
        width = vol["end_bit"] - vol["start_bit"]
        mask = ((1 << width) - 1) << vol["start_bit"]
        try:
            size = vol["base_type"].size
        except (KeyError, AttributeError):
            size = 4
        layer = self.ctx.layers[layer_name]
        cur = int.from_bytes(layer.read(vol["offset"], size), "little")
        new = (cur & ~mask) | ((value << vol["start_bit"]) & mask)
        self.write(layer_name, vol["offset"], new.to_bytes(size, "little"))

    def close(self):
        self.fh.flush()
        self.fh.close()


def vad_flags(vad):
    """VadFlags bit-field container for both _MMVAD layouts (Win8+ keep it under Core)."""
    return vad.Core.u.VadFlags if vad.has_member("Core") else vad.u.VadFlags


def build_context(image):
    framework.require_interface_version(2, 0, 0)
    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    plugin = framework.list_plugins()["windows.pslist.PsList"]
    automagics = automagic.choose_automagic(automagic.available(ctx), plugin)
    ctx.config["automagic.LayerStacker.single_location"] = "file://" + os.path.abspath(image)
    constructed = fw_plugins.construct_plugin(ctx, automagics, plugin, "plugins", None, None)
    return ctx, constructed


def main(src, dst, manifest_path):
    src_hash_before = sha256(src)
    shutil.copyfile(src, dst)
    pev = load_pevad()
    ctx, plugin = build_context(dst)
    kernel_name = plugin.config["kernel"]
    kernel = ctx.modules[kernel_name]
    patcher = Patcher(ctx, dst)
    manifest = {"source": os.path.basename(src), "source_sha256": src_hash_before,
                "note": "SYNTHETIC structural tampering of a clean image; not real malware.",
                "operations": []}

    procs = {int(p.UniqueProcessId): p for p in pslist.PsList.list_processes(ctx, kernel_name)}
    by_name = {}
    for pid, p in procs.items():
        try:
            by_name.setdefault(pev.utility.array_to_string(p.ImageFileName), []).append(pid)
        except Exception:  # noqa: BLE001
            continue

    # only use processes that PEVAD already rates Clean on the pristine image, with complete lists
    # the harness only needs the plugin's analysis helpers, not a validated plugin instance
    holder = pev.Pevad.__new__(pev.Pevad)
    holder._context = ctx

    def pristine(pid):
        proc = procs[pid]
        try:
            report, _ = holder._analyse(proc, kernel)
        except exceptions.InvalidAddressException:
            return None
        return report

    eligible = {}
    for name in ("RuntimeBroker.exe", "sihost.exe", "taskhostw.exe", "dllhost.exe", "ctfmon.exe",
                 "ShellExperienceHost.exe", "svchost.exe"):
        for pid in by_name.get(name, []):
            rep = pristine(pid)
            if rep and rep.tier == pev.CLEAN and rep.coverage.get("loader_lists_complete") \
                    and rep.coverage.get("vad_tree_complete") and rep.coverage.get("peb_modules", 0) > 20:
                eligible.setdefault(name, []).append(pid)
    flat = [pid for pids in eligible.values() for pid in pids]
    if len(flat) < 6:
        sys.exit(f"not enough eligible clean processes ({len(flat)}); aborting")
    picks = iter(flat)

    # ---- peb_path -------------------------------------------------------------------------
    pid = next(picks)
    proc = procs[pid]
    peb = proc.get_peb()
    path_buf = int(peb.ProcessParameters.ImagePathName.Buffer)
    original = peb.ProcessParameters.ImagePathName.get_string()
    name_index = original.rfind("\\") + 1
    edited = original[:name_index] + ("x" if original[name_index] != "x" else "y") + original[name_index + 1:]
    patcher.write(proc.add_process_layer(), path_buf + 2 * name_index,
                  edited[name_index].encode("utf-16-le"))
    manifest["operations"].append({"op": "peb_path", "pid": pid, "from": original, "to": edited,
                                   "expect": ["PEVAD-I04"]})

    # ---- peb_imagebase --------------------------------------------------------------------
    pid = next(picks)
    proc = procs[pid]
    peb = proc.get_peb()
    old = int(peb.ImageBaseAddress)
    patcher.write(proc.add_process_layer(), int(proc.Peb) + peb.ImageBaseAddress.vol.offset - peb.vol.offset,
                  struct.pack("<Q", old + 0x10000))
    manifest["operations"].append({"op": "peb_imagebase", "pid": pid, "from": hex(old),
                                   "to": hex(old + 0x10000), "expect": ["PEVAD-I01"]})

    # ---- unlink a module from all three loader lists --------------------------------------
    pid = next(picks)
    proc = procs[pid]
    layer = proc.add_process_layer()
    victim = None
    for mod in proc.load_order_modules():
        nm = mod.BaseDllName.get_string().lower()
        if nm.endswith(".dll") and nm not in ("ntdll.dll", "kernel32.dll", "kernelbase.dll"):
            victim = mod
    sym = proc.get_symbol_table_name()
    removed = []
    for link in ("InLoadOrderLinks", "InMemoryOrderLinks", "InInitializationOrderLinks"):
        entry = getattr(victim, link)
        f, b = int(entry.Flink), int(entry.Blink)
        patcher.write(layer, b, struct.pack("<Q", f))          # B.Flink = F
        patcher.write(layer, f + 8, struct.pack("<Q", b))      # F.Blink = B
        removed.append(link)
    manifest["operations"].append({
        "op": "unlink", "pid": pid, "module": victim.BaseDllName.get_string(),
        "base": hex(int(victim.DllBase)), "lists": removed, "expect": ["PEVAD-I07"]})

    # ---- main image VAD re-typed as private memory ----------------------------------------
    pid = next(picks)
    proc = procs[pid]
    sb = int(proc.SectionBaseAddress)
    main_vad = next(v for v in vadinfo.VadInfo.list_vads(proc) if v.get_start() == sb)
    flags = vad_flags(main_vad)
    patcher.set_bits(kernel.layer_name, flags.member("PrivateMemory"), 1)
    patcher.set_bits(kernel.layer_name, flags.member("VadType"), 0)
    manifest["operations"].append({"op": "main_not_image", "pid": pid, "vad": hex(sb),
                                   "expect": ["PEVAD-I02"]})

    # ---- reflective-injection-like region and wx_only region ------------------------------
    def private_rw_vad(proc):
        layer = self_layer = proc.add_process_layer()
        pl = ctx.layers[self_layer]
        for v in vadinfo.VadInfo.list_vads(proc):
            try:
                if not v.get_private_memory():
                    continue
                size = v.get_end() + 1 - v.get_start()
                if size < 0x2000 or size > 0x200000:
                    continue
                start = v.get_start()
                if pl.is_valid(start) and pl.is_valid(start + 0x1000):
                    prot = v.get_protection(vadinfo.VadInfo.protect_values(ctx, kernel.layer_name, kernel.symbol_table_name), vadinfo.winnt_protections)
                    if prot == "PAGE_READWRITE":
                        return v
            except exceptions.InvalidAddressException:
                continue
        return None

    for op, expect in (("reflective", ["PEVAD-II01", "PEVAD-II02"]), ("wx_only", ["PEVAD-II01", "PEVAD-II02"])):
        pid = next(picks)
        proc = procs[pid]
        v = private_rw_vad(proc)
        if v is None:
            sys.exit(f"no suitable private RW VAD in pid {pid}")
        layer = proc.add_process_layer()
        patcher.set_bits(kernel.layer_name, vad_flags(v).member("Protection"), 6)  # PAGE_EXECUTE_READWRITE
        entry = {"op": op, "pid": pid, "vad": hex(v.get_start()), "expect": expect}
        if op == "reflective":
            header = bytearray(0x400)
            header[0:2] = b"MZ"
            struct.pack_into("<I", header, 0x3C, 0x80)
            header[0x80:0x84] = b"PE\0\0"
            stub = bytes.fromhex("fc4883e4f0e8c0000000")       # cld; and rsp,-16; call +0xC0
            patcher.write(layer, v.get_start(), bytes(header) + stub)
            entry["expect_tags"] = ["pe_header", "shellcode_stager"]
        manifest["operations"].append(entry)

    patcher.close()
    manifest["tampered"] = os.path.basename(dst)
    manifest["tampered_sha256"] = sha256(dst)
    if sha256(src) != src_hash_before:
        sys.exit("SOURCE IMAGE CHANGED - abort")
    Path(manifest_path).write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
