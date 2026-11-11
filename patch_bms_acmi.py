"""Version-specific, reversible high-rate ACMI patch for Falcon BMS 4.38.1 x64.

Uses only the Python standard library. It edits the installed executable only
after identifying the exact original build. No running-process memory changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile


ORIGINAL_SHA256 = "2e74e9a9d09efd257ea9bd6ed623bae1bcfe00d49d144c2441616642f7529b24"
DEFAULT_EXE = Path(r"D:\Falcon BMS 4.38\Bin\x64\Falcon BMS.exe")
IMAGE_BASE = 0x140000000
MANDATORY_LOGIC = 0x2E8550
MANDATORY_SLOT = 0xC7ED60
RECORD_AIRCRAFT = 0x6DF780
TACVIEW_ENABLED = 0xE74B7B
RECORDER = 0x16E8600
RECORDER_LOCK = RECORDER + 0x1B0
SIM_DRIVER = 0xE97B40
ACQUIRE_LOCK_IAT = 0xC315A0
RELEASE_LOCK_IAT = 0xC31598
INTERVAL_SITES = (
    (0x2E2D1B, "AircraftClass::DoLogicNew"),
    (0x2E6AFB, "AircraftClass::DoLogicOld"),
    (0xA53064, "TacviewRecorder::RecordMissile"),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


class PE:
    def __init__(self, data):
        self.data = data
        self.nt = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.nt:self.nt + 4] != b"PE\0\0":
            raise ValueError("Not a PE executable")
        machine, self.count = struct.unpack_from("<HH", data, self.nt + 4)
        self.optional = self.nt + 24
        optional_size = struct.unpack_from("<H", data, self.nt + 20)[0]
        if machine != 0x8664 or struct.unpack_from("<H", data, self.optional)[0] != 0x20B:
            raise ValueError("Expected an x64 PE32+ executable")
        self.base = struct.unpack_from("<Q", data, self.optional + 24)[0]
        self.section_alignment, self.file_alignment = struct.unpack_from("<II", data, self.optional + 32)
        self.image_size = struct.unpack_from("<I", data, self.optional + 56)[0]
        self.section_table = self.optional + optional_size
        self.sections = []
        for n in range(self.count):
            off = self.section_table + n * 40
            vs, va, raw_size, raw = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append((va, vs, raw, raw_size))

    def offset(self, rva):
        for va, vs, raw, raw_size in self.sections:
            if va <= rva < va + raw_size:
                return raw + rva - va
        raise ValueError(f"RVA {rva:#x} has no file bytes")

    def directory(self, index):
        return struct.unpack_from("<II", self.data, self.optional + 112 + 8 * index)

    def has_dir64_relocation(self, target_rva):
        rva, size = self.directory(5)
        cursor, end = self.offset(rva), self.offset(rva) + size
        while cursor < end:
            page, block_size = struct.unpack_from("<II", self.data, cursor)
            if block_size < 8 or cursor + block_size > end:
                raise ValueError("Malformed relocation block")
            for pos in range(cursor + 8, cursor + block_size, 2):
                entry = struct.unpack_from("<H", self.data, pos)[0]
                if entry >> 12 == 10 and page + (entry & 0xFFF) == target_rva:
                    return True
            cursor += block_size
        return False


class Code:
    """Small explicit x64 emitter; all external references are RIP-relative."""

    def __init__(self, rva):
        self.rva = rva
        self.data = bytearray()
        self.labels = {}
        self.branches = []

    def emit(self, text):
        self.data.extend(bytes.fromhex(text))

    def relative(self, opcode, target, suffix=b""):
        prefix = bytes.fromhex(opcode)
        next_rva = self.rva + len(self.data) + len(prefix) + 4 + len(suffix)
        self.data.extend(prefix + struct.pack("<i", target - next_rva) + suffix)

    def branch(self, opcode, label):
        self.emit(opcode)
        self.branches.append((len(self.data), label))
        self.data.extend(b"\0" * 4)

    def label(self, name):
        self.labels[name] = len(self.data)

    def finish(self):
        for off, label in self.branches:
            struct.pack_into("<i", self.data, off, self.labels[label] - (off + 4))
        return bytes(self.data)


def aircraft_shim(rva):
    c = Code(rva)
    c.emit("53")                         # push rbx
    c.emit("48 83 ec 50")                # sub rsp, 0x50 (32-byte shadow + captures)
    c.emit("48 8b d9")                   # mov rbx, rcx (aircraft)
    c.relative("e8", MANDATORY_LOGIC)     # preserve the complete original behavior
    c.relative("80 3d", TACVIEW_ENABLED, b"\0")
    c.branch("0f 84", "done")
    c.relative("80 3d", RECORDER + 8, b"\0")
    c.branch("0f 84", "done")
    c.emit("48 8b 03 48 8b cb")          # IsDead(), matching the native lifecycle check
    c.emit("ff 90 b0 01 00 00 85 c0")
    c.branch("0f 85", "done")
    c.relative("48 8d 0d", RECORDER_LOCK)
    c.relative("ff 15", ACQUIRE_LOCK_IAT)
    # Native InitTacviewRecord RecordAirplane capture layout:
    # outer = {aircraft, &inner}; inner = {&aircraft, &SimDriver}.
    c.emit("48 89 5c 24 20")             # outer.aircraft
    c.emit("48 8d 44 24 30")
    c.emit("48 89 44 24 28")             # outer.inner
    c.emit("48 8d 44 24 20")
    c.emit("48 89 44 24 30")             # inner.aircraft_ref
    c.relative("48 8d 05", SIM_DRIVER)
    c.emit("48 89 44 24 38")             # inner.driver
    c.relative("48 8d 0d", RECORDER)
    c.emit("48 8b d3")                   # rdx = aircraft
    c.emit("4c 8d 44 24 20")             # r8 = &outer
    c.emit("41 b9 01 00 00 00")          # r9d = 1 ms: skip an already-recorded timestamp
    c.relative("e8", RECORD_AIRCRAFT)
    c.relative("48 8d 0d", RECORDER_LOCK)
    c.relative("ff 15", RELEASE_LOCK_IAT)
    c.label("done")
    c.emit("48 83 c4 50 5b c3")
    return c.finish()


def checksum(data, checksum_offset):
    total = 0
    padded = data if len(data) % 2 == 0 else data + b"\0"
    for index, (word,) in enumerate(struct.iter_unpack("<H", padded)):
        if checksum_offset <= index * 2 < checksum_offset + 4:
            continue
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total & 0xFFFF) + len(data)


def build_patch(original):
    if digest(original) != ORIGINAL_SHA256:
        raise ValueError("Executable is not the identified BMS 4.38.1 x64 build")
    pe = PE(original)
    if pe.base != IMAGE_BASE or pe.directory(4) != (0, 0):
        raise ValueError("Unexpected executable layout")
    if not pe.has_dir64_relocation(MANDATORY_SLOT):
        raise ValueError("Aircraft vtable slot lacks its expected ASLR relocation")
    if struct.unpack_from("<Q", original, pe.offset(MANDATORY_SLOT))[0] != IMAGE_BASE + MANDATORY_LOGIC:
        raise ValueError("Unexpected aircraft vtable target")

    result = bytearray(original)
    changes = []
    for rva, name in INTERVAL_SITES:
        off = pe.offset(rva)
        before = bytes.fromhex("41 b9 64 00 00 00")
        after = bytes.fromhex("41 b9 01 00 00 00")
        if original[off:off + len(before)] != before:
            raise ValueError(f"Unexpected interval instruction in {name}")
        result[off:off + len(before)] = after
        changes.append({"function": name, "rva": hex(rva), "file_offset": off,
                        "before": before.hex(), "after": after.hex()})

    new_rva = align(pe.image_size, pe.section_alignment)
    code = aircraft_shim(new_rva)
    unwind_offset = align(len(code), 4)
    payload = bytearray(code)
    payload.extend(b"\0" * (unwind_offset - len(payload)))
    # UNWIND_INFO v1: prologue 5 bytes; ALLOC_SMALL(0x50), PUSH_NONVOL(RBX).
    payload.extend(bytes.fromhex("01 05 02 00 05 92 01 30"))
    table_offset = align(len(payload), 4)
    payload.extend(b"\0" * (table_offset - len(payload)))
    old_table_rva, old_table_size = pe.directory(3)
    old_off = pe.offset(old_table_rva)
    old_table = original[old_off:old_off + old_table_size]
    if len(old_table) != old_table_size or old_table_size % 12:
        raise ValueError("Unexpected exception directory")
    entries = list(struct.iter_unpack("<III", old_table))
    if entries != sorted(entries) or entries[-1][1] > new_rva:
        raise ValueError("Unexpected runtime-function ordering")
    payload.extend(old_table)
    payload.extend(struct.pack("<III", new_rva, new_rva + len(code), new_rva + unwind_offset))

    header = pe.section_table + pe.count * 40
    first_raw = min(s[2] for s in pe.sections)
    if header + 40 > first_raw or any(original[header:header + 40]):
        raise ValueError("No unused PE section-header slot")
    raw = align(len(original), pe.file_alignment)
    raw_size = align(len(payload), pe.file_alignment)
    result.extend(b"\0" * (raw - len(result)))
    result.extend(payload)
    result.extend(b"\0" * (raw + raw_size - len(result)))
    struct.pack_into("<8sIIIIIIHHI", result, header, b".acmifix", len(payload), new_rva,
                     raw_size, raw, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<H", result, pe.nt + 6, pe.count + 1)
    old_code_size = struct.unpack_from("<I", original, pe.optional + 4)[0]
    struct.pack_into("<I", result, pe.optional + 4, old_code_size + raw_size)
    struct.pack_into("<I", result, pe.optional + 56, align(new_rva + len(payload), pe.section_alignment))
    struct.pack_into("<II", result, pe.optional + 112 + 3 * 8,
                     new_rva + table_offset, old_table_size + 12)
    struct.pack_into("<Q", result, pe.offset(MANDATORY_SLOT), IMAGE_BASE + new_rva)
    checksum_offset = pe.optional + 64
    struct.pack_into("<I", result, checksum_offset, checksum(result, checksum_offset))
    patched = bytes(result)
    manifest = {
        "patch": "BMS 4.38.1 x64 high-rate ACMI v1",
        "original_sha256": ORIGINAL_SHA256,
        "patched_sha256": digest(patched),
        "original_size": len(original), "patched_size": len(patched),
        "interval_ms": 1, "interval_changes": changes,
        "aircraft_hook": {"vtable_slot_rva": hex(MANDATORY_SLOT), "original_rva": hex(MANDATORY_LOGIC),
                          "shim_rva": hex(new_rva), "shim_size": len(code), "shim_hex": code.hex(),
                          "unwind_rva": hex(new_rva + unwind_offset)},
    }
    return patched, manifest


def paths(exe):
    return (exe.with_name(exe.name + ".acmi-original.bak"),
            exe.with_name(exe.name + ".acmi-patch.json"))


def atomic_write(path, data):
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def perform(action, exe):
    exe = Path(exe)
    current = exe.read_bytes()
    backup, manifest_path = paths(exe)
    is_original = digest(current) == ORIGINAL_SHA256
    original = current if is_original else backup.read_bytes()
    patched, manifest = build_patch(original)
    if not is_original and current != patched:
        raise ValueError("Executable has other changes; refusing to overwrite them")
    if action in ("status", "check"):
        return {"state": "original" if is_original else "patched", "exe": str(exe), **manifest}
    if action == "apply":
        if backup.exists():
            if backup.read_bytes() != original:
                raise ValueError("Existing backup differs from the identified original")
        else:
            with backup.open("xb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
        if is_original:
            atomic_write(exe, patched)
        manifest.update({"exe": str(exe), "backup": str(backup)})
        atomic_write(manifest_path, (json.dumps(manifest, indent=2) + "\n").encode())
        if exe.read_bytes() != patched:
            raise OSError("Patched executable readback mismatch")
        return {"state": "patched", "exe": str(exe), "backup": str(backup),
                "sha256": manifest["patched_sha256"]}
    if action == "restore":
        if not is_original:
            atomic_write(exe, original)
        if digest(exe.read_bytes()) != ORIGINAL_SHA256:
            raise OSError("Restored executable readback mismatch")
        return {"state": "original", "exe": str(exe), "sha256": ORIGINAL_SHA256}
    raise ValueError(f"Unknown action: {action}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "restore", "status", "check"))
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    args = parser.parse_args()
    try:
        print(json.dumps(perform(args.action, args.exe), indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
