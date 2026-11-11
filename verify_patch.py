"""Exercise the patch on copied bytes and execute its shim in an isolated process.

The copied BMS image is not launched. External calls used by the shim are
replaced with callbacks; the original timestamp gate is separately exercised.
"""

import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import struct
import tempfile
import unittest

import patch_bms_acmi as patch


def source_bytes():
    data = patch.DEFAULT_EXE.read_bytes()
    if patch.digest(data) != patch.ORIGINAL_SHA256:
        data = patch.paths(patch.DEFAULT_EXE)[0].read_bytes()
    return data


class Image:
    def __init__(self, data):
        self.pe = patch.PE(data)
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.kernel.VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, W.DWORD, W.DWORD]
        self.kernel.VirtualAlloc.restype = C.c_void_p
        self.kernel.VirtualFree.argtypes = [C.c_void_p, C.c_size_t, W.DWORD]
        self.kernel.VirtualFree.restype = W.BOOL
        self.size = self.pe.image_size + 0x2000
        self.base = self.kernel.VirtualAlloc(None, self.size, 0x3000, 0x40)
        if not self.base:
            raise C.WinError(C.get_last_error())
        C.memmove(self.base, data, 1024)
        for va, vs, raw, raw_size in self.pe.sections:
            C.memmove(self.base + va, data[raw:raw + raw_size], raw_size)
        self.keepalive = []

    def put(self, rva, data):
        C.memmove(self.base + rva, data, len(data))

    def pointer(self, rva, pointer):
        self.put(rva, struct.pack("<Q", pointer))

    def callback(self, callback_type, function):
        cb = callback_type(function)
        self.keepalive.append(cb)
        return C.cast(cb, C.c_void_p).value

    def redirect(self, rva, callback):
        self.put(rva, b"\x48\xb8" + struct.pack("<Q", callback) + b"\xff\xe0")

    def close(self):
        self.kernel.VirtualFree(self.base, 0, 0x8000)


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = source_bytes()
        cls.patched, cls.manifest = patch.build_patch(cls.original)

    def test_apply_restore_and_foreign_edits(self):
        with tempfile.TemporaryDirectory(prefix="bms-acmi-test-", dir=Path(__file__).parent) as directory:
            exe = Path(directory) / "Falcon BMS.exe"
            exe.write_bytes(self.original)
            patch.perform("apply", exe)
            self.assertEqual(exe.read_bytes(), self.patched)
            self.assertEqual(patch.paths(exe)[0].read_bytes(), self.original)
            patch.perform("apply", exe)
            self.assertEqual(patch.perform("status", exe)["state"], "patched")
            foreign = bytearray(self.patched)
            foreign[0x2000] ^= 1
            exe.write_bytes(foreign)
            with self.assertRaises(ValueError):
                patch.perform("restore", exe)
            self.assertEqual(exe.read_bytes(), foreign)
            exe.write_bytes(self.patched)
            patch.perform("restore", exe)
            self.assertEqual(exe.read_bytes(), self.original)
            foreign = bytearray(self.original)
            foreign[0x2000] ^= 1
            with self.assertRaises(ValueError):
                patch.build_patch(foreign)

    def test_windows_checksum_and_unwind(self):
        imagehlp = C.WinDLL("imagehlp", use_last_error=True)
        imagehlp.CheckSumMappedFile.argtypes = [C.c_void_p, W.DWORD,
                                              C.POINTER(W.DWORD), C.POINTER(W.DWORD)]
        imagehlp.CheckSumMappedFile.restype = C.c_void_p
        buf = C.create_string_buffer(self.patched)
        header, computed = W.DWORD(), W.DWORD()
        self.assertTrue(imagehlp.CheckSumMappedFile(buf, len(self.patched), C.byref(header), C.byref(computed)))
        self.assertEqual(header.value, computed.value)

        image = Image(self.patched)
        try:
            table_rva, table_size = image.pe.directory(3)
            table = image.base + table_rva
            ntdll = C.WinDLL("ntdll")
            ntdll.RtlAddFunctionTable.argtypes = [C.c_void_p, W.DWORD, C.c_ulonglong]
            ntdll.RtlAddFunctionTable.restype = W.BOOL
            ntdll.RtlDeleteFunctionTable.argtypes = [C.c_void_p]
            ntdll.RtlDeleteFunctionTable.restype = W.BOOL
            ntdll.RtlLookupFunctionEntry.argtypes = [C.c_ulonglong, C.POINTER(C.c_ulonglong), C.c_void_p]
            ntdll.RtlLookupFunctionEntry.restype = C.c_void_p
            ntdll.RtlVirtualUnwind.argtypes = [W.DWORD, C.c_ulonglong, C.c_ulonglong, C.c_void_p,
                                            C.c_void_p, C.POINTER(C.c_void_p),
                                            C.POINTER(C.c_ulonglong), C.c_void_p]
            ntdll.RtlVirtualUnwind.restype = C.c_void_p
            self.assertTrue(ntdll.RtlAddFunctionTable(table, table_size // 12, image.base))
            try:
                shim_rva = int(self.manifest["aircraft_hook"]["shim_rva"], 16)
                pc = image.base + shim_rva + 8
                actual_base = C.c_ulonglong()
                entry = ntdll.RtlLookupFunctionEntry(pc, C.byref(actual_base), None)
                self.assertEqual(actual_base.value, image.base)
                self.assertEqual(entry, table + table_size - 12)
                context_buffer = C.create_string_buffer(1232 + 16)
                context = patch.align(C.addressof(context_buffer), 16)
                stack = C.create_string_buffer(0x200)
                rsp = patch.align(C.addressof(stack), 16) + 0x40
                sentinel, return_address = 0x123456789ABCDEF0, 0x1122334455667788
                C.memmove(rsp + 0x50, struct.pack("<QQ", sentinel, return_address), 16)
                C.c_uint32.from_address(context + 48).value = 0x100003
                C.c_uint64.from_address(context + 144).value = 0x99  # RBX
                C.c_uint64.from_address(context + 152).value = rsp   # RSP
                C.c_uint64.from_address(context + 248).value = pc    # RIP
                handler_data, establisher = C.c_void_p(), C.c_ulonglong()
                ntdll.RtlVirtualUnwind(0, image.base, pc, entry, context,
                                      C.byref(handler_data), C.byref(establisher), None)
                self.assertEqual(C.c_uint64.from_address(context + 144).value, sentinel)
                self.assertEqual(C.c_uint64.from_address(context + 152).value, rsp + 0x60)
                self.assertEqual(C.c_uint64.from_address(context + 248).value, return_address)
            finally:
                ntdll.RtlDeleteFunctionTable(table)
        finally:
            image.close()

    def test_native_shim_capture_lock_lifecycle_and_abi(self):
        image = Image(self.patched)
        try:
            events, failures = [], []
            aircraft = C.create_string_buffer(0x5000)
            vtable = C.create_string_buffer(0x500)
            aircraft_pointer = C.addressof(aircraft)
            C.c_uint64.from_buffer(aircraft).value = C.addressof(vtable)
            dead = [False]
            unary = C.WINFUNCTYPE(None, C.c_void_p)
            def mandatory(ptr):
                events.append("mandatory")
                if ptr != aircraft_pointer:
                    failures.append("mandatory aircraft pointer")
            def is_dead(ptr):
                events.append("dead_check")
                return int(dead[0])
            def lock(ptr):
                events.append("lock")
                if ptr != image.base + patch.RECORDER_LOCK:
                    failures.append("lock pointer")
            def unlock(ptr):
                events.append("unlock")
                if ptr != image.base + patch.RECORDER_LOCK:
                    failures.append("unlock pointer")
            def record(rec, air, outer, interval):
                events.append("record")
                values = (C.c_uint64 * 2).from_address(outer)
                inner = (C.c_uint64 * 2).from_address(values[1])
                if (rec != image.base + patch.RECORDER or air != aircraft_pointer
                        or values[0] != aircraft_pointer or interval != 1
                        or C.c_uint64.from_address(inner[0]).value != aircraft_pointer
                        or inner[1] != image.base + patch.SIM_DRIVER):
                    failures.append("native lambda capture or recorder arguments")
            image.redirect(patch.MANDATORY_LOGIC, image.callback(unary, mandatory))
            image.pointer(patch.ACQUIRE_LOCK_IAT, image.callback(unary, lock))
            image.pointer(patch.RELEASE_LOCK_IAT, image.callback(unary, unlock))
            image.redirect(patch.RECORD_AIRCRAFT, image.callback(
                C.WINFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32), record))
            C.c_uint64.from_address(C.addressof(vtable) + 0x1B0).value = image.callback(
                C.WINFUNCTYPE(C.c_int, C.c_void_p), is_dead)

            shim_rva = int(self.manifest["aircraft_hook"]["shim_rva"], 16)
            wrapper_rva = image.pe.image_size
            c = patch.Code(wrapper_rva)
            c.emit("53 48 83 ec 20 48 bb")
            c.data.extend(struct.pack("<Q", 0x123456789ABCDEF0))
            c.relative("e8", shim_rva)
            c.emit("48 b8")
            c.data.extend(struct.pack("<Q", 0x123456789ABCDEF0))
            c.emit("48 39 c3 0f 94 c0 0f b6 c0 48 83 c4 20 5b c3")
            image.put(wrapper_rva, c.finish())
            run = C.WINFUNCTYPE(C.c_int, C.c_void_p)(image.base + wrapper_rva)
            for enabled, recording, isdead, expected in [
                (1, 1, False, ["mandatory", "dead_check", "lock", "record", "unlock"]),
                (0, 1, False, ["mandatory"]),
                (1, 0, False, ["mandatory"]),
                (1, 1, True, ["mandatory", "dead_check"]),
            ]:
                events.clear()
                image.put(patch.TACVIEW_ENABLED, bytes([enabled]))
                image.put(patch.RECORDER + 8, bytes([recording]))
                dead[0] = isdead
                self.assertEqual(run(aircraft_pointer), 1, "RBX was not preserved")
                self.assertEqual(events, expected)
                self.assertFalse(failures, failures)
        finally:
            image.close()

    def test_original_machine_code_timestamp_gate(self):
        image = Image(self.patched)
        try:
            # Allow the native FoW precondition, then exercise the actual native
            # hash lookup and unsigned time comparison. Intercept serialization
            # at the accepted-sample branch so no simulator state is needed.
            image.put(0x2EADB0, bytes.fromhex("c6 01 01 c6 41 01 01 48 8b c1 c3"))
            hits = []
            hit = image.callback(C.WINFUNCTYPE(None), lambda: hits.append(True))
            accepted = 0x6DF94E
            code = b"\x48\xb8" + struct.pack("<Q", hit) + b"\xff\xd0"
            code += b"\xe9" + struct.pack("<i", 0x6E066F - (accepted + len(code) + 5))
            image.put(accepted, code)
            entity = C.create_string_buffer(0x100)
            node, sentinel, buckets = C.create_string_buffer(0x30), C.create_string_buffer(0x30), C.create_string_buffer(16)
            entity_id = struct.pack("<II", 0x1234, 0x5678)
            C.memmove(C.addressof(entity) + 0x10, entity_id, 8)
            C.memmove(C.addressof(node) + 0x10, entity_id, 8)
            for offset in (0, 8):
                C.c_uint64.from_address(C.addressof(buckets) + offset).value = C.addressof(node)
            image.pointer(patch.RECORDER + 0x120, C.addressof(sentinel))
            image.pointer(patch.RECORDER + 0x130, C.addressof(buckets))
            image.pointer(patch.RECORDER + 0x148, 0)
            image.put(patch.RECORDER + 8, b"\1")
            fn = C.WINFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint32)(
                image.base + patch.RECORD_AIRCRAFT)
            for last, now, interval, expected in [
                (1000, 1000, 1, False), (1000, 1001, 1, True),
                (1000, 1011, 1, True), (1000, 1011, 100, False),
                (1000, 1099, 100, False), (1000, 1100, 100, True),
                (0xFFFFFFFA, 2, 1, True),
            ]:
                hits.clear()
                C.c_uint32.from_address(C.addressof(node) + 0x18).value = last
                image.put(0x1645F28, struct.pack("<I", now))
                fn(image.base + patch.RECORDER, C.addressof(entity), None, interval)
                self.assertEqual(bool(hits), expected, (last, now, interval))
        finally:
            image.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
