"""Parsing-rule tests: the first structural error must be located."""
import struct
import unittest

from elfaudit.elf import (
    DT_GNU_HASH,
    DT_HASH,
    DT_SYMTAB,
    DT_VERSYM,
    ElfFile,
    StructuralError,
)
from elfbuilder import ElfBuilder, dynamic_value, patch_dynamic, patch_u16


def good_lib() -> bytes:
    return (ElfBuilder(soname="liba.so")
            .verdef("FC_1.0")
            .symbol("alpha", version="FC_1.0")
            .symbol("beta")
            .build())


def good_target() -> bytes:
    return (ElfBuilder(soname="fc_core.so")
            .need("liba.so")
            .symbol("alpha", defined=False, version="FC_1.0",
                    version_file="liba.so")
            .symbol("beta", defined=False)
            .build())


def expect_error(tc, data, field, needle=""):
    with tc.assertRaises(StructuralError) as ctx:
        ElfFile.parse(data, "obj.so")
    tc.assertEqual(ctx.exception.field, field, ctx.exception.message)
    if needle:
        tc.assertIn(needle, ctx.exception.message)
    return ctx.exception


class HeaderRules(unittest.TestCase):
    def test_valid_object_parses(self):
        elf = ElfFile.parse(good_lib(), "liba.so")
        self.assertEqual(elf.soname, "liba.so")
        self.assertEqual([s.name for s in elf.symbols], ["", "alpha", "beta"])

    def test_truncated_header(self):
        expect_error(self, good_lib()[:40], "e_ident", "truncated")

    def test_bad_magic(self):
        data = b"\x7fELG" + good_lib()[4:]
        expect_error(self, data, "e_ident", "magic")

    def test_not_64bit(self):
        data = good_lib()
        data = data[:4] + bytes([1]) + data[5:]
        expect_error(self, data, "e_ident", "ELF64")

    def test_not_little_endian(self):
        data = good_lib()
        data = data[:5] + bytes([2]) + data[6:]
        expect_error(self, data, "e_ident", "little-endian")

    def test_not_et_dyn(self):
        data = bytearray(good_lib())
        struct.pack_into("<H", data, 16, 2)  # ET_EXEC
        expect_error(self, bytes(data), "e_type", "ET_DYN")

    def test_truncated_program_headers(self):
        # e_phnum claims 2 entries but the file ends inside the table.
        expect_error(self, good_lib()[:100], "e_phoff", "truncated")

    def test_zero_program_headers(self):
        data = bytearray(good_lib())
        struct.pack_into("<H", data, 56, 0)
        expect_error(self, bytes(data), "e_phnum")


class SegmentRules(unittest.TestCase):
    def test_load_file_range_beyond_end(self):
        data = bytearray(good_lib())
        # PT_LOAD p_filesz beyond object size.
        struct.pack_into("<Q", data, 64 + 32, len(data) + 0x100)
        expect_error(self, bytes(data), "p_filesz", "exceeds")

    def test_load_filesz_exceeds_memsz(self):
        data = bytearray(good_lib())
        total = struct.unpack_from("<Q", data, 64 + 32)[0]
        struct.pack_into("<Q", data, 64 + 40, total - 1)  # p_memsz < p_filesz
        expect_error(self, bytes(data), "p_memsz")

    def test_load_misaligned(self):
        lib = ElfBuilder(soname="liba.so")
        lib.symbol("alpha")
        data = bytearray(lib.build())
        total = len(data)
        # p_offset = 8 while p_vaddr = 0 with p_align = 0x1000 -> misaligned.
        struct.pack_into("<Q", data, 64 + 8, 8)
        struct.pack_into("<Q", data, 64 + 32, total - 8)  # keep file range valid
        expect_error(self, bytes(data), "p_vaddr", "misaligned")

    def test_load_align_not_power_of_two(self):
        data = bytearray(good_lib())
        struct.pack_into("<Q", data, 64 + 48, 0x300)
        expect_error(self, bytes(data), "p_align", "power of two")

    def test_duplicate_dynamic_segment(self):
        data = bytearray(good_lib())
        # Turn the PT_LOAD phdr into a second PT_DYNAMIC.
        struct.pack_into("<I", data, 64, 2)
        expect_error(self, bytes(data), "PT_DYNAMIC", "duplicate")

    def test_missing_dynamic_segment(self):
        data = bytearray(good_lib())
        struct.pack_into("<I", data, 64 + 56, 0)  # PT_DYNAMIC -> PT_NULL
        expect_error(self, bytes(data), "PT_DYNAMIC")

    def test_missing_load_segment(self):
        data = bytearray(good_lib())
        struct.pack_into("<I", data, 64, 0)  # PT_LOAD -> PT_NULL
        expect_error(self, bytes(data), "PT_LOAD")


class DynamicTableRules(unittest.TestCase):
    def test_unterminated_dynamic_segment(self):
        data = bytearray(good_lib())
        dyn_off = None
        phoff = struct.unpack_from("<Q", data, 32)[0]
        for i in range(2):
            p = phoff + i * 56
            if struct.unpack_from("<I", data, p)[0] == 2:
                dyn_off = struct.unpack_from("<Q", data, p + 8)[0]
                dyn_size = struct.unpack_from("<Q", data, p + 32)[0]
        # Overwrite every DT_NULL tag with DT_DEBUG (21).
        for k in range(dyn_off, dyn_off + dyn_size, 16):
            if struct.unpack_from("<q", data, k)[0] == 0:
                struct.pack_into("<q", data, k, 21)
        expect_error(self, bytes(data), "DT_NULL", "terminated")

    def test_unmappable_symtab(self):
        data = patch_dynamic(good_lib(), DT_SYMTAB, 0x00DEAD0000)
        expect_error(self, data, "DT_SYMTAB", "not mapped")

    def test_unmappable_strtab(self):
        from elfaudit.elf import DT_STRTAB
        data = patch_dynamic(good_lib(), DT_STRTAB, 0x00DEAD0000)
        expect_error(self, data, "DT_STRTAB", "not mapped")

    def test_bad_syment(self):
        from elfaudit.elf import DT_SYMENT
        data = patch_dynamic(good_lib(), DT_SYMENT, 32)
        expect_error(self, data, "DT_SYMENT")

    def test_missing_hash_tables(self):
        lib = ElfBuilder(soname="liba.so")
        lib.emit_sysv = False
        lib.emit_gnu = False
        lib.symbol("alpha")
        expect_error(self, lib.build(), "DT_HASH", "hash")

    def test_hash_count_mismatch(self):
        # SysV nchain corrupted to disagree with the GNU-derived count.
        lib = ElfBuilder(soname="liba.so")
        lib.symbol("alpha")
        data = bytearray(lib.build())
        hash_v = dynamic_value(bytes(data), DT_HASH)
        struct.pack_into("<I", data, hash_v + 4, 5)  # nchain = 5
        expect_error(self, bytes(data), "DT_GNU_HASH", "disagree")

    def test_sysv_only_and_gnu_only(self):
        for sysv, gnu in ((True, False), (False, True)):
            lib = ElfBuilder(soname="liba.so")
            lib.emit_sysv, lib.emit_gnu = sysv, gnu
            lib.symbol("alpha").symbol("beta")
            elf = ElfFile.parse(lib.build(), "liba.so")
            self.assertEqual(elf.find("beta"), [2])
            self.assertEqual(elf.find("nope"), [])

    def test_duplicate_needed(self):
        tgt = ElfBuilder(soname="fc.so")
        tgt.need("liba.so").need("liba.so")
        tgt.symbol("alpha", defined=False)
        expect_error(self, tgt.build(), "DT_NEEDED", "duplicate")


class VersionRules(unittest.TestCase):
    def test_versym_dangling_index(self):
        tgt = bytearray(good_target())
        versym_off = dynamic_value(bytes(tgt), DT_VERSYM)
        # Symbol 1 references version index 9 which exists nowhere.
        struct.pack_into("<H", tgt, versym_off + 2, 9)
        expect_error(self, bytes(tgt), "DT_VERSYM", "unknown version index")

    def test_hidden_version_on_undefined_symbol(self):
        tgt = bytearray(good_target())
        versym_off = dynamic_value(bytes(tgt), DT_VERSYM)
        struct.pack_into("<H", tgt, versym_off + 2, 0x8002)
        expect_error(self, bytes(tgt), "DT_VERSYM", "hidden")

    def test_undefined_symbol_bound_to_verdef(self):
        # Give the target its own verdef at index 2, then point the
        # undefined symbol's versym at it: contradiction.
        tgt = ElfBuilder(soname="fc.so")
        tgt.need("liba.so")
        tgt.verdef("LOCAL_1")
        tgt.symbol("mine")  # defined, uses index 2
        tgt.symbol("ext", defined=False, version="FC_1.0", version_file="liba.so")
        data = bytearray(tgt.build())
        versym_off = dynamic_value(bytes(data), DT_VERSYM)
        struct.pack_into("<H", data, versym_off + 2 * 2, 2)  # sym 2 -> verdef 2
        expect_error(self, bytes(data), "DT_VERSYM", "defined version")

    def test_verneed_unknown_file(self):
        tgt = ElfBuilder(soname="fc.so")
        tgt.need("liba.so")
        tgt.symbol("alpha", defined=False, version="FC_1.0",
                   version_file="liba.so")
        data = bytearray(tgt.build())
        # Point vn_file at the "FC_1.0" string (not a DT_NEEDED name).
        verneed_v = dynamic_value(bytes(data), 0x6FFFFFFE)
        strtab_v = dynamic_value(bytes(data), 5)
        strsz = dynamic_value(bytes(data), 10)
        raw = bytes(data)
        fc_off = raw.index(b"FC_1.0\0", strtab_v, strtab_v + strsz) - strtab_v
        struct.pack_into("<I", data, verneed_v + 4, fc_off)
        expect_error(self, bytes(data), "DT_VERNEED", "not a DT_NEEDED")

    def test_version_index_both_defined_and_needed(self):
        tgt = ElfBuilder(soname="fc.so")
        tgt.need("liba.so")
        tgt.verdef("MINE_1")
        tgt.symbol("mine")
        tgt.symbol("ext", defined=False, version="FC_1.0", version_file="liba.so")
        data = bytearray(tgt.build())
        # verdef takes index 2, verneed index 3; force verneed aux to 2.
        verneed_v = dynamic_value(bytes(data), 0x6FFFFFFE)
        struct.pack_into("<H", data, verneed_v + 16 + 6, 2)  # vna_other = 2
        expect_error(self, bytes(data), "DT_VERNEED", "both defined and needed")

    def test_verdef_without_versym(self):
        from elfbuilder import dynamic_tag_offset
        lib = ElfBuilder(soname="liba.so")
        lib.verdef("FC_1.0")
        lib.symbol("alpha", version="FC_1.0")
        data = bytearray(lib.build())
        # Retag DT_VERSYM as DT_DEBUG: version tables without the array.
        val_off = dynamic_tag_offset(bytes(data), DT_VERSYM)
        struct.pack_into("<q", data, val_off - 8, 21)
        expect_error(self, bytes(data), "DT_VERSYM", "without")


if __name__ == "__main__":
    unittest.main()
