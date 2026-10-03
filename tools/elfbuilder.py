"""Synthetic ELF64 little-endian ET_DYN object builder.

Produces strictly valid objects (per the audit parser's rules) for unit
tests and for the end-to-end verifier, plus helpers to corrupt specific
fields so rejection paths can be exercised deterministically.

Layout: ELF header, two program headers (one PT_LOAD covering the whole
file with vaddr == file offset, one PT_DYNAMIC), then .dynstr, .dynsym,
.hash / .gnu.hash, .gnu.version, .gnu.version_d, .gnu.version_r and
.dynamic.
"""
from __future__ import annotations

import struct

from elfaudit.elf import (
    DT_GNU_HASH,
    DT_HASH,
    DT_NEEDED,
    DT_NULL,
    DT_SONAME,
    DT_STRSZ,
    DT_STRTAB,
    DT_SYMENT,
    DT_SYMTAB,
    DT_VERDEF,
    DT_VERDEFNUM,
    DT_VERNEED,
    DT_VERNEEDNUM,
    DT_VERSYM,
    elf_hash,
    gnu_hash,
)

_BIND = {"LOCAL": 0, "GLOBAL": 1, "WEAK": 2}
_EHDR_SIZE = 64
_PHDR_SIZE = 56
_SYM_SIZE = 24
_DYN_SIZE = 16
_PT_LOAD = 1
_PT_DYNAMIC = 2


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class _Strtab:
    def __init__(self):
        self.data = bytearray(b"\0")
        self.offsets = {"": 0}

    def add(self, s: str) -> int:
        if s in self.offsets:
            return self.offsets[s]
        off = len(self.data)
        self.data += s.encode("utf-8") + b"\0"
        self.offsets[s] = off
        return off


class ElfBuilder:
    """Builds one ELF64 ET_DYN object."""

    def __init__(self, soname: str | None = None, machine: int = 62):
        self.soname = soname
        self.machine = machine
        self.needed: list[str] = []
        self.symbols: list[dict] = []
        self.verdef_names: list[str] = []
        self.verneed_pairs: list[tuple[str, str]] = []
        self.emit_sysv = True
        self.emit_gnu = True
        self.load_align = 0x1000

    # -- declaration helpers --------------------------------------------
    def need(self, name: str) -> "ElfBuilder":
        self.needed.append(name)
        return self

    def verdef(self, version: str) -> "ElfBuilder":
        if version not in self.verdef_names:
            self.verdef_names.append(version)
        return self

    def verneed(self, file: str, version: str) -> "ElfBuilder":
        pair = (file, version)
        if pair not in self.verneed_pairs:
            self.verneed_pairs.append(pair)
        return self

    def symbol(self, name: str, bind: str = "GLOBAL", defined: bool = True,
               version: str | None = None, version_file: str | None = None,
               hidden_version: bool = False, visibility: int = 0,
               value: int = 0x1000, size: int = 0x20) -> "ElfBuilder":
        """Add a dynamic symbol.

        ``version`` names a version definition for defined symbols, or a
        version need (together with ``version_file``) for undefined ones.
        """
        self.symbols.append({
            "name": name,
            "bind": bind,
            "defined": defined,
            "version": version,
            "version_file": version_file,
            "hidden_version": hidden_version,
            "visibility": visibility,
            "value": value,
            "size": size,
        })
        return self

    # -- build ------------------------------------------------------------
    def build(self) -> bytes:
        # Auto-register versions referenced by symbols.
        for sym in self.symbols:
            if sym["version"] is None:
                continue
            if sym["defined"]:
                self.verdef(sym["version"])
            else:
                if not sym["version_file"]:
                    raise ValueError(
                        f"undefined versioned symbol '{sym['name']}' needs "
                        f"version_file")
                self.verneed(sym["version_file"], sym["version"])

        strtab = _Strtab()
        needed_offs = [strtab.add(n) for n in self.needed]
        soname_off = strtab.add(self.soname) if self.soname else None
        sym_name_offs = [strtab.add(s["name"]) for s in self.symbols]
        verdef_name_offs = [strtab.add(v) for v in self.verdef_names]
        verneed_file_offs = [strtab.add(f) for f, _ in self.verneed_pairs]
        verneed_name_offs = [strtab.add(v) for _, v in self.verneed_pairs]

        verdef_index = {name: 2 + i for i, name in enumerate(self.verdef_names)}
        base = 2 + len(self.verdef_names)
        verneed_index = {pair: base + i for i, pair in enumerate(self.verneed_pairs)}

        have_versions = bool(self.verdef_names or self.verneed_pairs)

        # versym values per user symbol (index 0 is the null symbol).
        versym = [0]
        for sym in self.symbols:
            if sym["defined"]:
                value = verdef_index[sym["version"]] if sym["version"] else 1
            else:
                if sym["version"]:
                    value = verneed_index[(sym["version_file"], sym["version"])]
                else:
                    value = 0
            if sym["hidden_version"]:
                value |= 0x8000
            versym.append(value)

        # ---- layout ----
        off = _EHDR_SIZE + 2 * _PHDR_SIZE
        dynstr_off = off
        off += len(strtab.data)

        off = _align(off, 8)
        dynsym_off = off
        nsym = 1 + len(self.symbols)
        off += _SYM_SIZE * nsym

        sysv_off = None
        nbucket = max(1, len(self.symbols))
        if self.emit_sysv:
            off = _align(off, 4)
            sysv_off = off
            off += 8 + 4 * (nbucket + nsym)

        gnu_off = None
        if self.emit_gnu:
            off = _align(off, 8)
            gnu_off = off
            # header(16) + bloom(8) + 1 bucket(4) + chain per user symbol
            off += 16 + 8 + 4 + 4 * len(self.symbols)

        versym_off = None
        if have_versions:
            off = _align(off, 2)
            versym_off = off
            off += 2 * nsym

        verdef_off = None
        if self.verdef_names:
            off = _align(off, 8)
            verdef_off = off
            off += 28 * len(self.verdef_names)  # 20-byte header + 8-byte aux

        verneed_off = None
        if self.verneed_pairs:
            off = _align(off, 8)
            verneed_off = off
            off += 32 * len(self.verneed_pairs)  # 16-byte header + 16-byte aux

        off = _align(off, 8)
        dynamic_off = off
        dyn_entries: list[tuple[int, int]] = []
        for noff in needed_offs:
            dyn_entries.append((DT_NEEDED, noff))
        if soname_off is not None:
            dyn_entries.append((DT_SONAME, soname_off))
        dyn_entries += [
            (DT_STRTAB, dynstr_off),
            (DT_STRSZ, len(strtab.data)),
            (DT_SYMTAB, dynsym_off),
            (DT_SYMENT, _SYM_SIZE),
        ]
        if sysv_off is not None:
            dyn_entries.append((DT_HASH, sysv_off))
        if gnu_off is not None:
            dyn_entries.append((DT_GNU_HASH, gnu_off))
        if versym_off is not None:
            dyn_entries.append((DT_VERSYM, versym_off))
        if verdef_off is not None:
            dyn_entries += [
                (DT_VERDEF, verdef_off),
                (DT_VERDEFNUM, len(self.verdef_names)),
            ]
        if verneed_off is not None:
            dyn_entries += [
                (DT_VERNEED, verneed_off),
                (DT_VERNEEDNUM, len(self.verneed_pairs)),
            ]
        dyn_entries.append((DT_NULL, 0))
        off += _DYN_SIZE * len(dyn_entries)
        total = off

        # ---- emit ----
        buf = bytearray(total)
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        struct.pack_into(
            "<16sHHIQQQIHHHHHH", buf, 0,
            ident, 3, self.machine, 1, 0,
            _EHDR_SIZE, 0, 0,
            _EHDR_SIZE, _PHDR_SIZE, 2, _EHDR_SIZE, 0, 0,
        )
        # PT_LOAD: whole file, vaddr == offset.
        struct.pack_into(
            "<IIQQQQQQ", buf, _EHDR_SIZE,
            _PT_LOAD, 5, 0, 0, 0, total, total, self.load_align,
        )
        # PT_DYNAMIC.
        struct.pack_into(
            "<IIQQQQQQ", buf, _EHDR_SIZE + _PHDR_SIZE,
            _PT_DYNAMIC, 6, dynamic_off, dynamic_off, dynamic_off,
            _DYN_SIZE * len(dyn_entries), _DYN_SIZE * len(dyn_entries), 8,
        )

        buf[dynstr_off:dynstr_off + len(strtab.data)] = bytes(strtab.data)

        # .dynsym (index 0 is the null symbol).
        for i, sym in enumerate(self.symbols, start=1):
            info = (_BIND[sym["bind"]] << 4) | (2 if sym["defined"] else 0)
            struct.pack_into(
                "<IBBHQQ", buf, dynsym_off + i * _SYM_SIZE,
                sym_name_offs[i - 1], info, sym["visibility"],
                1 if sym["defined"] else 0,
                sym["value"] if sym["defined"] else 0,
                sym["size"] if sym["defined"] else 0,
            )

        if sysv_off is not None:
            buckets = [0] * nbucket
            chains = [0] * nsym
            for i, sym in enumerate(self.symbols, start=1):
                b = elf_hash(sym["name"].encode("utf-8")) % nbucket
                chains[i] = buckets[b]
                buckets[b] = i
            struct.pack_into("<II", buf, sysv_off, nbucket, nsym)
            struct.pack_into(f"<{nbucket}I", buf, sysv_off + 8, *buckets)
            struct.pack_into(f"<{nsym}I", buf, sysv_off + 8 + 4 * nbucket, *chains)

        if gnu_off is not None:
            # One bucket holding every user symbol keeps the chain
            # contiguous without reordering .dynsym.
            struct.pack_into("<IIII", buf, gnu_off, 1, 1, 1, 5)
            struct.pack_into("<Q", buf, gnu_off + 16, 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<I", buf, gnu_off + 24, 1 if self.symbols else 0)
            for i, sym in enumerate(self.symbols, start=1):
                value = gnu_hash(sym["name"].encode("utf-8")) & ~1
                if i == len(self.symbols):
                    value |= 1
                struct.pack_into("<I", buf, gnu_off + 28 + 4 * (i - 1), value)

        if versym_off is not None:
            struct.pack_into(f"<{nsym}H", buf, versym_off, *versym)

        if verdef_off is not None:
            for i, (name, stroff) in enumerate(
                    zip(self.verdef_names, verdef_name_offs)):
                entry = verdef_off + 28 * i
                struct.pack_into(
                    "<HHHHIII", buf, entry,
                    1, 0, verdef_index[name], 1,
                    elf_hash(name.encode("utf-8")), 20,
                    28 if i < len(self.verdef_names) - 1 else 0,
                )
                struct.pack_into("<II", buf, entry + 20, stroff, 0)

        if verneed_off is not None:
            for i, (pair, foff, noff) in enumerate(
                    zip(self.verneed_pairs, verneed_file_offs, verneed_name_offs)):
                entry = verneed_off + 32 * i
                struct.pack_into(
                    "<HHIII", buf, entry,
                    1, 1, foff, 16,
                    32 if i < len(self.verneed_pairs) - 1 else 0,
                )
                struct.pack_into(
                    "<IHHII", buf, entry + 16,
                    elf_hash(pair[1].encode("utf-8")), 0, verneed_index[pair],
                    noff, 0,
                )

        for i, (tag, val) in enumerate(dyn_entries):
            struct.pack_into("<qQ", buf, dynamic_off + i * _DYN_SIZE, tag, val)

        return bytes(buf)


# -- corruption / inspection helpers --------------------------------------

def dynamic_tag_offset(data: bytes, tag: int, occurrence: int = 0) -> int:
    """File offset of the d_val field of the ``occurrence``-th ``tag``."""
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    dyn_off = dyn_size = None
    for i in range(phnum):
        p = phoff + i * _PHDR_SIZE
        if struct.unpack_from("<I", data, p)[0] == _PT_DYNAMIC:
            dyn_off = struct.unpack_from("<Q", data, p + 8)[0]
            dyn_size = struct.unpack_from("<Q", data, p + 32)[0]
            break
    if dyn_off is None:
        raise ValueError("no PT_DYNAMIC segment")
    for k in range(dyn_off, dyn_off + dyn_size, _DYN_SIZE):
        t = struct.unpack_from("<q", data, k)[0]
        if t == tag:
            if occurrence == 0:
                return k + 8
            occurrence -= 1
        if t == DT_NULL:
            break
    raise ValueError(f"dynamic tag {tag:#x} not found")


def dynamic_value(data: bytes, tag: int, occurrence: int = 0) -> int:
    off = dynamic_tag_offset(data, tag, occurrence)
    return struct.unpack_from("<Q", data, off)[0]


def patch_dynamic(data: bytes, tag: int, value: int, occurrence: int = 0) -> bytes:
    """Return a copy of ``data`` with one dynamic entry value replaced."""
    off = dynamic_tag_offset(data, tag, occurrence)
    return data[:off] + struct.pack("<Q", value) + data[off + 8:]


def patch_u16(data: bytes, offset: int, value: int) -> bytes:
    return data[:offset] + struct.pack("<H", value) + data[offset + 2:]
