"""Strict ELF64 little-endian ET_DYN parser.

Every dynamic-table virtual address is resolved through the PT_LOAD
segment map.  Validation runs in a fixed order (ELF header, program
headers, dynamic segment, string table, symbol/hash tables, version
tables, cross-table consistency) and the first violation raises
:class:`~elfaudit.errors.StructuralError`, so callers can always locate
the first structural error deterministically.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import StructuralError

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_SYMENT = 11
DT_STRSZ = 10
DT_SONAME = 14
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

STB_GLOBAL = 1
STB_WEAK = 2

SHN_UNDEF = 0

STV_DEFAULT = 0
STV_INTERNAL = 1
STV_HIDDEN = 2
STV_PROTECTED = 3

VERSYM_HIDDEN = 0x8000
VERSYM_INDEX = 0x7FFF

_EHDR_SIZE = 64
_PHDR_SIZE = 56
_SYM_SIZE = 24
_DYN_SIZE = 16


def elf_hash(name: bytes) -> int:
    """Traditional SysV ELF hash."""
    h = 0
    for c in name:
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= (~g) & 0xFFFFFFFF
    return h & 0xFFFFFFFF


def gnu_hash(name: bytes) -> int:
    """GNU hash (djb2 variant used by the GNU toolchain)."""
    h = 5381
    for c in name:
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h


@dataclass
class Symbol:
    index: int
    name: str
    name_offset: int
    info: int
    other: int
    shndx: int
    value: int
    size: int

    @property
    def bind(self) -> int:
        return self.info >> 4

    @property
    def type(self) -> int:
        return self.info & 0xF

    @property
    def defined(self) -> bool:
        return self.shndx != SHN_UNDEF

    @property
    def visible(self) -> bool:
        return (self.other & 0x3) in (STV_DEFAULT, STV_PROTECTED)


class ElfFile:
    """A parsed and structurally validated ELF64 LE ET_DYN object."""

    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data
        self.needed: list[str] = []
        self.soname: str | None = None
        self.symbols: list[Symbol] = []
        self.versym: list[int] | None = None
        self.verdef: dict[int, str] = {}
        self.verneed: dict[int, tuple[str, str]] = {}
        self._loads: list[tuple[int, int, int]] = []
        self._strtab: tuple[int, int] | None = None
        self._sysv = None  # (nbucket, buckets, chains)
        self._gnu = None   # (nbuckets, symoffset, buckets, chain_vaddr)

    # ------------------------------------------------------------------
    # public helpers
    # ------------------------------------------------------------------
    @classmethod
    def parse(cls, data: bytes, name: str) -> "ElfFile":
        elf = cls(name, data)
        elf._parse()
        return elf

    def find(self, name: str) -> list[int]:
        """Return dynsym indexes of every entry called ``name`` (sorted)."""
        out: list[int] = []
        encoded = name.encode("utf-8")
        if self._sysv is not None:
            nbucket, buckets, chains = self._sysv
            i = buckets[elf_hash(encoded) % nbucket]
            steps = 0
            while i:
                if i >= len(self.symbols):
                    break  # already proven impossible at parse time
                if self.symbols[i].name == name:
                    out.append(i)
                i = chains[i]
                steps += 1
                if steps > len(chains):
                    break
        elif self._gnu is not None:
            nbuckets, symoffset, buckets, chain_vaddr = self._gnu
            h = gnu_hash(encoded)
            i = buckets[h % nbuckets]
            if i >= symoffset:
                while i < len(self.symbols):
                    off = self._map(chain_vaddr + 4 * (i - symoffset), 4, "DT_GNU_HASH")
                    cv = self._u32(off, "DT_GNU_HASH")
                    if (cv | 1) == (h | 1) and self.symbols[i].name == name:
                        out.append(i)
                    if cv & 1:
                        break
                    i += 1
        return sorted(out)

    def version_of(self, index: int) -> str | None:
        """Version name carried by a *defined* symbol, or ``None``."""
        if self.versym is None:
            return None
        v = self.versym[index] & VERSYM_INDEX
        if v < 2:
            return None
        return self.verdef.get(v)

    def requirement_of(self, index: int) -> tuple[str, str] | None:
        """``(version, file)`` required by an *undefined* symbol, or ``None``."""
        if self.versym is None:
            return None
        v = self.versym[index] & VERSYM_INDEX
        if v < 2:
            return None
        return self.verneed.get(v)

    def version_hidden(self, index: int) -> bool:
        return bool(self.versym is not None and (self.versym[index] & VERSYM_HIDDEN))

    # ------------------------------------------------------------------
    # low level readers (bounds checked, raise StructuralError)
    # ------------------------------------------------------------------
    def _need(self, off: int, size: int, field: str) -> None:
        if off < 0 or off + size > len(self._data):
            raise StructuralError(
                field,
                f"truncated: cannot read {size} bytes at offset {off} "
                f"(object size {len(self._data)})",
                off,
            )

    def _u8(self, off: int, field: str) -> int:
        self._need(off, 1, field)
        return self._data[off]

    def _u16(self, off: int, field: str) -> int:
        self._need(off, 2, field)
        return struct.unpack_from("<H", self._data, off)[0]

    def _u32(self, off: int, field: str) -> int:
        self._need(off, 4, field)
        return struct.unpack_from("<I", self._data, off)[0]

    def _u64(self, off: int, field: str) -> int:
        self._need(off, 8, field)
        return struct.unpack_from("<Q", self._data, off)[0]

    def _i64(self, off: int, field: str) -> int:
        self._need(off, 8, field)
        return struct.unpack_from("<q", self._data, off)[0]

    def _map(self, vaddr: int, size: int, field: str) -> int:
        """Map a virtual address range to a file offset via PT_LOAD."""
        for v, o, f in self._loads:
            if v <= vaddr and vaddr + size <= v + f:
                return o + (vaddr - v)
        raise StructuralError(
            field,
            f"virtual address range {vaddr:#x}..{vaddr + size:#x} "
            f"not mapped by any PT_LOAD segment",
            None,
        )

    def _str(self, stroff: int, field: str) -> str:
        base, size = self._strtab
        if stroff >= size:
            raise StructuralError(
                field, f"string offset {stroff} outside string table (size {size})", None
            )
        end = self._data.find(b"\0", base + stroff, base + size)
        if end < 0:
            raise StructuralError(field, "unterminated string in string table", base + stroff)
        try:
            return self._data[base + stroff:end].decode("utf-8")
        except UnicodeDecodeError:
            raise StructuralError(field, "string is not valid UTF-8", base + stroff)

    # ------------------------------------------------------------------
    # parsing stages (executed in a fixed order)
    # ------------------------------------------------------------------
    def _parse(self) -> None:
        data = self._data

        # 1. ELF header -------------------------------------------------
        if len(data) < _EHDR_SIZE:
            raise StructuralError(
                "e_ident", f"truncated ELF header: {len(data)} of {_EHDR_SIZE} bytes", 0
            )
        if data[0:4] != ELF_MAGIC:
            raise StructuralError("e_ident", "bad ELF magic", 0)
        if data[4] != ELFCLASS64:
            raise StructuralError("e_ident", "not an ELF64 object", 4)
        if data[5] != ELFDATA2LSB:
            raise StructuralError("e_ident", "not a little-endian object", 5)
        if data[6] != EV_CURRENT:
            raise StructuralError("e_ident", "unsupported identification version", 6)
        e_type = self._u16(16, "e_type")
        if e_type != ET_DYN:
            raise StructuralError("e_type", f"not an ET_DYN object (e_type={e_type})", 16)
        if self._u32(20, "e_version") != EV_CURRENT:
            raise StructuralError("e_version", "unsupported ELF version", 20)
        if self._u16(52, "e_ehsize") != _EHDR_SIZE:
            raise StructuralError("e_ehsize", "unexpected ELF header size", 52)
        e_phoff = self._u64(32, "e_phoff")
        e_phentsize = self._u16(54, "e_phentsize")
        if e_phentsize != _PHDR_SIZE:
            raise StructuralError(
                "e_phentsize", f"unexpected program header entry size {e_phentsize}", 54
            )
        e_phnum = self._u16(56, "e_phnum")
        if e_phnum == 0:
            raise StructuralError("e_phnum", "object has no program headers", 56)
        if e_phnum == 0xFFFF:
            raise StructuralError(
                "e_phnum", "extended program header counts are not supported", 56
            )
        if e_phoff + e_phnum * _PHDR_SIZE > len(data):
            raise StructuralError("e_phoff", "program header table is truncated", e_phoff)

        # 2. program headers --------------------------------------------
        dynamics = []
        for i in range(e_phnum):
            off = e_phoff + i * _PHDR_SIZE
            p_type = self._u32(off, "p_type")
            if p_type == 0:
                continue
            p_offset = self._u64(off + 8, "p_offset")
            p_vaddr = self._u64(off + 16, "p_vaddr")
            p_filesz = self._u64(off + 32, "p_filesz")
            p_memsz = self._u64(off + 40, "p_memsz")
            p_align = self._u64(off + 48, "p_align")
            if p_offset + p_filesz > len(data):
                raise StructuralError(
                    "p_filesz", f"segment {i} file range exceeds object size", off + 32
                )
            if p_filesz > p_memsz:
                raise StructuralError(
                    "p_memsz", f"segment {i} file size exceeds memory size", off + 40
                )
            if p_align:
                if p_align & (p_align - 1):
                    raise StructuralError(
                        "p_align", f"segment {i} alignment is not a power of two", off + 48
                    )
                if p_align > 1 and (p_vaddr % p_align) != (p_offset % p_align):
                    raise StructuralError(
                        "p_vaddr",
                        f"segment {i} virtual address is misaligned with its file offset",
                        off + 16,
                    )
            if p_type == PT_LOAD:
                self._loads.append((p_vaddr, p_offset, p_filesz))
            elif p_type == PT_DYNAMIC:
                dynamics.append((p_offset, p_vaddr, p_filesz, off))
        if len(dynamics) > 1:
            raise StructuralError("PT_DYNAMIC", "duplicate dynamic segments", dynamics[1][3])
        if not self._loads:
            raise StructuralError("PT_LOAD", "object has no loadable segment", None)
        if not dynamics:
            raise StructuralError("PT_DYNAMIC", "object has no dynamic segment", None)
        dyn_off, _dyn_vaddr, dyn_filesz, dyn_phoff = dynamics[0]
        if dyn_filesz == 0 or dyn_filesz % _DYN_SIZE:
            raise StructuralError(
                "p_filesz", "dynamic segment size is not a multiple of 16", dyn_phoff + 32
            )

        # 3. dynamic entries --------------------------------------------
        tags: dict[int, int] = {}
        needed_offsets: list[tuple[int, int]] = []
        terminated = False
        for i in range(dyn_filesz // _DYN_SIZE):
            off = dyn_off + i * _DYN_SIZE
            d_tag = self._i64(off, "d_tag")
            d_val = self._u64(off + 8, "d_val")
            if d_tag == DT_NULL:
                terminated = True
                break
            if d_tag == DT_NEEDED:
                needed_offsets.append((d_val, off + 8))
            elif d_tag not in tags:
                tags[d_tag] = d_val
        if not terminated:
            raise StructuralError("DT_NULL", "dynamic segment is not terminated", dyn_off)

        # 4. dynamic string table ---------------------------------------
        if DT_STRTAB not in tags:
            raise StructuralError("DT_STRTAB", "missing dynamic string table address", None)
        if DT_STRSZ not in tags:
            raise StructuralError("DT_STRSZ", "missing dynamic string table size", None)
        strsz = tags[DT_STRSZ]
        if strsz == 0:
            raise StructuralError("DT_STRSZ", "dynamic string table is empty", None)
        strtab_off = self._map(tags[DT_STRTAB], strsz, "DT_STRTAB")
        self._strtab = (strtab_off, strsz)

        # 5. needed objects and soname ----------------------------------
        for stroff, tag_off in needed_offsets:
            needed = self._str(stroff, "DT_NEEDED")
            if needed in self.needed:
                raise StructuralError(
                    "DT_NEEDED", f"duplicate needed object '{needed}'", tag_off
                )
            self.needed.append(needed)
        if DT_SONAME in tags:
            self.soname = self._str(tags[DT_SONAME], "DT_SONAME")

        # 6. symbol table and hash tables -------------------------------
        if DT_SYMTAB not in tags:
            raise StructuralError("DT_SYMTAB", "missing dynamic symbol table", None)
        syment = tags.get(DT_SYMENT, _SYM_SIZE)
        if syment != _SYM_SIZE:
            raise StructuralError(
                "DT_SYMENT", f"unsupported symbol entry size {syment}", None
            )
        have_sysv = DT_HASH in tags
        have_gnu = DT_GNU_HASH in tags
        if not have_sysv and not have_gnu:
            raise StructuralError(
                "DT_HASH", "neither SysV nor GNU hash table is present", None
            )
        symcount = None
        if have_sysv:
            symcount = self._parse_sysv(tags[DT_HASH])
        if have_gnu:
            gnu_count = self._parse_gnu(tags[DT_GNU_HASH])
            if symcount is not None and gnu_count != symcount:
                raise StructuralError(
                    "DT_GNU_HASH",
                    f"SysV and GNU hash tables disagree on the symbol count "
                    f"({symcount} != {gnu_count})",
                    None,
                )
            symcount = gnu_count
        if symcount < 1:
            raise StructuralError("DT_SYMTAB", "symbol table is empty", None)
        symtab_v = tags[DT_SYMTAB]
        for i in range(symcount):
            off = self._map(symtab_v + i * _SYM_SIZE, _SYM_SIZE, "DT_SYMTAB")
            st_name = self._u32(off, "st_name")
            st_info = self._u8(off + 4, "st_info")
            st_other = self._u8(off + 5, "st_other")
            st_shndx = self._u16(off + 6, "st_shndx")
            st_value = self._u64(off + 8, "st_value")
            st_size = self._u64(off + 16, "st_size")
            name = self._str(st_name, "st_name") if st_name else ""
            self.symbols.append(
                Symbol(i, name, st_name, st_info, st_other, st_shndx, st_value, st_size)
            )

        # 7. version tables ---------------------------------------------
        have_verdef = DT_VERDEF in tags or DT_VERDEFNUM in tags
        have_verneed = DT_VERNEED in tags or DT_VERNEEDNUM in tags
        if (DT_VERDEF in tags) != (DT_VERDEFNUM in tags):
            raise StructuralError(
                "DT_VERDEFNUM", "version definition table without its count", None
            )
        if (DT_VERNEED in tags) != (DT_VERNEEDNUM in tags):
            raise StructuralError(
                "DT_VERNEEDNUM", "version need table without its count", None
            )
        have_versym = DT_VERSYM in tags
        if (have_verdef or have_verneed) and not have_versym:
            raise StructuralError(
                "DT_VERSYM",
                "version definition/need tables present without the symbol "
                "version array",
                None,
            )
        if have_versym:
            self.versym = []
            for i in range(symcount):
                off = self._map(tags[DT_VERSYM] + 2 * i, 2, "DT_VERSYM")
                self.versym.append(self._u16(off, "DT_VERSYM"))
        if have_verdef:
            self._parse_verdef(tags[DT_VERDEF], tags[DT_VERDEFNUM])
        if have_verneed:
            self._parse_verneed(tags[DT_VERNEED], tags[DT_VERNEEDNUM])
        if have_versym:
            self._check_versym()

    def _parse_sysv(self, vaddr: int) -> int:
        off = self._map(vaddr, 8, "DT_HASH")
        nbucket = self._u32(off, "DT_HASH")
        nchain = self._u32(off + 4, "DT_HASH")
        if nbucket == 0:
            raise StructuralError("DT_HASH", "hash table has zero buckets", off)
        total = 8 + 4 * (nbucket + nchain)
        off = self._map(vaddr, total, "DT_HASH")
        buckets = [self._u32(off + 8 + 4 * i, "DT_HASH") for i in range(nbucket)]
        chains = [
            self._u32(off + 8 + 4 * nbucket + 4 * i, "DT_HASH") for i in range(nchain)
        ]
        for start in buckets:
            if start >= nchain and start != 0:
                raise StructuralError("DT_HASH", "bucket index out of range", off)
            i, steps = start, 0
            while i:
                if i >= nchain:
                    raise StructuralError("DT_HASH", "chain index out of range", off)
                i = chains[i]
                steps += 1
                if steps > nchain:
                    raise StructuralError("DT_HASH", "cycle in hash chain", off)
        self._sysv = (nbucket, buckets, chains)
        return nchain

    def _parse_gnu(self, vaddr: int) -> int:
        off = self._map(vaddr, 16, "DT_GNU_HASH")
        nbuckets = self._u32(off, "DT_GNU_HASH")
        symoffset = self._u32(off + 4, "DT_GNU_HASH")
        bloom_size = self._u32(off + 8, "DT_GNU_HASH")
        if nbuckets == 0:
            raise StructuralError("DT_GNU_HASH", "hash table has zero buckets", off)
        if bloom_size == 0 or (bloom_size & (bloom_size - 1)):
            raise StructuralError(
                "DT_GNU_HASH", "bloom filter size is not a power of two", off + 8
            )
        header = 16 + bloom_size * 8 + nbuckets * 4
        off = self._map(vaddr, header, "DT_GNU_HASH")
        buckets = [
            self._u32(off + 16 + bloom_size * 8 + 4 * i, "DT_GNU_HASH")
            for i in range(nbuckets)
        ]
        chain_vaddr = vaddr + header
        maxb = max(buckets) if buckets else 0
        if maxb == 0:
            count = symoffset
        else:
            if maxb < symoffset:
                raise StructuralError(
                    "DT_GNU_HASH", "bucket refers below the chain symbol offset", off
                )
            i = maxb
            steps = 0
            while True:
                coff = self._map(chain_vaddr + 4 * (i - symoffset), 4, "DT_GNU_HASH")
                value = self._u32(coff, "DT_GNU_HASH")
                i += 1
                if value & 1:
                    break
                steps += 1
                if steps > len(self._data):
                    raise StructuralError(
                        "DT_GNU_HASH", "unterminated symbol hash chain", coff
                    )
            count = i
        for b in buckets:
            if b and (b < symoffset or b >= count):
                raise StructuralError("DT_GNU_HASH", "bucket index out of range", off)
        self._gnu = (nbuckets, symoffset, buckets, chain_vaddr)
        return count

    def _parse_verdef(self, vaddr: int, count: int) -> None:
        if count == 0:
            raise StructuralError("DT_VERDEFNUM", "zero version definitions", None)
        seen: dict[int, str] = {}
        v = vaddr
        for n in range(count):
            off = self._map(v, 20, "DT_VERDEF")
            if self._u16(off, "DT_VERDEF") != 1:
                raise StructuralError(
                    "DT_VERDEF", "unsupported version definition format", off
                )
            vd_ndx = self._u16(off + 4, "DT_VERDEF")
            vd_cnt = self._u16(off + 6, "DT_VERDEF")
            vd_aux = self._u32(off + 12, "DT_VERDEF")
            vd_next = self._u32(off + 16, "DT_VERDEF")
            if vd_ndx == 0:
                raise StructuralError(
                    "DT_VERDEF", f"reserved version index {vd_ndx}", off + 4
                )
            if vd_ndx in seen:
                raise StructuralError(
                    "DT_VERDEF", f"duplicate version index {vd_ndx}", off + 4
                )
            if vd_cnt < 1:
                raise StructuralError(
                    "DT_VERDEF", "version definition without a name", off + 6
                )
            aux_v = v + vd_aux
            name = None
            for j in range(vd_cnt):
                aoff = self._map(aux_v, 8, "DT_VERDEF")
                vda_name = self._u32(aoff, "DT_VERDEF")
                vda_next = self._u32(aoff + 4, "DT_VERDEF")
                if j == 0:
                    name = self._str(vda_name, "DT_VERDEF")
                if j < vd_cnt - 1:
                    if vda_next == 0:
                        raise StructuralError(
                            "DT_VERDEF", "auxiliary entry chain ends early", aoff + 4
                        )
                    aux_v += vda_next
            seen[vd_ndx] = name
            if n < count - 1:
                if vd_next == 0:
                    raise StructuralError(
                        "DT_VERDEF", "fewer entries than DT_VERDEFNUM declares", off + 16
                    )
                v += vd_next
            elif vd_next != 0:
                raise StructuralError(
                    "DT_VERDEF", "more entries than DT_VERDEFNUM declares", off + 16
                )
        self.verdef = seen

    def _parse_verneed(self, vaddr: int, count: int) -> None:
        if count == 0:
            raise StructuralError("DT_VERNEEDNUM", "zero version needs", None)
        result: dict[int, tuple[str, str]] = {}
        v = vaddr
        for n in range(count):
            off = self._map(v, 16, "DT_VERNEED")
            if self._u16(off, "DT_VERNEED") != 1:
                raise StructuralError(
                    "DT_VERNEED", "unsupported version need format", off
                )
            vn_cnt = self._u16(off + 2, "DT_VERNEED")
            vn_file = self._u32(off + 4, "DT_VERNEED")
            vn_aux = self._u32(off + 8, "DT_VERNEED")
            vn_next = self._u32(off + 12, "DT_VERNEED")
            fname = self._str(vn_file, "DT_VERNEED")
            if fname not in self.needed:
                raise StructuralError(
                    "DT_VERNEED",
                    f"version reference names '{fname}' which is not a "
                    f"DT_NEEDED dependency",
                    off + 4,
                )
            if vn_cnt < 1:
                raise StructuralError(
                    "DT_VERNEED", "version need without auxiliary entries", off + 2
                )
            aux_v = v + vn_aux
            for j in range(vn_cnt):
                aoff = self._map(aux_v, 16, "DT_VERNEED")
                vna_other = self._u16(aoff + 6, "DT_VERNEED")
                vna_name = self._u32(aoff + 8, "DT_VERNEED")
                vna_next = self._u32(aoff + 12, "DT_VERNEED")
                vname = self._str(vna_name, "DT_VERNEED")
                if vna_other < 2:
                    raise StructuralError(
                        "DT_VERNEED", f"reserved version index {vna_other}", aoff + 6
                    )
                if vna_other in self.verdef:
                    raise StructuralError(
                        "DT_VERNEED",
                        f"version index {vna_other} is both defined and needed",
                        aoff + 6,
                    )
                if vna_other in result:
                    raise StructuralError(
                        "DT_VERNEED",
                        f"duplicate needed version index {vna_other}",
                        aoff + 6,
                    )
                result[vna_other] = (vname, fname)
                if j < vn_cnt - 1:
                    if vna_next == 0:
                        raise StructuralError(
                            "DT_VERNEED", "auxiliary entry chain ends early", aoff + 12
                        )
                    aux_v += vna_next
            if n < count - 1:
                if vn_next == 0:
                    raise StructuralError(
                        "DT_VERNEED", "fewer entries than DT_VERNEEDNUM declares", off + 12
                    )
                v += vn_next
            elif vn_next != 0:
                raise StructuralError(
                    "DT_VERNEED", "more entries than DT_VERNEEDNUM declares", off + 12
                )
        self.verneed = result

    def _check_versym(self) -> None:
        for i, sym in enumerate(self.symbols):
            if i == 0:
                continue
            raw = self.versym[i]
            v = raw & VERSYM_INDEX
            hidden = bool(raw & VERSYM_HIDDEN)
            if v >= 2:
                in_def = v in self.verdef
                in_need = v in self.verneed
                if not in_def and not in_need:
                    raise StructuralError(
                        "DT_VERSYM",
                        f"symbol {i} ('{sym.name}') references unknown version "
                        f"index {v}",
                        None,
                    )
                if sym.defined and in_need:
                    raise StructuralError(
                        "DT_VERSYM",
                        f"defined symbol {i} ('{sym.name}') is bound to a needed "
                        f"version index {v}",
                        None,
                    )
                if not sym.defined and in_def:
                    raise StructuralError(
                        "DT_VERSYM",
                        f"undefined symbol {i} ('{sym.name}') is bound to a "
                        f"defined version index {v}",
                        None,
                    )
            if hidden and not sym.defined:
                raise StructuralError(
                    "DT_VERSYM",
                    f"undefined symbol {i} ('{sym.name}') carries a hidden version",
                    None,
                )
