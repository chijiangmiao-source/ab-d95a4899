"""Minimal synthetic ELF64 little-endian ET_DYN builder for tests.

The generated files contain just one PT_LOAD segment (identity vaddr==offset
mapping) plus PT_DYNAMIC, and support GNU/SysV hashes, Verdef/Verneed tables,
weak/global defined and undefined symbols, and targeted corruption hooks.
"""

from __future__ import annotations

from dataclasses import dataclass

# ELF constants mirrored from app.elfparser.
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STV_DEFAULT = 0
STV_HIDDEN = 2
SHN_UNDEF = 0
SHN_ABS = 0xFFF1

STT_FUNC = 2


def sysv_hash(name: str) -> int:
    h = 0
    for c in name.encode():
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def gnu_hash(name: str) -> int:
    h = 5381
    for c in name.encode():
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


@dataclass
class Sym:
    name: str
    bind: int
    defined: bool
    version: int  # versym index (0 local, 1 global/BASE, >=2 versioned)
    visibility: int = STV_DEFAULT
    weak: bool = False


class ElfBuilder:
    def __init__(self, *, hash_style: str = "gnu"):
        self.hash_style = hash_style  # "gnu" | "sysv" | "none"
        self.needed: list[str] = []
        self.soname: str | None = None
        self.symbols: list[Sym] = [Sym("", STB_LOCAL, False, 0)]  # mandatory null sym
        self.verdefs: list[tuple[int, str, int]] = []  # (index, name, flags)
        self.verneeds: list[tuple[str, list[tuple[int, str]]]] = []  # (file, [(idx,name)])
        # result of last build()
        self.addrs: dict[str, int] = {}

    def need(self, name: str) -> None:
        self.needed.append(name)

    def set_soname(self, name: str) -> None:
        self.soname = name

    def add_verdef(self, index: int, name: str, *, base: bool = False, hidden: bool = False) -> None:
        flags = (1 if base else 0) | (2 if hidden else 0)
        self.verdefs.append((index, name, flags))

    def add_verneed_file(self, file: str, vers: list[tuple[int, str]]) -> None:
        self.verneeds.append((file, vers))

    def undefined(self, name: str, *, weak: bool = False, version: int = 1) -> None:
        self.symbols.append(Sym(name, STB_WEAK if weak else STB_GLOBAL, False, version))

    def define(self, name: str, *, weak: bool = False, version: int = 1, visibility: int = STV_DEFAULT) -> None:
        self.symbols.append(Sym(name, STB_WEAK if weak else STB_GLOBAL, True, version, visibility))

    # ------------------------------------------------------------------
    def _strtab_and_dynstr(self) -> tuple[bytes, dict[str, int]]:
        blob = bytearray(b"\x00")
        idx: dict[str, int] = {}

        def intern(s: str) -> int:
            if s in idx:
                return idx[s]
            off = len(blob)
            blob.extend(s.encode() + b"\x00")
            idx[s] = off
            return off

        self._str_intern = intern
        for n in self.needed:
            intern(n)
        if self.soname:
            intern(self.soname)
        for s in self.symbols:
            if s.name:
                intern(s.name)
        for _, name, _ in self.verdefs:
            intern(name)
        for file, vers in self.verneeds:
            intern(file)
            for _, vn in vers:
                intern(vn)
        return bytes(blob), idx

    def _gnu_hash_blob(self, nsym: int) -> bytes:
        # A single bucket keeps the table valid regardless of symbol names:
        # every symbol belongs to bucket 0 and chains are simply the
        # consecutive dynsym indices starting at symndx.
        nbuckets = 1
        bloom_size = 1
        symndx = 1
        mask64 = 0xFFFFFFFFFFFFFFFF
        bloom = 0
        for i in range(symndx, nsym):
            h = gnu_hash(self.symbols[i].name)
            bloom |= (1 << (h % 64)) & mask64
            bloom |= (1 << ((h >> 6) % 64)) & mask64
            bloom &= mask64
        out = bytearray()
        out += nbuckets.to_bytes(4, "little")
        out += symndx.to_bytes(4, "little")
        out += bloom_size.to_bytes(4, "little")
        out += (6).to_bytes(4, "little")          # bloom shift for 64-bit words
        out += bloom.to_bytes(8, "little")
        out += ((symndx if nsym > 1 else 0)).to_bytes(4, "little")  # bucket head
        for i in range(symndx, nsym):
            h = gnu_hash(self.symbols[i].name) & ~1
            if i == nsym - 1:
                h |= 1  # last chain entry terminates the chain
            out += h.to_bytes(4, "little")
        return bytes(out)

    def _sysv_hash_blob(self, nsym: int) -> bytes:
        nbuckets = 4
        buckets = [0] * nbuckets
        chain = [0] * nsym
        tails: dict[int, int] = {}
        for i in range(1, nsym):
            h = sysv_hash(self.symbols[i].name)
            b = h % nbuckets
            if buckets[b] == 0:
                buckets[b] = i
            else:
                chain[tails[b]] = i
            tails[b] = i
            chain[i] = h
        out = bytearray()
        out += nbuckets.to_bytes(4, "little")
        out += nsym.to_bytes(4, "little")
        for v in buckets:
            out += v.to_bytes(4, "little")
        for v in chain:
            out += v.to_bytes(4, "little")
        return bytes(out)

    def build(self) -> bytes:
        strtab, _ = self._strtab_and_dynstr()
        nsym = len(self.symbols)

        # dynsym
        dynsym = bytearray()
        for i, s in enumerate(self.symbols):
            st_name = self._str_intern(s.name) if s.name else 0
            st_info = (s.bind << 4) | STT_FUNC
            st_other = s.visibility & 3
            st_shndx = SHN_ABS if s.defined else SHN_UNDEF
            st_value = 0x4000 + i * 0x10 if s.defined else 0
            dynsym += st_name.to_bytes(4, "little")
            dynsym += bytes([st_info, st_other])
            dynsym += st_shndx.to_bytes(2, "little")
            dynsym += st_value.to_bytes(8, "little")
            dynsym += (0x10 if s.defined else 0).to_bytes(8, "little")
        dynsym = bytes(dynsym)

        versym = b"".join((s.version & 0xFFFF).to_bytes(2, "little") for s in self.symbols)

        if self.hash_style == "gnu":
            hashblob = self._gnu_hash_blob(nsym)
        elif self.hash_style == "sysv":
            hashblob = self._sysv_hash_blob(nsym)
        else:
            hashblob = b""

        # verdef blob -------------------------------------------------------
        verdef = bytearray()
        for n, (index, name, flags) in enumerate(self.verdefs):
            vd_start = len(verdef)
            aux_off = 20
            next_off = 0
            if n < len(self.verdefs) - 1:
                # next entry size = 20 header + 8 aux
                next_off = 20 + 8
            head = (
                (1).to_bytes(2, "little")          # vd_version
                + flags.to_bytes(2, "little")      # vd_flags
                + index.to_bytes(2, "little")      # vd_ndx
                + (1).to_bytes(2, "little")        # vd_cnt
                + (0x17).to_bytes(4, "little")     # vd_hash (unused)
                + aux_off.to_bytes(4, "little")    # vd_aux
                + next_off.to_bytes(4, "little")   # vd_next
            )
            aux = self._str_intern(name).to_bytes(4, "little") + (0).to_bytes(4, "little")
            verdef += head + aux

        # verneed blob -----------------------------------------------------
        verneed = bytearray()
        flat = [(f, vs) for f, vs in self.verneeds]
        for n, (file, vers) in enumerate(flat):
            vn_start = len(verneed)
            next_off = 0
            if n < len(flat) - 1:
                # header 16 + sum(16 per aux)
                next_off = 16 + 16 * len(vers)
            head = (
                (1).to_bytes(2, "little")                 # vn_version
                + len(vers).to_bytes(2, "little")         # vn_cnt
                + self._str_intern(file).to_bytes(4, "little")  # vn_file
                + (16).to_bytes(4, "little")              # vn_aux
                + next_off.to_bytes(4, "little")          # vn_next
            )
            auxs = bytearray()
            for j, (idx, vname) in enumerate(vers):
                vna_next = 16 if j < len(vers) - 1 else 0
                auxs += (
                    (sysv_hash(vname)).to_bytes(4, "little")  # vna_hash
                    + (2).to_bytes(2, "little")               # vna_flags WEAK
                    + idx.to_bytes(2, "little")               # vna_other
                    + self._str_intern(vname).to_bytes(4, "little")  # vna_name
                    + vna_next.to_bytes(4, "little")          # vna_next
                )
            verneed += head + bytes(auxs)

        # ------------------------------------------------------------------
        # Assemble one image with identity vaddr==offset mapping.
        layout = bytearray(b"\x00" * 64)  # ELF header reserved up-front
        ph_off = 64
        layout += b"\x00" * (56 * 2)       # two program headers

        def place(blob: bytes, align: int, key: str) -> int:
            if len(layout) % align:
                layout.extend(b"\x00" * (align - len(layout) % align))
            va = len(layout)
            layout.extend(blob)
            self.addrs[key] = va
            return va

        a_sym = place(dynsym, 8, "symtab")
        a_str = place(strtab, 1, "strtab")
        a_ver = place(versym, 2, "versym")
        a_hash = None
        if hashblob:
            tag = "gnu_hash" if self.hash_style == "gnu" else "hash"
            a_hash = place(hashblob, 4, tag)
        a_vd = place(bytes(verdef), 4, "verdef") if verdef else None
        a_vn = place(bytes(verneed), 4, "verneed") if verneed else None
        a_dyn = place(b"", 8, "dynamic")

        # dynamic entries
        dyn = bytearray()

        def ent(tag: int, val: int) -> None:
            dyn.extend(tag.to_bytes(8, "little") + val.to_bytes(8, "little"))

        for n in self.needed:
            ent(DT_NEEDED, self._str_intern(n))
        if self.soname is not None:
            ent(DT_SONAME, self._str_intern(self.soname))
        ent(DT_STRTAB, a_str)
        ent(DT_STRSZ, len(strtab))
        ent(DT_SYMTAB, a_sym)
        ent(DT_SYMENT, 24)
        if a_hash is not None:
            ent(DT_GNU_HASH if self.hash_style == "gnu" else DT_HASH, a_hash)
        if versym:
            ent(DT_VERSYM, a_ver)
        if verdef:
            ent(DT_VERDEF, a_vd)
            ent(DT_VERDEFNUM, len(self.verdefs))
        if verneed:
            ent(DT_VERNEED, a_vn)
            ent(DT_VERNEEDNUM, len(self.verneeds))
        ent(DT_NULL, 0)
        dyn_va = a_dyn
        layout[dyn_va:dyn_va + len(dyn)] = dyn

        # ELF header --------------------------------------------------------
        eh = bytearray()
        eh += b"\x7fELF"
        eh += bytes([2, 1, 1, 0])         # class64, LE, version current, SYSV
        eh += b"\x00" * 8
        eh += ET_DYN.to_bytes(2, "little")
        eh += (0xB7).to_bytes(2, "little")  # e_machine AArch64 (irrelevant)
        eh += (1).to_bytes(4, "little")    # e_version
        eh += (0).to_bytes(8, "little")    # e_entry
        eh += (0).to_bytes(8, "little")    # e_phoff placeholder
        eh += (0).to_bytes(8, "little")    # e_shoff
        eh += (0).to_bytes(4, "little")    # e_flags
        eh += (64).to_bytes(2, "little")   # e_ehsize
        eh += (56).to_bytes(2, "little")   # e_phentsize
        eh += (2).to_bytes(2, "little")    # e_phnum
        eh += (64).to_bytes(2, "little")   # e_shentsize
        eh += (0).to_bytes(2, "little")    # e_shnum
        eh += (0).to_bytes(2, "little")    # e_shstrndx
        layout[0:64] = eh
        layout[32:40] = ph_off.to_bytes(8, "little")

        filesz = len(layout)
        # Elf64_Phdr (56 bytes): p_type u32, p_flags u32, then six u64.
        ph1 = bytearray()
        ph1 += PT_LOAD.to_bytes(4, "little")
        ph1 += (7).to_bytes(4, "little")       # PF_R|W|X
        ph1 += (0).to_bytes(8, "little")       # p_offset
        ph1 += (0).to_bytes(8, "little")       # p_vaddr
        ph1 += (0).to_bytes(8, "little")       # p_paddr
        ph1 += filesz.to_bytes(8, "little")    # p_filesz
        ph1 += filesz.to_bytes(8, "little")    # p_memsz
        ph1 += (0x1000).to_bytes(8, "little")  # p_align (offset 0 ≡ vaddr 0)
        ph2 = bytearray()
        ph2 += PT_DYNAMIC.to_bytes(4, "little")
        ph2 += (6).to_bytes(4, "little")       # PF_R|W
        ph2 += dyn_va.to_bytes(8, "little")    # p_offset (identity map)
        ph2 += dyn_va.to_bytes(8, "little")    # p_vaddr
        ph2 += (0).to_bytes(8, "little")       # p_paddr
        ph2 += len(dyn).to_bytes(8, "little")  # p_filesz
        ph2 += len(dyn).to_bytes(8, "little")  # p_memsz
        ph2 += (8).to_bytes(8, "little")       # p_align
        layout[ph_off:ph_off + 56] = ph1
        layout[ph_off + 56:ph_off + 112] = ph2
        return bytes(layout)
