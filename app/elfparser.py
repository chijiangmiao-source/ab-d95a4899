"""ELF64 little-endian ET_DYN parser for the flight-control audit service.

The parser is deliberately section-header independent: every dynamic table is
located through PT_DYNAMIC / PT_LOAD virtual-address mappings, exactly as the
dynamic loader would see the object after a shared-library replacement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

ELFMAG = b"\x7fELF"
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
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

VER_DEF_CURRENT = 1
VER_NEED_CURRENT = 1
VER_NDX_LOCAL = 0
VER_NDX_GLOBAL = 1
VERSYM_VERSION = 0x7FFF
VERSYM_HIDDEN = 0x8000

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_GNU_UNIQUE = 10
STV_DEFAULT = 0
STV_PROTECTED = 3
SHN_UNDEF = 0
SHN_COMMON = 0xFFF2

# Tags that occur at most once and carry a table pointer / size.
_SINGLE_TAGS = {
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_STRSZ,
    DT_SYMENT,
    DT_GNU_HASH,
    DT_VERSYM,
    DT_VERDEF,
    DT_VERDEFNUM,
    DT_VERNEED,
    DT_VERNEEDNUM,
}

# Error codes used in frozen audit verdicts.
TRUNCATION = "truncation"
MISALIGNED = "misaligned"
UNMAPPABLE_TABLE = "unmappable_table"
CONTRADICTORY_VERSION = "contradictory_version"
BAD_FORMAT = "bad_format"


class ElfError(Exception):
    """Structural error located at the first offending point."""

    def __init__(self, code: str, message: str, *, stage: str = "", offset: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage
        self.offset = offset
        self.object_name: str | None = None

    def as_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
        if self.stage:
            d["stage"] = self.stage
        if self.offset is not None:
            d["offset"] = self.offset
        if self.object_name is not None:
            d["object"] = self.object_name
        return d


@dataclass
class LoadSeg:
    offset: int
    vaddr: int
    filesz: int


@dataclass
class VersionDef:
    name: str
    hidden: bool
    base: bool


@dataclass
class VersionNeed:
    name: str
    file: str


@dataclass
class Ref:
    index: int
    name: str
    binding: int  # STB_GLOBAL / STB_WEAK
    version: str | None
    required_file: str | None


@dataclass(frozen=True)
class ExportKey:
    name: str
    version: str | None


@dataclass
class Export:
    index: int
    binding: int
    version: str | None
    hidden: bool  # exported under a VER_FLG_WEAK/hidden version node (e.g. GLIBC_PRIVATE)


@dataclass
class ParsedObject:
    name: str
    soname: str | None
    needed: list[str]
    refs: list[Ref] = field(default_factory=list)
    # (symbol name, version name|None) -> first definition in dynsym order
    exports: dict[ExportKey, Export] = field(default_factory=dict)


class Elf64Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.segments: list[LoadSeg] = []
        self.dyn_va: int = 0
        self.dyn_off: int = 0
        self.dyn_size: int = 0
        self.tags: dict[int, int] = {}
        self.needed: list[int] = []
        self.strtab = b""
        self.verdef: dict[int, VersionDef] = {}
        self.verneed: dict[int, VersionNeed] = {}
        self.versym: bytes | None = None
        self.refs: list[Ref] = []
        self.exports: dict[ExportKey, Export] = {}

    # ------------------------------------------------------------------
    # low level helpers
    # ------------------------------------------------------------------

    def _u16(self, off: int, stage: str) -> int:
        if off < 0 or off + 2 > len(self.data):
            raise ElfError(TRUNCATION, f"table read past end of file at {off}", stage=stage, offset=off)
        return int.from_bytes(self.data[off:off + 2], "little")

    def _u32(self, off: int, stage: str) -> int:
        if off < 0 or off + 4 > len(self.data):
            raise ElfError(TRUNCATION, f"table read past end of file at {off}", stage=stage, offset=off)
        return int.from_bytes(self.data[off:off + 4], "little")

    def _u64(self, off: int, stage: str) -> int:
        if off < 0 or off + 8 > len(self.data):
            raise ElfError(TRUNCATION, f"table read past end of file at {off}", stage=stage, offset=off)
        return int.from_bytes(self.data[off:off + 8], "little")

    def _va_to_off(self, va: int) -> int | None:
        for seg in self.segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def _read_va(self, va: int, size: int, stage: str, *, align: int = 1) -> bytes:
        """Read a (possibly segment-spanning) virtual-address range."""
        if size < 0:
            raise ElfError(UNMAPPABLE_TABLE, f"negative size for {stage}", stage=stage, offset=va)
        if align > 1 and va % align != 0:
            raise ElfError(
                MISALIGNED,
                f"{stage} virtual address 0x{va:x} is not {align}-byte aligned",
                stage=stage,
                offset=va,
            )
        out = bytearray()
        cur = va
        remaining = size
        while remaining > 0:
            off = self._va_to_off(cur)
            if off is None:
                raise ElfError(
                    UNMAPPABLE_TABLE,
                    f"{stage} at virtual address 0x{cur:x} is not covered by any PT_LOAD segment",
                    stage=stage,
                    offset=cur,
                )
            seg = next(s for s in self.segments if s.vaddr <= cur < s.vaddr + s.filesz)
            chunk = min(remaining, seg.vaddr + seg.filesz - cur)
            out += self.data[off:off + chunk]
            cur += chunk
            remaining -= chunk
        return bytes(out)

    def _str(self, idx: int, stage: str) -> str:
        if idx < 0 or idx >= len(self.strtab):
            raise ElfError(
                UNMAPPABLE_TABLE,
                f"{stage} string index {idx} lies outside DT_STRTAB",
                stage=stage,
                offset=idx,
            )
        end = self.strtab.find(b"\x00", idx)
        if end < 0:
            raise ElfError(
                TRUNCATION,
                f"{stage} string at index {idx} is not null terminated",
                stage=stage,
                offset=idx,
            )
        try:
            return self.strtab[idx:end].decode("utf-8")
        except UnicodeDecodeError:
            return self.strtab[idx:end].decode("latin-1")

    # ------------------------------------------------------------------
    # parsing
    # ------------------------------------------------------------------

    def parse(self) -> None:
        self._parse_header()
        self._parse_dynamic()
        self._parse_strtab()
        self.needed_names = [self._str(i, "DT_NEEDED") for i in self.needed]
        self.soname_name = self._str(self.tags[DT_SONAME], "DT_SONAME") if DT_SONAME in self.tags else None
        nsym = self._parse_hash_and_symbols()
        self._parse_versions(nsym)
        self._parse_symbol_rows(nsym)

    def _parse_header(self) -> None:
        stage = "ELF header"
        if len(self.data) < 64:
            raise ElfError(TRUNCATION, "file shorter than 64-byte ELF64 header", stage=stage, offset=len(self.data))
        if self.data[:4] != ELFMAG:
            raise ElfError(BAD_FORMAT, "bad ELF magic", stage=stage, offset=0)
        if self.data[4] != ELFCLASS64:
            raise ElfError(BAD_FORMAT, "only ELFCLASS64 targets are accepted", stage=stage, offset=4)
        if self.data[5] != ELFDATA2LSB:
            raise ElfError(BAD_FORMAT, "only little-endian (ELFDATA2LSB) targets are accepted", stage=stage, offset=5)
        if self.data[6] != EV_CURRENT:
            raise ElfError(BAD_FORMAT, f"unsupported EI_VERSION {self.data[6]}", stage=stage, offset=6)
        e_type = self._u16(16, stage)
        if e_type != ET_DYN:
            raise ElfError(BAD_FORMAT, f"e_type {e_type} is not ET_DYN", stage=stage, offset=16)

        e_phoff = self._u64(32, stage)
        e_phentsize = self._u16(54, stage)
        e_phnum = self._u16(56, stage)
        if e_phentsize < 56:
            raise ElfError(TRUNCATION, "program-header entry smaller than 56 bytes", stage=stage, offset=54)
        if e_phoff == 0 or e_phnum == 0:
            raise ElfError(UNMAPPABLE_TABLE, "object has no program headers", stage="program headers")
        ph_end = e_phoff + e_phnum * e_phentsize
        if ph_end > len(self.data):
            raise ElfError(TRUNCATION, "program-header table runs past end of file", stage="program headers", offset=e_phoff)

        dyn_seen = False
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = self._u32(off, "program headers")
            if p_type == PT_LOAD:
                p_offset = self._u64(off + 8, stage)
                p_vaddr = self._u64(off + 16, stage)
                p_filesz = self._u64(off + 32, stage)
                p_align = self._u64(off + 48, stage)
                if p_offset + p_filesz > len(self.data):
                    raise ElfError(
                        TRUNCATION,
                        f"PT_LOAD segment (offset 0x{p_offset:x}, filesz 0x{p_filesz:x}) runs past end of file",
                        stage="PT_LOAD",
                        offset=p_offset,
                    )
                if p_align > 1 and (p_offset % p_align) != (p_vaddr % p_align):
                    raise ElfError(
                        MISALIGNED,
                        f"PT_LOAD offset/vaddr congruence violates p_align 0x{p_align:x}",
                        stage="PT_LOAD",
                        offset=off,
                    )
                self.segments.append(LoadSeg(p_offset, p_vaddr, p_filesz))
            elif p_type == PT_DYNAMIC:
                if dyn_seen:
                    raise ElfError(BAD_FORMAT, "multiple PT_DYNAMIC segments", stage="PT_DYNAMIC", offset=off)
                dyn_seen = True
                self.dyn_off = self._u64(off + 8, stage)
                self.dyn_size = self._u64(off + 32, stage)
                self.dyn_va = self._u64(off + 16, stage)

        if not self.segments:
            raise ElfError(UNMAPPABLE_TABLE, "object has no PT_LOAD segment", stage="program headers")
        if not dyn_seen:
            raise ElfError(UNMAPPABLE_TABLE, "object has no PT_DYNAMIC segment", stage="PT_DYNAMIC")
        if self.dyn_off + self.dyn_size > len(self.data):
            raise ElfError(TRUNCATION, "PT_DYNAMIC runs past end of file", stage="PT_DYNAMIC", offset=self.dyn_off)
        if self._va_to_off(self.dyn_va) is None:
            raise ElfError(
                UNMAPPABLE_TABLE,
                "PT_DYNAMIC virtual address is not covered by a PT_LOAD segment",
                stage="PT_DYNAMIC",
                offset=self.dyn_va,
            )

    def _parse_dynamic(self) -> None:
        stage = "PT_DYNAMIC"
        if self.dyn_va % 8:
            raise ElfError(MISALIGNED, "PT_DYNAMIC virtual address is not 8-byte aligned", stage=stage, offset=self.dyn_va)
        max_entries = self.dyn_size // 16
        null_seen = False
        for i in range(max_entries):
            off = self.dyn_off + i * 16
            tag = int.from_bytes(self.data[off:off + 8], "little")
            val = int.from_bytes(self.data[off + 8:off + 16], "little")
            if tag == DT_NULL:
                null_seen = True
                break
            if tag == DT_NEEDED or tag == DT_SONAME:
                if tag == DT_NEEDED:
                    self.needed.append(val)
                else:
                    if tag in self.tags:
                        raise ElfError(BAD_FORMAT, "duplicate DT_SONAME", stage=stage, offset=off)
                    self.tags[tag] = val
            elif tag in _SINGLE_TAGS:
                if tag in self.tags:
                    raise ElfError(
                        UNMAPPABLE_TABLE,
                        f"duplicate dynamic tag {tag} in PT_DYNAMIC",
                        stage=stage,
                        offset=off,
                    )
                self.tags[tag] = val
        if not null_seen:
            raise ElfError(TRUNCATION, "PT_DYNAMIC is not terminated by DT_NULL", stage=stage, offset=self.dyn_off)

    def _parse_strtab(self) -> None:
        if DT_STRTAB not in self.tags:
            raise ElfError(UNMAPPABLE_TABLE, "DT_STRTAB is missing", stage="DT_STRTAB")
        if DT_STRSZ not in self.tags:
            raise ElfError(UNMAPPABLE_TABLE, "DT_STRSZ is missing", stage="DT_STRSZ")
        va = self.tags[DT_STRTAB]
        size = self.tags[DT_STRSZ]
        if size == 0:
            raise ElfError(UNMAPPABLE_TABLE, "DT_STRSZ is zero", stage="DT_STRSZ")
        self.strtab = self._read_va(va, size, "DT_STRTAB", align=1)
        if self.strtab[0] != 0:
            raise ElfError(UNMAPPABLE_TABLE, "dynamic string table does not start with a NUL byte", stage="DT_STRTAB", offset=va)

    def _sysv_nsym(self) -> int:
        va = self.tags[DT_HASH]
        head = self._read_va(va, 8, "DT_HASH", align=4)
        nbucket = int.from_bytes(head[:4], "little")
        nchain = int.from_bytes(head[4:], "little")
        # whole hash table must be mappable
        self._read_va(va, 4 * (nbucket + nchain), "DT_HASH")
        if nchain < 1:
            raise ElfError(UNMAPPABLE_TABLE, "DT_HASH nchain is zero", stage="DT_HASH", offset=va)
        return nchain

    def _gnu_nsym(self) -> int:
        """Derive the dynsym count by walking every GNU hash bucket chain.

        The count is one past the largest symbol index reachable from a bucket
        head; symbols below ``symndx`` always exist even if unhashed.
        """
        va = self.tags[DT_GNU_HASH]
        head = self._read_va(va, 16, "DT_GNU_HASH", align=4)
        nbucket = int.from_bytes(head[0:4], "little")
        symndx = int.from_bytes(head[4:8], "little")
        bloom_size = int.from_bytes(head[8:12], "little")
        if nbucket == 0 or bloom_size == 0:
            raise ElfError(
                UNMAPPABLE_TABLE,
                "DT_GNU_HASH has zero buckets or zero bloom words",
                stage="DT_GNU_HASH",
                offset=va,
            )
        if symndx > 0x100000:
            raise ElfError(
                UNMAPPABLE_TABLE,
                f"DT_GNU_HASH symndx {symndx} is implausibly large",
                stage="DT_GNU_HASH",
                offset=va,
            )
        buckets_off = 16 + 8 * bloom_size
        chains_off = buckets_off + 4 * nbucket
        buckets = self._read_va(va + buckets_off, 4 * nbucket, "DT_GNU_HASH buckets", align=4)
        heads = [int.from_bytes(buckets[i * 4:i * 4 + 4], "little") for i in range(nbucket)]

        # The whole fixed prefix (header + bloom + buckets) must be mappable.
        self._read_va(va, chains_off, "DT_GNU_HASH")

        # The chain array ends where the next mapped dynamic table begins.
        boundaries = [
            v for t, v in self.tags.items()
            if t in (DT_STRTAB, DT_SYMTAB, DT_HASH, DT_VERSYM, DT_VERDEF, DT_VERNEED) and v > va
        ]
        chain_end_va = min(boundaries) if boundaries else None

        def chain_hash(symidx: int) -> int:
            off = va + chains_off + (symidx - symndx) * 4
            if chain_end_va is not None and off + 4 > chain_end_va:
                raise ElfError(
                    UNMAPPABLE_TABLE,
                    "GNU hash chain runs past the following table without terminating",
                    stage="DT_GNU_HASH",
                    offset=va,
                )
            w = self._read_va(off, 4, "DT_GNU_HASH chain")
            return int.from_bytes(w, "little")

        max_idx = symndx - 1
        for head_sym in heads:
            if head_sym == 0:
                continue
            if head_sym < symndx:
                raise ElfError(
                    UNMAPPABLE_TABLE,
                    f"GNU hash bucket head {head_sym} precedes symndx {symndx}",
                    stage="DT_GNU_HASH",
                    offset=va,
                )
            idx = head_sym
            steps = 0
            while True:
                steps += 1
                if steps > 1_000_000:
                    raise ElfError(
                        UNMAPPABLE_TABLE,
                        "GNU hash chain is cyclic or unbounded",
                        stage="DT_GNU_HASH",
                        offset=va,
                    )
                max_idx = max(max_idx, idx)
                if chain_hash(idx) & 1:  # end-of-chain marker
                    break
                idx += 1
        return max_idx + 1

    def _parse_hash_and_symbols(self) -> int:
        if DT_SYMTAB not in self.tags:
            raise ElfError(UNMAPPABLE_TABLE, "DT_SYMTAB is missing", stage="DT_SYMTAB")
        syment = self.tags.get(DT_SYMENT, 24)
        if syment != 24:
            raise ElfError(UNMAPPABLE_TABLE, f"DT_SYMENT {syment} is not the ELF64 value 24", stage="DT_SYMENT")

        nsym: int | None = None
        if DT_HASH in self.tags:
            nsym = self._sysv_nsym()
        if DT_GNU_HASH in self.tags:
            gnu_nsym = self._gnu_nsym()
            if nsym is not None and gnu_nsym != nsym:
                raise ElfError(
                    UNMAPPABLE_TABLE,
                    f"SysV hash ({nsym}) and GNU hash ({gnu_nsym}) disagree on symbol count",
                    stage="DT_HASH",
                )
            nsym = gnu_nsym
        if nsym is None:
            # No hash table: fall back to the next table pointer after dynsym.
            va = self.tags[DT_SYMTAB]
            pointers = [
                v for t, v in self.tags.items()
                if t in (DT_STRTAB, DT_HASH, DT_GNU_HASH, DT_VERSYM, DT_VERDEF, DT_VERNEED) and v > va
            ]
            if not pointers:
                raise ElfError(UNMAPPABLE_TABLE, "cannot size DT_SYMTAB: no hash table", stage="DT_SYMTAB")
            span = min(pointers) - va
            if span <= 0 or span % 24:
                raise ElfError(MISALIGNED, "DT_SYMTAB span is not a multiple of 24", stage="DT_SYMTAB", offset=va)
            nsym = span // 24

        va = self.tags[DT_SYMTAB]
        self._read_va(va, nsym * 24, "DT_SYMTAB", align=8)

        if DT_VERSYM in self.tags:
            vva = self.tags[DT_VERSYM]
            self.versym = self._read_va(vva, nsym * 2, "DT_VERSYM", align=2)
        return nsym

    def _parse_versions(self, nsym: int) -> None:
        # --- version definitions -------------------------------------------------
        if DT_VERDEF in self.tags:
            if DT_VERDEFNUM not in self.tags:
                raise ElfError(UNMAPPABLE_TABLE, "DT_VERDEF without DT_VERDEFNUM", stage="DT_VERDEFNUM")
            va = self.tags[DT_VERDEF]
            num = self.tags[DT_VERDEFNUM]
            cur = va
            for i in range(num):
                block = self._read_va(cur, 20, "DT_VERDEF", align=4)
                vd_version = int.from_bytes(block[0:2], "little")
                vd_flags = int.from_bytes(block[2:4], "little")
                vd_ndx = int.from_bytes(block[4:6], "little")
                vd_cnt = int.from_bytes(block[6:8], "little")
                vd_aux = int.from_bytes(block[12:16], "little")
                vd_next = int.from_bytes(block[16:20], "little")
                if vd_version != VER_DEF_CURRENT:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"Verdef entry {i} has unsupported version {vd_version}",
                        stage="DT_VERDEF",
                        offset=cur,
                    )
                if vd_ndx < VER_NDX_GLOBAL or vd_cnt < 1:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"Verdef entry {i} has invalid ndx {vd_ndx} or aux count {vd_cnt}",
                        stage="DT_VERDEF",
                        offset=cur,
                    )
                if vd_ndx in self.verdef or vd_ndx in self.verneed:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"duplicate version index {vd_ndx}",
                        stage="DT_VERDEF",
                        offset=cur,
                    )
                aux = cur + vd_aux
                name: str | None = None
                for j in range(vd_cnt):
                    ab = self._read_va(aux, 8, "DT_VERDEF aux")
                    vda_name = int.from_bytes(ab[0:4], "little")
                    vda_next = int.from_bytes(ab[4:8], "little")
                    sname = self._str(vda_name, "DT_VERDEF aux")
                    if j == 0:
                        name = sname
                    if vda_next == 0 and j != vd_cnt - 1:
                        raise ElfError(TRUNCATION, "Verdef aux chain ends early", stage="DT_VERDEF", offset=aux)
                    aux += vda_next
                assert name is not None
                is_base = bool(vd_flags & 1)  # VER_FLG_BASE: the object's default node
                if is_base and vd_ndx != VER_NDX_GLOBAL:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"BASE verdef {name!r} must use version index 1, uses {vd_ndx}",
                        stage="DT_VERDEF",
                        offset=cur,
                    )
                self.verdef[vd_ndx] = VersionDef(name, bool(vd_flags & 2), is_base)
                if i < num - 1:
                    if vd_next == 0:
                        raise ElfError(TRUNCATION, "Verdef chain ends before DT_VERDEFNUM entries", stage="DT_VERDEF", offset=cur)
                    cur += vd_next

        # --- version needs -------------------------------------------------------
        if DT_VERNEED in self.tags:
            if DT_VERNEEDNUM not in self.tags:
                raise ElfError(UNMAPPABLE_TABLE, "DT_VERNEED without DT_VERNEEDNUM", stage="DT_VERNEEDNUM")
            va = self.tags[DT_VERNEED]
            num = self.tags[DT_VERNEEDNUM]
            cur = va
            for i in range(num):
                block = self._read_va(cur, 16, "DT_VERNEED", align=4)
                vn_version = int.from_bytes(block[0:2], "little")
                vn_cnt = int.from_bytes(block[2:4], "little")
                vn_file = int.from_bytes(block[4:8], "little")
                vn_aux = int.from_bytes(block[8:12], "little")
                vn_next = int.from_bytes(block[12:16], "little")
                if vn_version != VER_NEED_CURRENT:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"Verneed entry {i} has unsupported version {vn_version}",
                        stage="DT_VERNEED",
                        offset=cur,
                    )
                if vn_cnt < 1 or vn_aux == 0:
                    raise ElfError(
                        CONTRADICTORY_VERSION,
                        f"Verneed entry {i} has no version auxiliaries",
                        stage="DT_VERNEED",
                        offset=cur,
                    )
                fname = self._str(vn_file, "DT_VERNEED file")
                aux = cur + vn_aux
                for j in range(vn_cnt):
                    ab = self._read_va(aux, 16, "DT_VERNEED aux")
                    vna_other = int.from_bytes(ab[6:8], "little")
                    vna_name = int.from_bytes(ab[8:12], "little")
                    vna_next = int.from_bytes(ab[12:16], "little")
                    vname = self._str(vna_name, "DT_VERNEED aux")
                    if vna_other <= VER_NDX_GLOBAL:
                        raise ElfError(
                            CONTRADICTORY_VERSION,
                            f"Vernaux for {vname} uses reserved version index {vna_other}",
                            stage="DT_VERNEED",
                            offset=aux,
                        )
                    if vna_other in self.verneed or vna_other in self.verdef:
                        raise ElfError(
                            CONTRADICTORY_VERSION,
                            f"duplicate version index {vna_other}",
                            stage="DT_VERNEED",
                            offset=aux,
                        )
                    self.verneed[vna_other] = VersionNeed(vname, fname)
                    if vna_next == 0 and j != vn_cnt - 1:
                        raise ElfError(TRUNCATION, "Verneed aux chain ends early", stage="DT_VERNEED", offset=aux)
                    aux += vna_next
                if i < num - 1:
                    if vn_next == 0:
                        raise ElfError(TRUNCATION, "Verneed chain ends before DT_VERNEEDNUM entries", stage="DT_VERNEED", offset=cur)
                    cur += vn_next

    def _resolve_version_index(self, raw: int, stage: str, off: int) -> tuple[str | None, str | None, bool]:
        """Return (version_name|None, required_file|None, hidden).

        The VERSYM_HIDDEN bit (e.g. GLIBC_PRIVATE references) does not erase
        the explicit version requirement: such references still bind only by
        version name + dependency file.  Hidden (VER_FLG_WEAK) definition
        nodes never act as default providers for unversioned references.
        """
        idx = raw & VERSYM_VERSION
        if idx in (VER_NDX_LOCAL, VER_NDX_GLOBAL):
            # Index 1 may coincide with the BASE verdef node; either way the
            # symbol has no explicit version attached.
            return None, None, False
        if idx in self.verdef:
            vd = self.verdef[idx]
            return (None if vd.base else vd.name), None, vd.hidden
        if idx in self.verneed:
            need = self.verneed[idx]
            return need.name, need.file, False
        raise ElfError(
            CONTRADICTORY_VERSION,
            f"symbol references version index {idx} absent from Verdef/Verneed tables",
            stage=stage,
            offset=off,
        )

    def _parse_symbol_rows(self, nsym: int) -> None:
        va = self.tags[DT_SYMTAB]
        sym = self._read_va(va, nsym * 24, "DT_SYMTAB")
        for i in range(nsym):
            row = sym[i * 24:i * 24 + 24]
            st_name = int.from_bytes(row[0:4], "little")
            st_info = row[4]
            st_other = row[5]
            st_shndx = int.from_bytes(row[6:8], "little")
            if i == 0 and st_name != 0:
                raise ElfError(
                    CONTRADICTORY_VERSION,
                    "dynsym entry 0 must be the null symbol",
                    stage="DT_SYMTAB",
                    offset=va,
                )
            if st_name == 0:
                continue
            name = self._str(st_name, "symbol st_name")
            binding = st_info >> 4
            visibility = st_other & 3
            raw_ver = int.from_bytes(self.versym[i * 2:i * 2 + 2], "little") if self.versym else 0
            ver_idx = raw_ver & VERSYM_VERSION
            version, req_file, ver_hidden = self._resolve_version_index(raw_ver, "DT_VERSYM", i * 2)

            if st_shndx == SHN_UNDEF or st_shndx == SHN_COMMON:
                if binding in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE):
                    ref_binding = STB_GLOBAL if binding == STB_GNU_UNIQUE else binding
                    self.refs.append(Ref(i, name, ref_binding, version, req_file))
            else:
                if binding == STB_LOCAL:
                    continue
                # A defined symbol tagged VER_NDX_LOCAL is hidden from the
                # external version namespace even if STB_GLOBAL (common ld
                # idiom used by libicudata/cairo-gobject).
                if ver_idx == VER_NDX_LOCAL:
                    continue
                if visibility not in (STV_DEFAULT, STV_PROTECTED):
                    continue  # STV_HIDDEN/STV_INTERNAL definitions are invisible
                key = ExportKey(name, version)
                if key not in self.exports:
                    self.exports[key] = Export(i, binding, version, ver_hidden)


def parse_elf64(data: bytes, name: str) -> ParsedObject:
    parser = Elf64Parser(data)
    parser.parse()
    return ParsedObject(
        name=name,
        soname=getattr(parser, "soname_name", None),
        needed=list(getattr(parser, "needed_names", [])),
        refs=parser.refs,
        exports=parser.exports,
    )
