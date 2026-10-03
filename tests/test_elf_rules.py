"""Tests for the PT_DYNAMIC-based ELF parser and the dynamic load rules."""

from __future__ import annotations

import struct

import pytest

from app.elfparser import (
    CONTRADICTORY_VERSION,
    MISALIGNED,
    TRUNCATION,
    UNMAPPABLE_TABLE,
    parse_elf64,
)
from app.linker import MISSING_DEPENDENCY, build_load_order, link
from tests.elfbuild import ElfBuilder


def _parse(builder: ElfBuilder, name="x.so"):
    return parse_elf64(builder.build(), name)


# ---------------------------------------------------------------------------
# Parser: happy paths with GNU and SysV hash styles.
# ---------------------------------------------------------------------------

def test_parse_gnu_hash_with_verdef_and_soname():
    b = ElfBuilder(hash_style="gnu")
    b.set_soname("libok.so.2")
    b.add_verdef(1, "libok.so.2", base=True)
    b.add_verdef(2, "LIBOK_2.0")
    b.add_verdef(3, "LIBOK_2.1", hidden=True)
    b.define("pub", version=2)
    b.define("priv_thing", version=3)
    obj = _parse(b)
    assert obj.soname == "libok.so.2"
    assert ("pub", "LIBOK_2.0") in [(k.name, k.version) for k in obj.exports]
    # Hidden (WEAK/PRIVATE) verdef nodes still resolve by explicit version name.
    assert ("priv_thing", "LIBOK_2.1") in [(k.name, k.version) for k in obj.exports]


def test_parse_sysv_hash():
    b = ElfBuilder(hash_style="sysv")
    b.set_soname("libold.so")
    b.add_verdef(1, "libold.so", base=True)
    b.define("legacy_fn")
    obj = _parse(b)
    assert obj.needed == []
    assert any(k.name == "legacy_fn" and k.version is None for k in obj.exports)


def test_verneed_resolves_version_name_and_file():
    b = ElfBuilder(hash_style="gnu")
    b.need("libdep.so.4")
    b.add_verneed_file("libdep.so.4", [(2, "DEP_4.2"), (3, "DEP_4.3")])
    b.undefined("vfn", version=2)
    b.undefined("vfn2", version=3)
    obj = _parse(b, "consumer")
    refs = {r.name: r for r in obj.refs}
    assert refs["vfn"].version == "DEP_4.2"
    assert refs["vfn"].required_file == "libdep.so.4"
    assert refs["vfn2"].version == "DEP_4.3"


# ---------------------------------------------------------------------------
# Parser: truncation / misalignment / unmappable / contradiction.
# ---------------------------------------------------------------------------

def test_truncated_header():
    blob = ElfBuilder().build()[:40]
    with pytest.raises(Exception) as ei:
        parse_elf64(blob, "x")
    assert ei.value.code == TRUNCATION


def test_truncated_program_headers():
    full = ElfBuilder().build()
    # Claim 3 program headers but truncate inside the third one.
    blob = bytearray(full[:64 + 3 * 56 - 7])
    struct.pack_into("<H", blob, 56, 3)
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == TRUNCATION


def test_reject_non_et_dyn():
    blob = bytearray(ElfBuilder().build())
    struct.pack_into("<H", blob, 16, 2)  # ET_EXEC
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == "bad_format"


def test_reject_big_endian_or_wrong_class():
    blob = bytearray(ElfBuilder().build())
    blob[5] = 2  # ELFDATA2MSB
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == "bad_format"
    blob2 = bytearray(ElfBuilder().build())
    blob2[4] = 1  # ELFCLASS32
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob2), "x")
    assert ei.value.code == "bad_format"


def test_strtab_pointer_unmappable():
    b = ElfBuilder()
    blob = bytearray(b.build())
    # Corrupt DT_STRTAB value inside PT_DYNAMIC to an address with no segment.
    dyn_off = struct.unpack_from("<Q", blob, 64 + 56 + 8)[0]
    i = 0
    while True:
        tag, val = struct.unpack_from("<qQ", blob, dyn_off + i * 16)
        if tag == 0:
            break
        if tag == 5:  # DT_STRTAB
            struct.pack_into("<Q", blob, dyn_off + i * 16 + 8, 0x9999999)
            break
        i += 1
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == UNMAPPABLE_TABLE


def test_misaligned_dynamic():
    b = ElfBuilder()
    blob = bytearray(b.build())
    # Set an odd PT_DYNAMIC vaddr that is still covered by the low PT_LOAD so
    # the dedicated alignment check (not the mapping check) must fire.
    struct.pack_into("<Q", blob, 64 + 56 + 16, 0x101)  # p_vaddr odd
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == MISALIGNED


def test_missing_dt_null():
    b = ElfBuilder()
    blob = bytearray(b.build())
    dyn_off = struct.unpack_from("<Q", blob, 64 + 56 + 8)[0]
    dyn_sz = struct.unpack_from("<Q", blob, 64 + 56 + 32)[0]
    # overwrite DT_NULL tag with garbage, leave room within p_filesz
    struct.pack_into("<qQ", blob, dyn_off + dyn_sz - 16, 0x6FFFFFF5, 0)
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == TRUNCATION


def test_contradictory_versym_index():
    b = ElfBuilder()
    b.define("lonely", version=7)  # index 7 has no Verdef/Verneed node
    with pytest.raises(Exception) as ei:
        _parse(b)
    assert ei.value.code == CONTRADICTORY_VERSION


def test_duplicate_dynamic_tag_rejected():
    b = ElfBuilder()
    blob = bytearray(b.build())
    dyn_off = struct.unpack_from("<Q", blob, 64 + 56 + 8)[0]
    dyn_sz = struct.unpack_from("<Q", blob, 64 + 56 + 32)[0]
    null_off = dyn_off + dyn_sz - 16
    # Insert a second DT_SYMTAB (tag 6) right before DT_NULL: expand by
    # overwriting DT_NULL and adding a new DT_NULL beyond p_filesz is invalid;
    # instead patch an existing entry. Easiest: patch DT_SYMENT->DT_SYMTAB.
    i = 0
    while True:
        tag, _ = struct.unpack_from("<qQ", blob, dyn_off + i * 16)
        if tag == 11:  # DT_SYMENT
            struct.pack_into("<q", blob, dyn_off + i * 16, 6)
            break
        i += 1
    with pytest.raises(Exception) as ei:
        parse_elf64(bytes(blob), "x")
    assert ei.value.code == UNMAPPABLE_TABLE


# ---------------------------------------------------------------------------
# Load order: BFS first-discovery, cycle de-duplication, missing dep.
# ---------------------------------------------------------------------------

def _lib(name, needs=(), hash_style="gnu"):
    b = ElfBuilder(hash_style=hash_style)
    b.set_soname(name)
    b.add_verdef(1, name, base=True)
    for n in needs:
        b.need(n)
    b.define(name.replace(".", "_") + "_sym")
    return b.build()


def test_bfs_first_discovery_load_order():
    # target -> A, B; A -> C; B -> C  => target,A,B,C
    a = _lib("liba.so", ("libc.so",))
    b = _lib("libb.so", ("libc.so",))
    c = _lib("libc.so")
    t = ElfBuilder()
    t.need("liba.so")
    t.need("libb.so")
    from app.elfparser import parse_elf64
    order = build_load_order(
        parse_elf64(t.build(), "target"),
        {"liba.so": parse_elf64(a, "liba.so"),
         "libb.so": parse_elf64(b, "libb.so"),
         "libc.so": parse_elf64(c, "libc.so")},
    )
    assert [o.name for o in order] == ["target", "liba.so", "libb.so", "libc.so"]


def test_dependency_cycle_deduplicated():
    a = _lib("liba.so", ("libb.so",))
    b = _lib("libb.so", ("liba.so",))
    from app.elfparser import parse_elf64
    t = ElfBuilder()
    t.need("liba.so")
    order = build_load_order(
        parse_elf64(t.build(), "target"),
        {"liba.so": parse_elf64(a, "liba.so"),
         "libb.so": parse_elf64(b, "libb.so")},
    )
    names = [o.name for o in order]
    assert names == ["target", "liba.so", "libb.so"]
    assert len(names) == len(set(names))


def test_missing_dependency_fails():
    from app.elfparser import parse_elf64
    t = ElfBuilder()
    t.need("libghost.so")
    with pytest.raises(Exception) as ei:
        build_load_order(parse_elf64(t.build(), "target"), {})
    assert ei.value.code == MISSING_DEPENDENCY


# ---------------------------------------------------------------------------
# Symbol binding: version shadowing, weak symbols, strong failure.
# ---------------------------------------------------------------------------

def _def_lib(name, defs, verdefs=None):
    """defs: list of (symname, version_label|None)."""
    b = ElfBuilder()
    b.set_soname(name)
    b.add_verdef(1, name, base=True)
    label_index = {}
    if verdefs:
        for i, label in enumerate(verdefs, start=2):
            b.add_verdef(i, label)
            label_index[label] = i
    for sym, label in defs:
        b.define(sym, version=label_index.get(label, 1))
    return b.build()


def test_version_scoped_binding_to_required_file():
    # Two libs export the same symbol under the same version label; the
    # reference carries Verneed file=libreal.so, so it must bind there.
    a = _def_lib("libshim.so", [("svc_call", "SVC_2.0")], verdefs=["SVC_2.0"])
    r = _def_lib("libreal.so", [("svc_call", "SVC_2.0")], verdefs=["SVC_2.0"])
    t = ElfBuilder()
    t.need("libshim.so")
    t.need("libreal.so")
    t.add_verneed_file("libreal.so", [(2, "SVC_2.0")])
    t.undefined("svc_call", version=2)
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libshim.so": parse_elf64(a, "libshim.so"),
         "libreal.so": parse_elf64(r, "libreal.so")},
    )
    assert res["verdict"] == "pass"
    b = res["bindings"][0]
    assert b["bound_to_object"] == "libreal.so"
    assert b["basis"] == "version"


def test_unversioned_shadow_wins_for_unversioned_ref():
    a = _def_lib("libfirst.so", [("plain", None)])
    r = _def_lib("libsecond.so", [("plain", None)])
    t = ElfBuilder()
    t.need("libfirst.so")
    t.need("libsecond.so")
    t.undefined("plain")
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libfirst.so": parse_elf64(a, "libfirst.so"),
         "libsecond.so": parse_elf64(r, "libsecond.so")},
    )
    assert res["bindings"][0]["bound_to_object"] == "libfirst.so"


def test_weak_reference_may_stay_unbound():
    t = ElfBuilder()
    t.undefined("maybe_fn", weak=True)
    from app.elfparser import parse_elf64
    res = link(parse_elf64(t.build(), "target"), {})
    assert res["verdict"] == "pass"
    assert len(res["unbound_weak"]) == 1
    assert res["bindings"] == []


def test_weak_binds_when_provider_exists():
    a = _def_lib("libw.so", [("maybe_fn", None)])
    t = ElfBuilder()
    t.need("libw.so")
    t.undefined("maybe_fn", weak=True)
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libw.so": parse_elf64(a, "libw.so")},
    )
    assert res["verdict"] == "pass"
    assert res["bindings"][0]["bound_to_object"] == "libw.so"
    assert res["unbound_weak"] == []


def test_strong_unresolved_fails_and_locates_first():
    t = ElfBuilder()
    t.undefined("definitely_missing")
    from app.elfparser import parse_elf64
    res = link(parse_elf64(t.build(), "fctl.bin"), {})
    assert res["verdict"] == "fail"
    assert res["first_failure"]["reason"] == "unresolved_strong"
    assert res["first_failure"]["object"] == "fctl.bin"
    assert res["first_failure"]["symbol"] == "definitely_missing"


def test_version_mismatch_leaves_strong_ref_unresolved():
    # Provider exports svc@SVC_1.0 but target requires svc@SVC_2.0.
    a = _def_lib("libp.so", [("svc", "SVC_1.0")], verdefs=["SVC_1.0"])
    t = ElfBuilder()
    t.need("libp.so")
    t.add_verneed_file("libp.so", [(2, "SVC_2.0")])
    t.undefined("svc", version=2)
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libp.so": parse_elf64(a, "libp.so")},
    )
    assert res["verdict"] == "fail"
    assert res["first_failure"]["symbol"] == "svc"


# ---------------------------------------------------------------------------
# Real shared objects present in the build/CI environment.
# ---------------------------------------------------------------------------

def test_unversioned_ref_defaults_to_visible_versioned_provider():
    # glibc semantics: with no unversioned definition, the unversioned
    # reference binds the first non-hidden versioned definition.
    b = ElfBuilder()
    b.set_soname("libv.so")
    b.add_verdef(1, "libv.so", base=True)
    b.add_verdef(2, "V_9.0")
    b.define("only_versioned", version=2)
    t = ElfBuilder()
    t.need("libv.so")
    t.undefined("only_versioned")
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libv.so": parse_elf64(b.build(), "libv.so")},
    )
    assert res["verdict"] == "pass"
    assert res["bindings"][0]["bound_to_object"] == "libv.so"
    assert res["bindings"][0]["basis"] == "version_default"


def test_hidden_version_node_is_not_a_default_provider():
    b = ElfBuilder()
    b.set_soname("libsecret.so")
    b.add_verdef(1, "libsecret.so", base=True)
    b.add_verdef(2, "SECRET_PRIVATE", hidden=True)
    b.define("private_fn", version=2)
    t = ElfBuilder()
    t.need("libsecret.so")
    t.undefined("private_fn")  # unversioned strong reference
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libsecret.so": parse_elf64(b.build(), "libsecret.so")},
    )
    assert res["verdict"] == "fail"
    assert res["first_failure"]["symbol"] == "private_fn"


def test_explicit_hidden_version_ref_still_binds_by_name_and_file():
    b = ElfBuilder()
    b.set_soname("libsecret.so")
    b.add_verdef(1, "libsecret.so", base=True)
    b.add_verdef(2, "SECRET_PRIVATE", hidden=True)
    b.define("private_fn", version=2)
    t = ElfBuilder()
    t.need("libsecret.so")
    t.add_verneed_file("libsecret.so", [(2, "SECRET_PRIVATE")])
    t.undefined("private_fn", version=2)
    from app.elfparser import parse_elf64
    res = link(
        parse_elf64(t.build(), "target"),
        {"libsecret.so": parse_elf64(b.build(), "libsecret.so")},
    )
    assert res["verdict"] == "pass"
    assert res["bindings"][0]["bound_to_object"] == "libsecret.so"
    assert res["bindings"][0]["basis"] == "version"


def test_earlier_loaded_dependency_satisfies_later_deps_ref():
    # liblater.so (loaded after libfirst.so) has an unversioned undefined
    # reference to plain(); the earlier loader must interpose and satisfy it.
    a = _def_lib("libfirst.so", [("plain", None)])
    lb = ElfBuilder()
    lb.set_soname("liblater.so")
    lb.add_verdef(1, "liblater.so", base=True)
    lb.need("libfirst.so")
    lb.undefined("plain")
    t = ElfBuilder()
    t.need("liblater.so")
    from app.elfparser import parse_elf64
    pa, pb = parse_elf64(a, "libfirst.so"), parse_elf64(lb.build(), "liblater.so")
    res = link(parse_elf64(t.build(), "target"), {"libfirst.so": pa, "liblater.so": pb})
    assert res["verdict"] == "pass"
    b = next(x for x in res["bindings"] if x["object"] == "liblater.so")
    assert b["bound_to_object"] == "libfirst.so"


def test_parse_real_system_library_if_present():
    import glob
    candidates = glob.glob("/lib*/**/libc.so.6", recursive=True)
    if not candidates:
        pytest.skip("no system libc available")
    obj = parse_elf64(open(candidates[0], "rb").read(), "libc.so.6")
    assert obj.soname == "libc.so.6"
    names = {k.name for k in obj.exports}
    assert "malloc" in names
