"""Dependency-graph audit: BFS load ordering and version-aware binding.

Given a target ET_DYN object and its named dependency objects, the audit

* rejects the first structural error found while parsing (truncation,
  misalignment, duplicate object names, missing dependencies, unmappable
  tables, contradictory version references),
* computes the breadth-first load order, de-duplicating dependency rings
  by first discovery,
* binds every undefined global/weak dynamic symbol to the first
  compatible visible definition in load order (version shadowing is
  resolved in favour of the earlier-loaded object),
* fails the verdict when a strong (global) reference has no compatible
  definition, while weak references may stay unbound.
"""
from __future__ import annotations

from collections import deque

from .elf import STB_GLOBAL, STB_WEAK, VERSYM_INDEX, ElfFile
from .errors import StructuralError

MAX_DEPENDENCIES = 8

_BIND_NAME = {STB_GLOBAL: "GLOBAL", STB_WEAK: "WEAK"}


def run_audit(target_name: str, target_bytes: bytes, dependencies: list) -> dict:
    """Run a full audit and return the verdict as a JSON-ready dict.

    ``dependencies`` is a list of ``(name, raw_bytes)`` pairs.  Malformed
    input never raises: the first structural error becomes a ``rejected``
    verdict that pinpoints the object, field and offset involved.
    """
    # Duplicate object names make the request itself ambiguous; reject
    # before parsing anything.
    seen: set = set()
    for obj_name in [target_name] + [name for name, _ in dependencies]:
        if obj_name in seen:
            return _rejected(target_name, "request",
                             f"duplicate object name '{obj_name}'")
        seen.add(obj_name)

    objects: dict[str, ElfFile] = {}
    load_order: list[str] = []

    try:
        target = ElfFile.parse(target_bytes, target_name)
    except StructuralError as exc:
        return _rejected(target_name, exc.field, exc.message, target_name, exc.offset)
    objects[target_name] = target
    load_order.append(target_name)

    provided = dict(dependencies)

    # Breadth-first load order; dependency rings are de-duplicated by
    # first discovery.
    queue = deque((needed, target_name) for needed in target.needed)
    while queue:
        name, needed_by = queue.popleft()
        if name in objects:
            continue
        if name not in provided:
            return _rejected(target_name, "DT_NEEDED",
                             f"missing dependency '{name}' required by "
                             f"'{needed_by}'", needed_by)
        try:
            elf = ElfFile.parse(provided[name], name)
        except StructuralError as exc:
            return _rejected(target_name, exc.field, exc.message, name, exc.offset)
        objects[name] = elf
        load_order.append(name)
        for nxt in elf.needed:
            queue.append((nxt, name))

    references: list[dict] = []
    first_unresolved: dict | None = None
    for obj_name in load_order:
        elf = objects[obj_name]
        for sym in elf.symbols:
            if sym.index == 0 or sym.defined:
                continue
            if sym.bind not in (STB_GLOBAL, STB_WEAK):
                continue
            req = elf.requirement_of(sym.index)
            requirement = None
            if req is not None:
                requirement = {"version": req[0], "file": req[1]}
            ref = {
                "object": obj_name,
                "symbol_index": sym.index,
                "symbol": sym.name,
                "bind": _BIND_NAME[sym.bind],
                "requirement": requirement,
            }
            resolution = _resolve(objects, load_order, sym.name, requirement)
            if resolution is not None:
                ref["status"] = "bound"
                ref["resolution"] = resolution
            else:
                ref["status"] = "unbound"
                ref["reason"] = _unresolved_reason(objects, load_order,
                                                   sym.name, requirement)
                if sym.bind == STB_GLOBAL and first_unresolved is None:
                    first_unresolved = ref
            references.append(ref)

    return {
        "status": "failed" if first_unresolved is not None else "passed",
        "target": target_name,
        "load_order": load_order,
        "unused_objects": [n for n, _ in dependencies if n not in objects],
        "objects": {n: {"soname": objects[n].soname, "needed": objects[n].needed}
                    for n in load_order},
        "references": references,
        "first_unresolved": first_unresolved,
        "error": None,
    }


def _resolve(objects: dict, load_order: list, name: str,
             requirement: dict | None) -> dict | None:
    """First compatible visible definition in load order, or ``None``.

    A versioned reference requires a definition carrying the same version
    name inside an object whose name or SONAME matches the required file.
    An unversioned reference accepts any default-visible definition.
    Version shadowing is decided by load order: the earliest compatible
    object wins.
    """
    for obj_name in load_order:
        elf = objects[obj_name]
        for idx in elf.find(name):
            cand = elf.symbols[idx]
            if not cand.defined or not cand.visible:
                continue
            if cand.bind not in (STB_GLOBAL, STB_WEAK):
                continue
            if requirement is not None:
                if not _file_matches(elf, obj_name, requirement["file"]):
                    continue
                version = elf.version_of(idx)
                if version is None or version != requirement["version"]:
                    continue
                basis = {"kind": "verdef", "version": version,
                         "index": elf.versym[idx] & VERSYM_INDEX}
            else:
                if elf.version_hidden(idx):
                    continue
                version = elf.version_of(idx)
                if version is not None:
                    basis = {"kind": "verdef", "version": version,
                             "index": elf.versym[idx] & VERSYM_INDEX}
                else:
                    basis = {"kind": "unversioned"}
            return {"object": obj_name, "symbol_index": idx,
                    "version_basis": basis}
    return None


def _file_matches(elf: ElfFile, obj_name: str, needed_file: str) -> bool:
    return obj_name == needed_file or elf.soname == needed_file


def _unresolved_reason(objects: dict, load_order: list, name: str,
                       requirement: dict | None) -> str:
    available = []
    for obj_name in load_order:
        elf = objects[obj_name]
        for idx in elf.find(name):
            cand = elf.symbols[idx]
            if cand.defined and cand.visible and cand.bind in (STB_GLOBAL, STB_WEAK):
                available.append((obj_name, elf.version_of(idx)))
    if not available:
        return f"no visible definition of '{name}' in load scope"
    if requirement is not None:
        desc = ", ".join(
            f"{obj} provides {ver or 'unversioned'}" for obj, ver in available
        )
        return (f"no definition of '{name}' with version "
                f"'{requirement['version']}' from an object matching file "
                f"'{requirement['file']}' ({desc})")
    return (f"no default-visible definition of '{name}'; only hidden "
            f"version definitions exist in load scope")


def _rejected(target_name: str, field: str, message: str,
              obj: str | None = None, offset: int | None = None) -> dict:
    return {
        "status": "rejected",
        "target": target_name,
        "load_order": [],
        "unused_objects": [],
        "objects": {},
        "references": [],
        "first_unresolved": None,
        "error": {
            "object": obj if obj is not None else target_name,
            "field": field,
            "message": message,
            "offset": offset,
        },
    }
