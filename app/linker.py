"""Dynamic-load simulation: BFS load order, cycle de-duplication and the
first-found / version-scoped symbol lookup used by the audit service.
"""

from __future__ import annotations

from collections import deque

from .elfparser import ParsedObject, STB_WEAK

MISSING_DEPENDENCY = "missing_dependency"
DUPLICATE_OBJECT_NAME = "duplicate_object_name"
UNRESOLVED_STRONG = "unresolved_strong"


class LoadError(Exception):
    def __init__(self, code: str, message: str, *, object_name: str | None = None, partial_order=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.object_name = object_name
        self.partial_order = partial_order or []

    def as_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
        if self.object_name is not None:
            d["object"] = self.object_name
        return d


def build_load_order(target: ParsedObject, deps: dict[str, ParsedObject]) -> list[ParsedObject]:
    """Breadth-first, first-discovery expansion of DT_NEEDED edges.

    The target is enqueued first; each DT_NEEDED is resolved by the object's
    SONAME-style name (the key under which the dependency was submitted).
    Dependency cycles are de-duplicated (each object loads at most once).
    """
    order: list[ParsedObject] = []
    seen: set[str] = set()
    queue: deque[ParsedObject] = deque([target])
    seen.add(target.name)
    while queue:
        obj = queue.popleft()
        order.append(obj)
        for need in obj.needed:
            if need in seen:
                continue
            dep = deps.get(need)
            if dep is None:
                raise LoadError(
                    MISSING_DEPENDENCY,
                    f"{obj.name} needs {need!r}, which was not supplied among the dependency objects",
                    object_name=need,
                    partial_order=[o.name for o in order],
                )
            seen.add(need)
            queue.append(dep)
    return order


def lookup(
    ref_name: str,
    version: str | None,
    required_file: str | None,
    order: list[ParsedObject],
    referrer: str,
) -> tuple[ParsedObject, int, str] | None:
    """First-found lookup over the global load scope.

    Candidates are searched in breadth-first load order, skipping the
    referring object itself (its undefined symbols are not self-definitions).
    This is exactly the rule that lets an earlier-loaded compatible object
    shadow a later one.

    Matching rules:

    * a versioned reference binds only to a definition carrying the same
      version name *and* the file (SONAME) named by its Verneed record —
      a same-named version in another object cannot hijack it;
    * an unversioned reference first seeks an unversioned definition; if none
      exists it falls back, glibc-style, to the first visible (non-hidden)
      versioned definition — a GLIBC_PRIVATE node never serves as default.
    """
    from .elfparser import ExportKey

    # Pass 1: exact (name, version) match.
    for obj in order:
        if obj.name == referrer:
            continue
        exp = obj.exports.get(ExportKey(ref_name, version))
        if exp is None:
            continue
        if required_file is not None and obj.name != required_file:
            continue
        basis = "version" if version is not None else "unversioned"
        return obj, exp.index, basis

    # Pass 2: unversioned reference defaulting to a visible versioned export.
    if version is None and required_file is None:
        for obj in order:
            if obj.name == referrer:
                continue
            for key, exp in obj.exports.items():
                if key.name == ref_name and key.version is not None and not exp.hidden:
                    return obj, exp.index, "version_default"
    return None


def link(target: ParsedObject, deps: dict[str, ParsedObject]) -> dict:
    """Produce the frozen binding verdict for one target."""
    order = build_load_order(target, deps)

    bindings: list[dict] = []
    unbound_weak: list[dict] = []
    first_failure: dict | None = None

    # Resolve in object load order and, within an object, dynsym order.
    for obj in order:
        for ref in obj.refs:
            found = lookup(ref.name, ref.version, ref.required_file, order, obj.name)
            if found is None:
                entry = {
                    "object": obj.name,
                    "symbol_index": ref.index,
                    "symbol": ref.name,
                    "binding": "weak" if ref.binding == STB_WEAK else "global",
                    "version": ref.version,
                    "required_file": ref.required_file,
                }
                if ref.binding == STB_WEAK:
                    unbound_weak.append(entry)
                elif first_failure is None:
                    first_failure = {**entry, "reason": UNRESOLVED_STRONG,
                                     "message": f"strong reference to {ref.name!r} has no compatible definition"}
                # strong failures are recorded but evaluation continues so the
                # first one (load/dynsym order) is deterministically reported.
            else:
                def_obj, sym_idx, basis = found
                bindings.append({
                    "object": obj.name,
                    "symbol_index": ref.index,
                    "symbol": ref.name,
                    "bound_to_object": def_obj.name,
                    "bound_to_symbol_index": sym_idx,
                    "version": ref.version,
                    "required_file": ref.required_file,
                    "basis": basis,
                })

    verdict = "fail" if first_failure is not None else "pass"
    result = {
        "verdict": verdict,
        "load_order": [obj.name for obj in order],
        "bindings": bindings,
        "unbound_weak": unbound_weak,
    }
    if first_failure is not None:
        result["first_failure"] = first_failure
    return result
