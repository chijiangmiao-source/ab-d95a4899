"""Frozen audit-result store with byte-exact replay semantics."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass

from .elfparser import ElfError, parse_elf64
from .linker import LoadError, link

MAX_DEPS = 8


class RequestError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass
class FrozenAudit:
    audit_id: str
    fingerprint: str
    verdict: dict


class AuditStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, FrozenAudit] = {}

    def get(self, audit_id: str) -> FrozenAudit | None:
        with self._lock:
            return self._records.get(audit_id)

    def submit(self, payload: dict) -> tuple[FrozenAudit, bool]:
        """Submit (or replay) an audit.

        Returns ``(record, created)``.  Replaying the exact same bytes for an
        audit id returns the frozen record; different bytes raise Conflict.
        """
        audit_id, target_name, target_bytes, deps = _validate_payload(payload)
        fingerprint = _fingerprint(target_name, target_bytes, deps)

        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise RequestError(
                        "audit_id_conflict",
                        f"audit id {audit_id!r} is frozen to different bytes; "
                        "the original verdict remains readable",
                        status=409,
                    )
                return existing, False

            verdict = _evaluate(target_name, target_bytes, deps)
            record = FrozenAudit(audit_id, fingerprint, verdict)
            self._records[audit_id] = record
            return record, True


def _validate_payload(payload) -> tuple[str, str, bytes, list[tuple[str, bytes]]]:
    if not isinstance(payload, dict):
        raise RequestError("bad_request", "request body must be a JSON object")
    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not audit_id.strip():
        raise RequestError("bad_audit_id", "audit_id must be a non-empty string")
    if len(audit_id) > 256:
        raise RequestError("bad_audit_id", "audit_id is too long (max 256)")

    target = payload.get("target")
    if not isinstance(target, dict):
        raise RequestError("bad_target", "target must be an object {name, data_b64}")
    target_name = target.get("name")
    if not isinstance(target_name, str) or not target_name.strip():
        raise RequestError("bad_target_name", "target.name must be a non-empty string")
    target_bytes = _decode_b64(target.get("data_b64"), "target.data_b64")

    raw_deps = payload.get("dependencies", [])
    if not isinstance(raw_deps, list):
        raise RequestError("bad_dependencies", "dependencies must be a list")
    if len(raw_deps) > MAX_DEPS:
        raise RequestError("too_many_dependencies", f"at most {MAX_DEPS} dependency objects are accepted")

    deps: list[tuple[str, bytes]] = []
    names: set[str] = set()
    for i, dep in enumerate(raw_deps):
        if not isinstance(dep, dict):
            raise RequestError("bad_dependency", f"dependencies[{i}] must be an object")
        name = dep.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RequestError("bad_dependency_name", f"dependencies[{i}].name must be a non-empty string")
        if name == target_name:
            raise RequestError("duplicate_object_name", f"dependency name {name!r} duplicates the target object name")
        if name in names:
            raise RequestError("duplicate_object_name", f"dependency object name {name!r} is repeated")
        names.add(name)
        data = _decode_b64(dep.get("data_b64"), f"dependencies[{i}].data_b64")
        deps.append((name, data))

    return audit_id, target_name, target_bytes, deps


def _decode_b64(value, field: str) -> bytes:
    import base64

    if not isinstance(value, str):
        raise RequestError("bad_base64", f"{field} must be a Base64 string")
    try:
        # validate=True rejects embedded whitespace / stray characters.
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RequestError("bad_base64", f"{field} is not valid Base64: {exc}") from exc


def _fingerprint(target_name: str, target_bytes: bytes, deps: list[tuple[str, bytes]]) -> str:
    h = hashlib.sha256()
    h.update(b"v1\n")
    h.update(str(len(target_name)).encode())
    h.update(b"\n")
    h.update(target_name.encode())
    h.update(b"\n")
    h.update(str(len(target_bytes)).encode())
    h.update(b"\n")
    h.update(target_bytes)
    h.update(b"\n")
    for name, data in deps:
        h.update(str(len(name)).encode())
        h.update(b"\n")
        h.update(name.encode())
        h.update(b"\n")
        h.update(str(len(data)).encode())
        h.update(b"\n")
        h.update(data)
        h.update(b"\n")
    return h.hexdigest()


def _evaluate(target_name: str, target_bytes: bytes, deps: list[tuple[str, bytes]]) -> dict:
    # Parse the target first, then dependencies in submission order; the
    # first structural error is located and frozen into the verdict.
    try:
        target = parse_elf64(target_bytes, target_name)
    except ElfError as exc:
        exc.object_name = target_name
        return _reject(target_name, exc)

    parsed_deps: dict[str, object] = {}
    parsed_names: list[str] = []
    for name, data in deps:
        try:
            parsed_deps[name] = parse_elf64(data, name)
            parsed_names.append(name)
        except ElfError as exc:
            exc.object_name = name
            return _reject(target_name, exc, parsed_objects=[target_name] + parsed_names)

    try:
        result = link(target, parsed_deps)  # type: ignore[arg-type]
    except LoadError as exc:
        return {
            "target": target_name,
            "verdict": "fail",
            "load_order": exc.partial_order,
            "bindings": [],
            "unbound_weak": [],
            "first_error": exc.as_dict(),
        }

    return {"target": target_name, **result}


def _reject(target_name: str, exc: ElfError, *, parsed_objects: list[str] | None = None) -> dict:
    err = exc.as_dict()
    return {
        "target": target_name,
        "verdict": "fail",
        "load_order": parsed_objects or [],
        "bindings": [],
        "unbound_weak": [],
        "first_error": err,
    }
