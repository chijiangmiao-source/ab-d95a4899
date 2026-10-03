"""HTTP API for the shared-library replacement audit service.

Endpoints:
    POST /audits        submit an audit (target object + named dependencies,
                        all Base64); the verdict is computed once and frozen
    GET  /audits/{id}   read the frozen verdict
    GET  /healthz       liveness/readiness probe

An audit id is frozen together with the exact request bytes.  Replaying
the same id with byte-equivalent content returns the frozen verdict;
reusing the id with any difference (target name, target bytes, or any
dependency name/bytes) conflicts with HTTP 409 and leaves the original
verdict readable.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from elfaudit.audit import MAX_DEPENDENCIES, run_audit

MAX_BODY_BYTES = 64 * 1024 * 1024
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
AUDIT_PATH_RE = re.compile(r"^/audits/([A-Za-z0-9][A-Za-z0-9._:\-]{0,127})$")


def fingerprint(target_name: str, target_bytes: bytes, dependencies: list) -> str:
    """Byte-exact identity of an audit request."""
    h = hashlib.sha256()
    h.update(target_name.encode("utf-8"))
    h.update(b"\0")
    h.update(target_bytes)
    h.update(b"\0")
    for name, data in dependencies:
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()


class AuditStore:
    """Frozen verdicts keyed by audit id."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            return self._records.get(audit_id)

    def submit(self, audit_id: str, request_fp: str, compute) -> tuple[str, dict]:
        """Create, replay, or conflict an audit.

        Returns ``(outcome, verdict)`` where outcome is one of
        ``created`` / ``replayed`` / ``conflict``.
        """
        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                if existing["request_sha256"] == request_fp:
                    return "replayed", existing
                return "conflict", existing
            verdict = compute()
            record = {"audit_id": audit_id, "request_sha256": request_fp, **verdict}
            self._records[audit_id] = record
            return "created", record


class Handler(BaseHTTPRequestHandler):
    server_version = "elfaudit/1.0"
    protocol_version = "HTTP/1.1"

    # -- helpers --------------------------------------------------------
    @property
    def store(self) -> AuditStore:
        return self.server.store  # type: ignore[attr-defined]

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bad_request(self, message: str) -> None:
        self._send(400, {"error": message})

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- routes ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        match = AUDIT_PATH_RE.match(self.path)
        if match:
            record = self.store.get(match.group(1))
            if record is None:
                self._send(404, {"error": "unknown audit id"})
            else:
                self._send(200, record)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/audits":
            self._send(404, {"error": "not found"})
            return
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._bad_request("missing Content-Length")
            return
        try:
            length = int(length_header)
        except ValueError:
            self._bad_request("invalid Content-Length")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(413, {"error": "request body too large"})
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._bad_request("truncated request body")
            return
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._bad_request("request body is not valid JSON")
            return
        if not isinstance(payload, dict):
            self._bad_request("request body must be a JSON object")
            return

        audit_id = payload.get("audit_id")
        if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
            self._bad_request(
                "audit_id must match " + AUDIT_ID_RE.pattern)
            return
        target_name = payload.get("target_name")
        if not isinstance(target_name, str) or not target_name or len(target_name) > 256:
            self._bad_request("target_name must be a non-empty string")
            return
        target_bytes = self._decode(payload.get("target"), "target")
        if target_bytes is None:
            return
        deps_raw = payload.get("dependencies", [])
        if not isinstance(deps_raw, list):
            self._bad_request("dependencies must be a list")
            return
        if len(deps_raw) > MAX_DEPENDENCIES:
            self._bad_request(
                f"at most {MAX_DEPENDENCIES} dependency objects are accepted")
            return
        dependencies = []
        for i, entry in enumerate(deps_raw):
            if not isinstance(entry, dict):
                self._bad_request(f"dependencies[{i}] must be an object")
                return
            name = entry.get("name")
            if not isinstance(name, str) or not name or len(name) > 256:
                self._bad_request(f"dependencies[{i}].name must be a non-empty string")
                return
            data = self._decode(entry.get("data"), f"dependencies[{i}].data")
            if data is None:
                return
            dependencies.append((name, data))

        request_fp = fingerprint(target_name, target_bytes, dependencies)
        outcome, record = self.store.submit(
            audit_id,
            request_fp,
            lambda: run_audit(target_name, target_bytes, dependencies),
        )
        if outcome == "conflict":
            self._send(409, {
                "error": "audit id conflict",
                "audit_id": audit_id,
                "message": "audit id is already frozen with different request "
                           "bytes; the original verdict remains available",
                "frozen_request_sha256": record["request_sha256"],
            })
        elif outcome == "replayed":
            self._send(200, record)
        else:
            self._send(201, record)

    def _decode(self, value, field: str) -> bytes | None:
        if not isinstance(value, str):
            self._bad_request(f"{field} must be a Base64 string")
            return None
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            self._bad_request(f"{field} is not valid Base64")
            return None


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.store = AuditStore()  # type: ignore[attr-defined]
    sys.stderr.write(f"elfaudit listening on 0.0.0.0:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
