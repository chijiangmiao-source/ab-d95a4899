"""HTTP API for the ELF dynamic-link audit service.

Endpoints
---------
POST /audits        submit or replay an audit
GET  /audits/{id}   read a frozen verdict
GET  /healthz       liveness/readiness probe
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .store import AuditStore, RequestError

STORE = AuditStore()
_MAX_BODY = 32 * 1024 * 1024  # 32 MiB cap for a single audit submission


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "ElfAudit/1.0"

    def log_message(self, fmt, *args):  # keep container logs quiet
        pass

    # ------------------------------------------------------------------
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(status, {"error": code, "message": message})

    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if path.startswith("/audits/"):
            audit_id = urllib.parse.unquote(path[len("/audits/"):])
            if not audit_id or "/" in audit_id:
                self._error(404, "not_found", "unknown path")
                return
            record = STORE.get(audit_id)
            if record is None:
                self._error(404, "audit_not_found", f"no frozen audit with id {audit_id!r}")
                return
            self._send_json(200, {
                "audit_id": record.audit_id,
                "fingerprint": record.fingerprint,
                "result": record.verdict,
            })
            return
        self._error(404, "not_found", "unknown path")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/audits":
            self._error(404, "not_found", "unknown path")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(400, "bad_request", "invalid Content-Length")
            return
        if length <= 0:
            self._error(400, "empty_body", "request body is empty")
            return
        if length > _MAX_BODY:
            self._error(413, "body_too_large", "request body exceeds 32 MiB")
            return
        raw = self.rfile.read(length)

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(400, "bad_json", f"request body is not valid JSON: {exc}")
            return

        try:
            record, created = STORE.submit(payload)
        except RequestError as exc:
            self._send_json(exc.status, {"error": exc.code, "message": exc.message})
            return

        self._send_json(201 if created else 200, {
            "audit_id": record.audit_id,
            "fingerprint": record.fingerprint,
            "replayed": not created,
            "result": record.verdict,
        })


def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), AuditHandler)
    server.daemon_threads = True
    print(f"ELF audit service listening on {host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    import os

    serve(port=int(os.environ.get("PORT", "8080")))
