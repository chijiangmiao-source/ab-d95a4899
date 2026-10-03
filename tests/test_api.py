"""Tests for the frozen audit store and HTTP API."""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from app import server as srvmod
from app.elfparser import parse_elf64
from app.store import AuditStore, RequestError
from tests.elfbuild import ElfBuilder

B64 = lambda b: base64.b64encode(b).decode()


# ---------------------------------------------------------------------------
# Fixture objects
# ---------------------------------------------------------------------------

def _good_lib():
    b = ElfBuilder()
    b.set_soname("libact.so.1")
    b.add_verdef(1, "libact.so.1", base=True)
    b.add_verdef(2, "ACT_1.0")
    b.define("actuate", version=2)
    return b.build()


def _consumer():
    b = ElfBuilder()
    b.need("libact.so.1")
    b.add_verneed_file("libact.so.1", [(2, "ACT_1.0")])
    b.undefined("actuate", version=2)
    b.undefined("optional_cal", weak=True)
    return b.build()


def _payload(audit_id="AUDIT-001", dep_bytes=None, dep_name="libact.so.1", target_name="fctl-main"):
    return {
        "audit_id": audit_id,
        "target": {"name": target_name, "data_b64": B64(_consumer())},
        "dependencies": [
            {"name": dep_name, "data_b64": B64(dep_bytes if dep_bytes is not None else _good_lib())},
        ],
    }


# ---------------------------------------------------------------------------
# Store-level semantics
# ---------------------------------------------------------------------------

def test_submit_then_replay_byte_identical():
    store = AuditStore()
    rec1, created1 = store.submit(_payload())
    assert created1 is True
    assert rec1.verdict["verdict"] == "pass"
    rec2, created2 = store.submit(_payload())
    assert created2 is False
    assert rec2.verdict == rec1.verdict
    assert rec2.fingerprint == rec1.fingerprint


def test_conflict_when_dependency_bytes_change_and_old_remains_readable():
    store = AuditStore()
    rec, _ = store.submit(_payload())

    changed = bytearray(_good_lib())
    changed[-1] ^= 0xFF  # may or may not land in payload padding; force real edit:
    # Append a tagged section byte by rebuilding with an extra symbol instead.
    b2 = ElfBuilder()
    b2.set_soname("libact.so.1")
    b2.add_verdef(1, "libact.so.1", base=True)
    b2.add_verdef(2, "ACT_1.0")
    b2.define("actuate", version=2)
    b2.define("newly_added", version=2)
    payload2 = _payload(dep_bytes=b2.build())

    with pytest.raises(RequestError) as ei:
        store.submit(payload2)
    assert ei.value.status == 409

    # Original frozen verdict is still readable and unchanged.
    again = store.get("AUDIT-001")
    assert again.fingerprint == rec.fingerprint
    assert again.verdict == rec.verdict


def test_conflict_when_target_name_changes():
    store = AuditStore()
    store.submit(_payload())
    payload2 = _payload(target_name="fctl-main-renamed")
    with pytest.raises(RequestError) as ei:
        store.submit(payload2)
    assert ei.value.status == 409


def test_duplicate_dependency_object_name_rejected():
    store = AuditStore()
    p = _payload()
    p["dependencies"].append({"name": "libact.so.1", "data_b64": B64(_good_lib())})
    with pytest.raises(RequestError) as ei:
        store.submit(p)
    assert ei.value.code == "duplicate_object_name"


def test_dependency_name_equal_to_target_rejected():
    store = AuditStore()
    p = _payload(target_name="dup.so", dep_name="dup.so")
    with pytest.raises(RequestError) as ei:
        store.submit(p)
    assert ei.value.code == "duplicate_object_name"


def test_too_many_dependencies():
    store = AuditStore()
    p = _payload()
    p["dependencies"] = [
        {"name": f"lib{i}.so", "data_b64": B64(_good_lib())} for i in range(9)
    ]
    with pytest.raises(RequestError) as ei:
        store.submit(p)
    assert ei.value.code == "too_many_dependencies"


def test_bad_base64_rejected():
    store = AuditStore()
    p = _payload()
    p["target"]["data_b64"] = "@@@not-base64@@@"
    with pytest.raises(RequestError) as ei:
        store.submit(p)
    assert ei.value.code == "bad_base64"


def test_missing_dependency_freeze():
    store = AuditStore()
    # Target needs libact.so.1 but no dependency object supplied.
    p = _payload()
    p["dependencies"] = []
    rec, created = store.submit(p)
    assert created is True
    assert rec.verdict["verdict"] == "fail"
    assert rec.verdict["first_error"]["code"] == "missing_dependency"
    assert rec.verdict["first_error"]["object"] == "libact.so.1"


def test_corrupt_dynamic_table_freezes_first_error():
    store = AuditStore()
    import struct
    blob = bytearray(_good_lib())
    dyn_off = struct.unpack_from("<Q", blob, 64 + 56 + 8)[0]
    # Point DT_STRTAB (tag 5) at an unmapped virtual address.
    i = 0
    while True:
        tag, _ = struct.unpack_from("<qQ", blob, dyn_off + i * 16)
        if tag == 5:
            struct.pack_into("<Q", blob, dyn_off + i * 16 + 8, 0x7777770)
            break
        if tag == 0:
            raise AssertionError("no DT_STRTAB to corrupt")
        i += 1
    p = _payload(dep_bytes=bytes(blob))
    rec, _ = store.submit(p)
    assert rec.verdict["verdict"] == "fail"
    err = rec.verdict["first_error"]
    assert err["code"] == "unmappable_table"
    assert err["object"] == "libact.so.1"
    assert err["stage"] == "DT_STRTAB"


def test_corrupt_target_reports_target_name():
    store = AuditStore()
    p = _payload()
    p["target"]["data_b64"] = B64(b"\x7fELF\x02\x01garbage")
    rec, _ = store.submit(p)
    assert rec.verdict["verdict"] == "fail"
    assert rec.verdict["first_error"]["object"] == "fctl-main"
    assert rec.verdict["first_error"]["code"] in ("truncation", "bad_format")


def test_frozen_verdict_includes_binding_basis():
    store = AuditStore()
    rec, _ = store.submit(_payload())
    result = rec.verdict
    binding = result["bindings"][0]
    assert binding["symbol"] == "actuate"
    assert binding["bound_to_object"] == "libact.so.1"
    assert binding["version"] == "ACT_1.0"
    assert binding["basis"] == "version"
    # Weak undefined stays unbound but does not fail the verdict.
    assert result["verdict"] == "pass"
    assert result["unbound_weak"][0]["symbol"] == "optional_cal"


# ---------------------------------------------------------------------------
# HTTP-level smoke tests (real stdlib server on an ephemeral port).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def http_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srvmod.AuditHandler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _req(base, method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_http_health(http_server):
    status, body = _req(http_server, "GET", "/healthz")
    assert status == 200
    assert body["status"] == "ok"


def test_http_submit_get_replay_conflict(http_server):
    status, body = _req(http_server, "POST", "/audits", _payload(audit_id="HTTP-1"))
    assert status == 201
    assert body["result"]["verdict"] == "pass"

    status2, body2 = _req(http_server, "GET", "/audits/HTTP-1")
    assert status2 == 200
    assert body2["result"] == body["result"]

    # identical replay
    status3, body3 = _req(http_server, "POST", "/audits", _payload(audit_id="HTTP-1"))
    assert status3 == 200
    assert body3["replayed"] is True

    # conflicting bytes
    conflict = _payload(audit_id="HTTP-1", target_name="different-name")
    status4, body4 = _req(http_server, "POST", "/audits", conflict)
    assert status4 == 409
    assert body4["error"] == "audit_id_conflict"

    # original still readable
    status5, body5 = _req(http_server, "GET", "/audits/HTTP-1")
    assert status5 == 200
    assert body5["result"]["verdict"] == "pass"


def test_http_get_unknown_audit_404(http_server):
    status, body = _req(http_server, "GET", "/audits/does-not-exist")
    assert status == 404
    assert body["error"] == "audit_not_found"


def test_http_bad_json_400(http_server):
    req = urllib.request.Request(
        http_server + "/audits", data=b"not-json", method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        raise AssertionError("expected 400")
    except urllib.error.HTTPError as e:
        assert e.code == 400
        assert json.loads(e.read())["error"] == "bad_json"
