#!/usr/bin/env python3
"""Acceptance verifier for the ELF dynamic-link audit service.

It runs after the app reports healthy (see docker-compose.yml) and reports the
overall result through its exit code.  Phases are interleaved:

  1. parser/linker rule code tests (pytest tests/test_elf_rules.py)
  2. API / HTTP smoke
  3. binding scenarios: version shadowing, weak symbols, strong failure,
     corrupted dynamic table
  4. frozen replay, byte-conflict and original-still-readable checks

Use ``python verify.py --local`` outside Compose: it spawns the service
process itself.  Inside Compose AUDIT_BASE_URL points at the app container.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests.elfbuild import ElfBuilder  # noqa: E402

B64 = lambda b: base64.b64encode(b).decode()

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        _failures.append(name)
    return ok


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http(method: str, url: str, body=None, timeout: int = 5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_healthy(base: str, attempts: int = 30) -> bool:
    for _ in range(attempts):
        try:
            status, _ = http("GET", base + "/healthz")
            if status == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Object factories
# ---------------------------------------------------------------------------

def make_shim_lib():
    """Earlier-loaded library carrying the same version label but wrong file."""
    b = ElfBuilder()
    b.set_soname("libshim.so.1")
    b.add_verdef(1, "libshim.so.1", base=True)
    b.add_verdef(2, "ACT_1.0")  # same version NAME as the real library
    b.define("actuate", version=2)
    return b.build()


def make_real_lib():
    b = ElfBuilder()
    b.set_soname("libact.so.1")
    b.add_verdef(1, "libact.so.1", base=True)
    b.add_verdef(2, "ACT_1.0")
    b.add_verdef(3, "ACT_1.2")
    b.define("actuate", version=2)
    b.define("actuate", version=3)  # dynsym keeps first; later index exists
    b.define("calibrate", version=2)
    return b.build()


def make_shadowing_target():
    """Needs libshim first, libact second; versioned ref pinned to libact."""
    b = ElfBuilder()
    b.need("libshim.so.1")
    b.need("libact.so.1")
    b.add_verneed_file("libact.so.1", [(2, "ACT_1.0")])
    b.undefined("actuate", version=2)
    # unversioned symbol: earlier loader must interpose/shadow
    b.undefined("plain_global")
    return b.build()


def make_shim_with_plain():
    b = ElfBuilder()
    b.set_soname("libshim.so.1")
    b.add_verdef(1, "libshim.so.1", base=True)
    b.add_verdef(2, "ACT_1.0")
    b.define("actuate", version=2)
    b.define("plain_global", version=1)
    return b.build()


def make_weak_target():
    b = ElfBuilder()
    b.need("libact.so.1")
    b.undefined("optional_telem", weak=True)          # no provider: stays unbound
    b.undefined("mandatory_kill_switch")               # strong, no provider: FAIL
    return b.build()


def make_corrupt_lib(good: bytes) -> bytes:
    """Point DT_STRTAB at an unmapped virtual address (first error located)."""
    blob = bytearray(good)
    dyn_off = struct.unpack_from("<Q", blob, 64 + 56 + 8)[0]
    i = 0
    while True:
        tag, _ = struct.unpack_from("<qQ", blob, dyn_off + i * 16)
        if tag == 5:  # DT_STRTAB
            struct.pack_into("<Q", blob, dyn_off + i * 16 + 8, 0x7777770)
            return bytes(blob)
        if tag == 0:
            raise AssertionError("DT_STRTAB not found in dynamic table")
        i += 1


def payload(audit_id, target_name, target_bytes, deps):
    return {
        "audit_id": audit_id,
        "target": {"name": target_name, "data_b64": B64(target_bytes)},
        "dependencies": [{"name": n, "data_b64": B64(d)} for n, d in deps],
    }


# ---------------------------------------------------------------------------
# Scenario phases
# ---------------------------------------------------------------------------

def phase_rule_tests() -> bool:
    print("phase 1: parser/linker rule code tests")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_elf_rules.py", "-q"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    return check("rule test-suite exits zero", proc.returncode == 0, f"exit={proc.returncode}")


def phase_http_smoke(base: str) -> bool:
    print("phase 2: API / HTTP smoke")
    ok = True
    status, body = http("GET", base + "/healthz")
    ok &= check("GET /healthz -> 200 ok", status == 200 and body.get("status") == "ok")

    status, body = http("GET", base + "/audits/nope")
    ok &= check("GET /audits/{unknown} -> 404", status == 404 and body["error"] == "audit_not_found")

    req = urllib.request.Request(base + "/audits", data=b"{bad", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
        ok &= check("POST malformed JSON -> 400", False)
    except urllib.error.HTTPError as e:
        ok &= check("POST malformed JSON -> 400", e.code == 400)
    return ok


def phase_version_shadowing(base: str) -> bool:
    print("phase 3a: version shadowing")
    ok = True
    p = payload(
        "SHADOW-1", "fctl-main", make_shadowing_target(),
        [("libshim.so.1", make_shim_with_plain()), ("libact.so.1", make_real_lib())],
    )
    status, body = http("POST", base + "/audits", p)
    ok &= check("shadow scenario accepted (201)", status == 201, str(body))
    result = body.get("result", {})
    ok &= check("verdict pass despite identically-named versions",
                result.get("verdict") == "pass", json.dumps(result)[:200])

    # Version+file pinning must defeat the earlier shim.
    act_binding = next(
        (b for b in result.get("bindings", []) if b["symbol"] == "actuate"), None)
    ok &= check(
        "actuate@ACT_1.0 binds to libact (file-scoped), not the earlier shim",
        act_binding is not None and act_binding["bound_to_object"] == "libact.so.1"
        and act_binding["basis"] == "version",
        json.dumps(act_binding),
    )
    plain = next((b for b in result.get("bindings", []) if b["symbol"] == "plain_global"), None)
    ok &= check(
        "unversioned plain_global is shadowed by the earlier libshim",
        plain is not None and plain["bound_to_object"] == "libshim.so.1",
        json.dumps(plain),
    )
    return ok


def phase_weak_symbols(base: str) -> bool:
    print("phase 3b: weak vs strong references")
    ok = True
    p = payload(
        "WEAK-1", "fctl-main", make_weak_target(),
        [("libact.so.1", make_real_lib())],
    )
    status, body = http("POST", base + "/audits", p)
    ok &= check("weak scenario accepted (201)", status == 201, str(body))
    result = body.get("result", {})
    ok &= check("missing strong symbol makes verdict fail", result.get("verdict") == "fail")
    fail = result.get("first_failure", {})
    ok &= check(
        "first failure locates the strong symbol and object",
        fail.get("symbol") == "mandatory_kill_switch" and fail.get("object") == "fctl-main"
        and fail.get("reason") == "unresolved_strong",
        json.dumps(fail),
    )
    weak = [w for w in result.get("unbound_weak", []) if w["symbol"] == "optional_telem"]
    ok &= check("weak optional_telem remains unbound without failing", len(weak) == 1)
    return ok


def phase_corrupt_dynamic(base: str) -> bool:
    print("phase 3c: corrupted dynamic table rejection")
    ok = True
    corrupt = make_corrupt_lib(make_real_lib())
    p = payload(
        "CORRUPT-1", "fctl-main", make_shadowing_target(),
        [("libshim.so.1", make_shim_with_plain()), ("libact.so.1", corrupt)],
    )
    status, body = http("POST", base + "/audits", p)
    ok &= check("corrupt submission accepted for frozen verdict (201)", status == 201, str(body))
    err = body.get("result", {}).get("first_error", {})
    ok &= check(
        "verdict fails with unmappable_table at the offending object/stage",
        body.get("result", {}).get("verdict") == "fail"
        and err.get("code") == "unmappable_table"
        and err.get("object") == "libact.so.1"
        and err.get("stage") == "DT_STRTAB",
        json.dumps(err),
    )
    status, got = http("GET", base + "/audits/CORRUPT-1")
    ok &= check("rejection verdict is frozen and readable",
                status == 200 and got["result"]["first_error"]["code"] == "unmappable_table")
    return ok


def phase_freeze_and_conflict(base: str) -> bool:
    print("phase 4: frozen replay / conflict / original still readable")
    ok = True
    p = payload(
        "FREEZE-1", "fctl-main", make_shadowing_target(),
        [("libshim.so.1", make_shim_with_plain()), ("libact.so.1", make_real_lib())],
    )
    s1, b1 = http("POST", base + "/audits", p)
    ok &= check("first submission creates the audit", s1 == 201)

    s2, b2 = http("POST", base + "/audits", p)  # byte-identical replay
    ok &= check("byte-identical replay returns 200 with same fingerprint",
                s2 == 200 and b2.get("replayed") is True
                and b2["fingerprint"] == b1["fingerprint"]
                and b2["result"] == b1["result"])

    # Replace one object's bytes -> conflict.
    p_changed = json.loads(json.dumps(p))
    p_changed["dependencies"][1]["data_b64"] = B64(make_corrupt_lib(make_real_lib()))
    s3, b3 = http("POST", base + "/audits", p_changed)
    ok &= check("replacing a dependency object conflicts (409)",
                s3 == 409 and b3["error"] == "audit_id_conflict", str(b3))

    # Change the target object name -> conflict as well.
    p_renamed = json.loads(json.dumps(p))
    p_renamed["target"]["name"] = "fctl-main-replaced"
    s4, b4 = http("POST", base + "/audits", p_renamed)
    ok &= check("renaming the target object conflicts (409)",
                s4 == 409 and b4["error"] == "audit_id_conflict", str(b4))

    s5, b5 = http("GET", base + "/audits/FREEZE-1")
    ok &= check("original frozen verdict remains readable after conflicts",
                s5 == 200 and b5["result"] == b1["result"]
                and b5["fingerprint"] == b1["fingerprint"])
    return ok


def phase_over_limit(base: str) -> bool:
    print("phase 5: request validation")
    ok = True
    deps = [(f"lib{i}.so", make_real_lib()) for i in range(9)]
    p = payload("LIMIT-1", "fctl-main", make_shadowing_target(), deps)
    status, body = http("POST", base + "/audits", p)
    ok &= check("more than eight dependencies rejected",
                status == 400 and body["error"] == "too_many_dependencies", str(body))

    dup = payload("DUP-1", "fctl-main", make_shadowing_target(),
                  [("libact.so.1", make_real_lib()), ("libact.so.1", make_real_lib())])
    status, body = http("POST", base + "/audits", dup)
    ok &= check("duplicate dependency object name rejected",
                status == 400 and body["error"] == "duplicate_object_name", str(body))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true", help="spawn the service locally")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()

    base = os.environ.get("AUDIT_BASE_URL")
    proc = None
    if args.local or not base:
        base = f"http://127.0.0.1:{args.port}"
        env = dict(os.environ, PORT=str(args.port))
        proc = subprocess.Popen(
            [sys.executable, "-m", "app.server"],
            cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    try:
        print(f"waiting for app health at {base}")
        if not wait_healthy(base):
            print(f"{RED}app never became healthy{RESET}")
            return 2
        print("app healthy\n")

        phase_rule_tests()
        phase_http_smoke(base)
        phase_version_shadowing(base)
        phase_weak_symbols(base)
        phase_corrupt_dynamic(base)
        phase_freeze_and_conflict(base)
        phase_over_limit(base)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    print()
    if _failures:
        print(f"{RED}ACCEPTANCE FAILED: {len(_failures)} check(s){RESET}")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print(f"{GREEN}ACCEPTANCE PASSED{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
