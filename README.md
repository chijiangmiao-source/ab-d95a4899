# Flight-Control Shared-Library ELF Audit Service

A deploy-time auditor for replaced flight-control simulation images.  It takes
an **ELF64 little-endian `ET_DYN`** target plus up to eight named dependency
objects (Base64 raw bytes), parses the dynamic linking metadata strictly from
`PT_DYNAMIC` virtual-address mappings (no section headers — which disappear
after a naive `strip`/binary replacement), simulates the loader, and freezes a
binding verdict under the caller's audit id.

## What it checks

* Dynamic structures resolved through `PT_LOAD` ↔ `PT_DYNAMIC` VA mapping:
  `DT_NEEDED`, `DT_STRTAB`/`DT_STRSZ`, `DT_SYMTAB`/`DT_SYMENT`, **SysV and GNU
  hash**, `DT_VERSYM`, `DT_VERDEF`/`DT_VERDEFNUM`, `DT_VERNEED`/`DT_VERNEEDNUM`.
* Rejection with the **first located structural error** (`code`, `stage`,
  `offset`, `object`) for truncation, misalignment, duplicate object names,
  missing dependencies, unmappable tables and contradictory version references
  (dangling versym index, bad Verdef/Verneed version, broken chains, …).
* **BFS first-discovery** dependency expansion; dependency cycles are
  de-duplicated (each object loads once).
* Symbol resolution for undefined global/weak references:
  * a **versioned** reference binds only to a definition with the same version
    name *and* the dependency file (SONAME) named by its Verneed record —
    a same-named version in an earlier-loaded object cannot hijack it;
  * an **unversioned** reference follows first-found load order, so an earlier
    loaded compatible object correctly shadows later ones;
  * **strong** references with no compatible definition fail the audit;
    **weak** references may remain unbound.

## HTTP API

| Method | Path            | Meaning |
|--------|-----------------|---------|
| POST   | `/audits`       | submit or replay an audit |
| GET    | `/audits/{id}`  | read the frozen verdict |
| GET    | `/healthz`      | health probe |

```json
{
  "audit_id": "FC-BUILD-77",
  "target": {"name": "fctl-main", "data_b64": "<base64 ELF bytes>"},
  "dependencies": [
    {"name": "libact.so.1", "data_b64": "<base64 ELF bytes>"}
  ]
}
```

Frozen semantics: the same `audit_id` only ever replays a **byte-identical**
submission (same target name and exact bytes for every object).  Replacing any
object, or renaming the target, returns `409 audit_id_conflict`; the original
verdict stays readable via `GET /audits/{id}`.

Verdict shape:

```json
{
  "target": "fctl-main",
  "verdict": "pass",
  "load_order": ["fctl-main", "libshim.so.1", "libact.so.1"],
  "bindings": [{
    "object": "fctl-main", "symbol_index": 3, "symbol": "actuate",
    "bound_to_object": "libact.so.1", "bound_to_symbol_index": 8,
    "version": "ACT_1.0", "required_file": "libact.so.1", "basis": "version"
  }],
  "unbound_weak": [ ... ]
}
```

Failures add either `first_failure` (an unresolved strong reference) or
`first_error` (structural/load rejection with `code`/`stage`/`offset`/`object`).

## Run with Docker Compose

```bash
docker compose up --build --abort-on-container-exit --exit-code-from verify
```

`app` starts and becomes healthy first; `verify` then runs the parser rule
tests, interleaves API/HTTP smoke with the version-shadowing, weak-symbol and
corrupted-dynamic-table scenarios, and exits non-zero if any acceptance check
fails.

## Develop / run locally (no Docker)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q          # unit + HTTP tests
.venv/bin/python verify.py --local     # full acceptance, spawns the service
```

The application itself uses only the Python 3.11 standard library.

## Layout

```
app/elfparser.py   PT_DYNAMIC-driven ELF64 parser (SysV/GNU hash, versions)
app/linker.py      BFS load order + version/file-scoped first-found binding
app/store.py       validation, byte fingerprints, frozen replay/conflict
app/server.py      stdlib HTTP API (POST /audits, GET /audits/{id}, /healthz)
tests/             synthetic ELF builder + 38 parser/linker/API tests
verify.py          acceptance orchestrator (Compose and --local modes)
```
