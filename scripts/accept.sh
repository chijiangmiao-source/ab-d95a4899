#!/bin/sh
# Acceptance pipeline: image build, then compose up where `verify`
# (gated on the app's health check) runs HTTP smoke checks, the
# version-shadowing / weak-symbol / corrupted-dynamic-table scenarios and
# the interleaved parsing-rule unit tests.  The verify container's exit
# code is the acceptance result.
set -e
cd "$(dirname "$0")/.."

docker compose build
code=0
docker compose up \
    --exit-code-from verify \
    --abort-on-container-exit \
    || code=$?
docker compose down -v >/dev/null 2>&1 || true
exit "$code"
