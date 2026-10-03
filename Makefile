.PHONY: accept test run verify-local

# Full acceptance: build images, run compose, propagate verify's exit code.
accept:
	sh scripts/accept.sh

# Parsing-rule and audit-semantics unit tests (host).
test:
	PYTHONPATH=app/src:tools python3 -m unittest discover -s tests -v

# Run the API server locally on :8000.
run:
	PYTHONPATH=app/src python3 app/src/server.py

# Run the end-to-end verifier against a locally running server.
verify-local:
	PYTHONPATH=app/src:tools APP_URL=http://127.0.0.1:8000 python3 verify/verify.py
