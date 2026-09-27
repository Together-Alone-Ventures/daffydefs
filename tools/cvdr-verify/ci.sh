#!/usr/bin/env bash
# Run from any working directory. Requires Python 3, rustup and cargo-audit.
# Fixed baseline captured at 25c2945 with Rust 1.97.1; see slice4_notes §12.
# Step 5 (OpenChatZD suite-v5 verifier): the accepted pre-existing OpenChatZD fmt/clippy baseline
# is retired — `src/openchatzd/` is now clean, so fmt and clippy must exit 0 like the rest.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 - <<'PYTHON'
import json
import os
from pathlib import Path
import subprocess
import sys

os.environ["CARGO_TERM_COLOR"] = "never"

MAINTENANCE = {
    ("backoff", "0.4.0", "RUSTSEC-2025-0012"),
    ("instant", "0.1.13", "RUSTSEC-2024-0384"),
    ("paste", "1.0.15", "RUSTSEC-2024-0436"),
    ("serde_cbor", "0.11.2", "RUSTSEC-2021-0127"),
}


def run(args, **kwargs):
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, text=True, **kwargs)


def require(ok, message, result):
    if not ok:
        print(result.stdout or "", file=sys.stderr)
        print(result.stderr or "", file=sys.stderr)
        sys.exit("FAIL: " + message)


fmt = run(["cargo", "fmt", "--check"], stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT)
require(fmt.returncode == 0, "cargo fmt --check must be clean", fmt)
print("fmt: clean", flush=True)

clippy = run(["cargo", "clippy", "--quiet", "--locked", "--all-targets",
              "--", "-D", "warnings"], capture_output=True)
require(clippy.returncode == 0, "cargo clippy -D warnings must be clean", clippy)
print("clippy: clean (no diagnostics)", flush=True)

result = run(["cargo", "test", "--locked"])
if result.returncode:
    sys.exit(result.returncode)

audit = run(["cargo", "audit", "--json"], capture_output=True)
require(audit.returncode == 0, "cargo audit failed", audit)
try:
    report = json.loads(audit.stdout)
    require(report["vulnerabilities"]["count"] == 0
            and report["vulnerabilities"]["found"] is False
            and report["vulnerabilities"]["list"] == [], "audit vulnerabilities", audit)
    for kind, warnings in report["warnings"].items():
        for warning in warnings:
            package = warning["package"]
            key = (package["name"], package["version"], warning["advisory"]["id"])
            require(kind == "unmaintained" and key in MAINTENANCE,
                    "unexpected audit warning", audit)
            print("audit: permitted maintenance warning " + " / ".join(key))
except (ValueError, KeyError, TypeError) as error:
    require(False, "invalid audit output: " + str(error), audit)
print("audit: zero vulnerabilities", flush=True)
result = run(["cargo", "test", "--locked", "--test", "v5_corpus_acceptance"])
if result.returncode:
    sys.exit(result.returncode)
print("Local checks passed with the explicitly reported OpenChatZD baseline.")
PYTHON
