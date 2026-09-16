#!/usr/bin/env bash
# Run from any working directory. Requires Python 3, rustup and cargo-audit.
# Fixed baseline captured at 25c2945 with Rust 1.97.1; see slice4_notes §12.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 - <<'PYTHON'
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = str(Path.cwd())
os.environ["CARGO_TERM_COLOR"] = "never"

# Full rustfmt output, normalized only for the absolute crate path.
FMT_SHA256 = "40d2e141704ecc7a768c97f4d7de9a0602fde9c425ea21df91bb7851ab4a5b47"
# Full structured diagnostics (including spans, children and suggestions), minus
# presentation-only `rendered`; sorted-key JSON, crate path normalized. Counts
# retain duplicate bin/test diagnostics. Nothing is filtered by source directory.
CLIPPY_SHA256_COUNTS = {
    "37a7574a6fa79470f5676a04b33674b66e498142160986f1ea2325e623a03041": 2,
    "433fc671756879ffa539c03bcb3052dd48beb7e66bad07eb6a00c77576b6c45f": 1,
    "b5d124ae3173b629bfac4d8761f9cdc3de1cd321df012209e1b79530725c6b78": 2,
    "ba7866bd944bb368d39911ecc3be87b3b3aa5f785fff27a5246a559b3df555c1": 1,
    "bdf57f97447113a2d79519a70bfe22d999b40311cfdcae259283cca4f07b3b9c": 2,
    "e00dfa2d9205d823d718dbc5878cd0f1cac039e8387955210c23b3bd2cdaadd3": 2
}
CLIPPY_STDERR = sorted([
    'error: could not compile `mktd02-verify` (bin "mktd02-verify") due to 5 previous errors',
    'error: could not compile `mktd02-verify` (bin "mktd02-verify" test) due to 5 previous errors',
])
MAINTENANCE = {
    ("backoff", "0.4.0", "RUSTSEC-2025-0012"),
    ("instant", "0.1.13", "RUSTSEC-2024-0384"),
    ("paste", "1.0.15", "RUSTSEC-2024-0436"),
    ("serde_cbor", "0.11.2", "RUSTSEC-2021-0127"),
}


def digest(text):
    return hashlib.sha256(text.replace(ROOT, "<crate>").encode()).hexdigest()


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
require(fmt.returncode == 1 and digest(fmt.stdout) == FMT_SHA256,
        "format output/exit differs from the fixed OpenChatZD baseline", fmt)
print("fmt: accepted exact pre-existing OpenChatZD baseline (raw exit 1)", flush=True)

clippy = run(["cargo", "clippy", "--quiet", "--locked", "--all-targets",
              "--message-format=json", "--", "-D", "warnings"], capture_output=True)
counts = collections.Counter()
finished = []
try:
    for line in clippy.stdout.splitlines():
        event = json.loads(line)
        reason = event["reason"]
        if reason == "compiler-message":
            message = event["message"]
            message.pop("rendered", None)
            record = {"target_name": event["target"]["name"],
                      "target_kind": event["target"]["kind"], "message": message}
            counts[digest(json.dumps(record, sort_keys=True, separators=(",", ":")))]+=1
        elif reason == "build-finished":
            finished.append(event["success"])
        elif reason not in ("compiler-artifact", "build-script-executed"):
            raise ValueError("unknown cargo event: " + reason)
except (ValueError, KeyError, TypeError) as error:
    require(False, "invalid Clippy output: " + str(error), clippy)
require(clippy.returncode == 101 and finished == [False]
        and counts == CLIPPY_SHA256_COUNTS
        and sorted(clippy.stderr.splitlines()) == CLIPPY_STDERR,
        "Clippy diagnostics/counts/exit differ from the fixed baseline", clippy)
print("clippy: accepted exact baseline: 10 diagnostics across bin/test at six "
      "OpenChatZD locations (raw exit 101); no new warnings", flush=True)

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
