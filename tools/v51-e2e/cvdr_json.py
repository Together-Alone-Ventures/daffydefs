"""Shared helpers for the v5.1 local end-to-end and mutation scripts.

Converts a `dfx canister call ... mktd_get_receipt --output json` response into
the CVDR JSON a user downloads from the frontend: canonical field order applied
to the fields present, absent optional fields omitted, integers as JSON
numbers, byte fields as lowercase hex.
"""

import base64
import json
import subprocess
import textwrap

FIELD_ORDER = [
    "protocol_version", "receipt_id", "canister_id", "record_id",
    "pre_state_hash", "post_state_hash", "tombstone_hash", "deletion_event_hash",
    "module_hash", "timestamp", "deletion_seq", "bls_certificate",
    "trust_root_key_id", "module_hash_certificate",
]
OPT_TEXT = {"module_hash", "trust_root_key_id"}
OPT_BLOB = {"bls_certificate", "module_hash_certificate"}
INTEGERS = {"timestamp", "deletion_seq"}


def dfx(*args, identity=None, check=True):
    cmd = ["dfx", *args]
    if identity:
        cmd += ["--identity", identity]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout


def blob(value):
    """dfx renders `blob` as a list of ints (or occasionally a hex string)."""
    if isinstance(value, str):
        return bytes.fromhex(value)
    return bytes(value)


def cvdr_from_dfx(raw):
    """Map one dfx JSON receipt record onto the ordered CVDR dict."""
    out = {}
    for key in FIELD_ORDER:
        value = raw[key]
        if key in OPT_TEXT:
            if value:
                out[key] = value[0]
        elif key in OPT_BLOB:
            if value:
                out[key] = blob(value[0]).hex()
        elif key == "record_id":
            out[key] = blob(value).hex()
        elif key in INTEGERS:
            out[key] = int(value)
        else:
            out[key] = value
    return out


def render(cvdr):
    """Frontend-style rendering: one key per line, integers unquoted."""
    lines = []
    for key, value in cvdr.items():
        encoded = str(value) if isinstance(value, int) else json.dumps(value)
        lines.append(f"  {json.dumps(key)}: {encoded}")
    return "{\n" + ",\n".join(lines) + "\n}"


def local_root_pem():
    """The local replica's root key (from `dfx ping`) as a PEM public key."""
    der = bytes(json.loads(dfx("ping"))["root_key"])
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


def root_args(pem_path=None, trust_root=None):
    """Verifier trust-root arguments: a PEM file or a built-in root id."""
    if (pem_path is None) == (trust_root is None):
        raise ValueError("exactly one of pem_path / trust_root is required")
    return ["--trust-root-pem", pem_path] if pem_path else ["--trust-root", trust_root]


def verify(verifier, receipt_path, pem_path=None, trust_root=None):
    """Run mktd02-verify --json and return the parsed facts."""
    proc = subprocess.run(
        [verifier, "--receipt-file", receipt_path, *root_args(pem_path, trust_root), "--json"],
        capture_output=True, text=True,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"intake_error": proc.stderr.strip() or proc.stdout.strip(), "checks": {}}


def failing_checks(facts):
    """Names of gating checks (V1, V2, V3A) that did not pass."""
    checks = facts.get("checks") or {}
    return {
        name.upper()
        for name in ("v1", "v2", "v3a")
        if (checks.get(name) or {}).get("outcome") != "pass"
    }
