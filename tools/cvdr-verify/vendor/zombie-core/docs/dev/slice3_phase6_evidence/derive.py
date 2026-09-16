#!/usr/bin/env python3
"""Superseded, non-original reconstructed implementation primitives.

The exact original clean-room script is archived at ../phase6/derive.py.

This evidence file has no repository, Rust, subprocess, FFI, or encoder
reachability. The comparison result is recorded in the adjacent report.
"""

import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path


def sha256(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def tagged(tag, *parts):
    return sha256(tag.encode("ascii"), *parts)


def hx(value):
    return bytes.fromhex(value)


def u32(value):
    return value.to_bytes(4, "big")


def u64(value):
    return value.to_bytes(8, "big")


def principal_text(raw):
    checksum = binascii.crc32(raw).to_bytes(4, "big")
    encoded = base64.b32encode(checksum + raw).decode("ascii").lower().rstrip("=")
    return "-".join(encoded[offset:offset + 5] for offset in range(0, len(encoded), 5))


def receipt_id(canister, record, deletion_seq):
    return tagged(
        "MKTD02_RECEIPT_V3",
        u32(len(canister)), canister,
        u32(len(record)), record,
        u64(deletion_seq),
    )


def event_v2(values, rid):
    return tagged(
        "MKTD02_EVENT_V2",
        hx(values["pre_state_hash"]),
        hx(values["post_state_hash"]),
        rid,
        u64(values["timestamp"]),
        hx(values["module_hash"]),
        u64(values["deletion_seq"]),
    )


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: derive.py INPUT_VECTOR.json")
    vector = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps({"id": vector["id"], "inputs_sha256": hashlib.sha256(
        json.dumps(vector["inputs"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()}, separators=(",", ":")))


if __name__ == "__main__":
    main()
