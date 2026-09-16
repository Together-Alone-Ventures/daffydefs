#!/usr/bin/env python3
"""Derive MKTd02-v5 corpus values from the ratified serialization text.

Authority: docs/spec/mktd02-v5-serialization.md.

This standard-library-only program implements the receipt encoding defined by
that document. It does not import, link, invoke, or inspect zombie-core, Rust,
or any Rust artefact. Default check mode is read-only.
"""

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "docs" / "test-vectors"
V5_ROOT = VECTOR_ROOT / "v5"
HIST_ROOT = VECTOR_ROOT / "v4-historical"
PROVENANCE = (
    "Spec-derived by scripts/rederive-v5-vectors.py from "
    "docs/spec/mktd02-v5-serialization.md; encoder not consulted. "
    "Pending Stef/G countersignature; no clean-room independence claimed."
)


def h(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def tagged(tag, *parts):
    return h(tag.encode("ascii"), *parts)


def hx(value):
    return bytes.fromhex(value)


def u32(value):
    return value.to_bytes(4, "big")


def u64(value):
    return value.to_bytes(8, "big")


def principal_text(raw):
    checksum = binascii.crc32(raw).to_bytes(4, "big")
    encoded = base64.b32encode(checksum + raw).decode("ascii").lower().rstrip("=")
    return "-".join(encoded[i:i + 5] for i in range(0, len(encoded), 5))


def receipt_id(receipt):
    canister = hx(receipt["canister_id_hex"])
    record = hx(receipt["record_id"])
    return tagged(
        "MKTD02_RECEIPT_V3",
        u32(len(canister)),
        canister,
        u32(len(record)),
        record,
        u64(receipt["deletion_seq"]),
    )


def event_v2(receipt, rid):
    return tagged(
        "MKTD02_EVENT_V2",
        hx(receipt["pre_state_hash"]),
        hx(receipt["post_state_hash"]),
        rid,
        u64(receipt["timestamp"]),
        hx(receipt["module_hash"]),
        u64(receipt["deletion_seq"]),
    )


def cbor_head(major, length):
    lead = major << 5
    if length < 24:
        return bytes([lead | length])
    if length <= 0xFF:
        return bytes([lead | 24, length])
    if length <= 0xFFFF:
        return bytes([lead | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([lead | 26]) + length.to_bytes(4, "big")
    return bytes([lead | 27]) + length.to_bytes(8, "big")


def cbor_bytes(value):
    return cbor_head(2, len(value)) + value


def cbor_text(value):
    raw = value.encode("utf-8")
    return cbor_head(3, len(raw)) + raw


def cbor_uint(value):
    return cbor_head(0, value)


def cbor_map(pairs):
    return cbor_head(5, len(pairs)) + b"".join(
        cbor_text(key) + encoded for key, encoded in pairs
    )


def receipt_values(source):
    rid = receipt_id(source)
    event = event_v2(source, rid)
    values = {
        "protocol_version": source["protocol_version"],
        "receipt_id": rid.hex(),
        "canister_id": source["canister_id_text"],
        "record_id": source["record_id"].lower(),
        "pre_state_hash": source["pre_state_hash"].lower(),
        "post_state_hash": source["post_state_hash"].lower(),
        "tombstone_hash": source["tombstone_hash"].lower(),
        "deletion_event_hash": event.hex(),
        "module_hash": source["module_hash"].lower(),
        "timestamp": source["timestamp"],
        "deletion_seq": source["deletion_seq"],
        "bls_certificate": source["bls_certificate"],
        "trust_root_key_id": source["trust_root_key_id"],
        "module_hash_certificate": source["module_hash_certificate"],
    }
    pairs = [
        ("protocol_version", cbor_text(values["protocol_version"])),
        ("receipt_id", cbor_bytes(rid)),
        ("canister_id", cbor_bytes(hx(source["canister_id_hex"]))),
        ("record_id", cbor_bytes(hx(values["record_id"]))),
        ("pre_state_hash", cbor_bytes(hx(values["pre_state_hash"]))),
        ("post_state_hash", cbor_bytes(hx(values["post_state_hash"]))),
        ("tombstone_hash", cbor_bytes(hx(values["tombstone_hash"]))),
        ("deletion_event_hash", cbor_bytes(event)),
        ("module_hash", cbor_bytes(hx(values["module_hash"]))),
        ("timestamp", cbor_uint(values["timestamp"])),
        ("deletion_seq", cbor_uint(values["deletion_seq"])),
        (
            "bls_certificate",
            b"\xf6"
            if values["bls_certificate"] is None
            else cbor_bytes(hx(values["bls_certificate"])),
        ),
        ("trust_root_key_id", cbor_text(values["trust_root_key_id"])),
        (
            "module_hash_certificate",
            b"\xf6"
            if values["module_hash_certificate"] is None
            else cbor_bytes(hx(values["module_hash_certificate"])),
        ),
    ]
    state = (
        "Pending"
        if values["bls_certificate"] is None
        and values["module_hash_certificate"] is None
        else "FinalizedCandidate"
        if values["bls_certificate"] is not None
        and values["module_hash_certificate"] is not None
        else "InvalidIncompleteFinalization"
    )
    return {
        "receipt_id": rid.hex(),
        "deletion_event_hash": event.hex(),
        "cbor_hex": cbor_map(pairs).hex(),
        "json_text": json.dumps(values, separators=(",", ":"), ensure_ascii=False),
        "state": state,
    }


def derive(vector):
    ident = vector["id"]
    inputs = vector["inputs"]
    if ident == "gv5-001":
        parts = [hx(v) for v in inputs["parts_hex"]]
        swapped = [hx(v) for v in inputs["swapped_parts_hex"]]
        return {"digest": tagged(inputs["tag_ascii"], *parts).hex(),
                "swapped_digest": tagged(inputs["tag_ascii"], *swapped).hex()}
    if ident == "gv5-002":
        tombstone = h(b"MKTD_TOMBSTONE_V1")
        digest = tagged("MKTD02_TOMBSTONE_HASH_V1", hx(inputs["canister_id_hex"]),
                        tombstone, u64(inputs["timestamp"]), u64(inputs["deletion_seq"]))
        return {"tombstone_constant": tombstone.hex(), "tombstone_hash": digest.hex()}
    if ident == "gv5-003":
        return {"cases": [{"deletion_seq": seq, "deletion_event_hash": tagged(
            "MKTD02_EVENT_V2", hx(inputs["pre_state_hash"]), hx(inputs["post_state_hash"]),
            hx(inputs["receipt_id"]), u64(inputs["timestamp"]), hx(inputs["module_hash"]),
            u64(seq)).hex()} for seq in inputs["deletion_seq_cases"]]}
    if ident == "gv5-004":
        canister = hx(inputs["canister_id_hex"])
        return {"cases": [{"record_id_hex": record_hex, "receipt_id": tagged(
            "MKTD02_RECEIPT_V3", u32(len(canister)), canister,
            u32(len(hx(record_hex))), hx(record_hex), u64(inputs["deletion_seq"])).hex()}
            for record_hex in inputs["record_id_cases_hex"]]}
    if ident == "gv5-005":
        return {"cases": [{"canister_id_hex": value,
                            "genesis_certified_data": tagged("MKTD02_GENESIS_V1", hx(value)).hex()}
                           for value in inputs["canister_id_cases_hex"]]}
    if ident == "gv5-006":
        genesis = tagged("MKTD02_GENESIS_V1", hx(inputs["canister_id_hex"]))
        event = tagged("MKTD02_EVENT_V2", hx(inputs["pre_state_hash"]),
                       hx(inputs["post_state_hash"]), hx(inputs["receipt_id"]),
                       u64(inputs["timestamp"]), hx(inputs["module_hash"]),
                       u64(inputs["deletion_seq"]))
        return {"genesis_certified_data": genesis.hex(), "deletion_event_hash": event.hex(),
                "different": genesis != event}
    if ident in ("gv5-007", "gv5-008"):
        return receipt_values(inputs["receipt"])
    if ident == "gv5-009":
        return {"cases": [{"name": case["name"], "state": (
            "Pending" if case["bls_certificate"] is None and case["module_hash_certificate"] is None
            else "FinalizedCandidate" if case["bls_certificate"] is not None and case["module_hash_certificate"] is not None
            else "InvalidIncompleteFinalization")} for case in inputs["certificate_cases"]]}
    if ident == "gv5-010":
        part = hx(inputs["part_hex"])
        return {group: [{"tag_ascii": tag, "digest": tagged(tag, part).hex()} for tag in tags]
                for group, tags in inputs["tag_groups"].items()}
    if ident == "gv5-011":
        salt = tagged("MKTD02_SALT_V1", hx(inputs["canister_id_hex"]))
        return {"mktd_salt": salt.hex(), "state_hash": h(salt, hx(inputs["state_bytes_hex"])).hex()}
    if ident == "gv5-012":
        canonical = inputs["canonical"]
        if principal_text(hx(inputs["canister_id_hex"])) != canonical["canister_id"]:
            raise ValueError("gv5-012 canister_id text does not match canister_id_hex")
        normalized = []
        for case in inputs["tolerated"]:
            value = dict(canonical)
            value.update(case["overrides"])
            for key, item in list(value.items()):
                if key in {"receipt_id", "record_id", "pre_state_hash", "post_state_hash",
                           "tombstone_hash", "deletion_event_hash", "module_hash",
                           "bls_certificate", "module_hash_certificate"} and item is not None:
                    if isinstance(item, list):
                        value[key] = bytes(item).hex()
                    else:
                        value[key] = item.removeprefix("0x").removeprefix("0X").lower()
            normalized.append({"name": case["name"], "equals_canonical": value == canonical})
        return {"cases": normalized}
    if ident.startswith("nv5-"):
        if ident == "nv5-006":
            return {"certified_data": tagged("MKTD02_GENESIS_V1", hx(inputs["canister_id_hex"])).hex(),
                    "error": "no-deletion-certified", "layer": inputs["operation"]}
        if ident == "nv5-009":
            valid = inputs["valid_receipt_id_inputs"]
            canister, record = hx(valid["canister_id_hex"]), hx(valid["record_id_hex"])
            actual = tagged("MKTD02_RECEIPT_V3", u32(len(canister)), canister,
                            u32(len(record)), record, u64(valid["deletion_seq"])).hex()
            return {"recomputed_receipt_id": actual, "presented_receipt_id": inputs["presented_receipt_id"],
                    "matches": actual == inputs["presented_receipt_id"],
                    "error": "v1:receipt-id-mismatch", "layer": "verify"}
        if ident == "nv5-010":
            valid = inputs["valid_event_inputs"]
            actual = tagged("MKTD02_EVENT_V2", hx(valid["pre_state_hash"]), hx(valid["post_state_hash"]),
                            hx(valid["receipt_id"]), u64(valid["timestamp"]), hx(valid["module_hash"]),
                            u64(valid["deletion_seq"])).hex()
            return {"recomputed_deletion_event_hash": actual,
                    "presented_deletion_event_hash": inputs["presented_deletion_event_hash"],
                    "matches": actual == inputs["presented_deletion_event_hash"],
                    "error": "v1:event-hash-mismatch", "layer": "verify"}
        if ident.startswith("nv5-011"):
            return {"result": "accepted", "protocol_version": inputs["protocol_version"],
                    "layer": inputs["operation"]}
        if ident == "nv5-001":
            return {"cases": [{"name": case["name"],
                                "error": "retired-field:certified_commitment"}
                               for case in inputs["cases"]], "layer": inputs["operation"]}
        if ident == "nv5-002":
            return {"error_prefix": "unknown field", "layer": inputs["operation"]}
        if ident == "nv5-003":
            return {"error_prefix": "unknown field", "layer": inputs["operation"]}
        if ident in ("nv5-004", "nv5-005"):
            return {"error": "invalid-event-hash:zero", "layer": inputs["operation"]}
        if ident == "nv5-007":
            return {"cases": [{"label": label, "error": "unrecognised protocol_version"}
                              for label in inputs["labels"]], "layer": inputs["operation"]}
        if ident == "nv5-008":
            errors = {
                "v4_label_to_v5_type": "not a mktd02-v5 receipt",
                "v5_label_to_v4_type": "DeletionReceipt: unrecognised protocol_version",
            }
            return {"cases": [{"name": case["name"], "label": case["label"],
                                "error": errors[case["name"]]}
                               for case in inputs["cases"]], "layer": inputs["operation"]}
    if ident == "v4h-event-v1":
        event = tagged("MKTD02_EVENT_V1", hx(inputs["pre_state_hash"]),
                       hx(inputs["post_state_hash"]), u64(inputs["timestamp"]),
                       hx(inputs["module_hash"]), u64(inputs["deletion_seq"]))
        return {"deletion_event_hash": event.hex()}
    if ident == "v4h-certified-commitment":
        event = tagged("MKTD02_EVENT_V1", hx(inputs["pre_state_hash"]),
                       hx(inputs["post_state_hash"]), u64(inputs["timestamp"]),
                       hx(inputs["module_hash"]), u64(inputs["deletion_seq"]))
        certified = tagged("MKTD02_CERTIFIED_V1", hx(inputs["post_state_hash"]), event)
        return {"deletion_event_hash": event.hex(), "certified_commitment": certified.hex()}
    if ident == "v4h-certified-tag":
        return {"digest": tagged(inputs["tag_ascii"], hx(inputs["part_hex"])).hex()}
    raise ValueError(f"unsupported vector {ident}")


def vector_paths():
    return sorted(V5_ROOT.glob("*.json")) + sorted(HIST_ROOT.glob("*.json"))


def write_vector(path, vector):
    path.write_text(json.dumps(vector, separators=(",", ":")) + "\n", encoding="utf-8")


def check(vectors):
    ok = True
    for path, vector in vectors:
        if vector["id"] == "v4h-v3-wire":
            print("SKIP v4h-v3-wire: frozen implementation regression artefact; not spec-derived")
            continue
        actual = derive(vector)
        if vector.get("expected") == actual:
            print(f"OK {vector['id']}")
        else:
            print(f"FAIL {vector['id']}: expected {vector.get('expected')!r}, derived {actual!r}")
            ok = False
    return ok


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--generate", action="store_true")
    mode.add_argument("--force-regenerate", action="store_true")
    parser.add_argument("--reason")
    parser.add_argument("--update-notes", action="store_true")
    args = parser.parse_args()
    if args.force_regenerate and not args.reason:
        parser.error("--force-regenerate requires --reason <ruling ref>")
    if args.reason and not args.force_regenerate:
        parser.error("--reason is only valid with --force-regenerate")
    if args.update_notes and (args.generate or args.force_regenerate):
        parser.error("--update-notes is allowed only after a clean check run")

    vectors = [(path, json.loads(path.read_text(encoding="utf-8")))
               for path in vector_paths()]
    if args.generate or args.force_regenerate:
        if args.generate:
            nonempty = [v["id"] for _, v in vectors if v.get("expected") is not None]
            if nonempty:
                print("refusing --generate: non-empty expected fields: " + ", ".join(nonempty), file=sys.stderr)
                return 2
        for path, vector in vectors:
            if vector["id"] == "v4h-v3-wire":
                print("SKIPPED v4h-v3-wire: frozen implementation regression artefact")
                continue
            vector["expected"] = derive(vector)
            write_vector(path, vector)
            print(f"GENERATED {vector['id']}")
        return 0

    if not check(vectors):
        return 1
    if args.update_notes:
        for path, vector in vectors:
            if vector.get("provenance"):
                print(f"SKIPPED notes {vector['id']}: frozen/copied provenance")
                continue
            vector["notes"] = PROVENANCE
            if vector["id"].startswith(("gv5-", "nv5-")):
                vector["status"] = "generated_pending_countersignature"
            write_vector(path, vector)
        print(f"UPDATED notes after clean check: {len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
