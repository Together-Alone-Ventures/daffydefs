#!/usr/bin/env python3
"""Independent rederivation of the mktd02-v5.1 vector corpus.

Standard library only. Imports nothing from zombie-core and reads no
production source and no normative v5.1 specification.

Derivation inputs (see DERIVATION.md):

  A. docs/rulings/2026-09-25-mktd02-v5.1-amendment.md
     (SHA-256 7fe9b0fa4cdb4055f0c44cac0fce47475356d4df30371311fb16dbf1096fc12a)
     -- every v5.1-specific rule: protocol string, EVENT_V3 formula, pending
        structural absence, finalisation set and state rule, exact dispatch,
        historical EVENT_V2 freeze.
  B. The Stef/G-ratified mktd02-v5 serialization text frozen at zombie-core
     commit 2237238 (before any v5.1 edit), used ONLY for byte rules the
     amendment carries forward unchanged under its section 3: hash_with_tag
     (1.1), TOMBSTONE_CONSTANT/tombstone_hash (3.1, 3.3), receipt_id (3.5),
     field order/CBOR/JSON (4.1-4.3), principal text form (4.3), named V1
     rejections (7).

Historical mktd02-v5 vector files are read only in check mode, to prove the
historical freeze. No v5 expected value is copied into a v5.1 expected value.

Usage:
  rederive_v5_1_independent.py --write   regenerate the v5.1 vector files
  rederive_v5_1_independent.py --check   regenerate in memory, compare with
                                          the committed files, and run the
                                          historical-freeze checks
"""

import base64
import hashlib
import json
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
V5_DIR = REPO / "docs" / "test-vectors" / "v5"
V5_MANIFEST = REPO / "docs" / "test-vectors" / "manifest.json"
AMENDMENT = REPO / "docs" / "rulings" / "2026-09-25-mktd02-v5.1-amendment.md"
AMENDMENT_SHA256 = "7fe9b0fa4cdb4055f0c44cac0fce47475356d4df30371311fb16dbf1096fc12a"

STATUS = "independently_rederived_pending_countersignature"
NOTES = (
    "Independently rederived by docs/test-vectors/v5.1/rederive_v5_1_independent.py "
    "from the v5.1 amendment (v5.1 rules) and the ratified v5 text at 2237238 "
    "(carried-forward byte rules only). Normative v5.1 spec and production source "
    "not consulted. Pending countersignature."
)

# --- Amendment-defined identifiers (A: sections 2, 3, 4) ---------------------
V5 = "mktd02-v5"
V51 = "mktd02-v5.1"
TAG_EVENT_V2 = b"MKTD02_EVENT_V2"
TAG_EVENT_V3 = b"MKTD02_EVENT_V3"
# Finalisation set (A: sections 6 and 9).
FINALISATION_SET = ["bls_certificate", "module_hash_certificate", "module_hash", "trust_root_key_id"]

# --- Carried-forward byte rules (B) --------------------------------------------
TAG_RECEIPT = b"MKTD02_RECEIPT_V3"          # B 3.5
TAG_TOMBSTONE_HASH = b"MKTD02_TOMBSTONE_HASH_V1"  # B 3.3
TOMBSTONE_SEED = b"MKTD_TOMBSTONE_V1"       # B 3.1
FIELD_ORDER = [                              # B 4.1, applied to fields present (A section 3)
    "protocol_version", "receipt_id", "canister_id", "record_id",
    "pre_state_hash", "post_state_hash", "tombstone_hash", "deletion_event_hash",
    "module_hash", "timestamp", "deletion_seq", "bls_certificate",
    "trust_root_key_id", "module_hash_certificate",
]
BYTE_FIELDS = {
    "receipt_id", "record_id", "pre_state_hash", "post_state_hash", "tombstone_hash",
    "deletion_event_hash", "module_hash", "bls_certificate", "module_hash_certificate",
}
TEXT_FIELDS = {"protocol_version", "trust_root_key_id"}
UINT_FIELDS = {"timestamp", "deletion_seq"}


def h_tag(tag, parts):
    """B 1.1: SHA-256(tag || part_0 || part_1 || ...), no framing."""
    return hashlib.sha256(tag + b"".join(parts)).digest()


def u32_be(n):
    return n.to_bytes(4, "big")


def u64_be(n):
    return n.to_bytes(8, "big")


def receipt_id(canister, record, seq):
    """A section 4 ReceiptId; bytes per B 3.5 (carried forward unchanged)."""
    return h_tag(TAG_RECEIPT, [u32_be(len(canister)), canister, u32_be(len(record)), record, u64_be(seq)])


def event_v3(pre, post, rid, ts, seq):
    """A section 4, written fresh: H_tag("MKTD02_EVENT_V3", pre, post, receipt_id,
    u64_be(timestamp), u64_be(deletion_seq)). module_hash is not an operand."""
    return h_tag(TAG_EVENT_V3, [pre, post, rid, u64_be(ts), u64_be(seq)])


def event_v2(pre, post, rid, ts, mh, seq):
    """A section 2 (frozen historical mktd02-v5 construction)."""
    return h_tag(TAG_EVENT_V2, [pre, post, rid, u64_be(ts), mh, u64_be(seq)])


def tombstone_hash(canister, ts, seq):
    """B 3.1 and 3.3 (diagnostic only)."""
    constant = hashlib.sha256(TOMBSTONE_SEED).digest()
    return h_tag(TAG_TOMBSTONE_HASH, [canister, constant, u64_be(ts), u64_be(seq)])


def principal_text(raw):
    """B 4.3: CRC-32 (big-endian) || raw, RFC 4648 base32, lowercase, unpadded,
    '-' after every five characters."""
    crc = zlib.crc32(raw).to_bytes(4, "big")
    b32 = base64.b32encode(crc + raw).decode("ascii").lower().rstrip("=")
    return "-".join(b32[i:i + 5] for i in range(0, len(b32), 5))


# --- CBOR (B 4.2): definite lengths, shortest-form heads ------------------------
def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * width)):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError("value too large")


def cbor_uint(n):
    return _head(0, n)


def cbor_bytes(b):
    return _head(2, len(b)) + b


def cbor_text(s):
    b = s.encode("utf-8")
    return _head(3, len(b)) + b


def encode_cbor(receipt):
    """B 4.2 applied to the fields present (A section 3). A v5.1 receipt never
    carries null: absent fields are omitted (A section 6)."""
    present = [k for k in FIELD_ORDER if k in receipt]
    out = _head(5, len(present))
    for key in present:
        value = receipt[key]
        out += cbor_text(key)
        if key == "canister_id":
            out += cbor_bytes(value)
        elif key in BYTE_FIELDS:
            out += cbor_bytes(value)
        elif key in TEXT_FIELDS:
            out += cbor_text(value)
        elif key in UINT_FIELDS:
            out += cbor_uint(value)
        else:
            raise KeyError(key)
    return out


def encode_json(receipt):
    """B 4.3 compact form applied to the fields present (A section 3)."""
    items = []
    for key in (k for k in FIELD_ORDER if k in receipt):
        value = receipt[key]
        if key == "canister_id":
            rendered = json.dumps(principal_text(value))
        elif key in BYTE_FIELDS:
            rendered = json.dumps(value.hex())
        elif key in TEXT_FIELDS:
            rendered = json.dumps(value)
        else:
            rendered = str(int(value))
        items.append(json.dumps(key) + ":" + rendered)
    return "{" + ",".join(items) + "}"


def classify(receipt):
    """A section 9: all absent -> Pending; all present -> FinalizedCandidate;
    any partial/mixed set -> InvalidIncompleteFinalization."""
    present = [f in receipt for f in FINALISATION_SET]
    if not any(present):
        return "Pending"
    if all(present):
        return "FinalizedCandidate"
    return "InvalidIncompleteFinalization"


def v1(receipt, line):
    """V1 per A sections 2/4 (formula by exact line) and B 7 (names, order)."""
    rid = receipt_id(receipt["canister_id"], receipt["record_id"], receipt["deletion_seq"])
    if rid != receipt["receipt_id"]:
        return "v1:receipt-id-mismatch"
    if line == V51:
        ev = event_v3(receipt["pre_state_hash"], receipt["post_state_hash"], receipt["receipt_id"],
                      receipt["timestamp"], receipt["deletion_seq"])
    elif line == V5:
        ev = event_v2(receipt["pre_state_hash"], receipt["post_state_hash"], receipt["receipt_id"],
                      receipt["timestamp"], receipt["module_hash"], receipt["deletion_seq"])
    else:
        raise ValueError(line)
    return "pass" if ev == receipt["deletion_event_hash"] else "v1:event-hash-mismatch"


def label(s):
    """Deterministic opaque 32-byte test value; carries no real-world identity."""
    return hashlib.sha256(b"mktd02-v5.1 independent vector: " + s.encode("ascii")).digest()


# --- Fixture inputs -------------------------------------------------------------
CANISTER = bytes.fromhex("00000000000000010101")   # 10-byte canister-style principal
RECORD = label("record_id")                          # opaque, non-identifying
PRE = label("pre_state_hash")
POST = label("post_state_hash")
MODULE_A = label("module_hash A")
MODULE_B = label("module_hash B")
TS = 1790000000000000000
SEQ = 300                                            # exercises 2-byte CBOR uint
BLS = bytes.fromhex("d9d9f7a1") + label("opaque bls_certificate bytes")
MHC = bytes.fromhex("d9d9f7a2") + label("opaque module_hash_certificate bytes")
TRUST_ROOT = "mainnet"


def base_receipt(line=V51, module=MODULE_A):
    rid = receipt_id(CANISTER, RECORD, SEQ)
    ev = event_v3(PRE, POST, rid, TS, SEQ) if line == V51 else event_v2(PRE, POST, rid, TS, module, SEQ)
    return {
        "protocol_version": line,
        "receipt_id": rid,
        "canister_id": CANISTER,
        "record_id": RECORD,
        "pre_state_hash": PRE,
        "post_state_hash": POST,
        "tombstone_hash": tombstone_hash(CANISTER, TS, SEQ),
        "deletion_event_hash": ev,
    }


def finalized(module=MODULE_A):
    r = base_receipt()
    r.update({
        "module_hash": module,
        "timestamp": TS,
        "deletion_seq": SEQ,
        "bls_certificate": BLS,
        "trust_root_key_id": TRUST_ROOT,
        "module_hash_certificate": MHC,
    })
    return r


def pending():
    r = base_receipt()
    r.update({"timestamp": TS, "deletion_seq": SEQ})
    return r


def display(receipt):
    """Input form for a vector file: hex for bytes, principal text alongside hex."""
    out = {}
    for key in (k for k in FIELD_ORDER if k in receipt):
        v = receipt[key]
        if key == "canister_id":
            out["canister_id_hex"] = v.hex()
            out["canister_id_text"] = principal_text(v)
        elif isinstance(v, bytes):
            out[key] = v.hex()
        else:
            out[key] = v
    return out


def wire(receipt):
    return {"cbor_hex": encode_cbor(receipt).hex(), "json_text": encode_json(receipt)}


def vec(ident, sections, inputs, expected):
    return {"id": ident, "governing": sections, "status": STATUS, "notes": NOTES,
            "inputs": inputs, "expected": expected}


# --- Corpus ---------------------------------------------------------------------
def build():
    V = {}
    one, two = bytes([0x11]) * 32, bytes([0x22]) * 32
    three, four = bytes([0x33]) * 32, bytes([0x44]) * 32
    t0 = 1700000000000000000

    # gv51-001: EVENT_V3 golden over fixed operands (inputs chosen to match the
    # historical gv5-003 operand values; expected values computed here, fresh).
    V["gv51-001"] = vec("gv51-001", ["A §4"], {
        "tag_ascii": TAG_EVENT_V3.decode(), "pre_state_hash": one.hex(), "post_state_hash": two.hex(),
        "receipt_id": three.hex(), "timestamp": t0, "deletion_seq_cases": [7, 8],
    }, {"cases": [{"deletion_seq": s, "deletion_event_hash": event_v3(one, two, three, t0, s).hex(),
                   "preimage_hex": (TAG_EVENT_V3 + one + two + three + u64_be(t0) + u64_be(s)).hex()}
                  for s in (7, 8)],
        "preimage_length": len(TAG_EVENT_V3) + 32 * 3 + 16})

    # gv51-002: receipt_id then EVENT_V3 over the derived identity (A §4 ordering).
    rid = receipt_id(CANISTER, RECORD, SEQ)
    V["gv51-002"] = vec("gv51-002", ["A §4", "B 3.5 (carried forward)"], {
        "canister_id_hex": CANISTER.hex(), "record_id": RECORD.hex(), "deletion_seq": SEQ,
        "pre_state_hash": PRE.hex(), "post_state_hash": POST.hex(), "timestamp": TS,
    }, {"receipt_id": rid.hex(), "deletion_event_hash": event_v3(PRE, POST, rid, TS, SEQ).hex()})

    # gv51-003: module_hash is not an operand of EVENT_V3 (A §4, §5).
    V["gv51-003"] = vec("gv51-003", ["A §4", "A §5", "A §2 (contrast)"], {
        "pre_state_hash": one.hex(), "post_state_hash": two.hex(), "receipt_id": three.hex(),
        "timestamp": t0, "deletion_seq": 7, "module_hash_a": four.hex(), "module_hash_b": MODULE_B.hex(),
    }, {
        "event_v3_with_module_hash_a": event_v3(one, two, three, t0, 7).hex(),
        "event_v3_with_module_hash_b": event_v3(one, two, three, t0, 7).hex(),
        "event_v3_equal": True,
        "historical_event_v2_with_module_hash_a": event_v2(one, two, three, t0, four, 7).hex(),
        "historical_event_v2_with_module_hash_b": event_v2(one, two, three, t0, MODULE_B, 7).hex(),
        "historical_event_v2_equal": False,
        "finalized_receipts_differing_only_in_module_hash": {
            "deletion_event_hash_a": finalized(MODULE_A)["deletion_event_hash"].hex(),
            "deletion_event_hash_b": finalized(MODULE_B)["deletion_event_hash"].hex(),
            "v1_a": v1(finalized(MODULE_A), V51), "v1_b": v1(finalized(MODULE_B), V51),
        },
    })

    # gv51-004: receipt_id is load-bearing in EVENT_V3 (A §4).
    base_ev = event_v3(one, two, three, t0, 7)
    alt_record = label("record_id alternative")
    rid_alt = receipt_id(CANISTER, alt_record, SEQ)
    V["gv51-004"] = vec("gv51-004", ["A §4", "B 3.5 (carried forward)"], {
        "pre_state_hash": one.hex(), "post_state_hash": two.hex(), "timestamp": t0, "deletion_seq": 7,
        "receipt_id": three.hex(), "receipt_id_changed": ("33" * 31 + "34"),
        "canister_id_hex": CANISTER.hex(), "record_id": RECORD.hex(), "record_id_changed": alt_record.hex(),
        "identity_deletion_seq": SEQ,
    }, {
        "direct": {"event_v3": base_ev.hex(),
                   "event_v3_receipt_id_changed": event_v3(one, two, bytes.fromhex("33" * 31 + "34"), t0, 7).hex(),
                   "changed": True},
        "via_record_id": {"receipt_id": rid.hex(), "receipt_id_changed": rid_alt.hex(),
                          "event_v3": event_v3(PRE, POST, rid, TS, SEQ).hex(),
                          "event_v3_changed": event_v3(PRE, POST, rid_alt, TS, SEQ).hex(),
                          "changed": True},
    })

    # gv51-005: positive finalized v5.1 receipt (A §3, §6, §9; B 4.1-4.3 carried forward).
    f = finalized()
    V["gv51-005"] = vec("gv51-005", ["A §3", "A §4", "A §9", "B 4.1-4.3 (carried forward)"],
                        {"receipt": display(f)},
                        {"receipt_id": f["receipt_id"].hex(), "deletion_event_hash": f["deletion_event_hash"].hex(),
                         "tombstone_hash": f["tombstone_hash"].hex(), "key_count": len(f),
                         **wire(f), "state": classify(f), "v1": v1(f, V51)})

    # gv51-006: positive pending v5.1 receipt — finalisation set structurally absent (A §6).
    p = pending()
    V["gv51-006"] = vec("gv51-006", ["A §3", "A §4", "A §6", "A §9", "B 4.1-4.3 (carried forward)"],
                        {"receipt": display(p), "absent_keys": FINALISATION_SET},
                        {"receipt_id": p["receipt_id"].hex(), "deletion_event_hash": p["deletion_event_hash"].hex(),
                         "key_count": len(p), **wire(p), "state": classify(p), "v1": v1(p, V51),
                         "deletion_event_hash_equals_gv51_005": p["deletion_event_hash"] == f["deletion_event_hash"]})

    # gv51-007: version/tag registry and exact dispatch (A §2, §3).
    V["gv51-007"] = vec("gv51-007", ["A §2", "A §3", "A §19"], {}, {
        "lines": [
            {"protocol_version": V5, "protocol_version_hex": V5.encode().hex(), "event_tag_ascii": TAG_EVENT_V2.decode(),
             "event_tag_hex": TAG_EVENT_V2.hex(), "event_tag_length": len(TAG_EVENT_V2), "event_operands": 6,
             "status": "frozen historical"},
            {"protocol_version": V51, "protocol_version_hex": V51.encode().hex(), "event_tag_ascii": TAG_EVENT_V3.decode(),
             "event_tag_hex": TAG_EVENT_V3.hex(), "event_tag_length": len(TAG_EVENT_V3), "event_operands": 5,
             "status": "active corrected"},
        ],
        "matching": "exact byte equality; no prefix, case, whitespace or numeric normalisation",
    })

    # nv51-001: near-match protocol versions are not mktd02-v5.1 (A §3 exact matching).
    near = ["mktd02-v5.1 ", " mktd02-v5.1", "mktd02-v5.10", "mktd02-v5.1.0", "mktd02-v5.1-x", "MKTD02-V5.1",
            "mktd02-V5.1", "mktd02-v51", "mktd02-v5.", "mktd02-v5,1", "mktd02-v5.2", "mktd02-v5.1\n", "mktd02-v5.1\u0000"]
    V["nv51-001"] = vec("nv51-001", ["A §3"], {
        "operation": "decode_and_serialise", "template": "gv51-005 with protocol_version replaced",
        "cases": [{"protocol_version": s, "protocol_version_hex": s.encode().hex()} for s in near],
    }, {"cases": [{"protocol_version_hex": s.encode().hex(), "outcome": "refused"} for s in near],
        "layer": "decode_and_serialise",
        "message": "not asserted: the governing inputs fix the rejection, not a v5.1 message fragment"})

    # nv51-002: cross-line dispatch — each label selects only its own frozen construction.
    v51_with_v2 = finalized()
    v51_with_v2["deletion_event_hash"] = event_v2(PRE, POST, v51_with_v2["receipt_id"], TS, MODULE_A, SEQ)
    v5_with_v3 = finalized()
    v5_with_v3["protocol_version"] = V5
    V["nv51-002"] = vec("nv51-002", ["A §2", "A §3", "A §4", "B 7 (carried forward)"], {
        "cases": [
            {"name": "v5.1_label_with_event_v2_value", "receipt": display(v51_with_v2)},
            {"name": "v5_label_with_event_v3_value", "receipt": display(v5_with_v3)},
        ]}, {"cases": [
            {"name": "v5.1_label_with_event_v2_value", "v1": v1(v51_with_v2, V51)},
            {"name": "v5_label_with_event_v3_value", "v1": v1(v5_with_v3, V5)},
        ], "layer": "verify"})

    # nv51-003: partial/mixed finalisation sets (A §9).
    cases = []
    for missing in FINALISATION_SET:
        r = finalized()
        del r[missing]
        cases.append(("missing_" + missing, r))
    for only in FINALISATION_SET:
        r = pending()
        r[only] = finalized()[only]
        cases.append(("only_" + only, r))
    V["nv51-003"] = vec("nv51-003", ["A §6", "A §9"], {
        "cases": [{"name": n, "receipt": display(r)} for n, r in cases]},
        {"cases": [{"name": n, "state": classify(r), "key_count": len(r), **wire(r)} for n, r in cases],
         "rule": "mixed finalisation fails closed"})

    # nv51-004: placeholders are not structural absence (A §6).
    zero = "00" * 32
    placeholders = [
        ("module_hash_null", "module_hash", None), ("module_hash_zero", "module_hash", zero),
        ("trust_root_key_id_empty", "trust_root_key_id", ""), ("trust_root_key_id_null", "trust_root_key_id", None),
        ("bls_certificate_null", "bls_certificate", None), ("module_hash_certificate_null", "module_hash_certificate", None),
    ]
    V["nv51-004"] = vec("nv51-004", ["A §6"], {
        "template": "gv51-006 (pending) with one key added carrying the placeholder",
        "cases": [{"name": n, "key": k, "value": v} for n, k, v in placeholders]},
        {"cases": [{"name": n, "conforming_pending": False, "outcome": "refused"} for n, _, _ in placeholders],
         "message": "not asserted: the amendment forbids the representation; layer and message are not fixed by the governing inputs"})

    # nv51-005: V1 mutations on the canonical finalized v5.1 receipt.
    m1 = finalized(); m1["record_id"] = label("record_id alternative")
    m2 = finalized(); m2["record_id"] = label("record_id alternative")
    m2["receipt_id"] = receipt_id(CANISTER, m2["record_id"], SEQ)
    m3 = finalized(); m3["timestamp"] = TS + 1
    m4 = finalized(); m4["deletion_seq"] = SEQ + 1
    m5 = finalized(); m5["module_hash"] = MODULE_B
    muts = [("record_id_only", m1), ("record_id_and_receipt_id", m2), ("timestamp", m3),
            ("deletion_seq", m4), ("module_hash_only", m5)]
    V["nv51-005"] = vec("nv51-005", ["A §4", "A §5", "B 7 (carried forward)"], {
        "template": "gv51-005", "cases": [{"name": n, "receipt": display(r)} for n, r in muts]},
        {"cases": [{"name": n, "v1": v1(r, V51)} for n, r in muts],
         "note": "module_hash_only passes V1 by design (A §5); code identity is V3A, outside this corpus"})

    # nv51-006: retired certified_commitment on a v5.1 receipt (A §3 carries B 4.4/4.6/7
    # unchanged: presence is refused whatever its value, including null). Outcome only;
    # no v5.1 message is governed, so none is asserted.
    rc_cases = []
    for tname, template in (("finalized", finalized()), ("pending", pending())):
        for vname, value in (("hex32", label("retired certified_commitment")), ("null", None)):
            rc_cases.append((f"{tname}_{vname}", tname, template, value))
    V["nv51-006"] = vec("nv51-006", ["A §3", "B 4.4, 4.6, 7 (carried forward)"], {
        "operation": "decode", "field": "certified_commitment",
        "templates": {"finalized": "gv51-005", "pending": "gv51-006"},
        "key_placement": "appended after the template's last key",
        "cases": [{"name": n, "template": t, "value": (v.hex() if v is not None else None)}
                  for n, t, _, v in rc_cases]},
        {"cases": [{"name": n, "outcome": "refused", **with_extra_key(r, "certified_commitment", v)}
                   for n, _, r, v in rc_cases],
         "layer": "decode",
         "message": "not asserted: the governing inputs fix the refusal, not a v5.1 message"})
    return V


def with_extra_key(receipt, key, value):
    """Candidate wire forms: the template receipt plus one appended key whose value
    is a byte string / hex, or CBOR null / JSON null."""
    cbor = encode_cbor(receipt)
    count = len([k for k in FIELD_ORDER if k in receipt])
    body = cbor[len(_head(5, count)):]
    cbor = _head(5, count + 1) + body + cbor_text(key) + (cbor_bytes(value) if value is not None else b"\xf6")
    js = encode_json(receipt)[:-1] + "," + json.dumps(key) + ":" + (json.dumps(value.hex()) if value is not None else "null") + "}"
    return {"cbor_hex": cbor.hex(), "json_text": js}


# --- Historical-freeze checks (read-only) ---------------------------------------
def historical_checks():
    results = []
    manifest = json.loads(V5_MANIFEST.read_text())
    pins = manifest["countersignature"]["vector_file_sha256"]
    for rel, pinned in sorted(pins.items()):
        actual = hashlib.sha256((REPO / rel).read_bytes()).hexdigest()
        results.append((f"pin {rel}", actual == pinned))
    # A §2: recompute historical EVENT_V2 from gv5-003 inputs with this harness.
    g3 = json.loads((V5_DIR / "gv5-003.json").read_text())
    i = g3["inputs"]
    for case in g3["expected"]["cases"]:
        ours = event_v2(bytes.fromhex(i["pre_state_hash"]), bytes.fromhex(i["post_state_hash"]),
                        bytes.fromhex(i["receipt_id"]), i["timestamp"], bytes.fromhex(i["module_hash"]),
                        case["deletion_seq"]).hex()
        results.append((f"gv5-003 seq {case['deletion_seq']} EVENT_V2 reproduced", ours == case["deletion_event_hash"]))
    # Carried-forward encoders reproduce the frozen v5 wire (gv5-007).
    g7 = json.loads((V5_DIR / "gv5-007.json").read_text())
    r = g7["inputs"]["receipt"]
    rec = {k: (bytes.fromhex(r[k]) if k in BYTE_FIELDS and r[k] is not None else r[k])
           for k in FIELD_ORDER if k in r}
    rec["canister_id"] = bytes.fromhex(r["canister_id_hex"])
    rec["receipt_id"] = receipt_id(rec["canister_id"], rec["record_id"], rec["deletion_seq"])
    rec["deletion_event_hash"] = event_v2(rec["pre_state_hash"], rec["post_state_hash"], rec["receipt_id"],
                                          rec["timestamp"], rec["module_hash"], rec["deletion_seq"])
    results.append(("gv5-007 receipt_id reproduced", rec["receipt_id"].hex() == g7["expected"]["receipt_id"]))
    results.append(("gv5-007 EVENT_V2 reproduced", rec["deletion_event_hash"].hex() == g7["expected"]["deletion_event_hash"]))
    results.append(("gv5-007 CBOR reproduced", encode_cbor(rec).hex() == g7["expected"]["cbor_hex"]))
    results.append(("gv5-007 JSON reproduced", encode_json(rec) == g7["expected"]["json_text"]))
    results.append(("B 4.3 principal example 01020304", principal_text(bytes.fromhex("01020304")) == "wy6px-tibai-bqi"))
    return results


def render(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":")) + "\n"


def main(argv):
    mode = argv[1] if len(argv) > 1 else "--check"
    amend = hashlib.sha256(AMENDMENT.read_bytes()).hexdigest()
    if amend != AMENDMENT_SHA256:
        print(f"FAIL amendment sha256 {amend} != {AMENDMENT_SHA256}")
        return 1
    corpus = build()
    manifest = {
        "corpus": "mktd02-v5.1 independent vectors",
        "protocol_version": V51,
        "status": STATUS,
        "amendment": {"path": "docs/rulings/2026-09-25-mktd02-v5.1-amendment.md", "sha256": AMENDMENT_SHA256},
        "carried_forward_source": {"text": "ratified mktd02-v5 serialization text", "commit": "2237238",
                                   "used_for": "hash_with_tag, receipt_id, tombstone_hash, field order, CBOR, JSON, principal text, V1 names"},
        "harness": "docs/test-vectors/v5.1/rederive_v5_1_independent.py",
        "vectors": sorted(corpus),
        "vector_file_sha256": {f"docs/test-vectors/v5.1/{k}.json": hashlib.sha256(render(v).encode()).hexdigest()
                               for k, v in sorted(corpus.items())},
        "countersignature": None,
    }
    files = {f"{k}.json": render(v) for k, v in corpus.items()}
    files["manifest.json"] = render(manifest)
    if mode == "--write":
        for name, text in files.items():
            (HERE / name).write_text(text)
        print(f"wrote {len(files)} files")
    ok = True
    for name, text in sorted(files.items()):
        path = HERE / name
        same = path.exists() and path.read_text() == text
        ok &= same
        print(("OK  " if same else "FAIL") + f" {name}")
    for label_, passed in historical_checks():
        ok &= passed
        print(("OK  " if passed else "FAIL") + f" historical: {label_}")
    print("ALL OK" if ok else "CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
