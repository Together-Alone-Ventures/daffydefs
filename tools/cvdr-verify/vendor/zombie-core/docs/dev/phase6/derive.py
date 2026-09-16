import json, struct, hashlib, glob, os

# ---------- own SHA-256 (FIPS 180-4) ----------
K = [int(abs(__import__('math').sin(0))) ]  # placeholder overwritten below
def _gen_consts():
    def is_prime(n):
        return n > 1 and all(n % p for p in range(2, int(n**0.5) + 1))
    primes = [p for p in range(2, 400) if is_prime(p)][:64]
    def frac(x, bits=32):
        return int((x - int(x)) * (1 << bits)) & 0xffffffff
    k = [frac(p ** (1/3)) for p in primes]
    h = [frac(p ** 0.5) for p in primes[:8]]
    return k, h
K, H0 = _gen_consts()
def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff
def sha256(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg += b'\x80'
    msg += b'\x00' * ((56 - len(msg) % 64) % 64)
    msg += struct.pack('>Q', ml)
    h = list(H0)
    for off in range(0, len(msg), 64):
        w = list(struct.unpack('>16L', msg[off:off+64])) + [0]*48
        for i in range(16, 64):
            s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        a,b,c,d,e,f,g,hh = h
        for i in range(64):
            S1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
            ch = (e & f) ^ (~e & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff
            S0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xffffffff
            hh,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
        h = [(x+y)&0xffffffff for x,y in zip(h,[a,b,c,d,e,f,g,hh])]
    return b''.join(struct.pack('>L', x) for x in h)
# self-test against reference implementation
for t in [b'', b'abc', b'x'*200]:
    assert sha256(t) == hashlib.sha256(t).digest()

# ---------- §0 conventions, §1 primitives ----------
def u32_be(n): return struct.pack('>I', n)
def u64_be(n): return struct.pack('>Q', n)
def hash_with_tag(tag: str, parts): return sha256(tag.encode('ascii') + b''.join(parts))
def sha256_concat(parts): return sha256(b''.join(parts))
hash_historical = hash_with_tag  # §1.3, same discipline
H = lambda b: b.hex()
X = bytes.fromhex

# ---------- §3 values ----------
TOMBSTONE_CONSTANT = sha256(b"MKTD_TOMBSTONE_V1")                       # §3.1
def mktd_salt(cid): return hash_with_tag("MKTD02_SALT_V1", [cid])        # §3.2
def state_hash(cid, state_bytes): return sha256_concat([mktd_salt(cid), state_bytes])
def tombstone_hash(cid, ts, seq):                                        # §3.3
    return hash_with_tag("MKTD02_TOMBSTONE_HASH_V1", [cid, TOMBSTONE_CONSTANT, u64_be(ts), u64_be(seq)])
def deletion_event_hash(pre, post, rid, ts, mh, seq):                    # §3.4
    return hash_with_tag("MKTD02_EVENT_V2", [pre, post, rid, u64_be(ts), mh, u64_be(seq)])
def receipt_id(cid, rec, seq):                                           # §3.5
    return hash_with_tag("MKTD02_RECEIPT_V3", [u32_be(len(cid)), cid, u32_be(len(rec)), rec, u64_be(seq)])
def genesis(cid): return hash_with_tag("MKTD02_GENESIS_V1", [cid])       # §3.6
def event_hash_v1(pre, post, ts, mh, seq):                               # §8.2
    return hash_historical("MKTD02_EVENT_V1", [pre, post, u64_be(ts), mh, u64_be(seq)])
def certified_commitment(post, ev):                                      # §8.1 via §1.3
    return hash_historical("MKTD02_CERTIFIED_V1", [post, ev])

# ---------- §4.2 own CBOR encoder ----------
def _head(major, n):
    if n < 24: return bytes([(major << 5) | n])
    if n < 0x100: return bytes([(major << 5) | 24, n])
    if n < 0x10000: return bytes([(major << 5) | 25]) + struct.pack('>H', n)
    if n < 0x100000000: return bytes([(major << 5) | 26]) + struct.pack('>I', n)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', n)
def c_uint(n): return _head(0, n)
def c_bytes(b): return _head(2, len(b)) + b
def c_text(s):
    e = s.encode('utf-8'); return _head(3, len(e)) + e
C_NULL = b'\xf6'
FIELDS = ["protocol_version","receipt_id","canister_id","record_id","pre_state_hash","post_state_hash",
          "tombstone_hash","deletion_event_hash","module_hash","timestamp","deletion_seq",
          "bls_certificate","trust_root_key_id","module_hash_certificate"]
BYTE_FIELDS = {"receipt_id","canister_id","record_id","pre_state_hash","post_state_hash","tombstone_hash",
               "deletion_event_hash","module_hash","bls_certificate","module_hash_certificate"}
def receipt_cbor(r):   # r: dict of python values; byte fields are bytes or None
    out = _head(5, 14)
    assert out == b'\xae'
    for k in FIELDS:
        out += c_text(k)
        v = r[k]
        if k in BYTE_FIELDS: out += C_NULL if v is None else c_bytes(v)
        elif k in ("timestamp","deletion_seq"): out += c_uint(v)
        else: out += c_text(v)
    return out

# ---------- §4.3 JSON (compact, ordered, no trailing newline) ----------
def jstr(s):
    o = '"'
    for ch in s:
        if ch == '"': o += '\\"'
        elif ch == '\\': o += '\\\\'
        elif ord(ch) < 0x20: o += {'\n':'\\n','\r':'\\r','\t':'\\t','\b':'\\b','\f':'\\f'}.get(ch, '\\u%04x' % ord(ch))
        else: o += ch
    return o + '"'
def receipt_json(r, cid_text):
    parts = []
    for k in FIELDS:
        v = r[k]
        if k == "canister_id": s = jstr(cid_text)
        elif k in BYTE_FIELDS: s = "null" if v is None else jstr(v.hex())
        elif k in ("timestamp","deletion_seq"): s = str(v)
        else: s = jstr(v)
        parts.append(jstr(k) + ":" + s)
    return ("{" + ",".join(parts) + "}").encode('utf-8')

def build_receipt(inp):
    cid = X(inp["canister_id_hex"]); rec = X(inp["record_id"])
    rid = receipt_id(cid, rec, inp["deletion_seq"])
    pre, post, mh = X(inp["pre_state_hash"]), X(inp["post_state_hash"]), X(inp["module_hash"])
    ev = deletion_event_hash(pre, post, rid, inp["timestamp"], mh, inp["deletion_seq"])
    r = dict(protocol_version=inp["protocol_version"], receipt_id=rid, canister_id=cid, record_id=rec,
             pre_state_hash=pre, post_state_hash=post, tombstone_hash=X(inp["tombstone_hash"]),
             deletion_event_hash=ev, module_hash=mh, timestamp=inp["timestamp"], deletion_seq=inp["deletion_seq"],
             bls_certificate=None if inp["bls_certificate"] is None else X(inp["bls_certificate"]),
             trust_root_key_id=inp["trust_root_key_id"],
             module_hash_certificate=None if inp["module_hash_certificate"] is None else X(inp["module_hash_certificate"]))
    return r

def state(bls, mhc):  # §5
    if bls is None and mhc is None: return "Pending"
    if bls is not None and mhc is not None: return "FinalizedCandidate"
    return "InvalidIncompleteFinalization"

V = {}
for p in sorted(glob.glob('/home/claude/bundle/bundle/vectors/*.json')):
    V[os.path.basename(p)[:-5]] = json.load(open(p))['inputs']

out = {}
# gv5-001
i = V['gv5-001']
out['gv5-001'] = dict(ordered=H(hash_with_tag(i['tag_ascii'], [X(x) for x in i['parts_hex']])),
                      swapped=H(hash_with_tag(i['tag_ascii'], [X(x) for x in i['swapped_parts_hex']])),
                      preimage_ordered=(i['tag_ascii'].encode()+b''.join(X(x) for x in i['parts_hex'])).hex())
# gv5-002
i = V['gv5-002']
out['gv5-002'] = dict(TOMBSTONE_CONSTANT=H(TOMBSTONE_CONSTANT),
                      tombstone_hash=H(tombstone_hash(X(i['canister_id_hex']), i['timestamp'], i['deletion_seq'])))
# gv5-003
i = V['gv5-003']
out['gv5-003'] = {f"seq_{s}": H(deletion_event_hash(X(i['pre_state_hash']),X(i['post_state_hash']),X(i['receipt_id']),i['timestamp'],X(i['module_hash']),s)) for s in i['deletion_seq_cases']}
# gv5-004
i = V['gv5-004']
out['gv5-004'] = {f"record_{r}": H(receipt_id(X(i['canister_id_hex']), X(r), i['deletion_seq'])) for r in i['record_id_cases_hex']}
# gv5-005
i = V['gv5-005']
out['gv5-005'] = {f"canister_{c}": H(genesis(X(c))) for c in i['canister_id_cases_hex']}
# gv5-006
i = V['gv5-006']
ev = deletion_event_hash(X(i['pre_state_hash']),X(i['post_state_hash']),X(i['receipt_id']),i['timestamp'],X(i['module_hash']),i['deletion_seq'])
g = genesis(X(i['canister_id_hex']))
out['gv5-006'] = dict(deletion_event_hash=H(ev), certified_data_after_deletion=H(ev), genesis_certified_data=H(g), distinct=(ev!=g))
# gv5-007 / gv5-008
for vid in ('gv5-007','gv5-008'):
    i = V[vid]['receipt']; r = build_receipt(i)
    cb = receipt_cbor(r); js = receipt_json(r, i['canister_id_text'])
    out[vid] = dict(receipt_id=H(r['receipt_id']), deletion_event_hash=H(r['deletion_event_hash']),
                    cbor_hex=cb.hex(), cbor_len=len(cb), cbor_sha256=H(sha256(cb)),
                    json=js.decode(), json_len=len(js), json_sha256=H(sha256(js)),
                    state=state(r['bls_certificate'], r['module_hash_certificate']))
# gv5-009
out['gv5-009'] = {c['name']: state(c['bls_certificate'], c['module_hash_certificate']) for c in V['gv5-009']['certificate_cases']}
# gv5-010
i = V['gv5-010']
out['gv5-010'] = {grp: {t: dict(len=len(t), digest=H(hash_with_tag(t,[X(i['part_hex'])]))) for t in tags} for grp,tags in i['tag_groups'].items()}
# gv5-011
i = V['gv5-011']
sb = X(i['state_bytes_hex']); cid = X(i['canister_id_hex'])
# independently rebuild the fixture from its schema description with own CBOR
rebuilt = _head(5,2) + c_text("name") + c_bytes(TOMBSTONE_CONSTANT) + c_text("email") + c_bytes(TOMBSTONE_CONSTANT)
out['gv5-011'] = dict(mktd_salt=H(mktd_salt(cid)), state_hash=H(state_hash(cid, sb)),
                      state_bytes_match_rebuilt_fixture=(rebuilt==sb), state_bytes_len=len(sb))
# gv5-012
i = V['gv5-012']; c = i['canonical']
r = dict(c); 
for k in BYTE_FIELDS - {"canister_id"}: r[k] = X(c[k]) if c[k] is not None else None
r['canister_id'] = X("01020304")  # bytes of wy6px-tibai-bqi per gv5-007/008 input pairing
cb = receipt_cbor(r); js = receipt_json(r, c['canister_id'])
def normalise_hex(v):
    if isinstance(v, list): return bytes(v).hex()
    v = v[2:] if v[:2] in ('0x','0X') else v
    return v.lower()
variants = {}
for var in i['variants']:
    merged = dict(c); merged.update(var['overrides'])
    norm = {k: (normalise_hex(v) if k in BYTE_FIELDS-{"canister_id"} and v is not None else v) for k,v in merged.items()}
    variants[var['name']] = dict(decodes_to_canonical=(norm==c), normalised_overrides={k: normalise_hex(v) for k,v in var['overrides'].items()})
out['gv5-012'] = dict(canonical_json=js.decode(), json_len=len(js), json_sha256=H(sha256(js)),
                      cbor_hex=cb.hex(), cbor_len=len(cb), cbor_sha256=H(sha256(cb)), variants=variants,
                      state=state(r['bls_certificate'], r['module_hash_certificate']))
# nv5-006 / nv5-009 / nv5-010 computed values
out['nv5-006'] = dict(genesis_certified_data=H(genesis(X(V['nv5-006']['canister_id_hex']))), error="no-deletion-certified", layer="verifier")
i = V['nv5-009']['receipt_id_inputs']
rid = receipt_id(X(i['canister_id_hex']), X(i['record_id_hex']), i['deletion_seq'])
out['nv5-009'] = dict(recomputed_receipt_id=H(rid), presented=V['nv5-009']['presented_receipt_id'], equal=(H(rid)==V['nv5-009']['presented_receipt_id']))
i = V['nv5-010']['event_inputs']
ev = deletion_event_hash(X(i['pre_state_hash']),X(i['post_state_hash']),X(i['receipt_id']),i['timestamp'],X(i['module_hash']),i['deletion_seq'])
out['nv5-010'] = dict(recomputed_deletion_event_hash=H(ev), presented=V['nv5-010']['presented_deletion_event_hash'], equal=(H(ev)==V['nv5-010']['presented_deletion_event_hash']))
# historical
i = V['event-v1']
ev1 = event_hash_v1(X(i['pre_state_hash']),X(i['post_state_hash']),i['timestamp'],X(i['module_hash']),i['deletion_seq'])
out['event-v1'] = dict(deletion_event_hash_v1=H(ev1))
i = V['certified-commitment']
ev1c = event_hash_v1(X(i['pre_state_hash']),X(i['post_state_hash']),i['timestamp'],X(i['module_hash']),i['deletion_seq'])
out['certified-commitment'] = dict(deletion_event_hash_v1=H(ev1c), certified_commitment=H(certified_commitment(X(i['post_state_hash']), ev1c)))
i = V['certified-tag']
out['certified-tag'] = dict(digest=H(hash_historical(i['tag_ascii'], [X(i['part_hex'])])))

print(json.dumps(out, indent=1))
