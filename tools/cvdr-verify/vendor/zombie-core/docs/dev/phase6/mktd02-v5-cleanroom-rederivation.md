# MKTd02-v5 clean-room rederivation report

Date: 2026-09-13. Sole input: `mktd02-v5-cleanroom-bundle.tgz`. SHA-256 of the tarball as received:
`5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`

## 1. Isolation evidence

Files received: 30 (spec.md, MANIFEST.txt, 28 vectors). Every entry in MANIFEST.txt was recomputed with `sha256sum`; all 29 listed hashes and all 29 listed sizes match exactly. MANIFEST.txt itself is not self-listed.

| File | Bytes | SHA-256 (manifest = computed) |
|---|---|---|
| spec.md | 22774 | 8aa795bd1aa7295147975b43bce2478765e2f9f4775a99fad0700274560a4fac |
| vectors/certified-commitment.json | 383 | 53253c476f2ca50d7dbf796ec05589f3e2e52d09e46f1adac952ad8c7c1f1101 |
| vectors/certified-tag.json | 145 | ef0749c05e75368c9ff7d6440b77cad8b1cf125ee22873710095442110e14e90 |
| vectors/event-v1.json | 364 | 5fd19a93a08ef8888423c1ed8d7283d4185984e27f736c0448ac4d46186409d8 |
| vectors/gv5-001.json | 171 | 5570e00d3e39265735ff06069fb23e12fe6b97f75298b37a82887abd6b3bd130 |
| vectors/gv5-002.json | 155 | f9e27fe3e2263ad5c4c4805ccaffffc6112a1503ddb8375369641e35eaf928e0 |
| vectors/gv5-003.json | 459 | 111310b2656d443b40be000bea89748489b4d822d3de20b89df11c7fc3c523e9 |
| vectors/gv5-004.json | 160 | c6edbf08c6eeaab39f6211bc3c7014531ae61316ec4275abde8f52e88fe77151 |
| vectors/gv5-005.json | 130 | 2630f1b7f7afe18f0a7907ca62c2d79711ad52f94ecee61039414bcd20bf8672 |
| vectors/gv5-006.json | 485 | dcbc4998e1ba8985b41bf2cb72283a56494d9ea5717ece8d429a293effc07572 |
| vectors/gv5-007.json | 686 | 5f59517a04f5428f161aaa9b24da818c403e23c398e24afe35cff6f8f0a42834 |
| vectors/gv5-008.json | 677 | 21fca3b97bccf3e3f53c5bad607d30fd6141fcd3c458e66a81a467501a0a4afc |
| vectors/gv5-009.json | 384 | 45e03e64606a054b50c13daacce672db4a16fc8ccdd74b457ffec911d5669415 |
| vectors/gv5-010.json | 303 | 28083f5ac4ab0b0fc06d370bb676ea215fec7fbf9f14a44114f14269814336f1 |
| vectors/gv5-011.json | 538 | ab1a2bbb5ba730028b8d73a46cc0689e1b4279d599e3bfff287de3ce74a64de4 |
| vectors/gv5-012.json | 1184 | c12bbb170c587a76c0bc1fa9a67c6329a577ca68a803a3734ac4743126535ec6 |
| vectors/nv5-001.json | 310 | 471905c92481df264f3ecd3df2fee8aad0b3a504e12b48bb3bf31c255978b0be |
| vectors/nv5-002.json | 185 | 28e305545a11536fdc2ded7bb017a391305838a286562cf457c956d93054e89e |
| vectors/nv5-003.json | 220 | 99cedc80f2a96282465d8198b5dd5899df3ad26c3e06afb85ce9666c5b22c64e |
| vectors/nv5-004.json | 216 | cf1c5dcd4a5aaa579dbbc5911116a462c1e4131bf04c1bc03a206f34282cafe0 |
| vectors/nv5-005.json | 219 | cfd73c2cdaeb2734275ee331491df33524388a903e5558cd33da2b109fd205e3 |
| vectors/nv5-006.json | 192 | 155cd96b02292eee17494caada11527504340d6ed2860689a63ace92b9b2acc0 |
| vectors/nv5-007.json | 172 | d7667c26d771011d107da2a65cbd8e759356a76bd1ebe0a378d82652800bdc31 |
| vectors/nv5-008.json | 226 | 5e2df30ecf203cb69b23db35bd89c3c520673a3a47af80b5f3ac5f450ff0ccf4 |
| vectors/nv5-009.json | 295 | 594f71744e4c2512aa9b056b7ee65cc746b84bc5ca651d48ba57bcc824cb701a |
| vectors/nv5-010.json | 607 | 88b33c68670370aa335a46b8dbf772ba2a50ca3e179739bc795ff855dc2a54ef |
| vectors/nv5-011a.json | 163 | 3f667f52b6ab0957ff2aaf3c4c42dca5387ee29e13c2f0cee090aa55ddc21f4f |
| vectors/nv5-011b.json | 163 | a50a07f5ceb1165da3d38bdc04bc8740cbd676b0d2499dac3fc44b31f4412dd1 |
| vectors/nv5-011c.json | 163 | de0358c33777c901861c69f913248ecb8543607ec2b57e93a38cc912abd3a515 |
| vectors/v3-wire.json | 110 | 41c38a34f436e4a11406cca1cc9aad5736c9d3cb24adf150c2ffca22bce4aee2 |

MANIFEST metadata (not files, recorded as received): spec-ratified `67204ab7…4fe9cd`; spec-bundle = spec.md `8aa795bd…4fac` (matches); 18 deletion-only edits D01–D18 (code-pointer / vector-result sentences); corpus-commit `3a3e01d8…`. No other material was consulted.

## 2. Method

SHA-256 was implemented from FIPS 180-4 (constants generated from prime roots) and self-tested against a reference on three strings; the CBOR encoder and compact-JSON writer were written from §4.2/§4.3. Preimages follow §0 conventions (`u32_be`, `u64_be`, bare concatenation) and the formulas in §1, §3 and §8 verbatim. All hex is lowercase.

## 3. Per-vector results

### gv5-001 (§1.1) — DERIVED
Tag `MKTd02_VECTOR_TEST` used byte-exact as given (18 bytes, mixed case). Preimage (ordered): `4d4b546430325f564543544f525f5445535400ff102030`.
- ordered `[00ff, 102030]`: `23a5ff7598bde7f20d5a1f6c818e0b500942765f7ce4d4e968bab530b1ba7900`
- swapped `[102030, 00ff]`: `4a81db486e8d0a24501983ea845bedad20f4c1e70cd2c23996cc745b579bdb0b`
- The two differ, as §1.1 (ordered, unframed concatenation) requires.

### gv5-002 (§3.1, §3.3) — DERIVED
- `TOMBSTONE_CONSTANT` = SHA-256 of the 17 ASCII bytes `MKTD_TOMBSTONE_V1`: `485a0cf91d7feb0f97f428df6328feca93788456a5b614b1bcedf6c4dc0e8d2a`
- `tombstone_hash` (canister `01020304`, ts 1700000000000000000, seq 7): `835fef4414ead5b4e2add6cd2861b05966d3a7e3b5d36fb2546d8ec0ff0c5657`
  (preimage: tag24 ‖ 01020304 ‖ TOMBSTONE_CONSTANT ‖ `17979cfe362a0000` ‖ `0000000000000007`)

### gv5-003 (§3.4) — DERIVED
- seq 7: `50cb452348fdb74381353af129a5c0a516af2f6675d1104ec1f14108c5592277`
- seq 8: `ed14afa3d20d017a9642e4f1280b3d1a8655ec5558ce488377adc6d3ce3e5c53`

### gv5-004 (§3.5) — DERIVED
- record `0a0b0c` (len prefix `00000003`): `231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d`
- record `0a0b0c0d` (len prefix `00000004`): `f0bd200e35c6a86531ee12c7ef1bba5b9325f36ee41eca05654de38d22659a4c`

### gv5-005 (§3.6) — DERIVED (raw bytes, no length prefix)
- canister `01020304`: `e59e31f962c52e335cb83549d8b72a7322f52dcf48486eac3a86ed79c881c19d`
- canister `00010203040506070809`: `b13fe4e86e05c41474a93b9cf34dfc85424b4f088cda91dd93800249ba4bd4b1`

### gv5-006 (§3.4, §3.6, §3.7) — DERIVED
- `deletion_event_hash` = `certified_data` after deletion: `e3ce0debcedf12ace29542d524b56ef089f6b4c9fcb4db034119333227544c2f`
- `genesis_certified_data(01020304)` (certified data before any deletion): `e59e31f962c52e335cb83549d8b72a7322f52dcf48486eac3a86ed79c881c19d`
- Distinct, as §3.7 requires.

### gv5-007 (§3.4, §3.5, §4) — DERIVED
Inputs omit `receipt_id` and `deletion_event_hash`; both derived:
- `receipt_id`: `231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d`
- `deletion_event_hash`: `0f351b6bf4eb27e69a0b97afe8bee6c0c1925cb6176146bb4d6cddaa3b9b2618`
- Receipt state (§5): FinalizedCandidate
- CBOR (459 bytes; sha256 `b816049feee79f0e2eefef206b25358633a21163bf429e32a112eb80fb34978d`). Encoding decisions from §4.2: map head `ae`; keys as text; 32-byte fields `58 20`; `canister_id` `44 01020304`; `record_id` `43 0a0b0c`; `timestamp` `1b 17979cfe362a0000`; `deletion_seq` `07`; `bls_certificate` `43 aabbcc`; `module_hash_certificate` `42 ddee`; text `69 "mktd02-v5"`, `68 "test-key"`.
  ```
  ae7070726f746f636f6c5f76657273696f6e696d6b746430322d76356a726563656970745f69645820231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d6b63616e69737465725f69644401020304697265636f72645f6964430a0b0c6e7072655f73746174655f68617368582011111111111111111111111111111111111111111111111111111111111111116f706f73745f73746174655f68617368582022222222222222222222222222222222222222222222222222222222222222226e746f6d6273746f6e655f68617368582033333333333333333333333333333333333333333333333333333333333333337364656c6574696f6e5f6576656e745f6861736858200f351b6bf4eb27e69a0b97afe8bee6c0c1925cb6176146bb4d6cddaa3b9b26186b6d6f64756c655f68617368582044444444444444444444444444444444444444444444444444444444444444446974696d657374616d701b17979cfe362a00006c64656c6574696f6e5f736571076f626c735f636572746966696361746543aabbcc7174727573745f726f6f745f6b65795f696468746573742d6b6579776d6f64756c655f686173685f636572746966696361746542ddee
  ```
- JSON (728 bytes, no trailing newline; sha256 `015e2d18ee7561defe8dceec0d024d826f28270f853d10c43afd393cd464ee58`):
  ```
  {"protocol_version":"mktd02-v5","receipt_id":"231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d","canister_id":"wy6px-tibai-bqi","record_id":"0a0b0c","pre_state_hash":"1111111111111111111111111111111111111111111111111111111111111111","post_state_hash":"2222222222222222222222222222222222222222222222222222222222222222","tombstone_hash":"3333333333333333333333333333333333333333333333333333333333333333","deletion_event_hash":"0f351b6bf4eb27e69a0b97afe8bee6c0c1925cb6176146bb4d6cddaa3b9b2618","module_hash":"4444444444444444444444444444444444444444444444444444444444444444","timestamp":1700000000000000000,"deletion_seq":7,"bls_certificate":"aabbcc","trust_root_key_id":"test-key","module_hash_certificate":"ddee"}
  ```

### gv5-008 (§3.4, §3.5, §4, §5) — DERIVED
Same identity inputs as gv5-007, so `receipt_id` and `deletion_event_hash` are identical (`231bca0d2351bb58…`, `0f351b6bf4eb27e6…`). Both certificate keys emitted with CBOR `f6` / JSON `null`; `trust_root_key_id` is `60` / `""`.
- Receipt state: Pending
- CBOR (446 bytes; sha256 `076e33e662e4bf3fd49cebf343ae8a7245fb4d7f949ae6c54cec23ba9d20426a`):
  ```
  ae7070726f746f636f6c5f76657273696f6e696d6b746430322d76356a726563656970745f69645820231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d6b63616e69737465725f69644401020304697265636f72645f6964430a0b0c6e7072655f73746174655f68617368582011111111111111111111111111111111111111111111111111111111111111116f706f73745f73746174655f68617368582022222222222222222222222222222222222222222222222222222222222222226e746f6d6273746f6e655f68617368582033333333333333333333333333333333333333333333333333333333333333337364656c6574696f6e5f6576656e745f6861736858200f351b6bf4eb27e69a0b97afe8bee6c0c1925cb6176146bb4d6cddaa3b9b26186b6d6f64756c655f68617368582044444444444444444444444444444444444444444444444444444444444444446974696d657374616d701b17979cfe362a00006c64656c6574696f6e5f736571076f626c735f6365727469666963617465f67174727573745f726f6f745f6b65795f696460776d6f64756c655f686173685f6365727469666963617465f6
  ```
- JSON (714 bytes; sha256 `277dd8e5f51b4bd5b89301ffae62f96b4e697f936461957e38f334fe6f0297cf`):
  ```
  {"protocol_version":"mktd02-v5","receipt_id":"231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d","canister_id":"wy6px-tibai-bqi","record_id":"0a0b0c","pre_state_hash":"1111111111111111111111111111111111111111111111111111111111111111","post_state_hash":"2222222222222222222222222222222222222222222222222222222222222222","tombstone_hash":"3333333333333333333333333333333333333333333333333333333333333333","deletion_event_hash":"0f351b6bf4eb27e69a0b97afe8bee6c0c1925cb6176146bb4d6cddaa3b9b2618","module_hash":"4444444444444444444444444444444444444444444444444444444444444444","timestamp":1700000000000000000,"deletion_seq":7,"bls_certificate":null,"trust_root_key_id":"","module_hash_certificate":null}
  ```

### gv5-009 (§5) — DERIVED
neither → Pending; both → FinalizedCandidate; bls_only → InvalidIncompleteFinalization; module_only → InvalidIncompleteFinalization.

### gv5-010 (§2.1) — DERIVED
`hash_with_tag(tag, ["test"])`; lengths all match the §2.1 registry.
- v5_used: `MKTD02_TOMBSTONE_HASH_V1` (len 24): `1d458fe278607fd548c30148ffd8eb9fba8c132cc9b1ec5039b7c973ef3bd322`
- v5_used: `MKTD02_EVENT_V2` (len 15): `fb61a86856b21184004af27249f86f870ed4d938accdc106edbc85c8044691ca`
- v5_used: `MKTD02_RECEIPT_V3` (len 17): `80cace4a6dd613ebab643c887df83b0240a801a607512cd5445031a32b30dd86`
- v5_used: `MKTD02_GENESIS_V1` (len 17): `219d6bf8035fa42d43e1ae1eec462b7e43982175607829b03956072c86534b04`
- v5_used: `MKTD02_SALT_V1` (len 14): `59c364395836b540971fcc4021eaf977deaf174d6eb87b2da68b30e46df66b4a`
- active_other_lines: `MKTD02_EVENT_V1` (len 15): `6393c15cb2820d70e84c82c0928fccf15792cb3f79bb0783a78eb050260a977f`
- active_other_lines: `MKTD02_RECEIPT_V1` (len 17): `b5acde122055eed7a27d1af0e0d6cf510b8afa1532c4383193587e3c57001b15`
- active_other_lines: `MKTD02_MANIFEST_V1` (len 18): `158e49fbae2d7356adccead6973a51722c587a935fdbda455592a1dbb8bc31f2`

### gv5-011 (§3.2, §10) — DERIVED
The supplied `state_bytes` (80 bytes) were independently rebuilt from the vector's schema statement (definite map of 2, text keys `name`,`email`, each value a 32-byte string of `TOMBSTONE_CONSTANT`) with my own encoder and matched byte-for-byte, confirming the fixture is reproducible from §3.1 + the stated schema.
- `mktd_salt` = hash_with_tag(`MKTD02_SALT_V1`, [01020304]): `137a4b3fcbed897879000a0b9415da4356c15fd1b38dda7383908fc622a1607a`
- `state_hash` = SHA-256(mktd_salt ‖ state_bytes), untagged: `f9e845fcf9339261838955a20037518669aac88f1a0b4608bdc46628a5d2ab31`

### gv5-012 (§4.4, §10) — DERIVED (with one noted dependency)
- Canonical JSON (728 bytes; sha256 `5369e7c973e39c6392b086cb059ff2c2380c2d0ed8a2aa6090d99fb3ecd72e7c`):
  ```
  {"protocol_version":"mktd02-v5","receipt_id":"1111111111111111111111111111111111111111111111111111111111111111","canister_id":"wy6px-tibai-bqi","record_id":"0a0b0c","pre_state_hash":"2222222222222222222222222222222222222222222222222222222222222222","post_state_hash":"3333333333333333333333333333333333333333333333333333333333333333","tombstone_hash":"4444444444444444444444444444444444444444444444444444444444444444","deletion_event_hash":"5555555555555555555555555555555555555555555555555555555555555555","module_hash":"6666666666666666666666666666666666666666666666666666666666666666","timestamp":1700000000000000000,"deletion_seq":7,"bls_certificate":"aabbcc","trust_root_key_id":"test-key","module_hash_certificate":"ddee"}
  ```
- Canonical CBOR (459 bytes; sha256 `ffc41b3c34fbda018c54e9438ace8dfceda64bb32f9d47496ba4bb123939f6d9`):
  ```
  ae7070726f746f636f6c5f76657273696f6e696d6b746430322d76356a726563656970745f6964582011111111111111111111111111111111111111111111111111111111111111116b63616e69737465725f69644401020304697265636f72645f6964430a0b0c6e7072655f73746174655f68617368582022222222222222222222222222222222222222222222222222222222222222226f706f73745f73746174655f68617368582033333333333333333333333333333333333333333333333333333333333333336e746f6d6273746f6e655f68617368582044444444444444444444444444444444444444444444444444444444444444447364656c6574696f6e5f6576656e745f68617368582055555555555555555555555555555555555555555555555555555555555555556b6d6f64756c655f68617368582066666666666666666666666666666666666666666666666666666666666666666974696d657374616d701b17979cfe362a00006c64656c6574696f6e5f736571076f626c735f636572746966696361746543aabbcc7174727573745f726f6f745f6b65795f696468746573742d6b6579776d6f64756c655f686173685f636572746966696361746542ddee
  ```
  Dependency: the canonical input gives `canister_id` only in textual form. spec.md does not define the principal text↔bytes conversion (§0 says only "raw bytes … not its textual form"; §4.3 gives an example). The raw bytes `01020304` were taken from the bundle's own pairing of `wy6px-tibai-bqi` with `canister_id_hex` in gv5-007/008. If that pairing is not accepted as an input, the CBOR rendering's `canister_id` payload is UNDERIVABLE from spec.md alone; the JSON rendering is unaffected.
- Variant `uppercase_0x` (0x/0X prefix, uppercase digits on receipt_id, record_id, pre_state_hash, bls_certificate): §4.4 accepts and canonical output is lowercase/unprefixed → decodes to the canonical receipt above, identical bytes on re-serialisation.
- Variant `byte_arrays` (record_id `[10,11,12]`, module_hash_certificate `[221,238]`): §4.4 accepts byte-array form → decodes to the canonical receipt above.
- Receipt state: FinalizedCandidate.

### nv5-001 (§7) — DERIVED
Operation: decode. All three cases (`valid_hex`, `null`, `garbage`) → named error `retired-field:certified_commitment`, raised at **decode**. §7 says the key is refused "with any value including null"; §4.4 makes it a declared probe key refused by name rather than as unknown. For `garbage`, the §4.6 level-1 "malformed hex" fault applies to §4.1 hex fields, of which `certified_commitment` is not one, so the named level-3 error is the first applicable.

### nv5-002 (§4.4, §7) — DERIVED
Operation: decode, formats json and cbor. Keys `nonce`, `subnet_id`, `extra` each → hard error whose message begins `unknown field`, raised at **decode**, in both encodings (§4.4 "any key outside §4.1"; §4.2 keys are the §4.1 names). Full message text is deliberately not frozen (ruling F-15: prefix only).

### nv5-003 (§4.6) — DERIVED
Both `certified_commitment` and `extra` present → `unknown field` … (for `extra`), raised at **decode**. §4.6 level 1 (structural unknown key) precedes level 3 (`certified_commitment` present), per ruling 1d. `retired-field:certified_commitment` is not reported.

### nv5-004 (§4.4, §7) — DERIVED
Operation: decode; `deletion_event_hash` all-zero → named error `invalid-event-hash:zero`, raised at **decode** (§4.6 level 4; no higher-level fault present).

### nv5-005 (§4.5, §7) — DERIVED
Operation: serialise; all-zero `deletion_event_hash` → named error `invalid-event-hash:zero`, raised at **serialise** (§4.5, symmetric with decode).

### nv5-006 (§3.6, §7) — DERIVED
Operation: verify. Certified data = `genesis_certified_data(01020304)` = `e59e31f962c52e335cb83549d8b72a7322f52dcf48486eac3a86ed79c881c19d` → named error `no-deletion-certified`, raised at the **verifier**.

### nv5-007 (§6) — DERIVED
Labels `mktd02-v5-x`, `mktd02-v50`, `mktd02-v5 ` (trailing space) → each unrecognised: hard error on **decode** and on **serialise** (§6; §4.6 level 2; §4.5 first bullet). The message text is explicitly outside the freeze (§7: "its message text is not part of this freeze"), so no string is derived, by the spec's own rule.

### nv5-008 (§6, §8.4) — DERIVED
- `v4_label_to_v5_type` (`mktd02-v4` into the v5 type): wrong-line `protocol_version` → hard error at **decode** (§6 exact match; §4.6 level 2). Message text not frozen.
- `v5_label_to_v4_type` (`mktd02-v5` into the frozen v4 type): refused at **decode** by the frozen v4 type; message begins `DeletionReceipt: unrecognised protocol_version` (§8.4).

### nv5-009 (§3.5) — DERIVED outcome; error name UNDERIVABLE
Recomputed `receipt_id` = `231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d` ≠ presented `ff…ff` → the V1 consistency check fails at its **first step** (the `receipt_id` equality check) in the **verifier**; the event-hash step is not reached (§3.4 "first recomputes receipt_id … equality-checks it"). Gap: §7 lists only four named rejections and §3.4 names no error for a `receipt_id` mismatch, so the error identifier is UNDERIVABLE from spec.md.

### nv5-010 (§3.4) — DERIVED outcome; error name UNDERIVABLE
With the supplied `receipt_id` (given as input, so the §3.5 pre-step cannot be exercised here), recomputed `deletion_event_hash` = `50cb452348fdb74381353af129a5c0a516af2f6675d1104ec1f14108c5592277` (identical to gv5-003 seq 7, same inputs) ≠ presented `ff…ff` → V1 consistency check fails at its **second step** in the **verifier**. Same gap as nv5-009: no named error in §7 or §3.4.

### nv5-011a / nv5-011b / nv5-011c (§8.4) — DERIVED
`mktd02-v2`, `mktd02-v3`, `mktd02-v4` receipts carrying unknown key `extra` → **accepted** at decode through each line's frozen type, which tolerates unknown keys (§8.4 first bullet). Line selection is by prefix (§8.4 last bullet); the labels here are exact anyway.

### v4h-event-v1 (§8.2) — DERIVED
`hash_historical(MKTD02_EVENT_V1, [pre, post, u64_be(1000000), module_hash, u64_be(1)])`: `9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023`

### v4h-certified-commitment (§8.1, §8.2) — DERIVED
- historical `deletion_event_hash` (same inputs as v4h-event-v1): `9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023`
- `certified_commitment` = SHA-256(`MKTD02_CERTIFIED_V1` ‖ post_state_hash ‖ that event hash) via §1.3: `932e7b4ec2249ea53dd7ec1ed76c4dc57fba00fb55957228d92fc416700ebc16`

### v4h-certified-tag (§1.3, §8.1) — DERIVED
SHA-256(`MKTD02_CERTIFIED_V1` ‖ `test`): `b2a533ef0b75007545bda617076df5a8694db1e3f6ae0c3050b45b81d0cfcf5c`

### v4h-v3-wire (§8.4) — UNDERIVABLE
The vector itself states "frozen artefact — not derivable" and supplies no inputs. §8.4 gives only differential facts about the v3 wire (no `module_hash_certificate` field; prefix label matching); it specifies no v3 field list, order or encoding. Quote of the gap: "The v3 wire shape carries no `module_hash_certificate` field at all; v4 adds it." — nothing further.

## 4. Counts

- Vectors received: 30 (12 gv5, 14 nv5, 3 historical, 1 frozen v3 wire).
- DERIVED: 29. UNDERIVABLE: 1 (v4h-v3-wire).
- Partial gaps inside derived vectors (spec.md does not determine a sub-value): nv5-009 and nv5-010 (no named error for V1 receipt_id / event-hash mismatch); gv5-012 CBOR `canister_id` bytes (principal text→bytes conversion not defined in spec.md; taken from the bundle's own gv5-007/008 pairing). nv5-007 and nv5-008 message text is unfrozen by the spec's explicit rule and is not counted as a gap.
- Lock-gate item "independent rederivation reports zero underivable values" is therefore **not** met as written: one vector is underivable by its own declaration, and two named-error identifiers plus one encoding dependency are absent from spec.md.

Bundle SHA-256 received: `5dc6e2b2a356c0d780538adeba373514c527e99578fd87dc775c49c72a33468a`
