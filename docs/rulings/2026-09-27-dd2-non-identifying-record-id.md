DD2 — DAFFYDEFS NON-IDENTIFYING RECORD ID
27 September 2026

Status: RATIFIED by Stef on 27 September 2026.

1. Scope

This ruling is specific to DaffyDefs.

It does not change generic MKTd02 record-id semantics and does not adopt the
OpenChatZD record-id construction.

2. Record identity

Each newly created DaffyDefs profile canister receives one fresh,
cryptographically random 32-byte record_id.

The record_id:

- is independent of the user's Internet Identity principal;
- is not derived from any user identifier;
- is not a deterministic or reversible derivative of the principal;
- is stable for the lifetime of that profile canister;
- survives upgrades;
- is never regenerated for that profile;
- is never reused for a replacement/new profile.

3. Generation

The DaffyDefs profile factory obtains the 32 bytes from ICP raw_rand before
creating/installing the profile canister.

The random record_id is passed to the profile canister in its init arguments.

The factory must not persist the record_id and must not deliberately log it.

4. Profile storage

The profile canister stores the record_id durably in dedicated stable storage.

The implementation must preserve the existing StoredProfile encoding and the
reserved MKTd02 stable-memory range.

A dedicated new stable-memory location may be used.

5. Deletion

DaffyDefs deletion must use:

  execute_deletion_with_record_id

with the stored random record_id.

The raw Internet Identity principal must no longer be supplied as the public
CVDR record_id.

6. Replacement profiles

A newly created replacement/rejoined profile is a new record and receives a
new independent random record_id.

The prior record_id is never recovered or reused.

7. Public linkage

DaffyDefs must not expose a public deterministic mapping from the random
record_id to the user's Internet Identity principal.

The factory's resolve(principal) API is restricted as follows:

- an ordinary authenticated caller may resolve only that caller's own principal;
- factory controllers may resolve other principals for administration;
- anonymous callers remain denied.

No public DaffyDefs interface may allow one ordinary user to discover another
user's profile canister from that user's principal.

The existing frontend self-routing path through
get_or_create_profile_canister() may remain.

The bulletin board must not introduce a public principal <-> profile-canister
mapping.

After deletion/unmap, DaffyDefs-controlled public interfaces must not provide a
principal -> deleted profile-canister mapping.

The implementation must confirm that no legitimate DaffyDefs function depends
on ordinary users resolving another user's principal. If such a dependency is
found, it is a conflict to escalate rather than a reason to weaken this rule.

This ruling does not claim that canister_id is globally unlinkable from a user
against an operator's private knowledge, a third party's previously retained
observation, or external historical records. That residual linkability must be
stated honestly in the applicable RTS.

8. Existing profiles

No migration of pre-v5.1 DaffyDefs profiles is required.

A profile created without the DD2 random record_id is not upgraded into a
DD2-compliant v5.1 demonstration profile.

Existing receipts/profiles retain their historical semantics.

The canonical v5.1 DaffyDefs ceremony must use a freshly created profile under
the corrected code path.

9. Release coupling

The DD2 correction ships in the same DaffyDefs rebuild and mainnet ceremony as
the MKTd02 v5.1 correction.

The resulting fresh receipt becomes the canonical demonstration receipt.

10. Repository authority

This ratified ruling must be committed in the DaffyDefs repository before its
implementation begins and cited by the implementation/test documentation.

It must not exist only in chat or external project notes.
