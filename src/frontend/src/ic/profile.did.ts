// IDL for profile_canister — updated for MKTd02 v0.4.0 (mktd02-v3)
export const idlFactory = ({ IDL }: { IDL: any }) => {
  const DaffyError = IDL.Variant({
    ProfileDeleted: IDL.Record({ message: IDL.Text }),
    InvalidInput: IDL.Record({ message: IDL.Text }),
    ProfileNotFound: IDL.Record({ message: IDL.Text }),
    NotAuthorized: IDL.Record({ message: IDL.Text }),
    CanisterCallFailed: IDL.Record({ message: IDL.Text }),
    AlreadyExists: IDL.Record({ message: IDL.Text }),
    InvalidWord: IDL.Record({ message: IDL.Text }),
    RateLimitExceeded: IDL.Record({ message: IDL.Text }),
  });

  const ProfileInfo = IDL.Record({
    owner: IDL.Principal,
    birthdate: IDL.Text,
    email: IDL.Text,
    display_name: IDL.Text,
    gender: IDL.Text,
  });

  const ProfileInput = IDL.Record({
    birthdate: IDL.Text,
    email: IDL.Text,
    display_name: IDL.Text,
    gender: IDL.Text,
  });

  // Common result types
  const ResultText = IDL.Variant({ Ok: IDL.Text, Err: DaffyError });
  const ResultProfileInfo = IDL.Variant({ Ok: ProfileInfo, Err: DaffyError });

  // MKTd02 support types
  const MktdStateHashResponse = IDL.Record({
    hash: IDL.Vec(IDL.Nat8),
    certificate: IDL.Opt(IDL.Vec(IDL.Nat8)),
  });

  const MktdTombstoneStatus = IDL.Record({
    is_tombstoned: IDL.Bool,
    tombstoned_at: IDL.Opt(IDL.Nat64),
  });

  const MktdReceiptResponse = IDL.Record({
    protocol_version: IDL.Text,
    receipt_id: IDL.Text,
    canister_id: IDL.Principal,
    record_id: IDL.Vec(IDL.Nat8),
    pre_state_hash: IDL.Text,
    post_state_hash: IDL.Text,
    tombstone_hash: IDL.Text,
    deletion_event_hash: IDL.Text,
    certified_commitment: IDL.Text,
    module_hash: IDL.Text,
    timestamp: IDL.Nat64,
    deletion_seq: IDL.Nat64,
    bls_certificate: IDL.Opt(IDL.Vec(IDL.Nat8)),
    trust_root_key_id: IDL.Text,
  });

  const MktdPendingCertificateResponse = IDL.Record({
    receipt_id: IDL.Text,
    certified_commitment: IDL.Vec(IDL.Nat8),
    certificate: IDL.Vec(IDL.Nat8),
  });

  return IDL.Service({
    // Profile actions
    delete_profile: IDL.Func([], [ResultText], []),
    get_display_name: IDL.Func([], [IDL.Opt(IDL.Text)], ["query"]),
    get_profile: IDL.Func([], [ResultProfileInfo], ["query"]),
    upsert_profile: IDL.Func([ProfileInput], [ResultProfileInfo], []),
    version: IDL.Func([], [IDL.Text], ["query"]),

    // MKTd02 query endpoints
    mktd_get_state_hash: IDL.Func([], [MktdStateHashResponse], ["query"]),
    mktd_get_tombstone_status: IDL.Func([], [MktdTombstoneStatus], ["query"]),
    mktd_get_receipt: IDL.Func([IDL.Text], [IDL.Opt(MktdReceiptResponse)], ["query"]),
    mktd_receipt_count: IDL.Func([], [IDL.Nat64], ["query"]),

    // Seamless finalization support (Phase B + status)
    mktd_get_certificate: IDL.Func([], [IDL.Opt(MktdPendingCertificateResponse)], ["query"]),
    mktd_is_pending: IDL.Func([], [IDL.Bool], ["query"]),

    // Phase C (controller-only; typically called via factory proxy)
    // v4: (receipt_id, phase_b_certificate, module_hash_certificate)
    mktd_finalize_receipt: IDL.Func([IDL.Text, IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)], [ResultText], []),
  });
};
