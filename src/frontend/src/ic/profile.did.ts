// IDL for profile_canister — updated for MKTd02 integration
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
  const MktdStateHashResponse = IDL.Record({
    hash: IDL.Vec(IDL.Nat8),
    certificate: IDL.Opt(IDL.Vec(IDL.Nat8)),
  });
  const MktdTombstoneStatus = IDL.Record({
    is_tombstoned: IDL.Bool,
    tombstoned_at: IDL.Opt(IDL.Nat64),
  });
  const MktdReceiptResponse = IDL.Record({
    receipt_id: IDL.Text,
    canister_id: IDL.Principal,
    subnet_id: IDL.Principal,
    commit_mode: IDL.Text,
    pre_state_hash: IDL.Text,
    post_state_hash: IDL.Text,
    tombstone_hash: IDL.Text,
    deletion_event_hash: IDL.Text,
    certified_commitment: IDL.Text,
    manifest_hash: IDL.Text,
    module_hash: IDL.Text,
    timestamp: IDL.Nat64,
    nonce: IDL.Nat64,
  });
  // delete_profile now returns Result<String> (receipt_id) not Result<()>
  const Result = IDL.Variant({ Ok: IDL.Text, Err: DaffyError });
  const Result_1 = IDL.Variant({ Ok: ProfileInfo, Err: DaffyError });
  return IDL.Service({
    delete_profile: IDL.Func([], [Result], []),
    get_display_name: IDL.Func([], [IDL.Opt(IDL.Text)], ["query"]),
    get_profile: IDL.Func([], [Result_1], ["query"]),
    upsert_profile: IDL.Func([ProfileInput], [Result_1], []),
    version: IDL.Func([], [IDL.Text], ["query"]),
    // MKTd02 query endpoints
    mktd_get_state_hash: IDL.Func([], [MktdStateHashResponse], ["query"]),
    mktd_get_tombstone_status: IDL.Func([], [MktdTombstoneStatus], ["query"]),
    mktd_get_receipt: IDL.Func([IDL.Text], [IDL.Opt(MktdReceiptResponse)], ["query"]),
    mktd_receipt_count: IDL.Func([], [IDL.Nat64], ["query"]),
  });
};
