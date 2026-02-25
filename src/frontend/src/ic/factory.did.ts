// Auto-generated IDL for profile_factory canister
// Based on src/profile_factory/profile_factory.did

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

  const Result = IDL.Variant({ Ok: IDL.Null, Err: DaffyError });
  const Result_1 = IDL.Variant({ Ok: IDL.Principal, Err: DaffyError });

  return IDL.Service({
    delete_profile_canister: IDL.Func([], [Result], []),
    get_cycle_balance: IDL.Func([], [IDL.Nat], ["query"]),
    get_or_create_profile_canister: IDL.Func([], [Result_1], []),
    resolve: IDL.Func([IDL.Principal], [Result_1], ["query"]),
    version: IDL.Func([], [IDL.Text], ["query"]),
    unmap_deleted_profile: IDL.Func([], [Result], []),
  });
};
