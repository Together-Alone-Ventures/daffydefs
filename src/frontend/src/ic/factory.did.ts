// IDL for profile_factory canister — updated for receipt finalization proxy
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

  const ResultNull = IDL.Variant({ Ok: IDL.Null, Err: DaffyError });
  const ResultPrincipal = IDL.Variant({ Ok: IDL.Principal, Err: DaffyError });
  const ResultText = IDL.Variant({ Ok: IDL.Text, Err: DaffyError });

  return IDL.Service({
    delete_profile_canister: IDL.Func([], [ResultNull], []),
    get_cycle_balance: IDL.Func([], [IDL.Nat], ["query"]),
    get_or_create_profile_canister: IDL.Func([], [ResultPrincipal], []),
    resolve: IDL.Func([IDL.Principal], [ResultPrincipal], ["query"]),
    version: IDL.Func([], [IDL.Text], ["query"]),

    // Phase C proxy (controller path)
    finalize_profile_receipt: IDL.Func(
      [IDL.Principal, IDL.Text, IDL.Vec(IDL.Nat8)],
      [ResultText],
      []
    ),
  });
};
