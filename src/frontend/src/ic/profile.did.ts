// Auto-generated IDL for profile_canister
// Based on src/profile_canister/profile_canister.did

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

  const Result = IDL.Variant({ Ok: IDL.Null, Err: DaffyError });
  const Result_1 = IDL.Variant({ Ok: ProfileInfo, Err: DaffyError });

  return IDL.Service({
    delete_profile: IDL.Func([], [Result], []),
    get_display_name: IDL.Func([], [IDL.Opt(IDL.Text)], ["query"]),
    get_profile: IDL.Func([], [Result_1], ["query"]),
    upsert_profile: IDL.Func([ProfileInput], [Result_1], []),
    version: IDL.Func([], [IDL.Text], ["query"]),
  });
};
