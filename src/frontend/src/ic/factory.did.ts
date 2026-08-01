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

    // DELIBERATELY ABSENT: unmap_deleted_profile.
    // Unmapping removes the principal → canister entry (profile_factory:513-529)
    // with NO pending-receipt check. Do it while a receipt is still pending and
    // the receipt becomes permanently unfinalisable: get_or_create then mints a
    // FRESH canister (:192-196) and finalize_profile_receipt's is_managed check
    // (:555-562) can never match the old one again.
    // CODED INVARIANT: if this is ever added, it may only be called after a
    // receipt-first confirmation that the receipt is finalized with BOTH
    // certificate fields present — use isReceiptFinalized() from
    // ./finalize/cvdr. Lazy repair must never unmap while pending.

    get_cycle_balance: IDL.Func([], [IDL.Nat], ["query"]),
    get_or_create_profile_canister: IDL.Func([], [ResultPrincipal], []),
    resolve: IDL.Func([IDL.Principal], [ResultPrincipal], ["query"]),
    version: IDL.Func([], [IDL.Text], ["query"]),

    // Phase C proxy (controller path)
    finalize_profile_receipt: IDL.Func(
      // v4: (subject, receipt_id, phase_b_certificate, module_hash_certificate)
      [IDL.Principal, IDL.Text, IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)],
      [ResultText],
      []
    ),
  });
};
