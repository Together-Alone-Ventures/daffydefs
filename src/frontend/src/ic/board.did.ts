// Auto-generated IDL for bulletin_board canister
// Based on src/bulletin_board/bulletin_board.did

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

  const CommentView = IDL.Record({
    id: IDL.Nat64,
    like_count: IDL.Nat64,
    text: IDL.Text,
    created_at: IDL.Nat64,
    liked_by_caller: IDL.Bool,
    author: IDL.Principal,
    challenge_id: IDL.Nat64,
  });

  const ChallengeSummary = IDL.Record({
    id: IDL.Nat64,
    comment_count: IDL.Nat64,
    word: IDL.Text,
    created_at: IDL.Nat64,
    author: IDL.Principal,
  });

  const ChallengesPage = IDL.Record({
    next_cursor: IDL.Opt(IDL.Nat64),
    challenges: IDL.Vec(ChallengeSummary),
  });

  const ChallengeDetail = IDL.Record({
    id: IDL.Nat64,
    word: IDL.Text,
    created_at: IDL.Nat64,
    author: IDL.Principal,
    comments: IDL.Vec(CommentView),
  });

  const CommentsPage = IDL.Record({
    next_cursor: IDL.Opt(IDL.Nat64),
    comments: IDL.Vec(CommentView),
  });

  const Result = IDL.Variant({ Ok: IDL.Nat64, Err: DaffyError });
  const Result_1 = IDL.Variant({ Ok: ChallengeDetail, Err: DaffyError });

  return IDL.Service({
    add_comment: IDL.Func([IDL.Nat64, IDL.Text], [Result], []),
    create_challenge: IDL.Func([IDL.Text], [Result], []),
    get_challenge: IDL.Func([IDL.Nat64], [Result_1], ["query"]),
    list_challenges: IDL.Func(
      [IDL.Opt(IDL.Nat64), IDL.Opt(IDL.Nat32)],
      [ChallengesPage],
      ["query"]
    ),
    list_comments: IDL.Func(
      [IDL.Nat64, IDL.Opt(IDL.Nat64), IDL.Opt(IDL.Nat32)],
      [CommentsPage],
      ["query"]
    ),
    toggle_like: IDL.Func([IDL.Nat64], [Result], []),
    version: IDL.Func([], [IDL.Text], ["query"]),
  });
};
