//! Split authorization reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/authorization/SplitAuthorization/Spec.lean` (`apply`, `runOps`).
//!
//! Every operation has one refusal function, ported from `opRefusals`, that lists
//! the codes in code order, and two rules: the refusal (state unchanged, the
//! codes observed) and the transition of `exec`. The checks are functions with
//! one equation per branch, so each branch and each condition operand is a
//! coverage obligation and a mutation target. List walks branch on their
//! element instead of recursing under `&&` or `||`. An `Option` of the oracle is
//! a list of at most one element. Requirement IDs refer to
//! `openspec/changes/add-split-line-dealing/specs/split-authorization/spec.md`.
//!
//! Cells are the oracle's `St` fields (`params`, `charters`, `records`, `used`,
//! `holds`, `recovered`, and `node` spread into `pending`, `inforce`, `landed`) and its
//! observation list `obs`; `ops` holds the
//! operations still to run and is empty at every end (FLOW.toml omits it).
//!
//! AU-029 (DECISIONS 60): a VOID settlement of an authorization accepted on a LOCKED
//! record keeps the lock; `lockedAtAccept` reads the record's pin.

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, list};

k::sorts! {
    Run: KItem;
    Mode;
    Profile;
    RState;
    Status;
    Settled;
    Source;
    Root;
    Nf;
    Auth;
    Rec;
    Charter;
    Params;
    AnPair;
    NfaPair;
    SlotRef;
    Leaf;
    Carry;
    Call;
    BfTuple;
    BfCall;
    Refusal;
    VoidReason;
    AuthMap;
    Op;
    Obs;
}

#[k::constructors(sort = Run, result = KResult)]
pub enum Step {
    #[k::syntax("#run")]
    Go,
}

#[k::constructors(sort = Mode, result = KResult)]
#[rustfmt::skip]
pub enum ModeC {
    #[k::syntax("modeTEE")] Tee,
    #[k::syntax("modeNONTEE")] NonTee,
}

#[k::constructors(sort = Profile, result = KResult)]
#[rustfmt::skip]
pub enum ProfileC {
    #[k::syntax("profP0")] P0,
    #[k::syntax("profP1")] P1,
    #[k::syntax("profP2")] P2,
}

/// AU-001
#[k::constructors(sort = RState, result = KResult)]
#[rustfmt::skip]
pub enum RStateC {
    #[k::syntax("rsUNSPENT")] Unspent,
    #[k::syntax("rsPENDING")] Pending,
    #[k::syntax("rsLOCKED")] Locked,
}

/// AU-002
#[k::constructors(sort = Status, result = KResult)]
#[rustfmt::skip]
pub enum StatusC {
    #[k::syntax("stSUBMITTED")] Submitted,
    #[k::syntax("stFINAL")] StFinal,
    #[k::syntax("stREVOKED")] Revoked,
}

/// AU-002: `settled ∈ {NONE, FINAL, VOID, RELEASED}`
#[k::constructors(sort = Settled, result = KResult)]
#[rustfmt::skip]
pub enum SettledC {
    #[k::syntax("setNONE")] SetNone,
    #[k::syntax("setFINAL")] SetFinal,
    #[k::syntax("setVOID")] SetVoid,
    #[k::syntax("setRELEASED")] SetReleased,
}

/// AU-006: the owner or initiator source, the seizure-order source, the recovery-exit source.
#[k::constructors(sort = Source, result = KResult)]
#[rustfmt::skip]
pub enum SourceC {
    #[k::syntax("srcOWNER")] Owner,
    #[k::syntax("srcSEIZURE")] Seizure,
    #[k::syntax("srcRECOVERY")] Recovery,
}

/// AU-001, AU-006: an ECDSA slot lies under `slr_own` or `slr_G`.
#[k::constructors(sort = Root, result = KResult)]
#[rustfmt::skip]
pub enum RootC {
    #[k::syntax("rootOWN")] Own,
    #[k::syntax("rootG")] RootG,
}

/// A nullifier: fresh at birth (AU-001), or `N(nsk, auth, outcome)` (AU-023).
#[k::constructors(sort = Nf, result = KResult)]
#[rustfmt::skip]
pub enum NfC {
    #[k::syntax("fresh({n})")] Fresh { n: Int },
    #[k::syntax("ofSettle({auth}, {o})")] OfSettle { auth: Int, o: Settled },
}

/// AU-002: an authorization.
#[k::constructors(sort = Auth, result = KResult)]
pub enum AuthC {
    #[k::syntax("auth({auth}, {nf}, {rh}, {status}, {final_height}, {settled}, {source}, {pin}, {direct})")]
    Au {
        auth: Int,
        nf: Nf,
        rh: Int,
        status: Status,
        final_height: List<Int>,
        settled: Settled,
        source: List<Source>,
        pin: List<Int>,
        direct: Bool,
    },
}

/// AU-001: an asset record.
#[k::constructors(sort = Rec, result = KResult)]
pub enum RecC {
    #[k::syntax(
        "rec({rid}, {cm_addr}, {profile}, {board_first}, {rstate}, {nf}, {pin}, {hold_tag}, {slr_own}, {slr_g}, {spent}, {auths})"
    )]
    Rc {
        rid: Int,
        cm_addr: Int,
        profile: Profile,
        board_first: Bool,
        rstate: RState,
        nf: Nf,
        pin: List<Int>,
        hold_tag: Int,
        slr_own: List<Int>,
        slr_g: List<Int>,
        spent: Bool,
        auths: List<Auth>,
    },
}

/// AU-011: a registered charter.
#[k::constructors(sort = Charter, result = KResult)]
pub enum CharterC {
    #[k::syntax("charter({cid}, {profile}, {board_first})")]
    Ch { cid: Int, profile: Profile, board_first: Bool },
}

/// `(auth, nf)` of an in-force board-first call.
#[k::constructors(sort = AnPair, result = KResult)]
pub enum AnPairC {
    #[k::syntax("an({a}, {nf})")]
    An { a: Int, nf: Nf },
}

/// `(nf, auth)` of an accepted `authorize`.
#[k::constructors(sort = NfaPair, result = KResult)]
pub enum NfaPairC {
    #[k::syntax("nfa({nf}, {a})")]
    Nfa { nf: Nf, a: Int },
}

#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    #[k::syntax("params({mode}, {q})")]
    Params { mode: Mode, q: Int },
}

/// The ECDSA slot root a call names, `(record, root)`.
#[k::constructors(sort = SlotRef, result = KResult)]
pub enum SlotRefC {
    #[k::syntax("slotRef({rid}, {root})")]
    Sr { rid: Int, root: Root },
}

/// A `settle_root` leaf `(auth, outcome)`.
#[k::constructors(sort = Leaf, result = KResult)]
pub enum LeafC {
    #[k::syntax("leaf({auth}, {o})")]
    Lf { auth: Int, o: Settled },
}

/// AU-021: a carried settlement leaf with the number of its signatures that verify.
#[k::constructors(sort = Carry, result = KResult)]
pub enum CarryC {
    #[k::syntax("carry({auth_0}, {outcome}, {sigs})")]
    Cy { auth_0: Int, outcome: Settled, sigs: Int },
}

/// An `authorize` call (AU-003 to AU-009, AU-012, AU-021, AU-022, AU-027).
#[k::constructors(sort = Call, result = KResult)]
pub enum CallC {
    #[k::syntax(
        "call({rid}, {nf}, {auth}, {rh}, {source}, {slot}, {inputs_ok}, {pred_ok}, {in_gamma}, {blacklisted}, {ticket_ok}, {pin}, {to_exit}, {carry})"
    )]
    Cl {
        rid: Int,
        nf: Nf,
        auth: Int,
        rh: Int,
        source: Source,
        slot: List<SlotRef>,
        inputs_ok: Bool,
        pred_ok: Bool,
        in_gamma: Bool,
        blacklisted: Bool,
        ticket_ok: Bool,
        pin: Int,
        to_exit: Bool,
        carry: List<Carry>,
    },
}

/// AU-026: a tuple `(auth, nf, rh, root)` of a `bf_root`.
#[k::constructors(sort = BfTuple, result = KResult)]
pub enum BfTupleC {
    #[k::syntax("tuple({auth}, {nf}, {rh}, {root})")]
    Tp { auth: Int, nf: Nf, rh: Int, root: Int },
}

/// AU-013: a board-first call as the node checks it.
#[k::constructors(sort = BfCall, result = KResult)]
pub enum BfCallC {
    #[k::syntax(
        "bfCall({auth}, {nf}, {proof_ok}, {root_final}, {root_age}, {bound}, {interval}, {f_m}, {carry_sigs})"
    )]
    Bc {
        auth: Int,
        nf: Nf,
        proof_ok: Bool,
        root_final: Bool,
        root_age: Int,
        bound: Int,
        interval: Int,
        f_m: Int,
        carry_sigs: List<Int>,
    },
}

/// The refusal codes, in code order.
#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("badCarry")] BadCarry,
    #[k::syntax("boardFirstForbidden")] BoardFirstForbidden,
    #[k::syntax("boardFirstRecord")] BoardFirstRecord,
    #[k::syntax("nfPending")] NfPending,
    #[k::syntax("nfUsed")] NfUsed,
    #[k::syntax("noRuleCode")] NoRule,
    #[k::syntax("noRecovery")] NoRecovery,
    #[k::syntax("notRevocable")] NotRevocable,
    #[k::syntax("outsideCapability")] OutsideCapability,
    #[k::syntax("pinMismatch")] PinMismatch,
}

/// AU-028: the reason of a VOID post.
#[k::constructors(sort = VoidReason, result = KResult)]
pub enum VoidReasonC {
    #[k::syntax("AUTH_REFUSED")]
    AuthRefused,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("charterOp({cid}, {profile}, {board_first}, {stateful})")]
    CharterOp { cid: Int, profile: Profile, board_first: Bool, stateful: Bool },
    #[k::syntax("recordOp({rid}, {cid}, {cm_addr}, {nf}, {hold_tag}, {slr_own}, {slr_g})")]
    RecordOp { rid: Int, cid: Int, cm_addr: Int, nf: Nf, hold_tag: Int, slr_own: List<Int>, slr_g: List<Int> },
    #[k::syntax("authorizeOp({c})")] AuthorizeOp { c: Call },
    #[k::syntax("finalizeOp({a}, {h})")] FinalizeOp { a: Int, h: Int },
    #[k::syntax("revokeOp({a}, {tag})")] RevokeOp { a: Int, tag: Int },
    #[k::syntax("settleRootOp({leaves})")] SettleRootOp { leaves: List<Leaf> },
    #[k::syntax("bfRootOp({ts})")] BfRootOp { ts: List<BfTuple> },
    #[k::syntax("recoverOp")] RecoverOp,
    #[k::syntax("bfCallOp({c})")] BfCallOp { c: BfCall },
    #[k::syntax("queryOp({a}, {h})")] QueryOp { a: Int, h: Int },
    #[k::syntax("seizureOp({a}, {all_to_dreg})")] SeizureOp { a: Int, all_to_dreg: Bool },
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("accepted")] Accepted,
    #[k::syntax("refused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("ok")] Ok,
    #[k::syntax("inForce({b})")] InForce { b: Bool },
    #[k::syntax("void({reason})")] Void { reason: VoidReason },
}

// ---------------------------------------------------------------------------
// Shared helpers.

/// `opt b r`: the code `r` when `b` holds. Two of the code functions use it in place of a
/// guarded pair whose conditions the critical-pair check of kink's baseline does not join.
#[k::function(total, internal)]
pub fn Opt(b: k::Term<Bool>, r: k::Term<Refusal>) -> k::Term<List<Refusal>> {
    match b {
        true => [r],
        false => [],
    }
}

/// `nodupB`: no element occurs twice.
#[k::function(total, internal)]
pub fn NodupB(xs: k::Term<List>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] if list::contains(x, rest) => false,
        [x, rest @ ..] if !list::contains(x, rest) => NodupB(rest),
    }
}

/// `s.used.map (·.1)`: the used nullifiers.
#[k::function(total, internal)]
pub fn UsedNfs(used: k::Term<List<NfaPair>>) -> k::Term<List<Nf>> {
    match used {
        [] => [],
        [NfaPairC::Nfa { nf, .. }, rest @ ..] => [nf, ..UsedNfs(rest)],
    }
}

/// `Nf.isFresh`
#[k::function(total, internal)]
pub fn IsFresh(nf: k::Term<Nf>) -> k::Term<Bool> {
    match nf {
        NfC::Fresh { .. } => true,
        NfC::OfSettle { .. } => false,
    }
}

/// `allAuths`: every authorization of the records, in record order.
#[k::function(total, internal)]
pub fn AllAuths(rs: k::Term<List<Rec>>) -> k::Term<List<Auth>> {
    match rs {
        [] => [],
        [RecC::Rc { auths, .. }, rest @ ..] => list::concat(auths, AllAuths(rest)),
    }
}

/// `authExists`: some authorization has id `a`.
#[k::function(total, internal)]
pub fn AuthExists(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, .. }, _rest @ ..] if auth == a => true,
        [AuthC::Au { auth, .. }, rest @ ..] if auth != a => AuthExists(rest, a),
    }
}

/// `sel a b`: `b` is authorization `a` with `settled = NONE`.
#[k::function(total, internal)]
pub fn Sel(a: k::Term<Int>, b: k::Term<Auth>) -> k::Term<Bool> {
    match b {
        AuthC::Au { auth, settled, .. } => auth == a && settled.eq::<K>(SettledC::SetNone),
    }
}

/// `bs.any (sel a)`
#[k::function(total, internal)]
pub fn AnySel(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [b, _rest @ ..] if Sel(a, b) => true,
        [b, rest @ ..] if !Sel(a, b) => AnySel(rest, a),
    }
}

// ---------------------------------------------------------------------------
// Settlement (AU-020, AU-021, AU-023).

/// `upd a o b`: settle authorization `a` with outcome `o` when it is unsettled.
#[k::function(total, internal)]
pub fn Upd(a: k::Term<Int>, o: k::Term<Settled>, b: k::Term<Auth>) -> k::Term<Auth> {
    match b {
        AuthC::Au { auth, nf, rh, status, final_height, source, pin, direct, .. } if Sel(a, b) => AuthC::Au {
            auth,
            nf,
            rh,
            status,
            final_height,
            settled: o,
            source,
            pin,
            direct,
        },
        _ if !Sel(a, b) => b,
    }
}

/// `r.auths.map (upd a o)`
#[k::function(total, internal)]
pub fn UpdAll(a: k::Term<Int>, o: k::Term<Settled>, bs: k::Term<List<Auth>>) -> k::Term<List<Auth>> {
    match bs {
        [] => [],
        [b, rest @ ..] => [Upd(a, o, b), ..UpdAll(a, o, rest)],
    }
}

/// `(r.auths.find? (sel a)).bind (·.pin)`: the pin of the first unsettled authorization `a`.
/// Auth ids are unique (ledger 5), so at most one authorization is `sel a`, and the pins
/// of all of them, concatenated, are that one's pin. The walk reads the whole list.
#[k::function(total, internal)]
pub fn PinOf(a: k::Term<Int>, bs: k::Term<List<Auth>>) -> k::Term<List<Int>> {
    match bs {
        [] => [],
        [b @ AuthC::Au { pin, .. }, rest @ ..] if Sel(a, b) => list::concat(pin, PinOf(a, rest)),
        [b, rest @ ..] if !Sel(a, b) => PinOf(a, rest),
    }
}

/// `settleIn a o r` (AU-020, AU-023): settle authorization `a` of the record with
/// `o` when it has `settled = NONE`, and make the successor.
#[k::function(total, internal)]
pub fn SettleIn(a: k::Term<Int>, o: k::Term<Settled>, r: k::Term<Rec>) -> k::Term<Rec> {
    match r {
        RecC::Rc { auths, .. } if AnySel(auths, a) => SettleOutcome(a, o, r),
        RecC::Rc { auths, .. } if !AnySel(auths, a) => r,
    }
}

/// The successor of a record whose authorization `a` settles with `o` (AU-023).
/// Never applied with NONE: a `settle_root` with a NONE leaf is refused (ledger 5) and a
/// carry settles VOID only, so the oracle's `.NONE => r` branch has no equation here.
#[k::function(partial, internal)]
pub fn SettleOutcome(a: k::Term<Int>, o: k::Term<Settled>, r: k::Term<Rec>) -> k::Term<Rec> {
    match (o, r) {
        // AU-023 FINAL: the record is spent; its change record lands by itself (ledger 3).
        (
            SettledC::SetFinal,
            RecC::Rc { rid, cm_addr, profile, board_first, rstate, nf, pin, hold_tag, slr_own, slr_g, auths, .. },
        ) => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate,
            nf,
            pin,
            hold_tag,
            slr_own,
            slr_g,
            spent: true,
            auths: UpdAll(a, o, auths),
        },
        // AU-023 VOID of an authorization accepted on an UNSPENT record (`lockedAtAccept`
        // false: the record holds no pin): UNSPENT under N(nsk, auth, VOID).
        (
            SettledC::SetVoid,
            RecC::Rc { rid, cm_addr, profile, board_first, pin, hold_tag, slr_own, slr_g, spent, auths, .. },
        ) if list::size(pin) == 0 => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Unspent,
            nf: NfC::OfSettle { auth: a, o: SettledC::SetVoid },
            pin,
            hold_tag,
            slr_own,
            slr_g,
            spent,
            auths: UpdAll(a, o, auths),
        },
        // AU-023, AU-029 (DECISIONS 60): VOID of an authorization accepted on a LOCKED
        // record (`lockedAtAccept`: the record holds a pin, from its RELEASED settlement on):
        // LOCKED to the same pin, under N(nsk, auth, VOID).
        (
            SettledC::SetVoid,
            RecC::Rc { rid, cm_addr, profile, board_first, pin, hold_tag, slr_own, slr_g, spent, auths, .. },
        ) if list::size(pin) != 0 => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Locked,
            nf: NfC::OfSettle { auth: a, o: SettledC::SetVoid },
            pin,
            hold_tag,
            slr_own,
            slr_g,
            spent,
            auths: UpdAll(a, o, auths),
        },
        // AU-023 RELEASED: LOCKED to the pinned input or nonce, under N(nsk, auth, RELEASED) (ledger 4).
        (
            SettledC::SetReleased,
            RecC::Rc { rid, cm_addr, profile, board_first, hold_tag, slr_own, slr_g, spent, auths, .. },
        ) => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Locked,
            nf: NfC::OfSettle { auth: a, o: SettledC::SetReleased },
            pin: PinOf(a, auths),
            hold_tag,
            slr_own,
            slr_g,
            spent,
            auths: UpdAll(a, o, auths),
        },
    }
}

/// `settleAll`: `records.map (settleIn a o)`.
#[k::function(total, internal)]
pub fn SettleAll(a: k::Term<Int>, o: k::Term<Settled>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [SettleIn(a, o, r), ..SettleAll(a, o, rest)],
    }
}

/// AU-021: a valid carried leaf `(auth_0, VOID)` with `q` signatures.
#[k::function(total, internal)]
pub fn CarryOk(q: k::Term<Int>, k: k::Term<Carry>) -> k::Term<Bool> {
    match k {
        CarryC::Cy { outcome, sigs, .. } => outcome.eq::<K>(SettledC::SetVoid) && q <= sigs,
    }
}

/// `afterCarry`: the records after the carried settlement of a call, when the carry is valid.
#[k::function(total, internal)]
pub fn AfterCarry(q: k::Term<Int>, carry: k::Term<List<Carry>>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match carry {
        [] => rs,
        [k @ CarryC::Cy { auth_0, .. }] if CarryOk(q, k) => SettleAll(auth_0, SettledC::SetVoid, rs),
        [k] if !CarryOk(q, k) => rs,
    }
}

/// `settleLeaves`: the leaves of a `settle_root` applied to a record in order.
#[k::function(total, internal)]
pub fn SettleLeaves(leaves: k::Term<List<Leaf>>, r: k::Term<Rec>) -> k::Term<Rec> {
    match leaves {
        [] => r,
        [LeafC::Lf { auth, o }, rest @ ..] => SettleLeaves(rest, SettleIn(auth, o, r)),
    }
}

/// `records.map (settleLeaves leaves)`
#[k::function(total, internal)]
pub fn SettleRecs(leaves: k::Term<List<Leaf>>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [SettleLeaves(leaves, r), ..SettleRecs(leaves, rest)],
    }
}

// ---------------------------------------------------------------------------
// The statement (AU-005 to AU-007).

/// AU-006: owner or initiator for P0, P1 and P2; seizure for P2 only; recovery
/// exit for P1 and P2 only.
#[k::function(total, internal)]
pub fn SourceOk(p: k::Term<Profile>, s: k::Term<Source>) -> k::Term<Bool> {
    match (p, s) {
        (_, SourceC::Owner) => true,
        (ProfileC::P2, SourceC::Seizure) => true,
        (ProfileC::P0 | ProfileC::P1, SourceC::Seizure) => false,
        (ProfileC::P0, SourceC::Recovery) => false,
        (ProfileC::P1 | ProfileC::P2, SourceC::Recovery) => true,
    }
}

/// AU-007: the check table.
#[k::function(total, internal)]
pub fn ChecksOk(held: k::Term<Bool>, p: k::Term<Profile>, c: k::Term<Call>) -> k::Term<Bool> {
    match (p, c) {
        (ProfileC::P0, CallC::Cl { source: SourceC::Owner, .. }) => true,
        (ProfileC::P1, CallC::Cl { source: SourceC::Owner, pred_ok, in_gamma, .. }) => pred_ok && in_gamma,
        (ProfileC::P2, CallC::Cl { source: SourceC::Owner, pred_ok, in_gamma, blacklisted, .. }) => {
            pred_ok && in_gamma && !blacklisted && !held
        }
        (ProfileC::P2, CallC::Cl { source: SourceC::Recovery, .. }) => !held,
        (ProfileC::P0 | ProfileC::P1, CallC::Cl { source: SourceC::Recovery, .. }) => true,
        (_, CallC::Cl { source: SourceC::Seizure, .. }) => true,
    }
}

/// AU-006: the root that a source opens.
#[k::function(total, internal)]
pub fn RootOf(s: k::Term<Source>) -> k::Term<Root> {
    match s {
        SourceC::Seizure => RootC::RootG,
        SourceC::Owner | SourceC::Recovery => RootC::Own,
    }
}

/// The record's root `root` is set (`slr_own` for OWN, `slr_G` for G).
#[k::function(total, internal)]
pub fn RootSet(root: k::Term<Root>, r: k::Term<Rec>) -> k::Term<Bool> {
    match (root, r) {
        (RootC::Own, RecC::Rc { slr_own, .. }) => list::size(slr_own) > 0,
        (RootC::RootG, RecC::Rc { slr_g, .. }) => list::size(slr_g) > 0,
    }
}

/// AU-005 item 4 and AU-006: a named ECDSA slot lies under the record's own
/// root that the source opens.
#[k::function(total, internal)]
pub fn SlotOk(r: k::Term<Rec>, c: k::Term<Call>) -> k::Term<Bool> {
    match (r, c) {
        (_, CallC::Cl { slot: [], .. }) => true,
        (RecC::Rc { rid, .. }, CallC::Cl { slot: [SlotRefC::Sr { rid: rid2, root }], source, .. }) => {
            rid2 == rid && root.eq::<K>(RootOf(source)) && RootSet(root, r)
        }
    }
}

/// AU-005: items 1 to 4, and item 5 in NON_TEE mode. The operands are pure and total, so
/// their order does not change the value; the check table comes before `sourceOk` so that
/// its rows for a source the profile does not allow are evaluated (and covered) too.
#[k::function(total, internal)]
pub fn StatementOk(m: k::Term<Mode>, held: k::Term<Bool>, r: k::Term<Rec>, c: k::Term<Call>) -> k::Term<Bool> {
    match (r, c) {
        (
            RecC::Rc { nf: rnf, spent, profile, .. },
            CallC::Cl { nf, inputs_ok, source, ticket_ok, .. },
        ) => {
            nf.eq::<K>(rnf)
                && !spent
                && inputs_ok
                && ChecksOk(held, profile, c)
                && SourceOk(profile, source)
                && SlotOk(r, c)
                && (m.eq::<K>(ModeC::Tee) || ticket_ok)
        }
    }
}

// ---------------------------------------------------------------------------
// `authorize` (AU-004 to AU-009, AU-012, AU-021, AU-022, AU-027).

/// `rs.any (·.boardFirst)` over the records of `rid`.
#[k::function(total, internal)]
pub fn AnyBfRec(rs: k::Term<List<Rec>>, rid: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { rid: x, board_first, .. }, _rest @ ..] if x == rid && board_first => true,
        [RecC::Rc { rid: x, board_first, .. }, rest @ ..] if !(x == rid && board_first) => AnyBfRec(rest, rid),
    }
}

/// `rs.isEmpty` for the records of `rid`.
#[k::function(total, internal)]
pub fn HasRid(rs: k::Term<List<Rec>>, rid: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { rid: x, .. }, _rest @ ..] if x == rid => true,
        [RecC::Rc { rid: x, .. }, rest @ ..] if x != rid => HasRid(rest, rid),
    }
}

/// `rs.any (fun r => !statementOk mode (held r) r c)` over the records of the call's `rid`.
#[k::function(total, internal)]
pub fn AnyBadStatement(
    m: k::Term<Mode>,
    holds: k::Term<List<Int>>,
    rs: k::Term<List<Rec>>,
    c: k::Term<Call>,
) -> k::Term<Bool> {
    match (rs, c) {
        ([], _) => false,
        ([r @ RecC::Rc { rid: x, hold_tag, .. }, _rest @ ..], CallC::Cl { rid, .. })
            if x == rid && !StatementOk(m, list::contains(hold_tag, holds), r, c) =>
        {
            true
        }
        ([r @ RecC::Rc { rid: x, hold_tag, .. }, rest @ ..], CallC::Cl { rid, .. })
            if !(x == rid && !StatementOk(m, list::contains(hold_tag, holds), r, c)) =>
        {
            AnyBadStatement(m, holds, rest, c)
        }
    }
}

/// `rs.any (fun r => r.rstate == .LOCKED && r.pin != some c.pin)` over the records of `rid`.
#[k::function(total, internal)]
pub fn AnyPinMismatch(rs: k::Term<List<Rec>>, rid: k::Term<Int>, pin: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { rid: x, rstate, pin: rpin, .. }, _rest @ ..]
            if x == rid && rstate.eq::<K>(RStateC::Locked) && rpin.ne::<K>(list::item(pin)) =>
        {
            true
        }
        [RecC::Rc { rid: x, rstate, pin: rpin, .. }, rest @ ..]
            if !(x == rid && rstate.eq::<K>(RStateC::Locked) && rpin.ne::<K>(list::item(pin))) =>
        {
            AnyPinMismatch(rest, rid, pin)
        }
    }
}

/// AU-022: `bad_carry` when a carry is present and not valid.
#[k::function(total, internal)]
pub fn CarryCode(q: k::Term<Int>, carry: k::Term<List<Carry>>) -> k::Term<List<Refusal>> {
    match carry {
        [] => [],
        [k] if !CarryOk(q, k) => [RefusalC::BadCarry],
        [k] if CarryOk(q, k) => [],
    }
}

/// AU-012: `board_first_record`.
#[k::function(total, internal)]
pub fn BfRecordCode(rs1: k::Term<List<Rec>>, rid: k::Term<Int>) -> k::Term<List<Refusal>> {
    if AnyBfRec(rs1, rid) { [RefusalC::BoardFirstRecord] } else { [] }
}

/// AU-008: `nf_used`.
#[k::function(total, internal)]
pub fn NfUsedCode(used: k::Term<List<NfaPair>>, nf: k::Term<Nf>) -> k::Term<List<Refusal>> {
    if list::contains(nf, UsedNfs(used)) { [RefusalC::NfUsed] } else { [] }
}

/// Ledger 6: a valid carry whose `auth_0` has no unsettled authorization.
#[k::function(total, internal)]
pub fn CarryNoRule(q: k::Term<Int>, carry: k::Term<List<Carry>>, bs: k::Term<List<Auth>>) -> k::Term<Bool> {
    match carry {
        [] => false,
        [k @ CarryC::Cy { auth_0, .. }] if CarryOk(q, k) => !AnySel(bs, auth_0),
        [k] if !CarryOk(q, k) => false,
    }
}

/// AU-005 to AU-007 (ledger 2): `no-rule` when the record is missing, the carry has
/// no unsettled authorization, or the statement fails.
#[k::function(total, internal)]
pub fn StatementCode(
    m: k::Term<Mode>,
    q: k::Term<Int>,
    holds: k::Term<List<Int>>,
    rs0: k::Term<List<Rec>>,
    rs1: k::Term<List<Rec>>,
    c: k::Term<Call>,
) -> k::Term<List<Refusal>> {
    match c {
        CallC::Cl { rid, carry, .. } => Opt(
            !HasRid(rs1, rid) || CarryNoRule(q, carry, AllAuths(rs0)) || AnyBadStatement(m, holds, rs1, c),
            RefusalC::NoRule,
        ),
    }
}

/// AU-027: `no_recovery` for the recovery source before `recover` or not to `D_exit`.
#[k::function(total, internal)]
pub fn RecoveryCode(recovered: k::Term<Bool>, c: k::Term<Call>) -> k::Term<List<Refusal>> {
    match c {
        CallC::Cl { source, to_exit, .. } if source.eq::<K>(SourceC::Recovery) && (!recovered || !to_exit) => {
            [RefusalC::NoRecovery]
        }
        CallC::Cl { source, to_exit, .. } if !(source.eq::<K>(SourceC::Recovery) && (!recovered || !to_exit)) => [],
    }
}

/// Ledger 5: the call's `auth` is not fresh (it exists, or the carry settles it).
#[k::function(total, internal)]
pub fn FreshAuth(bs: k::Term<List<Auth>>, c: k::Term<Call>) -> k::Term<Bool> {
    match c {
        CallC::Cl { auth, carry: [], .. } => !AuthExists(bs, auth),
        CallC::Cl { auth, carry: [CarryC::Cy { auth_0, .. }], .. } => !AuthExists(bs, auth) && auth_0 != auth,
    }
}

/// Ledger 5: `outside-capability` for an `auth` that is not fresh.
#[k::function(total, internal)]
pub fn FreshCode(bs: k::Term<List<Auth>>, c: k::Term<Call>) -> k::Term<List<Refusal>> {
    if !FreshAuth(bs, c) { [RefusalC::OutsideCapability] } else { [] }
}

/// AU-009: `pin_mismatch`.
#[k::function(total, internal)]
pub fn PinCode(rs1: k::Term<List<Rec>>, c: k::Term<Call>) -> k::Term<List<Refusal>> {
    match c {
        CallC::Cl { rid, pin, .. } if AnyPinMismatch(rs1, rid, pin) => [RefusalC::PinMismatch],
        CallC::Cl { rid, pin, .. } if !AnyPinMismatch(rs1, rid, pin) => [],
    }
}

/// `authorizeRefusals` over the records after a valid carry, in code order.
#[k::function(total, internal)]
pub fn AuthorizeRefusals(
    params: k::Term<Params>,
    records: k::Term<List<Rec>>,
    used: k::Term<List<NfaPair>>,
    holds: k::Term<List<Int>>,
    recovered: k::Term<Bool>,
    c: k::Term<Call>,
) -> k::Term<List<Refusal>> {
    match (params, c) {
        (ParamsC::Params { mode, q }, CallC::Cl { rid, nf, carry, .. }) => list::concat(
            CarryCode(q, carry),
            list::concat(
                BfRecordCode(AfterCarry(q, carry, records), rid),
                list::concat(
                    NfUsedCode(used, nf),
                    list::concat(
                        StatementCode(mode, q, holds, records, AfterCarry(q, carry, records), c),
                        list::concat(
                            RecoveryCode(recovered, c),
                            list::concat(
                                FreshCode(AllAuths(records), c),
                                PinCode(AfterCarry(q, carry, records), c),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    }
}

/// `newAuth`
#[k::function(total, internal)]
pub fn NewAuth(c: k::Term<Call>) -> k::Term<Auth> {
    match c {
        CallC::Cl { nf, auth, rh, source, pin, .. } => AuthC::Au {
            auth,
            nf,
            rh,
            status: StatusC::Submitted,
            final_height: [],
            settled: SettledC::SetNone,
            source: [source],
            pin: [pin],
            direct: true,
        },
    }
}

/// `addAuth` (AU-004): the record goes PENDING and the authorization is added SUBMITTED.
#[k::function(total, internal)]
pub fn AddAuth(c: k::Term<Call>, r: k::Term<Rec>) -> k::Term<Rec> {
    match (c, r) {
        (
            CallC::Cl { rid: crid, .. },
            RecC::Rc { rid, cm_addr, profile, board_first, nf, pin, hold_tag, slr_own, slr_g, spent, auths, .. },
        ) if rid == crid => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Pending,
            nf,
            pin,
            hold_tag,
            slr_own,
            slr_g,
            spent,
            auths: [NewAuth(c), ..auths],
        },
        (CallC::Cl { rid: crid, .. }, RecC::Rc { rid, .. }) if rid != crid => r,
    }
}

/// `records.map (addAuth c)`
#[k::function(total, internal)]
pub fn AddAuthAll(c: k::Term<Call>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [AddAuth(c, r), ..AddAuthAll(c, rest)],
    }
}

/// The used pair `(nf, auth)` of a call.
#[k::function(total, internal)]
pub fn UsedOf(c: k::Term<Call>) -> k::Term<NfaPair> {
    match c {
        CallC::Cl { nf, auth, .. } => NfaPairC::Nfa { nf, a: auth },
    }
}

/// The carry of a call (`[]` or `[k]`).
#[k::function(total, internal)]
pub fn CarryOf(c: k::Term<Call>) -> k::Term<List<Carry>> {
    match c {
        CallC::Cl { carry, .. } => carry,
    }
}

/// `q` of the parameters.
#[k::function(total, internal)]
pub fn QOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { q, .. } => q,
    }
}

// ---------------------------------------------------------------------------
// `charter` and `record` (AU-001, AU-011; ledger 5).

/// AU-011: `board_first` with P2 or a stateful predicate.
#[k::function(total, internal)]
pub fn BfForbiddenCode(p: k::Term<Profile>, bf: k::Term<Bool>, stateful: k::Term<Bool>) -> k::Term<List<Refusal>> {
    if bf && (p.eq::<K>(ProfileC::P2) || stateful) { [RefusalC::BoardFirstForbidden] } else { [] }
}

/// `s.charters.any (·.cid == cid)`
#[k::function(total, internal)]
pub fn HasCid(chs: k::Term<List<Charter>>, cid: k::Term<Int>) -> k::Term<Bool> {
    match chs {
        [] => false,
        [CharterC::Ch { cid: x, .. }, _rest @ ..] if x == cid => true,
        [CharterC::Ch { cid: x, .. }, rest @ ..] if x != cid => HasCid(rest, cid),
    }
}

/// Ledger 5: a charter id twice.
#[k::function(total, internal)]
pub fn CidCode(chs: k::Term<List<Charter>>, cid: k::Term<Int>) -> k::Term<List<Refusal>> {
    if HasCid(chs, cid) { [RefusalC::OutsideCapability] } else { [] }
}

/// The charter refusals: AU-011, then ledger 5.
#[k::function(total, internal)]
pub fn CharterRefusals(
    chs: k::Term<List<Charter>>,
    cid: k::Term<Int>,
    p: k::Term<Profile>,
    bf: k::Term<Bool>,
    stateful: k::Term<Bool>,
) -> k::Term<List<Refusal>> {
    list::concat(BfForbiddenCode(p, bf, stateful), CidCode(chs, cid))
}

/// `s.charters.find? (·.cid == cid)`, as a list of at most one charter.
#[k::function(total, internal)]
pub fn FindCharter(chs: k::Term<List<Charter>>, cid: k::Term<Int>) -> k::Term<List<Charter>> {
    match chs {
        [] => [],
        [ch @ CharterC::Ch { cid: x, .. }, _rest @ ..] if x == cid => [ch],
        [CharterC::Ch { cid: x, .. }, rest @ ..] if x != cid => FindCharter(rest, cid),
    }
}

/// `s.records.any (·.rid == rid)`
#[k::function(total, internal)]
pub fn AnyRid(rs: k::Term<List<Rec>>, rid: k::Term<Int>) -> k::Term<Bool> {
    HasRid(rs, rid)
}

/// `s.records.any (·.nf == nf)`
#[k::function(total, internal)]
pub fn AnyRecNf(rs: k::Term<List<Rec>>, nf: k::Term<Nf>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { nf: x, .. }, _rest @ ..] if x.eq::<K>(nf) => true,
        [RecC::Rc { nf: x, .. }, rest @ ..] if x.ne::<K>(nf) => AnyRecNf(rest, nf),
    }
}

/// Ledger 5: a record id twice, a birth nullifier that is not fresh or is in use,
/// `slr_G` on a record whose charter is not P2.
#[k::function(total, internal)]
pub fn RecordOutside(
    ch: k::Term<Charter>,
    rs: k::Term<List<Rec>>,
    used: k::Term<List<NfaPair>>,
    rid: k::Term<Int>,
    nf: k::Term<Nf>,
    slr_g: k::Term<List<Int>>,
) -> k::Term<Bool> {
    match ch {
        CharterC::Ch { profile, .. } => {
            // `Any3` evaluates every operand (no short circuit).
            Any3(
                Any3(AnyRid(rs, rid), !IsFresh(nf), list::contains(nf, UsedNfs(used))),
                AnyRecNf(rs, nf),
                list::size(slr_g) > 0 && profile.ne::<K>(ProfileC::P2),
            )
        }
    }
}

/// The record refusals: no charter (`no-rule`), or ledger 5.
#[k::function(total, internal)]
pub fn RecordRefusals(
    found: k::Term<List<Charter>>,
    rs: k::Term<List<Rec>>,
    used: k::Term<List<NfaPair>>,
    rid: k::Term<Int>,
    nf: k::Term<Nf>,
    slr_g: k::Term<List<Int>>,
) -> k::Term<List<Refusal>> {
    match found {
        [] => [RefusalC::NoRule],
        [ch] if RecordOutside(ch, rs, used, rid, nf, slr_g) => [RefusalC::OutsideCapability],
        [ch] if !RecordOutside(ch, rs, used, rid, nf, slr_g) => [],
    }
}

/// `newRec` (AU-001): UNSPENT with a fresh `nf`, under the charter's profile and `board_first`.
#[k::function(partial, internal)]
pub fn NewRec(
    found: k::Term<List<Charter>>,
    rid: k::Term<Int>,
    cm_addr: k::Term<Int>,
    nf: k::Term<Nf>,
    hold_tag: k::Term<Int>,
    slr_own: k::Term<List<Int>>,
    slr_g: k::Term<List<Int>>,
) -> k::Term<Rec> {
    match found {
        [CharterC::Ch { profile, board_first, .. }] => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Unspent,
            nf,
            pin: [],
            hold_tag,
            slr_own,
            slr_g,
            spent: false,
            auths: [],
        },
    }
}

// ---------------------------------------------------------------------------
// `finalize`, `revoke` (AU-002, AU-010, AU-018, AU-019; ledgers 9, 10).

/// `allAuths.any (fun b => b.auth == a && b.status == .SUBMITTED)`
#[k::function(total, internal)]
pub fn AnySubmitted(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, status, .. }, _rest @ ..] if auth == a && status.eq::<K>(StatusC::Submitted) => true,
        [AuthC::Au { auth, status, .. }, rest @ ..] if !(auth == a && status.eq::<K>(StatusC::Submitted)) => {
            AnySubmitted(rest, a)
        }
    }
}

/// Ledger 10: `finalize` of an authorization that is not SUBMITTED.
#[k::function(total, internal)]
pub fn FinalizeRefusals(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<List<Refusal>> {
    if !AnySubmitted(bs, a) { [RefusalC::NoRule] } else { [] }
}

/// `finalIn a h` (AU-002, AU-010): SUBMITTED becomes FINAL at height `h`.
#[k::function(total, internal)]
pub fn FinalIn(a: k::Term<Int>, h: k::Term<Int>, b: k::Term<Auth>) -> k::Term<Auth> {
    match b {
        AuthC::Au { auth, nf, rh, status, settled, source, pin, direct, .. }
            if auth == a && status.eq::<K>(StatusC::Submitted) =>
        {
            AuthC::Au { auth, nf, rh, status: StatusC::StFinal, final_height: [h], settled, source, pin, direct }
        }
        AuthC::Au { auth, status, .. } if !(auth == a && status.eq::<K>(StatusC::Submitted)) => b,
    }
}

/// `revokeIn a` (AU-018): REVOKED.
#[k::function(total, internal)]
pub fn RevokeIn(a: k::Term<Int>, b: k::Term<Auth>) -> k::Term<Auth> {
    match b {
        AuthC::Au { auth, nf, rh, final_height, settled, source, pin, direct, .. } if auth == a => {
            AuthC::Au { auth, nf, rh, status: StatusC::Revoked, final_height, settled, source, pin, direct }
        }
        AuthC::Au { auth, .. } if auth != a => b,
    }
}

/// The two maps over authorizations, by a tag: `FinalTag(h)` or `RevokeTag`.
#[k::constructors(sort = AuthMap, result = KResult)]
#[rustfmt::skip]
pub enum AuthMapC {
    #[k::syntax("finalTag({h})")] FinalTag { h: Int },
    #[k::syntax("revokeTag")] RevokeTag,
}

/// One authorization mapped by the tag.
#[k::function(total, internal)]
pub fn MapAuth(f: k::Term<AuthMap>, a: k::Term<Int>, b: k::Term<Auth>) -> k::Term<Auth> {
    match f {
        AuthMapC::FinalTag { h } => FinalIn(a, h, b),
        AuthMapC::RevokeTag => RevokeIn(a, b),
    }
}

/// `auths.map (f a)`
#[k::function(total, internal)]
pub fn MapAuths(f: k::Term<AuthMap>, a: k::Term<Int>, bs: k::Term<List<Auth>>) -> k::Term<List<Auth>> {
    match bs {
        [] => [],
        [b, rest @ ..] => [MapAuth(f, a, b), ..MapAuths(f, a, rest)],
    }
}

/// `records.map (fun r => { r with auths := r.auths.map (f a) })`
#[k::function(total, internal)]
pub fn MapRecAuths(f: k::Term<AuthMap>, a: k::Term<Int>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [RecC::Rc { rid, cm_addr, profile, board_first, rstate, nf, pin, hold_tag, slr_own, slr_g, spent, auths }, rest @ ..] => [
            RecC::Rc {
                rid,
                cm_addr,
                profile,
                board_first,
                rstate,
                nf,
                pin,
                hold_tag,
                slr_own,
                slr_g,
                spent,
                auths: MapAuths(f, a, auths),
            },
            ..MapRecAuths(f, a, rest)
        ],
    }
}

/// Ledger 9: no record holds `a`, a hit record has another tag, or `a` is REVOKED.
#[k::function(total, internal)]
/// The three operands are arguments of `Any3`, so each is evaluated (no short circuit).
pub fn RevokeNoRule(rs: k::Term<List<Rec>>, a: k::Term<Int>, tag: k::Term<Int>) -> k::Term<Bool> {
    Any3(!AnyHit(rs, a), AnyHitOtherTag(rs, a, tag), AnyRevoked(AllAuths(rs), a))
}

/// `x || y || z`, with every operand evaluated.
#[k::function(total, internal)]
pub fn Any3(x: k::Term<Bool>, y: k::Term<Bool>, z: k::Term<Bool>) -> k::Term<Bool> {
    match (x, y, z) {
        (true, _, _) => true,
        (false, true, _) => true,
        (false, false, true) => true,
        (false, false, false) => false,
    }
}

/// `hits` is not empty: some record has an authorization `a`.
#[k::function(total, internal)]
pub fn AnyHit(rs: k::Term<List<Rec>>, a: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { auths, .. }, _rest @ ..] if AuthExists(auths, a) => true,
        [RecC::Rc { auths, .. }, rest @ ..] if !AuthExists(auths, a) => AnyHit(rest, a),
    }
}

/// `hits.any (fun r => r.holdTag != tag)`
#[k::function(total, internal)]
pub fn AnyHitOtherTag(rs: k::Term<List<Rec>>, a: k::Term<Int>, tag: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { auths, hold_tag, .. }, _rest @ ..] if AuthExists(auths, a) && hold_tag != tag => true,
        [RecC::Rc { auths, hold_tag, .. }, rest @ ..] if !(AuthExists(auths, a) && hold_tag != tag) => {
            AnyHitOtherTag(rest, a, tag)
        }
    }
}

/// `hits.any (fun r => r.profile != .P2)`
#[k::function(total, internal)]
pub fn AnyHitNotP2(rs: k::Term<List<Rec>>, a: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { auths, profile, .. }, _rest @ ..] if AuthExists(auths, a) && profile.ne::<K>(ProfileC::P2) => {
            true
        }
        [RecC::Rc { auths, profile, .. }, rest @ ..] if !(AuthExists(auths, a) && profile.ne::<K>(ProfileC::P2)) => {
            AnyHitNotP2(rest, a)
        }
    }
}

/// `bs.any (fun b => b.status == .REVOKED)` over the authorizations `a`.
#[k::function(total, internal)]
pub fn AnyRevoked(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, status, .. }, _rest @ ..] if auth == a && status.eq::<K>(StatusC::Revoked) => true,
        [AuthC::Au { auth, status, .. }, rest @ ..] if !(auth == a && status.eq::<K>(StatusC::Revoked)) => {
            AnyRevoked(rest, a)
        }
    }
}

/// `bs.any (fun b => !b.settled.isNone)` over the authorizations `a`.
#[k::function(total, internal)]
pub fn AnySettled(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, settled, .. }, _rest @ ..] if auth == a && settled.ne::<K>(SettledC::SetNone) => true,
        [AuthC::Au { auth, settled, .. }, rest @ ..] if !(auth == a && settled.ne::<K>(SettledC::SetNone)) => {
            AnySettled(rest, a)
        }
    }
}

/// `revokeRefusals` (AU-018, AU-019, ledger 9).
#[k::function(total, internal)]
pub fn RevokeRefusals(rs: k::Term<List<Rec>>, a: k::Term<Int>, tag: k::Term<Int>) -> k::Term<List<Refusal>> {
    list::concat(RevokeNoRuleCode(rs, a, tag), NotRevocableCode(rs, a))
}

#[k::function(total, internal)]
pub fn RevokeNoRuleCode(rs: k::Term<List<Rec>>, a: k::Term<Int>, tag: k::Term<Int>) -> k::Term<List<Refusal>> {
    Opt(RevokeNoRule(rs, a, tag), RefusalC::NoRule)
}

/// AU-019: a P0 or P1 record, or `settled ≠ NONE`.
#[k::function(total, internal)]
pub fn NotRevocableCode(rs: k::Term<List<Rec>>, a: k::Term<Int>) -> k::Term<List<Refusal>> {
    if Any3(AnyHitNotP2(rs, a), AnySettled(AllAuths(rs), a), false) { [RefusalC::NotRevocable] } else { [] }
}

// ---------------------------------------------------------------------------
// `settle_root`, `bf_root` (AU-020, AU-026; ledgers 5, 8).

/// Ledger 5: a leaf with outcome NONE.
#[k::function(total, internal)]
pub fn AnyNoneLeaf(leaves: k::Term<List<Leaf>>) -> k::Term<Bool> {
    match leaves {
        [] => false,
        [LeafC::Lf { o, .. }, _rest @ ..] if o.eq::<K>(SettledC::SetNone) => true,
        [LeafC::Lf { o, .. }, rest @ ..] if o.ne::<K>(SettledC::SetNone) => AnyNoneLeaf(rest),
    }
}

#[k::function(total, internal)]
pub fn SettleRootRefusals(leaves: k::Term<List<Leaf>>) -> k::Term<List<Refusal>> {
    if AnyNoneLeaf(leaves) { [RefusalC::OutsideCapability] } else { [] }
}

/// `s.records.any (fun r => r.boardFirst && r.nf == nf)`
#[k::function(total, internal)]
pub fn BfRecHasNf(rs: k::Term<List<Rec>>, nf: k::Term<Nf>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rc { board_first, nf: x, .. }, _rest @ ..] if board_first && x.eq::<K>(nf) => true,
        [RecC::Rc { board_first, nf: x, .. }, rest @ ..] if !(board_first && x.eq::<K>(nf)) => BfRecHasNf(rest, nf),
    }
}

/// Ledger 8: every tuple's `nf` is a board-first record's.
#[k::function(total, internal)]
pub fn AllTuplesNamed(ts: k::Term<List<BfTuple>>, rs: k::Term<List<Rec>>) -> k::Term<Bool> {
    match ts {
        [] => true,
        [BfTupleC::Tp { nf, .. }, _rest @ ..] if !BfRecHasNf(rs, nf) => false,
        [BfTupleC::Tp { nf, .. }, rest @ ..] if BfRecHasNf(rs, nf) => AllTuplesNamed(rest, rs),
    }
}

/// Ledger 5: a tuple whose `auth` exists.
#[k::function(total, internal)]
pub fn AnyTupleAuthExists(ts: k::Term<List<BfTuple>>, bs: k::Term<List<Auth>>) -> k::Term<Bool> {
    match ts {
        [] => false,
        [BfTupleC::Tp { auth, .. }, _rest @ ..] if AuthExists(bs, auth) => true,
        [BfTupleC::Tp { auth, .. }, rest @ ..] if !AuthExists(bs, auth) => AnyTupleAuthExists(rest, bs),
    }
}

/// `ts.map (·.auth)`
#[k::function(total, internal)]
pub fn TupleAuths(ts: k::Term<List<BfTuple>>) -> k::Term<List<Int>> {
    match ts {
        [] => [],
        [BfTupleC::Tp { auth, .. }, rest @ ..] => [auth, ..TupleAuths(rest)],
    }
}

/// `ts.map (·.nf)`
#[k::function(total, internal)]
pub fn TupleNfs(ts: k::Term<List<BfTuple>>) -> k::Term<List<Nf>> {
    match ts {
        [] => [],
        [BfTupleC::Tp { nf, .. }, rest @ ..] => [nf, ..TupleNfs(rest)],
    }
}

#[k::function(total, internal)]
pub fn BfRootNoRuleCode(ts: k::Term<List<BfTuple>>, rs: k::Term<List<Rec>>) -> k::Term<List<Refusal>> {
    if !AllTuplesNamed(ts, rs) { [RefusalC::NoRule] } else { [] }
}

#[k::function(total, internal)]
pub fn BfRootOutsideCode(ts: k::Term<List<BfTuple>>, rs: k::Term<List<Rec>>) -> k::Term<List<Refusal>> {
    if Any3(AnyTupleAuthExists(ts, AllAuths(rs)), !NodupB(TupleAuths(ts)), false) { [RefusalC::OutsideCapability] } else { [] }
}

/// The `bf_root` refusals (AU-026, ledgers 5 and 8).
#[k::function(total, internal)]
pub fn BfRootRefusals(ts: k::Term<List<BfTuple>>, rs: k::Term<List<Rec>>) -> k::Term<List<Refusal>> {
    list::concat(BfRootNoRuleCode(ts, rs), BfRootOutsideCode(ts, rs))
}

/// `bfIn t r` (AU-026): a board-first record whose current `nf` is the tuple's goes
/// PENDING under its `auth`.
#[k::function(total, internal)]
pub fn BfIn(t: k::Term<BfTuple>, r: k::Term<Rec>) -> k::Term<Rec> {
    match (t, r) {
        (
            BfTupleC::Tp { auth, nf: tnf, rh, .. },
            RecC::Rc { rid, cm_addr, profile, board_first, nf, pin, hold_tag, slr_own, slr_g, spent, auths, .. },
        ) if board_first && nf.eq::<K>(tnf) => RecC::Rc {
            rid,
            cm_addr,
            profile,
            board_first,
            rstate: RStateC::Pending,
            nf,
            pin,
            hold_tag,
            slr_own,
            slr_g,
            spent,
            auths: [
                AuthC::Au {
                    auth,
                    nf: tnf,
                    rh,
                    status: StatusC::Submitted,
                    final_height: [],
                    settled: SettledC::SetNone,
                    source: [],
                    pin: [],
                    direct: false,
                },
                ..auths
            ],
        },
        (BfTupleC::Tp { nf: tnf, .. }, RecC::Rc { board_first, nf, .. }) if !(board_first && nf.eq::<K>(tnf)) => r,
    }
}

/// `bfAll ts r`: the tuples applied to a record in order.
#[k::function(total, internal)]
pub fn BfAll(ts: k::Term<List<BfTuple>>, r: k::Term<Rec>) -> k::Term<Rec> {
    match ts {
        [] => r,
        [t, rest @ ..] => BfAll(rest, BfIn(t, r)),
    }
}

/// `records.map (bfAll ts)`
#[k::function(total, internal)]
pub fn BfRecs(ts: k::Term<List<BfTuple>>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [BfAll(ts, r), ..BfRecs(ts, rest)],
    }
}

/// `pending.filter (fun x => !nfs.contains x)`
#[k::function(total, internal)]
pub fn DropNfs(pending: k::Term<List<Nf>>, nfs: k::Term<List<Nf>>) -> k::Term<List<Nf>> {
    match pending {
        [] => [],
        [x, rest @ ..] if list::contains(x, nfs) => DropNfs(rest, nfs),
        [x, rest @ ..] if !list::contains(x, nfs) => [x, ..DropNfs(rest, nfs)],
    }
}

// ---------------------------------------------------------------------------
// `bf_call`, `query`, `seizure` (AU-010, AU-013 to AU-016, AU-028).

/// AU-013: the checks of a board-first call at the node.
#[k::function(total, internal)]
pub fn BfChecks(q: k::Term<Int>, landed: k::Term<List<Nf>>, c: k::Term<BfCall>) -> k::Term<Bool> {
    match c {
        BfCallC::Bc { nf, proof_ok, root_final, root_age, bound, interval, f_m, carry_sigs, .. } => {
            proof_ok
                && root_final
                && root_age + interval + f_m <= bound
                && !list::contains(nf, landed)
                && CarrySigsOk(q, carry_sigs)
        }
    }
}

/// AU-013: a reissue's carried VOID leaf has `q` signatures that verify.
#[k::function(total, internal)]
pub fn CarrySigsOk(q: k::Term<Int>, sigs: k::Term<List<Int>>) -> k::Term<Bool> {
    match sigs {
        [] => true,
        [k] => q <= k,
    }
}

/// AU-013 (`no-rule`), then AU-015 (`nf_pending`, a verified call only).
#[k::function(total, internal)]
pub fn BfCallRefusals(
    q: k::Term<Int>,
    pending: k::Term<List<Nf>>,
    landed: k::Term<List<Nf>>,
    c: k::Term<BfCall>,
) -> k::Term<List<Refusal>> {
    match c {
        _ if !BfChecks(q, landed, c) => [RefusalC::NoRule],
        BfCallC::Bc { nf, .. } if BfChecks(q, landed, c) && list::contains(nf, pending) => [RefusalC::NfPending],
        BfCallC::Bc { nf, .. } if BfChecks(q, landed, c) && !list::contains(nf, pending) => [],
    }
}

/// The call's `nf`.
#[k::function(total, internal)]
pub fn CallNf(c: k::Term<BfCall>) -> k::Term<Nf> {
    match c {
        BfCallC::Bc { nf, .. } => nf,
    }
}

/// AU-016: the call's `(auth, nf)`, in force at the node.
#[k::function(total, internal)]
pub fn CallAn(c: k::Term<BfCall>) -> k::Term<AnPair> {
    match c {
        BfCallC::Bc { auth, nf, .. } => AnPairC::An { a: auth, nf },
    }
}

/// `finalAt h b` (AU-010): final at or below Midnight height `h`.
#[k::function(total, internal)]
pub fn FinalAt(h: k::Term<Int>, fh: k::Term<List<Int>>) -> k::Term<Bool> {
    match fh {
        [] => false,
        [f] => f <= h,
    }
}

/// `inForceMidnight` (AU-010).
#[k::function(total, internal)]
pub fn InForceMidnight(bs: k::Term<List<Auth>>, a: k::Term<Int>, h: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, final_height, .. }, _rest @ ..] if auth == a && FinalAt(h, final_height) => true,
        [AuthC::Au { auth, final_height, .. }, rest @ ..] if !(auth == a && FinalAt(h, final_height)) => {
            InForceMidnight(rest, a, h)
        }
    }
}

/// `inForceBoard` (AU-016): `inForce.any (·.1 == a)`
#[k::function(total, internal)]
pub fn AnyAn(xs: k::Term<List<AnPair>>, a: k::Term<Int>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [AnPairC::An { a: x, .. }, _rest @ ..] if x == a => true,
        [AnPairC::An { a: x, .. }, rest @ ..] if x != a => AnyAn(rest, a),
    }
}

/// AU-028: the request's authorization uses the seizure-order source.
#[k::function(total, internal)]
pub fn AnySeizureAuth(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<Bool> {
    match bs {
        [] => false,
        [AuthC::Au { auth, source, .. }, _rest @ ..] if auth == a && source.eq::<K>(list::item(SourceC::Seizure)) => {
            true
        }
        [AuthC::Au { auth, source, .. }, rest @ ..] if !(auth == a && source.eq::<K>(list::item(SourceC::Seizure))) => {
            AnySeizureAuth(rest, a)
        }
    }
}

#[k::function(total, internal)]
pub fn SeizureRefusals(bs: k::Term<List<Auth>>, a: k::Term<Int>) -> k::Term<List<Refusal>> {
    if !AnySeizureAuth(bs, a) { [RefusalC::NoRule] } else { [] }
}

/// AU-028: a seizure output that does not pay `D_reg` is VOID AUTH_REFUSED.
#[k::function(total, internal)]
pub fn SeizureObs(all_to_dreg: k::Term<Bool>) -> k::Term<Obs> {
    if all_to_dreg { ObsC::Ok } else { ObsC::Void { reason: VoidReasonC::AuthRefused } }
}

// ---------------------------------------------------------------------------
// Configuration.

#[k::configuration]
pub struct Machine {
    #[k::cell]
    pub k: KSequence,
    #[k::cell]
    pub params: Params,
    #[k::cell]
    pub charters: List<Charter>,
    #[k::cell]
    pub records: List<Rec>,
    #[k::cell]
    pub used: List<NfaPair>,
    #[k::cell]
    pub holds: List<Int>,
    #[k::cell]
    pub recovered: Bool,
    #[k::cell]
    pub pending: List<Nf>,
    #[k::cell]
    pub inforce: List<AnPair>,
    #[k::cell]
    pub landed: List<Nf>,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: no charter, record, used nullifier or hold; no recovery; an empty node view.
    #[k::init]
    pub fn init(params: Params, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            charters: [],
            records: [],
            used: [],
            holds: [],
            recovered: false,
            pending: [],
            inforce: [],
            landed: [],
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // AU-011: a charter registers (appended).
    #[k::requires(list::size(CharterRefusals(charters, cid, profile, board_first, stateful)) == 0)]
    charter: {
        k: [Step::Go, ..],
        charters,
        ops: [OpC::CharterOp { cid, profile, board_first, stateful }, ..],
        obs,
    } => {
        charters: [..charters, CharterC::Ch { cid, profile, board_first }],
        ops: [..],
        obs: [..obs, ObsC::Accepted],
    };

    // AU-011, ledger 5: a refused charter.
    #[k::requires(list::size(CharterRefusals(charters, cid, profile, board_first, stateful)) != 0)]
    charter_refuse: {
        k: [Step::Go, ..],
        charters,
        ops: [OpC::CharterOp { cid, profile, board_first, stateful }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: CharterRefusals(charters, cid, profile, board_first, stateful) }],
    };

    // AU-001: a record lands UNSPENT under its charter (appended).
    #[k::requires(list::size(RecordRefusals(FindCharter(charters, cid), records, used, rid, nf, slr_g)) == 0)]
    record: {
        k: [Step::Go, ..],
        charters,
        records,
        used,
        ops: [OpC::RecordOp { rid, cid, cm_addr, nf, hold_tag, slr_own, slr_g }, ..],
        obs,
    } => {
        records: [..records, NewRec(FindCharter(charters, cid), rid, cm_addr, nf, hold_tag, slr_own, slr_g)],
        ops: [..],
        obs: [..obs, ObsC::Accepted],
    };

    // AU-001, ledger 5: a record without a charter, or outside the domain.
    #[k::requires(list::size(RecordRefusals(FindCharter(charters, cid), records, used, rid, nf, slr_g)) != 0)]
    record_refuse: {
        k: [Step::Go, ..],
        charters,
        records,
        used,
        ops: [OpC::RecordOp { rid, cid, nf, slr_g, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: RecordRefusals(FindCharter(charters, cid), records, used, rid, nf, slr_g) }],
    };

    // AU-004, AU-021: the carried VOID leaf settles auth_0, the record goes PENDING
    // with the authorization SUBMITTED, and (nf, auth) is used (newest first).
    #[k::requires(list::size(AuthorizeRefusals(params, records, used, holds, recovered, c)) == 0)]
    authorize: {
        k: [Step::Go, ..],
        params,
        records,
        used,
        holds,
        recovered,
        ops: [OpC::AuthorizeOp { c }, ..],
        obs,
    } => {
        records: AddAuthAll(c, AfterCarry(QOf(params), CarryOf(c), records)),
        used: [UsedOf(c), ..used],
        ops: [..],
        obs: [..obs, ObsC::Accepted],
    };

    // AU-005 to AU-009, AU-012, AU-022, AU-027: a refused call, every code in code order.
    #[k::requires(list::size(AuthorizeRefusals(params, records, used, holds, recovered, c)) != 0)]
    authorize_refuse: {
        k: [Step::Go, ..],
        params,
        records,
        used,
        holds,
        recovered,
        ops: [OpC::AuthorizeOp { c }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: AuthorizeRefusals(params, records, used, holds, recovered, c) }],
    };

    // AU-002, AU-010: the authorize transaction of `a` is final at Midnight height `h`.
    #[k::requires(list::size(FinalizeRefusals(AllAuths(records), a)) == 0)]
    finalize: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::FinalizeOp { a, h }, ..],
        obs,
    } => {
        records: MapRecAuths(AuthMapC::FinalTag { h }, a, records),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 10: finalize of an authorization that is not SUBMITTED.
    #[k::requires(list::size(FinalizeRefusals(AllAuths(records), a)) != 0)]
    finalize_refuse: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::FinalizeOp { a, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: FinalizeRefusals(AllAuths(records), a) }],
    };

    // AU-018: REVOKED, and the tag joins the hold accumulator (newest first).
    #[k::requires(list::size(RevokeRefusals(records, a, tag)) == 0)]
    revoke: {
        k: [Step::Go, ..],
        records,
        holds,
        ops: [OpC::RevokeOp { a, tag }, ..],
        obs,
    } => {
        records: MapRecAuths(AuthMapC::RevokeTag, a, records),
        holds: [tag, ..holds],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // AU-019, ledger 9: a refused revoke.
    #[k::requires(list::size(RevokeRefusals(records, a, tag)) != 0)]
    revoke_refuse: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::RevokeOp { a, tag }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: RevokeRefusals(records, a, tag) }],
    };

    // AU-020, AU-023: a checkpoint lands with a settle_root; the leaves apply in order.
    #[k::requires(list::size(SettleRootRefusals(leaves)) == 0)]
    settle_root: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::SettleRootOp { leaves }, ..],
        obs,
    } => {
        records: SettleRecs(leaves, records),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 5: a leaf with outcome NONE.
    #[k::requires(list::size(SettleRootRefusals(leaves)) != 0)]
    settle_root_refuse: {
        k: [Step::Go, ..],
        ops: [OpC::SettleRootOp { leaves }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: SettleRootRefusals(leaves) }],
    };

    // AU-026: a checkpoint lands with a bf_root.
    #[k::requires(list::size(BfRootRefusals(ts, records)) == 0)]
    bf_root: {
        k: [Step::Go, ..],
        records,
        pending,
        landed,
        ops: [OpC::BfRootOp { ts }, ..],
        obs,
    } => {
        records: BfRecs(ts, records),
        pending: DropNfs(pending, TupleNfs(ts)),
        landed: list::concat(landed, TupleNfs(ts)),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledgers 5, 8: a refused bf_root.
    #[k::requires(list::size(BfRootRefusals(ts, records)) != 0)]
    bf_root_refuse: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::BfRootOp { ts }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: BfRootRefusals(ts, records) }],
    };

    // AU-027, ledger 12: a recovery transition is recorded (idempotent).
    recover: {
        k: [Step::Go, ..],
        recovered: _,
        ops: [OpC::RecoverOp, ..],
        obs,
    } => {
        recovered: true,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // AU-014, AU-016: the first verified board-first call for its nf.
    #[k::requires(list::size(BfCallRefusals(QOf(params), pending, landed, c)) == 0)]
    bf_call: {
        k: [Step::Go, ..],
        params,
        pending,
        inforce,
        landed,
        ops: [OpC::BfCallOp { c }, ..],
        obs,
    } => {
        pending: [CallNf(c), ..pending],
        inforce: [CallAn(c), ..inforce],
        ops: [..],
        obs: [..obs, ObsC::Accepted],
    };

    // AU-013, AU-015: a call that fails the checks, or whose nf is pending.
    #[k::requires(list::size(BfCallRefusals(QOf(params), pending, landed, c)) != 0)]
    bf_call_refuse: {
        k: [Step::Go, ..],
        params,
        pending,
        landed,
        ops: [OpC::BfCallOp { c }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: BfCallRefusals(QOf(params), pending, landed, c) }],
    };

    // AU-010, AU-016: is `a` in force for the node at Midnight height `h`.
    query: {
        k: [Step::Go, ..],
        records,
        inforce,
        ops: [OpC::QueryOp { a, h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::InForce { b: InForceMidnight(AllAuths(records), a, h) || AnyAn(inforce, a) }],
    };

    // AU-028: admission of a seizure request.
    #[k::requires(list::size(SeizureRefusals(AllAuths(records), a)) == 0)]
    seizure: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::SeizureOp { a, all_to_dreg }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, SeizureObs(all_to_dreg)],
    };

    // Ledger 2: a seizure request whose authorization does not use the seizure source.
    #[k::requires(list::size(SeizureRefusals(AllAuths(records), a)) != 0)]
    seizure_refuse: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::SeizureOp { a, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: SeizureRefusals(AllAuths(records), a) }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
