//! Split request reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/request/SplitRequest/Spec.lean` (`step`, `reqStep`, `apply`, `runOps`).
//!
//! The board events of `step` that change the board context (post, tick, rotate,
//! checkpoint, host fee) have one rule pair each. Every event that names a request
//! has one rule pair: the event applies (`reqStep` gives a new record and the
//! request's phase is observed) or it is refused with the codes in code order and
//! the state is unchanged. The transition of one request is a function per event
//! with one equation per branch of `reqStep`, so each branch and each condition
//! operand is a coverage obligation and a mutation target. Requirement IDs refer to
//! `openspec/changes/add-split-line-dealing/specs/split-request/spec.md`.
//!
//! Cells are the oracle's `St` fields (`params`, `height`, `cp_height` (cell `cpheight`), `epochs`,
//! `host_med` (cell `hostmed`), `requests`) and its observation list `obs`; `ops` holds the
//! operations still to run and is empty at every end (FLOW.toml omits it).
//!
//! An `Option Nat` of the oracle is a list of at most one entry. `anchor` and
//! `released` hold one entry per generation `g ∈ 1..G` (`[anchor[1], anchor[2]].take G`,
//! as the oracle prints them); the header sets `G` at OPENED, before any anchor.
//!
//! The node rules of `nodeAct` (RQ-008 to RQ-061 "the committee node SHALL") run
//! only in the oracle's `--step` mode and are not part of this definition
//! (../gaps.toml).
//!
//! The board records a RELEASE (RQ-037) when it commits in a board vote; a NON_TEE node
//! posts it before it sends any partial (RQ-069, a node rule), and a request with a
//! recorded RELEASE settles RELEASED, never VOID (RQ-050, RQ-051). A VOID end takes the
//! reason that `f + 1` reason posts carry, else MIXED (RQ-045, RQ-072 to RQ-074).

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, int, list};

k::sorts! {
    Run: KItem;
    Mode;
    Phase;
    Outcome;
    Reason;
    RType;
    Profile;
    Params;
    Epoch;
    Med;
    Frame;
    Vote2;
    Vote3;
    FinPost;
    VoidPost;
    Req;
    Ctx;
    Res;
    Refusal;
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
    #[k::syntax("TEE")] Tee,
    #[k::syntax("NON_TEE")] NonTee,
}

/// RQ-064: the phases.
#[k::constructors(sort = Phase, result = KResult)]
#[rustfmt::skip]
pub enum PhaseC {
    #[k::syntax("phPOSTED")] Posted,
    #[k::syntax("phORDERED")] Ordered,
    #[k::syntax("phOPENED")] Opened,
    #[k::syntax("phCOLLECTING")] Collecting,
    #[k::syntax("phADMITTED")] Admitted,
    #[k::syntax("phFINAL")] Final,
    #[k::syntax("phVOID")] Void,
    #[k::syntax("phEXPIRED")] Expired,
}

/// RQ-064: the outcomes.
#[k::constructors(sort = Outcome, result = KResult)]
#[rustfmt::skip]
pub enum OutcomeC {
    #[k::syntax("ocNONE")] ONone,
    #[k::syntax("ocFINAL")] OFinal,
    #[k::syntax("ocVOID")] OVoid,
    #[k::syntax("ocRELEASED")] OReleased,
}

/// RQ-065: the reasons.
#[k::constructors(sort = Reason, result = KResult)]
#[rustfmt::skip]
pub enum ReasonC {
    #[k::syntax("rsNONE")] RNone,
    #[k::syntax("rsSHARE_COMPLAINT")] ShareComplaint,
    #[k::syntax("rsMALFORMED")] Malformed,
    #[k::syntax("rsAUTH_REFUSED")] AuthRefused,
    #[k::syntax("rsREVOKED")] Revoked,
    #[k::syntax("rsRELEASE_CHECK")] ReleaseCheck,
    #[k::syntax("rsCONTRIBUTION")] Contribution,
    #[k::syntax("rsDEALER_FAULT")] DealerFault,
    #[k::syntax("rsPIN_SPENT")] PinSpent,
    #[k::syntax("rsSLOT_TAKEN")] SlotTaken,
    #[k::syntax("rsSTALLED")] Stalled,
    #[k::syntax("rsRESTART")] Restart,
    /// RQ-065, RQ-072: the reason of a VOID tombstone whose reason posts name no
    /// common reason; no node posts it.
    #[k::syntax("rsMIXED")] Mixed,
}

/// RQ-066: the request types.
#[k::constructors(sort = RType, result = KResult)]
#[rustfmt::skip]
pub enum RTypeC {
    #[k::syntax("SPEND")] Spend,
    #[k::syntax("EXIT")] Exit,
    #[k::syntax("SEIZURE")] Seizure,
    #[k::syntax("BIRTH")] Birth,
    #[k::syntax("REFILL")] Refill,
    #[k::syntax("tyP0")] TyP0,
    #[k::syntax("CONTRIB")] Contrib,
}

/// RQ-066: the profiles.
#[k::constructors(sort = Profile, result = KResult)]
#[rustfmt::skip]
pub enum ProfileC {
    #[k::syntax("pfP0")] PfP0,
    #[k::syntax("pfP1")] PfP1,
    #[k::syntax("pfP2")] PfP2,
}

/// RQ-001: the committee parameters (`delta_hold` is `Δ_hold` of RQ-033).
#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    #[k::syntax("params({n}, {f}, {delta_c}, {delta_hold}, {mode})")]
    Pm { n: Int, f: Int, delta_c: Int, delta_hold: Int, mode: Mode },
}

/// RQ-042: a registered epoch `(e, n_e, f_e)`.
#[k::constructors(sort = Epoch, result = KResult)]
pub enum EpochC {
    #[k::syntax("ep({e}, {n}, {f})")]
    Ep { e: Int, n: Int, f: Int },
}

/// RQ-027: the host chain's fee median `m` at host height `h`.
#[k::constructors(sort = Med, result = KResult)]
pub enum MedC {
    #[k::syntax("med({h}, {m})")]
    Md { h: Int, m: Int },
}

/// RQ-018 to RQ-021: a contribution frame.
#[k::constructors(sort = Frame, result = KResult)]
pub enum FrameC {
    #[k::syntax("frame({position}, {token_ok}, {lengths_ok}, {height}, {cid})")]
    Fr { position: Int, token_ok: Bool, lengths_ok: Bool, height: Int, cid: Int },
}

/// RQ-017: an OPENED vote `(node, H(header))`.
#[k::constructors(sort = Vote2, result = KResult)]
pub enum Vote2C {
    #[k::syntax("vOpened({node}, {hash})")]
    V2 { node: Int, hash: Int },
}

/// RQ-026: an ADMIT vote `(node, H(header), h)`.
#[k::constructors(sort = Vote3, result = KResult)]
pub enum Vote3C {
    #[k::syntax("vAdmit({node}, {hash}, {h})")]
    V3 { node: Int, hash: Int, h: Int },
}

/// RQ-042, RQ-044: a FINAL post `(epoch, member, Enc_{k_fin}(txid))`.
#[k::constructors(sort = FinPost, result = KResult)]
pub enum FinPostC {
    #[k::syntax("finalPost({epoch}, {member}, {ct})")]
    Fp { epoch: Int, member: Int, ct: Int },
}

/// RQ-042, RQ-045: a VOID post `(epoch, member, reason)`.
#[k::constructors(sort = VoidPost, result = KResult)]
pub enum VoidPostC {
    #[k::syntax("voidPost({epoch}, {member}, {reason})")]
    Vp { epoch: Int, member: Int, reason: Reason },
}

/// RQ-002: the request record, with the board record the counting and order rules read.
#[k::constructors(sort = Req, result = KResult)]
pub enum ReqC {
    #[k::syntax(
        "req({eid}, {epoch}, {exp}, {rtype}, {profile}, {order_pos}, {exp_c}, {phase}, {reason}, {collecting}, {kk}, {ll}, {gg}, {anchor}, {released}, {any_release}, {restart_end}, {outcome}, {rates}, {positions}, {held}, {opened_votes}, {admit_votes}, {early_complaint}, {dealer_fault}, {final_posts}, {void_posts}, {end_height}, {confirmed}, {carried})"
    )]
    Rq {
        eid: Int,
        epoch: Int,
        exp: Int,
        rtype: RType,
        profile: Profile,
        order_pos: List<Int>,
        exp_c: List<Int>,
        phase: Phase,
        reason: Reason,
        collecting: Bool,
        kk: Int,
        ll: Int,
        gg: Int,
        anchor: List<List<Int>>,
        released: List<List<Int>>,
        any_release: Bool,
        restart_end: Bool,
        outcome: Outcome,
        rates: List<Int>,
        positions: List<List<Int>>,
        held: List<Frame>,
        opened_votes: List<Vote2>,
        admit_votes: List<Vote3>,
        early_complaint: Bool,
        dealer_fault: Bool,
        final_posts: List<FinPost>,
        void_posts: List<VoidPost>,
        end_height: List<Int>,
        confirmed: Bool,
        carried: Bool,
    },
}

/// The board context `Ctx` that `reqStep` reads.
#[k::constructors(sort = Ctx, result = KResult)]
pub enum CtxC {
    #[k::syntax("ctx({params}, {height}, {cp}, {epochs}, {host_med})")]
    Cx { params: Params, height: Int, cp: Int, epochs: List<Epoch>, host_med: List<Med> },
}

/// `Except (List Refusal) Req`: `ok` with the new record, or the refusal codes.
#[k::constructors(sort = Res, result = KResult)]
pub enum ResC {
    #[k::syntax("res({ok}, {r}, {codes})")]
    Rs { ok: Bool, r: Req, codes: List<Refusal> },
}

/// The refusal codes a run can give, in code order (`exp_c_not_below_exp` is EN-023 at
/// the ordering block; `not_in_force`, `above_window`
/// and `pool_unlisted` are node refusals; `outside-state-domain` is `--step` only).
#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("rfExpCNotBelowExp")] ExpCNotBelowExp,
    #[k::syntax("rfLateContribution")] LateContribution,
    #[k::syntax("rfNoRule")] NoRule,
    #[k::syntax("rfNoQc")] NoQc,
    #[k::syntax("rfOutsideCapability")] OutsideCapability,
    #[k::syntax("rfPositionFilled")] PositionFilled,
    #[k::syntax("rfSettled")] Settled,
    #[k::syntax("rfTerminal")] Terminal,
    #[k::syntax("rfUnknownEpoch")] UnknownEpoch,
    #[k::syntax("rfUnknownRequest")] UnknownRequest,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("opPost({eid}, {epoch}, {exp}, {rtype}, {profile})")]
    Post { eid: Int, epoch: Int, exp: Int, rtype: RType, profile: Profile },
    #[k::syntax("opOrder({eid}, {qc}, {p})")] Order { eid: Int, qc: Bool, p: Int },
    #[k::syntax("opOpen({eid}, {kk}, {ll}, {collecting}, {npos}, {rates})")]
    Open { eid: Int, kk: Int, ll: Int, collecting: Bool, npos: Int, rates: List<Int> },
    #[k::syntax("opComplaint({eid})")] Complaint { eid: Int },
    #[k::syntax("opFrame({eid}, {fr})")] FrameOp { eid: Int, fr: Frame },
    #[k::syntax("opDetach({eid}, {position})")] Detach { eid: Int, position: Int },
    #[k::syntax("opVoteOpened({eid}, {node}, {hash})")] VoteOpened { eid: Int, node: Int, hash: Int },
    #[k::syntax("opVoteAdmit({eid}, {node}, {hash}, {h})")] VoteAdmit { eid: Int, node: Int, hash: Int, h: Int },
    #[k::syntax("opObs2({eid}, {gen1_missed}, {heights})")]
    Obs2 { eid: Int, gen1_missed: Bool, heights: List<Int> },
    #[k::syntax("opRelease({eid}, {g}, {j})")] Release { eid: Int, g: Int, j: Int },
    #[k::syntax("opPostFinal({eid}, {epoch}, {member}, {ct})")]
    PostFinal { eid: Int, epoch: Int, member: Int, ct: Int },
    #[k::syntax("opPostVoid({eid}, {epoch}, {member}, {reason})")]
    PostVoid { eid: Int, epoch: Int, member: Int, reason: Reason },
    #[k::syntax("opTick({h})")] Tick { h: Int },
    #[k::syntax("opRotate({e}, {n}, {f})")] Rotate { e: Int, n: Int, f: Int },
    #[k::syntax("opLandCp({h})")] LandCp { h: Int },
    #[k::syntax("opRestartBurn({eid})")] RestartBurn { eid: Int },
    #[k::syntax("opConfirm({eid})")] Confirm { eid: Int },
    #[k::syntax("opCarry({eid})")] Carry { eid: Int },
    #[k::syntax("opHostFee({h}, {m})")] HostFee { h: Int, m: Int },
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("obsOk")] Ok,
    #[k::syntax("refused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("phaseIs({p})")] PhaseIs { p: Phase },
}

// ---------------------------------------------------------------------------
// Record fields and updates (`{ r with .. }`).

#[k::function(total, internal)]
pub fn GetAdmitVotes(r: k::Term<Req>) -> k::Term<List<Vote3>> {
    match r {
        ReqC::Rq { admit_votes, .. } => admit_votes,
    }
}

#[k::function(total, internal)]
pub fn GetAnchor(r: k::Term<Req>) -> k::Term<List<List<Int>>> {
    match r {
        ReqC::Rq { anchor, .. } => anchor,
    }
}

#[k::function(total, internal)]
pub fn GetAnyRelease(r: k::Term<Req>) -> k::Term<Bool> {
    match r {
        ReqC::Rq { any_release, .. } => any_release,
    }
}

#[k::function(total, internal)]
pub fn GetCarried(r: k::Term<Req>) -> k::Term<Bool> {
    match r {
        ReqC::Rq { carried, .. } => carried,
    }
}

#[k::function(total, internal)]
pub fn GetCollecting(r: k::Term<Req>) -> k::Term<Bool> {
    match r {
        ReqC::Rq { collecting, .. } => collecting,
    }
}

#[k::function(total, internal)]
pub fn GetConfirmed(r: k::Term<Req>) -> k::Term<Bool> {
    match r {
        ReqC::Rq { confirmed, .. } => confirmed,
    }
}

#[k::function(total, internal)]
pub fn GetEndHeight(r: k::Term<Req>) -> k::Term<List<Int>> {
    match r {
        ReqC::Rq { end_height, .. } => end_height,
    }
}

#[k::function(total, internal)]
pub fn GetEpoch(r: k::Term<Req>) -> k::Term<Int> {
    match r {
        ReqC::Rq { epoch, .. } => epoch,
    }
}

#[k::function(total, internal)]
pub fn GetExp(r: k::Term<Req>) -> k::Term<Int> {
    match r {
        ReqC::Rq { exp, .. } => exp,
    }
}

#[k::function(total, internal)]
pub fn GetExpC(r: k::Term<Req>) -> k::Term<List<Int>> {
    match r {
        ReqC::Rq { exp_c, .. } => exp_c,
    }
}

#[k::function(total, internal)]
pub fn GetFinalPosts(r: k::Term<Req>) -> k::Term<List<FinPost>> {
    match r {
        ReqC::Rq { final_posts, .. } => final_posts,
    }
}

#[k::function(total, internal)]
pub fn GetGg(r: k::Term<Req>) -> k::Term<Int> {
    match r {
        ReqC::Rq { gg, .. } => gg,
    }
}

#[k::function(total, internal)]
pub fn GetHeld(r: k::Term<Req>) -> k::Term<List<Frame>> {
    match r {
        ReqC::Rq { held, .. } => held,
    }
}

#[k::function(total, internal)]
pub fn GetKk(r: k::Term<Req>) -> k::Term<Int> {
    match r {
        ReqC::Rq { kk, .. } => kk,
    }
}

#[k::function(total, internal)]
pub fn GetOpenedVotes(r: k::Term<Req>) -> k::Term<List<Vote2>> {
    match r {
        ReqC::Rq { opened_votes, .. } => opened_votes,
    }
}

#[k::function(total, internal)]
pub fn GetOutcome(r: k::Term<Req>) -> k::Term<Outcome> {
    match r {
        ReqC::Rq { outcome, .. } => outcome,
    }
}

#[k::function(total, internal)]
pub fn GetPhase(r: k::Term<Req>) -> k::Term<Phase> {
    match r {
        ReqC::Rq { phase, .. } => phase,
    }
}

#[k::function(total, internal)]
pub fn GetPositions(r: k::Term<Req>) -> k::Term<List<List<Int>>> {
    match r {
        ReqC::Rq { positions, .. } => positions,
    }
}

#[k::function(total, internal)]
pub fn GetRates(r: k::Term<Req>) -> k::Term<List<Int>> {
    match r {
        ReqC::Rq { rates, .. } => rates,
    }
}

#[k::function(total, internal)]
pub fn GetReason(r: k::Term<Req>) -> k::Term<Reason> {
    match r {
        ReqC::Rq { reason, .. } => reason,
    }
}

#[k::function(total, internal)]
pub fn GetReleased(r: k::Term<Req>) -> k::Term<List<List<Int>>> {
    match r {
        ReqC::Rq { released, .. } => released,
    }
}

#[k::function(total, internal)]
pub fn GetRestartEnd(r: k::Term<Req>) -> k::Term<Bool> {
    match r {
        ReqC::Rq { restart_end, .. } => restart_end,
    }
}

#[k::function(total, internal)]
pub fn GetRtype(r: k::Term<Req>) -> k::Term<RType> {
    match r {
        ReqC::Rq { rtype, .. } => rtype,
    }
}

#[k::function(total, internal)]
pub fn GetVoidPosts(r: k::Term<Req>) -> k::Term<List<VoidPost>> {
    match r {
        ReqC::Rq { void_posts, .. } => void_posts,
    }
}

/// RQ-006: `phase = ORDERED`, `order_pos = p`, `exp_c = b + Δ_c`.
#[k::function(total, internal)]
pub fn SetOrdered(r: k::Term<Req>, v_order_pos: k::Term<List<Int>>, v_exp_c: k::Term<List<Int>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos: v_order_pos,
            exp_c: v_exp_c,
            phase: PhaseC::Ordered,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-013: `phase = OPENED` with the header's `K`, `L`, `G`; `anchor` and `released` get `G` empty entries.
#[k::function(total, internal)]
pub fn SetOpened(r: k::Term<Req>, v_collecting: k::Term<Bool>, v_kk: k::Term<Int>, v_ll: k::Term<Int>, v_gg: k::Term<Int>, v_anchor: k::Term<List<List<Int>>>, v_released: k::Term<List<List<Int>>>, v_rates: k::Term<List<Int>>, v_positions: k::Term<List<List<Int>>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, reason, any_release, restart_end, outcome, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Opened,
            reason,
            collecting: v_collecting,
            kk: v_kk,
            ll: v_ll,
            gg: v_gg,
            anchor: v_anchor,
            released: v_released,
            any_release,
            restart_end,
            outcome,
            rates: v_rates,
            positions: v_positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-011: a share complaint before the first ADMIT vote.
#[k::function(total, internal)]
pub fn SetEarly(r: k::Term<Req>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint: true,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-012: the dealer's fault.
#[k::function(total, internal)]
pub fn SetDealerFault(r: k::Term<Req>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault: true,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-021: the held frames.
#[k::function(total, internal)]
pub fn SetHeld(r: k::Term<Req>, v_held: k::Term<List<Frame>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held: v_held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-018, RQ-022: the actor slot table.
#[k::function(total, internal)]
pub fn SetPositions(r: k::Term<Req>, v_positions: k::Term<List<List<Int>>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions: v_positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-017: the OPENED votes.
#[k::function(total, internal)]
pub fn SetOpenedVotes(r: k::Term<Req>, v_opened_votes: k::Term<List<Vote2>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes: v_opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-017, RQ-021: `phase = COLLECTING`, the held frames attached and dropped.
#[k::function(total, internal)]
pub fn SetCollecting(r: k::Term<Req>, v_positions: k::Term<List<List<Int>>>, v_opened_votes: k::Term<List<Vote2>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Collecting,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions: v_positions,
            held: [],
            opened_votes: v_opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-026: the ADMIT votes.
#[k::function(total, internal)]
pub fn SetAdmitVotes(r: k::Term<Req>, v_admit_votes: k::Term<List<Vote3>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes: v_admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-026, RQ-027: `phase = ADMITTED` and `anchor[1]`.
#[k::function(total, internal)]
pub fn SetAdmitted(r: k::Term<Req>, v_anchor: k::Term<List<List<Int>>>, v_admit_votes: k::Term<List<Vote3>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, reason, collecting, kk, ll, gg, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Admitted,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor: v_anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes: v_admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-028: `anchor[2]`.
#[k::function(total, internal)]
pub fn SetAnchor(r: k::Term<Req>, v_anchor: k::Term<List<List<Int>>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor: v_anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-042: the FINAL posts.
#[k::function(total, internal)]
pub fn SetFinalPosts(r: k::Term<Req>, v_final_posts: k::Term<List<FinPost>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts: v_final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-042: the VOID posts.
#[k::function(total, internal)]
pub fn SetVoidPosts(r: k::Term<Req>, v_void_posts: k::Term<List<VoidPost>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts: v_void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-044, RQ-049: `endFinal`.
#[k::function(total, internal)]
pub fn EndFinalAt(r: k::Term<Req>, v_end_height: k::Term<List<Int>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Final,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome: OutcomeC::OFinal,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height: v_end_height,
            confirmed: true,
            carried,
        },
    }
}

/// RQ-046: `phase = EXPIRED`.
#[k::function(total, internal)]
pub fn SetExpired(r: k::Term<Req>, v_outcome: k::Term<Outcome>, v_end_height: k::Term<List<Int>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Expired,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome: v_outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height: v_end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-048: `restart_end = true`.
#[k::function(total, internal)]
pub fn SetRestart(r: k::Term<Req>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end: true,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-068: the restart re-end.
#[k::function(total, internal)]
pub fn SetRestartOutcome(r: k::Term<Req>, v_outcome: k::Term<Outcome>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end: true,
            outcome: v_outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// The host chain shows a variant at confirmation depth.
#[k::function(total, internal)]
pub fn SetConfirmed(r: k::Term<Req>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed: true,
            carried,
        },
    }
}

/// AU-021, RQ-060: a reissue carried the VOID leaf.
#[k::function(total, internal)]
pub fn SetCarried(r: k::Term<Req>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, released, any_release, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried: true,
        },
    }
}

/// RQ-002, RQ-003: a new request; `K`, `L`, `G` are 0 until OPENED (ledger 3).
#[k::function(total, internal)]
pub fn NewReq(
    eid: k::Term<Int>,
    epoch: k::Term<Int>,
    exp: k::Term<Int>,
    rtype: k::Term<RType>,
    profile: k::Term<Profile>,
) -> k::Term<Req> {
    ReqC::Rq {
        eid,
        epoch,
        exp,
        rtype,
        profile,
        order_pos: [],
        exp_c: [],
        phase: PhaseC::Posted,
        reason: ReasonC::RNone,
        collecting: false,
        kk: 0,
        ll: 0,
        gg: 0,
        anchor: [],
        released: [],
        any_release: false,
        restart_end: false,
        outcome: OutcomeC::ONone,
        rates: [],
        positions: [],
        held: [],
        opened_votes: [],
        admit_votes: [],
        early_complaint: false,
        dealer_fault: false,
        final_posts: [],
        void_posts: [],
        end_height: [],
        confirmed: false,
        carried: false,
    }
}

// ---------------------------------------------------------------------------
// The board context.

#[k::function(total, internal)]
pub fn CtxN(c: k::Term<Ctx>) -> k::Term<Int> {
    match c {
        CtxC::Cx { params: ParamsC::Pm { n, .. }, .. } => n,
    }
}

#[k::function(total, internal)]
pub fn CtxF(c: k::Term<Ctx>) -> k::Term<Int> {
    match c {
        CtxC::Cx { params: ParamsC::Pm { f, .. }, .. } => f,
    }
}

#[k::function(total, internal)]
pub fn CtxDeltaC(c: k::Term<Ctx>) -> k::Term<Int> {
    match c {
        CtxC::Cx { params: ParamsC::Pm { delta_c, .. }, .. } => delta_c,
    }
}

#[k::function(total, internal)]
pub fn CtxHeight(c: k::Term<Ctx>) -> k::Term<Int> {
    match c {
        CtxC::Cx { height, .. } => height,
    }
}

#[k::function(total, internal)]
pub fn CtxCp(c: k::Term<Ctx>) -> k::Term<Int> {
    match c {
        CtxC::Cx { cp, .. } => cp,
    }
}

#[k::function(total, internal)]
pub fn CtxEpochs(c: k::Term<Ctx>) -> k::Term<List<Epoch>> {
    match c {
        CtxC::Cx { epochs, .. } => epochs,
    }
}

#[k::function(total, internal)]
pub fn CtxMeds(c: k::Term<Ctx>) -> k::Term<List<Med>> {
    match c {
        CtxC::Cx { host_med, .. } => host_med,
    }
}

// ---------------------------------------------------------------------------
// Helpers (Lean `opt`, `orNoRule`, `Phase.terminal`, `RType.signing`, `qOf`,
// `committeeOk`, `Option` and `List` operations).

/// `opt b r`.
#[k::function(total, internal)]
pub fn Opt(b: k::Term<Bool>, x: k::Term<Refusal>) -> k::Term<List<Refusal>> {
    if b { [x] } else { [] }
}

/// `orNoRule`: the spec codes, or `no-rule` when none applies and `ok` is false.
#[k::function(total, internal)]
pub fn OrNoRule(spec: k::Term<List<Refusal>>, ok: k::Term<Bool>) -> k::Term<List<Refusal>> {
    if list::size(spec) == 0 { Opt(!ok, RefusalC::NoRule) } else { spec }
}

/// `Phase.terminal`: FINAL, VOID and EXPIRED.
#[k::function(total, internal)]
pub fn IsTerminal(p: k::Term<Phase>) -> k::Term<Bool> {
    match p {
        PhaseC::Final => true,
        PhaseC::Void => true,
        PhaseC::Expired => true,
        _ => false,
    }
}

/// RQ-062: BIRTH, REFILL and CONTRIB keep no signing state.
#[k::function(total, internal)]
pub fn Signing(t: k::Term<RType>) -> k::Term<Bool> {
    match t {
        RTypeC::Birth => false,
        RTypeC::Refill => false,
        RTypeC::Contrib => false,
        _ => true,
    }
}

/// RQ-001: `q = ⌈(n + f + 1)/2⌉`.
#[k::function(total, internal)]
pub fn QOf(n: k::Term<Int>, f: k::Term<Int>) -> k::Term<Int> {
    (n + f + 2) / 2
}

/// RQ-001, RQ-067: `G = min(K, G_max)` with `G_max = 2`.
#[k::function(total, internal)]
pub fn GOf(kk: k::Term<Int>) -> k::Term<Int> {
    int::min(kk, 2)
}

/// RQ-001: the domain `n ≥ 3f + 1` and `f ≥ 1`.
#[k::function(total, internal)]
pub fn CommitteeOk(n: k::Term<Int>, f: k::Term<Int>) -> k::Term<Bool> {
    1 <= f && 3 * f + 1 <= n
}

/// `o.isSome`.
#[k::function(total, internal)]
pub fn IsSome(o: k::Term<List<Int>>) -> k::Term<Bool> {
    match o {
        [] => false,
        [_v, ..] => true,
    }
}

/// `o.getD d`.
#[k::function(total, internal)]
pub fn OrElse(o: k::Term<List<Int>>, d: k::Term<Int>) -> k::Term<Int> {
    match o {
        [] => d,
        [v, ..] => v,
    }
}

/// `ps.getD i none`.
#[k::function(total, internal)]
pub fn GetD(ps: k::Term<List<List<Int>>>, i: k::Term<Int>) -> k::Term<List<Int>> {
    if i < list::size(ps) { list::get(ps, i) } else { [] }
}

/// `List.replicate n none`.
#[k::function(total, internal)]
pub fn NoneList(n: k::Term<Int>) -> k::Term<List<List<Int>>> {
    if n <= 0 { [] } else { [[], ..NoneList(n - 1)] }
}

// ---------------------------------------------------------------------------
// Requests (`find`, `replace`, `expire`).

/// Some request has `eid`.
#[k::function(total, internal)]
pub fn HasReq(eid: k::Term<Int>, rs: k::Term<List<Req>>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [ReqC::Rq { eid: x, .. }, ..] if x == eid => true,
        [ReqC::Rq { eid: x, .. }, rest @ ..] if x != eid => HasReq(eid, rest),
    }
}

/// `find`: the request with `eid`; a fresh record when none has it (then
/// `Targeted` refuses the event and drops the record).
#[k::function(total, internal)]
pub fn Find(eid: k::Term<Int>, rs: k::Term<List<Req>>) -> k::Term<Req> {
    match rs {
        [] => NewReq(eid, 0, 0, RTypeC::Spend, ProfileC::PfP0),
        [r @ ReqC::Rq { eid: x, .. }, ..] if x == eid => r,
        [ReqC::Rq { eid: x, .. }, rest @ ..] if x != eid => Find(eid, rest),
    }
}

/// `replace e r' rs`.
#[k::function(total, internal)]
pub fn Replace(eid: k::Term<Int>, r2: k::Term<Req>, rs: k::Term<List<Req>>) -> k::Term<List<Req>> {
    match rs {
        [] => [],
        [ReqC::Rq { eid: x, .. }, rest @ ..] if x == eid => [r2, ..Replace(eid, r2, rest)],
        [r @ ReqC::Rq { eid: x, .. }, rest @ ..] if x != eid => [r, ..Replace(eid, r2, rest)],
    }
}

/// RQ-050 to RQ-052: the outcome of a VOID or EXPIRED end.
#[k::function(total, internal)]
pub fn EndOutcome(r: k::Term<Req>) -> k::Term<Outcome> {
    if GetRestartEnd(r) {
        RestartOutcome(r)
    } else if GetAnyRelease(r) {
        OutcomeC::OReleased
    } else {
        OutcomeC::OVoid
    }
}

/// RQ-052, RQ-068: FINAL when the host chain shows a variant at confirmation depth.
#[k::function(total, internal)]
pub fn RestartOutcome(r: k::Term<Req>) -> k::Term<Outcome> {
    if GetConfirmed(r) { OutcomeC::OFinal } else { OutcomeC::OReleased }
}

/// RQ-046: the request expires at height `h` when it is live and `exp < h`.
#[k::function(total, internal)]
pub fn Expire(h: k::Term<Int>, r: k::Term<Req>) -> k::Term<Req> {
    if !IsTerminal(GetPhase(r)) && GetExp(r) < h { SetExpired(r, EndOutcome(r), [h]) } else { r }
}

/// `reqs.map (expire h)`.
#[k::function(total, internal)]
pub fn ExpireAll(h: k::Term<Int>, rs: k::Term<List<Req>>) -> k::Term<List<Req>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [Expire(h, r), ..ExpireAll(h, rest)],
    }
}

/// RQ-044, RQ-049: `endFinal` at the board height.
#[k::function(total, internal)]
pub fn EndFinal(c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Req> {
    EndFinalAt(r, [CtxHeight(c)])
}

// ---------------------------------------------------------------------------
// Results of `reqStep`.

#[k::function(total, internal)]
pub fn ROk(r: k::Term<Req>) -> k::Term<Res> {
    ResC::Rs { ok: true, r, codes: [] }
}

#[k::function(total, internal)]
pub fn RErr(r: k::Term<Req>, codes: k::Term<List<Refusal>>) -> k::Term<Res> {
    ResC::Rs { ok: false, r, codes }
}

#[k::function(total, internal)]
pub fn ResOk(x: k::Term<Res>) -> k::Term<Bool> {
    match x {
        ResC::Rs { ok, .. } => ok,
    }
}

#[k::function(total, internal)]
pub fn ResReq(x: k::Term<Res>) -> k::Term<Req> {
    match x {
        ResC::Rs { r, .. } => r,
    }
}

#[k::function(total, internal)]
pub fn ResCodes(x: k::Term<Res>) -> k::Term<List<Refusal>> {
    match x {
        ResC::Rs { codes, .. } => codes,
    }
}

/// RQ-004: an event that names an `eid` the machine does not hold is refused
/// with `unknown_request`; otherwise `reqStep` on the request.
#[k::function(total, internal)]
pub fn Targeted(found: k::Term<Bool>, x: k::Term<Res>) -> k::Term<Res> {
    if found { x } else { RErr(ResReq(x), [RefusalC::UnknownRequest]) }
}

// ---------------------------------------------------------------------------
// Counting and selection (RQ-017, RQ-026, RQ-027, RQ-042).

/// `vs.any (·.1 == node)` for OPENED votes.
#[k::function(total, internal)]
pub fn AnyNode2(vs: k::Term<List<Vote2>>, node: k::Term<Int>) -> k::Term<Bool> {
    match vs {
        [] => false,
        [Vote2C::V2 { node: x, .. }, ..] if x == node => true,
        [Vote2C::V2 { node: x, .. }, rest @ ..] if x != node => AnyNode2(rest, node),
    }
}

/// `vs.any (·.1 == node)` for ADMIT votes.
#[k::function(total, internal)]
pub fn AnyNode3(vs: k::Term<List<Vote3>>, node: k::Term<Int>) -> k::Term<Bool> {
    match vs {
        [] => false,
        [Vote3C::V3 { node: x, .. }, ..] if x == node => true,
        [Vote3C::V3 { node: x, .. }, rest @ ..] if x != node => AnyNode3(rest, node),
    }
}

/// `countWith (·.2 == hash)` for OPENED votes.
#[k::function(total, internal)]
pub fn Count2(vs: k::Term<List<Vote2>>, hash: k::Term<Int>) -> k::Term<Int> {
    match vs {
        [] => 0,
        [Vote2C::V2 { hash: x, .. }, rest @ ..] if x == hash => 1 + Count2(rest, hash),
        [Vote2C::V2 { hash: x, .. }, rest @ ..] if x != hash => Count2(rest, hash),
    }
}

/// `vs.filter (·.2.1 == hash)` for ADMIT votes.
#[k::function(total, internal)]
pub fn Mine(vs: k::Term<List<Vote3>>, hash: k::Term<Int>) -> k::Term<List<Vote3>> {
    match vs {
        [] => [],
        [v @ Vote3C::V3 { hash: x, .. }, rest @ ..] if x == hash => [v, ..Mine(rest, hash)],
        [Vote3C::V3 { hash: x, .. }, rest @ ..] if x != hash => Mine(rest, hash),
    }
}

/// `mine.map (·.2.2)`: the host heights of the OBS reports.
#[k::function(total, internal)]
pub fn Heights(vs: k::Term<List<Vote3>>) -> k::Term<List<Int>> {
    match vs {
        [] => [],
        [Vote3C::V3 { h, .. }, rest @ ..] => [h, ..Heights(rest)],
    }
}

/// `insertDesc`.
#[k::function(total, internal)]
pub fn InsertDesc(x: k::Term<Int>, ys: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match ys {
        [] => [x],
        [y, rest @ ..] if y <= x => [x, y, ..rest],
        [y, rest @ ..] if y > x => [y, ..InsertDesc(x, rest)],
    }
}

/// `sortDesc`: the heights sorted highest first.
#[k::function(total, internal)]
pub fn SortDesc(xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [x, rest @ ..] => InsertDesc(x, SortDesc(rest)),
    }
}

/// RQ-027: the anchor height is entry `f + 1` of the heights sorted highest first.
/// The oracle's `getD f 0` never reaches its default: `q > f` votes (RQ-026) and
/// `f < |heights|` (RQ-028) both give at least `f + 1` heights.
#[k::function(total, internal)]
pub fn AnchorHeight(f: k::Term<Int>, hs: k::Term<List<Int>>) -> k::Term<Int> {
    list::get(SortDesc(hs), f)
}

/// `(firstMeet m rs).map (· + 1)`.
#[k::function(total, internal)]
pub fn Inc(o: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match o {
        [] => [],
        [i, ..] => [i + 1],
    }
}

/// `firstMeet`: the first variant (from 1) whose fee rate meets the median.
#[k::function(total, internal)]
pub fn FirstMeet(m: k::Term<Int>, rates: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match rates {
        [] => [],
        [x, ..] if m <= x => [1],
        [x, rest @ ..] if m > x => Inc(FirstMeet(m, rest)),
    }
}

/// RQ-027: the first variant whose fee rate meets the median, else the highest, `K` (ledger 6).
#[k::function(total, internal)]
pub fn Select(kk: k::Term<Int>, rates: k::Term<List<Int>>, m: k::Term<Int>) -> k::Term<Int> {
    OrElse(FirstMeet(m, rates), kk)
}

/// `lookupMed`: the host fee median at host height `h`, if the view holds it.
#[k::function(total, internal)]
pub fn LookupMed(meds: k::Term<List<Med>>, h: k::Term<Int>) -> k::Term<List<Int>> {
    match meds {
        [] => [],
        [MedC::Md { h: x, m }, ..] if x == h => [m],
        [MedC::Md { h: x, .. }, rest @ ..] if x != h => LookupMed(rest, h),
    }
}

/// `epochOf`: the registered epoch `e`, if any.
#[k::function(total, internal)]
pub fn FindEpoch(es: k::Term<List<Epoch>>, e: k::Term<Int>) -> k::Term<List<Epoch>> {
    match es {
        [] => [],
        [ep @ EpochC::Ep { e: x, .. }, ..] if x == e => [ep],
        [EpochC::Ep { e: x, .. }, rest @ ..] if x != e => FindEpoch(rest, e),
    }
}

/// Ledger 10: member `m` of epoch `e` already posted FINAL.
#[k::function(total, internal)]
pub fn AnyFin(ps: k::Term<List<FinPost>>, e: k::Term<Int>, m: k::Term<Int>) -> k::Term<Bool> {
    match ps {
        [] => false,
        [FinPostC::Fp { epoch, member, .. }, ..] if epoch == e && member == m => true,
        [FinPostC::Fp { epoch, member, .. }, rest @ ..] if !(epoch == e && member == m) => AnyFin(rest, e, m),
    }
}

/// RQ-042, RQ-044: the FINAL posts of epoch `e` with one `Enc_{k_fin}(txid)`.
#[k::function(total, internal)]
pub fn CountFin(ps: k::Term<List<FinPost>>, e: k::Term<Int>, ct: k::Term<Int>) -> k::Term<Int> {
    match ps {
        [] => 0,
        [FinPostC::Fp { epoch, ct: x, .. }, rest @ ..] if epoch == e && x == ct => 1 + CountFin(rest, e, ct),
        [FinPostC::Fp { epoch, ct: x, .. }, rest @ ..] if !(epoch == e && x == ct) => CountFin(rest, e, ct),
    }
}

/// Ledger 10: member `m` of epoch `e` already posted VOID.
#[k::function(total, internal)]
pub fn AnyVoid(ps: k::Term<List<VoidPost>>, e: k::Term<Int>, m: k::Term<Int>) -> k::Term<Bool> {
    match ps {
        [] => false,
        [VoidPostC::Vp { epoch, member, .. }, ..] if epoch == e && member == m => true,
        [VoidPostC::Vp { epoch, member, .. }, rest @ ..] if !(epoch == e && member == m) => AnyVoid(rest, e, m),
    }
}

/// RQ-042, RQ-045: the VOID posts of epoch `e`.
#[k::function(total, internal)]
pub fn CountVoid(ps: k::Term<List<VoidPost>>, e: k::Term<Int>) -> k::Term<Int> {
    match ps {
        [] => 0,
        [VoidPostC::Vp { epoch, .. }, rest @ ..] if epoch == e => 1 + CountVoid(rest, e),
        [VoidPostC::Vp { epoch, .. }, rest @ ..] if epoch != e => CountVoid(rest, e),
    }
}

// ---------------------------------------------------------------------------
// `reqStep`: one event on the request it names.

/// RQ-006, RQ-007, EN-023 (ordering block, ledger 23): `exp_c_not_below_exp` when
/// `exp_c = b + Δ_c` does not lie below `exp` (`atexp`), `no_qc`, `terminal`, in code
/// order, or `no-rule` outside POSTED.
#[k::function(total, internal)]
pub fn OrderCodes(atexp: k::Term<Bool>, qc: k::Term<Bool>, ph: k::Term<Phase>) -> k::Term<List<Refusal>> {
    OrNoRule(
        list::concat(
            Opt(atexp, RefusalC::ExpCNotBelowExp),
            list::concat(Opt(!qc, RefusalC::NoQc), Opt(IsTerminal(ph), RefusalC::Terminal)),
        ),
        ph.eq::<K>(PhaseC::Posted),
    )
}

/// EN-023 at the ordering block: `exp ≤ b + Δ_c`.
#[k::function(total, internal)]
pub fn AtExp(c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Bool> {
    GetExp(r) <= CtxHeight(c) + CtxDeltaC(c)
}

/// RQ-006, RQ-007, EN-023: the order event.
#[k::function(total, internal)]
pub fn StepOrder(c: k::Term<Ctx>, r: k::Term<Req>, qc: k::Term<Bool>, p: k::Term<Int>) -> k::Term<Res> {
    if list::size(OrderCodes(AtExp(c, r), qc, GetPhase(r))) == 0 {
        ROk(SetOrdered(r, [p], [CtxHeight(c) + CtxDeltaC(c)]))
    } else {
        RErr(r, OrderCodes(AtExp(c, r), qc, GetPhase(r)))
    }
}

/// RQ-013, RQ-062: the header of a request opens.
#[k::function(total, internal)]
pub fn StepOpen(
    _c: k::Term<Ctx>,
    r: k::Term<Req>,
    kk: k::Term<Int>,
    ll: k::Term<Int>,
    collecting: k::Term<Bool>,
    npos: k::Term<Int>,
    rates: k::Term<List<Int>>,
) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) {
        RErr(r, [RefusalC::Terminal])
    } else {
        OpenLive(r, kk, ll, collecting, npos, rates)
    }
}

/// RQ-067: `K ∈ 1..8`, `L ∈ 1..2`, one fee rate per variant.
#[k::function(total, internal)]
pub fn OpenInDomain(kk: k::Term<Int>, ll: k::Term<Int>, rates: k::Term<List<Int>>) -> k::Term<Bool> {
    1 <= kk && kk <= 8 && 1 <= ll && ll <= 2 && list::size(rates) == kk
}

#[k::function(total, internal)]
pub fn OpenLive(
    r: k::Term<Req>,
    kk: k::Term<Int>,
    ll: k::Term<Int>,
    collecting: k::Term<Bool>,
    npos: k::Term<Int>,
    rates: k::Term<List<Int>>,
) -> k::Term<Res> {
    if OpenInDomain(kk, ll, rates) {
        OpenOrdered(r, kk, ll, collecting, npos, rates)
    } else {
        RErr(r, [RefusalC::OutsideCapability])
    }
}

/// RQ-013: only an ORDERED request opens.
#[k::function(total, internal)]
pub fn OpenOrdered(
    r: k::Term<Req>,
    kk: k::Term<Int>,
    ll: k::Term<Int>,
    collecting: k::Term<Bool>,
    npos: k::Term<Int>,
    rates: k::Term<List<Int>>,
) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Ordered) {
        OpenHeader(r, kk, ll, collecting, npos, rates)
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

/// RQ-013: `phase = OPENED`, `K`, `L`, `G`; RQ-062: BIRTH, REFILL and CONTRIB keep no
/// signing state (`collecting = false`, no actor slot table).
#[k::function(total, internal)]
pub fn OpenHeader(
    r: k::Term<Req>,
    kk: k::Term<Int>,
    ll: k::Term<Int>,
    collecting: k::Term<Bool>,
    npos: k::Term<Int>,
    rates: k::Term<List<Int>>,
) -> k::Term<Res> {
    if Signing(GetRtype(r)) {
        ROk(SetOpened(r, collecting, kk, ll, GOf(kk), NoneList(GOf(kk)), NoneList(GOf(kk)), rates, NoneList(npos)))
    } else {
        ROk(SetOpened(r, false, kk, ll, GOf(kk), NoneList(GOf(kk)), NoneList(GOf(kk)), rates, GetPositions(r)))
    }
}

/// RQ-011 (before the first ADMIT vote), RQ-012 (after it).
#[k::function(total, internal)]
pub fn StepComplaint(_c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { ComplaintLive(r) }
}

#[k::function(total, internal)]
pub fn ComplaintLive(r: k::Term<Req>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Posted) { RErr(r, [RefusalC::NoRule]) } else { ComplaintOrdered(r) }
}

#[k::function(total, internal)]
pub fn ComplaintOrdered(r: k::Term<Req>) -> k::Term<Res> {
    if list::size(GetAdmitVotes(r)) == 0 { ROk(SetEarly(r)) } else { ROk(SetDealerFault(r)) }
}

/// RQ-018 to RQ-021: a contribution frame for the request is ordered.
#[k::function(total, internal)]
pub fn StepFrame(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { FrameLive(c, r, fr) }
}

/// RQ-018: a COLLECTING target takes the frame into its actor slot table.
#[k::function(total, internal)]
pub fn FrameLive(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Collecting) { FrameInTable(c, r, fr) } else { FrameWindow(c, r, fr) }
}

/// RQ-020 in every live phase (ledger 8): a frame ordered above `exp_c` of a target that
/// is not COLLECTING is refused (a POSTED target has no `exp_c`, so `Late` is false).
#[k::function(total, internal)]
pub fn FrameWindow(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if Late(GetExpC(r), CtxHeight(c)) { RErr(r, [RefusalC::LateContribution]) } else { FramePosted(c, r, fr) }
}

/// RQ-021: a frame for a POSTED target is held.
#[k::function(total, internal)]
pub fn FramePosted(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Posted) { FrameHold(c, r, fr) } else { FrameOrdered(c, r, fr) }
}

/// RQ-021: a frame for an ORDERED target is held; RQ-075 (DECISIONS 70, ledger 8): a frame
/// for a target in OPENED or ADMITTED (phase rank at least 2, not COLLECTING, not
/// terminal) is refused with `late_contribution`.
#[k::function(total, internal)]
pub fn FrameOrdered(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Ordered) { FrameHold(c, r, fr) } else { RErr(r, [RefusalC::LateContribution]) }
}

/// RQ-021: a frame for a POSTED or ORDERED request is held until the target reaches
/// COLLECTING, with the board height it was ordered at.
#[k::function(total, internal)]
pub fn FrameHold(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    ROk(SetHeld(r, list::concat(GetHeld(r), [FrameAt(fr, CtxHeight(c))])))
}

/// RQ-018: a position of the actor slot table.
#[k::function(total, internal)]
pub fn FrameInTable(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if FramePos(fr) < list::size(GetPositions(r)) {
        FrameAttach(c, r, fr)
    } else {
        RErr(r, [RefusalC::OutsideCapability])
    }
}

/// RQ-022: a share complaint against the frame at a position detaches it.
#[k::function(total, internal)]
pub fn StepDetach(_c: k::Term<Ctx>, r: k::Term<Req>, position: k::Term<Int>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { DetachLive(r, position) }
}

#[k::function(total, internal)]
pub fn DetachLive(r: k::Term<Req>, position: k::Term<Int>) -> k::Term<Res> {
    if IsSome(GetD(GetPositions(r), position)) {
        ROk(SetPositions(r, list::update(GetPositions(r), position, [])))
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

/// RQ-017: an OPENED vote commits.
#[k::function(total, internal)]
pub fn StepVoteOpened(c: k::Term<Ctx>, r: k::Term<Req>, node: k::Term<Int>, hash: k::Term<Int>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { OpenedNode(c, r, node, hash) }
}

/// RQ-001: node indices run `0..n − 1`.
#[k::function(total, internal)]
pub fn OpenedNode(c: k::Term<Ctx>, r: k::Term<Req>, node: k::Term<Int>, hash: k::Term<Int>) -> k::Term<Res> {
    if node < CtxN(c) { OpenedPhase(c, r, node, hash) } else { RErr(r, [RefusalC::OutsideCapability]) }
}

/// RQ-017: an OPENED request with `collecting = true`. Such a request is a signing
/// request (`openHdr` keeps `collecting = false` for BIRTH, REFILL and CONTRIB), so the
/// oracle's `signing` test is implied by `collecting`.
#[k::function(total, internal)]
pub fn OpenedPhase(c: k::Term<Ctx>, r: k::Term<Req>, node: k::Term<Int>, hash: k::Term<Int>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Opened) && GetCollecting(r) {
        OpenedFresh(c, r, node, hash)
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

/// RQ-017: one OPENED vote per node.
#[k::function(total, internal)]
pub fn OpenedFresh(c: k::Term<Ctx>, r: k::Term<Req>, node: k::Term<Int>, hash: k::Term<Int>) -> k::Term<Res> {
    if AnyNode2(GetOpenedVotes(r), node) {
        RErr(r, [RefusalC::NoRule])
    } else {
        OpenedCount(c, r, list::concat(GetOpenedVotes(r), [Vote2C::V2 { node, hash }]), hash)
    }
}

/// RQ-026, RQ-027: an ADMIT vote commits.
#[k::function(total, internal)]
pub fn StepVoteAdmit(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    node: k::Term<Int>,
    hash: k::Term<Int>,
    h: k::Term<Int>,
) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { AdmitNode(c, r, node, hash, h) }
}

/// RQ-001: node indices run `0..n − 1`.
#[k::function(total, internal)]
pub fn AdmitNode(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    node: k::Term<Int>,
    hash: k::Term<Int>,
    h: k::Term<Int>,
) -> k::Term<Res> {
    if node < CtxN(c) { AdmitPhase(c, r, node, hash, h) } else { RErr(r, [RefusalC::OutsideCapability]) }
}

/// RQ-026, RQ-062: an OPENED or COLLECTING signing request.
#[k::function(total, internal)]
pub fn AdmitPhase(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    node: k::Term<Int>,
    hash: k::Term<Int>,
    h: k::Term<Int>,
) -> k::Term<Res> {
    if (GetPhase(r).eq::<K>(PhaseC::Opened) || GetPhase(r).eq::<K>(PhaseC::Collecting)) && Signing(GetRtype(r)) {
        AdmitFresh(c, r, node, hash, h)
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

/// RQ-026: one ADMIT vote per node.
#[k::function(total, internal)]
pub fn AdmitFresh(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    node: k::Term<Int>,
    hash: k::Term<Int>,
    h: k::Term<Int>,
) -> k::Term<Res> {
    if AnyNode3(GetAdmitVotes(r), node) {
        RErr(r, [RefusalC::NoRule])
    } else {
        AdmitCount(c, r, list::concat(GetAdmitVotes(r), [Vote3C::V3 { node, hash, h }]), hash)
    }
}

/// RQ-028, RQ-029: generation 1 missed its deadline and a generation 2 OBS set commits.
#[k::function(total, internal)]
pub fn StepObs2(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    gen1_missed: k::Term<Bool>,
    heights: k::Term<List<Int>>,
) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { Obs2Heights(c, r, gen1_missed, heights) }
}

/// RQ-028: more than `f` OBS heights.
#[k::function(total, internal)]
pub fn Obs2Heights(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    gen1_missed: k::Term<Bool>,
    heights: k::Term<List<Int>>,
) -> k::Term<Res> {
    if CtxF(c) < list::size(heights) {
        Obs2Ready(c, r, gen1_missed, heights)
    } else {
        RErr(r, [RefusalC::OutsideCapability])
    }
}

/// RQ-028: ADMITTED, `G = 2`, `anchor[2] = none`, and generation 1 missed its deadline.
#[k::function(total, internal)]
pub fn Obs2Ready(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    gen1_missed: k::Term<Bool>,
    heights: k::Term<List<Int>>,
) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Admitted) && GetGg(r) == 2 && !IsSome(GetD(GetAnchor(r), 1)) && gen1_missed {
        Obs2Anchor(r, LookupMed(CtxMeds(c), AnchorHeight(CtxF(c), heights)))
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

/// RQ-042, RQ-044: a FINAL post of a member of the registered epoch `(e, n_e, f_e)`.
#[k::function(total, internal)]
pub fn FinalIn(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    ct: k::Term<Int>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { FinalMember(c, r, e, m, ct, ne, fe) }
}

/// RQ-042: member indices run `0..n_e − 1`.
#[k::function(total, internal)]
pub fn FinalMember(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    ct: k::Term<Int>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if m < ne { FinalServes(c, r, e, m, ct, ne, fe) } else { RErr(r, [RefusalC::OutsideCapability]) }
}

/// Ledger 10: an epoch older than the request's does not serve it.
#[k::function(total, internal)]
pub fn FinalServes(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    ct: k::Term<Int>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if e < GetEpoch(r) { RErr(r, [RefusalC::NoRule]) } else { FinalFresh(c, r, e, m, ct, ne, fe) }
}

/// Ledger 10: one FINAL post per member of an epoch.
#[k::function(total, internal)]
pub fn FinalFresh(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    ct: k::Term<Int>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if AnyFin(GetFinalPosts(r), e, m) {
        RErr(r, [RefusalC::NoRule])
    } else {
        FinalCount(c, r, list::concat(GetFinalPosts(r), [FinPostC::Fp { epoch: e, member: m, ct }]), e, ct, ne, fe)
    }
}

/// RQ-042, RQ-045: a VOID post of a member of the registered epoch `(e, n_e, f_e)`.
#[k::function(total, internal)]
pub fn VoidIn(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { VoidMember(c, r, e, m, reason, ne, fe) }
}

/// RQ-042: member indices run `0..n_e − 1`.
#[k::function(total, internal)]
pub fn VoidMember(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if m < ne { VoidReason(c, r, e, m, reason, fe) } else { RErr(r, [RefusalC::OutsideCapability]) }
}

/// RQ-065: a VOID post names a reason other than NONE (and MIXED, `VoidMixed`).
#[k::function(total, internal)]
pub fn VoidReason(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if reason.eq::<K>(ReasonC::RNone) {
        RErr(r, [RefusalC::OutsideCapability])
    } else {
        VoidMixed(c, r, e, m, reason, fe)
    }
}

/// RQ-065, RQ-072: MIXED is a tombstone reason, never a post reason.
#[k::function(total, internal)]
pub fn VoidMixed(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if reason.eq::<K>(ReasonC::Mixed) {
        RErr(r, [RefusalC::OutsideCapability])
    } else {
        VoidServes(c, r, e, m, reason, fe)
    }
}

/// Ledger 10: an epoch older than the request's does not serve it.
#[k::function(total, internal)]
pub fn VoidServes(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if e < GetEpoch(r) { RErr(r, [RefusalC::NoRule]) } else { VoidFresh(c, r, e, m, reason, fe) }
}

/// Ledger 10: one VOID post per member of an epoch.
#[k::function(total, internal)]
pub fn VoidFresh(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if AnyVoid(GetVoidPosts(r), e, m) {
        RErr(r, [RefusalC::NoRule])
    } else {
        VoidCount(c, r, list::concat(GetVoidPosts(r), [VoidPostC::Vp { epoch: e, member: m, reason }]), e, fe)
    }
}

/// RQ-048 (live request), RQ-068 (ended after the latest landed checkpoint), RQ-005, RQ-054.
#[k::function(total, internal)]
pub fn StepRestartBurn(c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { BurnEnded(c, r) } else { ROk(SetRestart(r)) }
}

/// Ledger 12: a carried leaf is settled.
#[k::function(total, internal)]
pub fn BurnEnded(c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    if GetCarried(r) { RErr(r, [RefusalC::Settled]) } else { BurnHeld(c, r) }
}

/// RQ-054: Midnight holds the leaf when the landed checkpoint covers the end. A terminal
/// request has an `end_height` (`reqInv`), so the default 0 is never read.
#[k::function(total, internal)]
pub fn BurnHeld(c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    if OrElse(GetEndHeight(r), 0) <= CtxCp(c) {
        RErr(r, [RefusalC::Terminal])
    } else {
        ROk(SetRestartOutcome(r, RestartOutcome(r)))
    }
}


#[k::function(total, internal)]
pub fn FramePos(fr: k::Term<Frame>) -> k::Term<Int> {
    match fr {
        FrameC::Fr { position, .. } => position,
    }
}

#[k::function(total, internal)]
pub fn FrameCid(fr: k::Term<Frame>) -> k::Term<Int> {
    match fr {
        FrameC::Fr { cid, .. } => cid,
    }
}

/// RQ-021: a held frame records the board height it was ordered at.
#[k::function(total, internal)]
pub fn FrameAt(fr: k::Term<Frame>, h: k::Term<Int>) -> k::Term<Frame> {
    match fr {
        FrameC::Fr { position, token_ok, lengths_ok, cid, .. } => {
            FrameC::Fr { position, token_ok, lengths_ok, height: h, cid }
        }
    }
}

/// RQ-020: ordered above `exp_c`; `exp_c` is set at ORDERED, and with none (POSTED) the
/// frame is not late (the oracle's `none => false`).
#[k::function(total, internal)]
pub fn Late(exp_c: k::Term<List<Int>>, h: k::Term<Int>) -> k::Term<Bool> {
    OrElse(exp_c, h) < h
}

/// RQ-018 to RQ-020: `late_contribution`, `position_filled`, or `no-rule` for a
/// token or length that fails.
#[k::function(total, internal)]
pub fn FrameCodes(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<List<Refusal>> {
    match fr {
        FrameC::Fr { position, token_ok, lengths_ok, .. } => OrNoRule(
            list::concat(
                Opt(Late(GetExpC(r), CtxHeight(c)), RefusalC::LateContribution),
                Opt(IsSome(GetD(GetPositions(r), position)), RefusalC::PositionFilled),
            ),
            token_ok && lengths_ok,
        ),
    }
}

/// RQ-018: attach the frame to its position.
#[k::function(total, internal)]
pub fn FrameAttach(c: k::Term<Ctx>, r: k::Term<Req>, fr: k::Term<Frame>) -> k::Term<Res> {
    if list::size(FrameCodes(c, r, fr)) == 0 {
        ROk(SetPositions(r, list::update(GetPositions(r), FramePos(fr), [FrameCid(fr)])))
    } else {
        RErr(r, FrameCodes(c, r, fr))
    }
}



/// RQ-018 for a held frame at the event that sets COLLECTING (RQ-021, ledger 9).
#[k::function(total, internal)]
pub fn HeldOk(e: k::Term<Int>, ps: k::Term<List<List<Int>>>, fr: k::Term<Frame>) -> k::Term<Bool> {
    match fr {
        FrameC::Fr { position, token_ok, lengths_ok, height, .. } => {
            height <= e && token_ok && lengths_ok && !IsSome(GetD(ps, position)) && position < list::size(ps)
        }
    }
}

#[k::function(total, internal)]
pub fn AttachOne(e: k::Term<Int>, ps: k::Term<List<List<Int>>>, fr: k::Term<Frame>) -> k::Term<List<List<Int>>> {
    if HeldOk(e, ps, fr) { list::update(ps, FramePos(fr), [FrameCid(fr)]) } else { ps }
}

/// `attachHeld`: RQ-018 on the held frames, in order.
#[k::function(total, internal)]
pub fn AttachHeld(
    e: k::Term<Int>,
    ps: k::Term<List<List<Int>>>,
    frs: k::Term<List<Frame>>,
) -> k::Term<List<List<Int>>> {
    match frs {
        [] => ps,
        [fr, rest @ ..] => AttachHeld(e, AttachOne(e, ps, fr), rest),
    }
}

/// RQ-017: `q` OPENED votes with one hash set COLLECTING and attach the held frames.
#[k::function(total, internal)]
pub fn OpenedCount(c: k::Term<Ctx>, r: k::Term<Req>, vs: k::Term<List<Vote2>>, hash: k::Term<Int>) -> k::Term<Res> {
    if QOf(CtxN(c), CtxF(c)) <= Count2(vs, hash) {
        ROk(SetCollecting(r, AttachHeld(OrElse(GetExpC(r), 0), GetPositions(r), GetHeld(r)), vs))
    } else {
        ROk(SetOpenedVotes(r, vs))
    }
}


/// RQ-027: `anchor[1]` from the host fee median at the anchor height; no median
/// in the view refuses the vote (ledger 7).
#[k::function(total, internal)]
pub fn AdmitAnchor(r: k::Term<Req>, vs: k::Term<List<Vote3>>, med: k::Term<List<Int>>) -> k::Term<Res> {
    match med {
        [] => RErr(r, [RefusalC::NoRule]),
        [m, ..] => ROk(SetAdmitted(r, list::update(GetAnchor(r), 0, [Select(GetKk(r), GetRates(r), m)]), vs)),
    }
}

/// RQ-026: the first `q` ADMIT votes with one hash set ADMITTED.
#[k::function(total, internal)]
pub fn AdmitCount(c: k::Term<Ctx>, r: k::Term<Req>, vs: k::Term<List<Vote3>>, hash: k::Term<Int>) -> k::Term<Res> {
    if QOf(CtxN(c), CtxF(c)) <= list::size(Mine(vs, hash)) {
        AdmitAnchor(r, vs, LookupMed(CtxMeds(c), AnchorHeight(CtxF(c), Heights(Mine(vs, hash)))))
    } else {
        ROk(SetAdmitVotes(r, vs))
    }
}


/// RQ-029: generation 2 must select a variant above `anchor[1]` (set at ADMITTED).
#[k::function(total, internal)]
pub fn Obs2Select(r: k::Term<Req>, j: k::Term<Int>) -> k::Term<Res> {
    if OrElse(GetD(GetAnchor(r), 0), 0) < j {
        ROk(SetAnchor(r, list::update(GetAnchor(r), 1, [j])))
    } else {
        RErr(r, [RefusalC::NoRule])
    }
}

#[k::function(total, internal)]
pub fn Obs2Anchor(r: k::Term<Req>, med: k::Term<List<Int>>) -> k::Term<Res> {
    match med {
        [] => RErr(r, [RefusalC::NoRule]),
        [m, ..] => Obs2Select(r, Select(GetKk(r), GetRates(r), m)),
    }
}


/// RQ-044: `q_e` FINAL posts with one `Enc_{k_fin}(txid)` end the request FINAL.
#[k::function(total, internal)]
pub fn FinalCount(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    ps: k::Term<List<FinPost>>,
    e: k::Term<Int>,
    ct: k::Term<Int>,
    ne: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if QOf(ne, fe) <= CountFin(ps, e, ct) {
        ROk(EndFinal(c, SetFinalPosts(r, ps)))
    } else {
        ROk(SetFinalPosts(r, ps))
    }
}


/// RQ-043: `terminal` and `unknown_epoch` in code order; the epoch's own `n_e`, `f_e` (RQ-042).
#[k::function(total, internal)]
pub fn FinalWith(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    ct: k::Term<Int>,
    found: k::Term<List<Epoch>>,
) -> k::Term<Res> {
    match found {
        [] => RErr(r, list::concat(Opt(IsTerminal(GetPhase(r)), RefusalC::Terminal), [RefusalC::UnknownEpoch])),
        [EpochC::Ep { n, f, .. }, ..] => FinalIn(c, r, e, m, ct, n, f),
    }
}

/// RQ-042 to RQ-044, RQ-049: a FINAL post.
#[k::function(total, internal)]
pub fn StepPostFinal(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    epoch: k::Term<Int>,
    member: k::Term<Int>,
    ct: k::Term<Int>,
) -> k::Term<Res> {
    FinalWith(c, r, epoch, member, ct, FindEpoch(CtxEpochs(c), epoch))
}


/// RQ-043: `terminal` and `unknown_epoch` in code order.
#[k::function(total, internal)]
pub fn VoidWith(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    e: k::Term<Int>,
    m: k::Term<Int>,
    reason: k::Term<Reason>,
    found: k::Term<List<Epoch>>,
) -> k::Term<Res> {
    match found {
        [] => RErr(r, list::concat(Opt(IsTerminal(GetPhase(r)), RefusalC::Terminal), [RefusalC::UnknownEpoch])),
        [EpochC::Ep { n, f, .. }, ..] => VoidIn(c, r, e, m, reason, n, f),
    }
}

/// RQ-042, RQ-043, RQ-045: a VOID post.
#[k::function(total, internal)]
pub fn StepPostVoid(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    epoch: k::Term<Int>,
    member: k::Term<Int>,
    reason: k::Term<Reason>,
) -> k::Term<Res> {
    VoidWith(c, r, epoch, member, reason, FindEpoch(CtxEpochs(c), epoch))
}


/// The host chain shows a variant transaction of the request at confirmation depth.
#[k::function(total, internal)]
pub fn StepConfirm(_c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    ROk(SetConfirmed(r))
}

/// AU-021, RQ-060 (ledger 25): a reissue's `authorize` carried the VOID leaf of the
/// stalled request: outcome VOID (`CarryStalled` reads the reason).
#[k::function(total, internal)]
pub fn StepCarry(_c: k::Term<Ctx>, r: k::Term<Req>) -> k::Term<Res> {
    if GetOutcome(r).eq::<K>(OutcomeC::OVoid) { CarryStalled(r) } else { RErr(r, [RefusalC::NoRule]) }
}

/// AU-021, RQ-060, RQ-071: the tombstone reason reads as STALLED.
#[k::function(total, internal)]
pub fn CarryStalled(r: k::Term<Req>) -> k::Term<Res> {
    if ReadsAs(GetReason(r), ReasonC::Stalled) { ROk(SetCarried(r)) } else { RErr(r, [RefusalC::NoRule]) }
}

/// RQ-071 (`readsAs`): a rule that reads a tombstone reason reads MIXED as none of
/// STALLED, SLOT_TAKEN and REVOKED, and as no other named reason.
#[k::function(total, internal)]
pub fn ReadsAs(reason: k::Term<Reason>, x: k::Term<Reason>) -> k::Term<Bool> {
    match reason {
        ReasonC::Mixed => false,
        _ => reason.eq::<K>(x),
    }
}

/// RQ-006, RQ-007: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TOrder(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, qc: k::Term<Bool>, p: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepOrder(c, Find(eid, rs), qc, p))
}

/// RQ-013, RQ-062: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TOpen(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, kk: k::Term<Int>, ll: k::Term<Int>, collecting: k::Term<Bool>, npos: k::Term<Int>, rates: k::Term<List<Int>>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepOpen(c, Find(eid, rs), kk, ll, collecting, npos, rates))
}

/// RQ-011, RQ-012: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TComplaint(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepComplaint(c, Find(eid, rs)))
}

/// RQ-018 to RQ-021: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TFrame(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, fr: k::Term<Frame>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepFrame(c, Find(eid, rs), fr))
}

/// RQ-022: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TDetach(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, position: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepDetach(c, Find(eid, rs), position))
}

/// RQ-017: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TVoteOpened(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, node: k::Term<Int>, hash: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepVoteOpened(c, Find(eid, rs), node, hash))
}

/// RQ-026, RQ-027: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TVoteAdmit(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, node: k::Term<Int>, hash: k::Term<Int>, h: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepVoteAdmit(c, Find(eid, rs), node, hash, h))
}

/// RQ-028, RQ-029: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TObs2(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, gen1_missed: k::Term<Bool>, heights: k::Term<List<Int>>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepObs2(c, Find(eid, rs), gen1_missed, heights))
}

/// RQ-042 to RQ-044, RQ-049: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TPostFinal(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, epoch: k::Term<Int>, member: k::Term<Int>, ct: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepPostFinal(c, Find(eid, rs), epoch, member, ct))
}

/// RQ-042, RQ-043, RQ-045: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TPostVoid(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, epoch: k::Term<Int>, member: k::Term<Int>, reason: k::Term<Reason>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepPostVoid(c, Find(eid, rs), epoch, member, reason))
}

/// RQ-048, RQ-068, RQ-005, RQ-054: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TRestartBurn(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepRestartBurn(c, Find(eid, rs)))
}

/// the host chain's confirmation fact: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TConfirm(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepConfirm(c, Find(eid, rs)))
}

/// AU-021, RQ-060: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TCarry(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepCarry(c, Find(eid, rs)))
}

// ---------------------------------------------------------------------------
// The RELEASE record (RQ-037, read by RQ-030, RQ-050 and RQ-051) and the VOID count that
// completes a VOID end (RQ-045, RQ-072 to RQ-074).

/// RQ-037: `released[g] = j`, `any_release = true`.
#[k::function(total, internal)]
pub fn SetReleased(r: k::Term<Req>, v_released: k::Term<List<List<Int>>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, phase, reason, collecting, kk, ll, gg, anchor, restart_end, outcome, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, end_height, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase,
            reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released: v_released,
            any_release: true,
            restart_end,
            outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-045, RQ-050 to RQ-052: `endVoid`.
#[k::function(total, internal)]
pub fn EndVoidAt(r: k::Term<Req>, v_reason: k::Term<Reason>, v_outcome: k::Term<Outcome>, v_end_height: k::Term<List<Int>>) -> k::Term<Req> {
    match r {
        ReqC::Rq { eid, epoch, exp, rtype, profile, order_pos, exp_c, collecting, kk, ll, gg, anchor, released, any_release, restart_end, rates, positions, held, opened_votes, admit_votes, early_complaint, dealer_fault, final_posts, void_posts, confirmed, carried, .. } => ReqC::Rq {
            eid,
            epoch,
            exp,
            rtype,
            profile,
            order_pos,
            exp_c,
            phase: PhaseC::Void,
            reason: v_reason,
            collecting,
            kk,
            ll,
            gg,
            anchor,
            released,
            any_release,
            restart_end,
            outcome: v_outcome,
            rates,
            positions,
            held,
            opened_votes,
            admit_votes,
            early_complaint,
            dealer_fault,
            final_posts,
            void_posts,
            end_height: v_end_height,
            confirmed,
            carried,
        },
    }
}

/// RQ-045, RQ-050 to RQ-052: `endVoid` with the tombstone reason.
#[k::function(total, internal)]
pub fn EndVoid(c: k::Term<Ctx>, r: k::Term<Req>, reason: k::Term<Reason>) -> k::Term<Req> {
    EndVoidAt(r, reason, EndOutcome(r), [CtxHeight(c)])
}

/// RQ-045, RQ-072 to RQ-074: the post that completes `f_e + 1` VOID posts of epoch `e`
/// ends the request VOID with the tombstone reason of the posts of epoch `e` (ledger 24).
#[k::function(total, internal)]
pub fn VoidCount(
    c: k::Term<Ctx>,
    r: k::Term<Req>,
    ps: k::Term<List<VoidPost>>,
    e: k::Term<Int>,
    fe: k::Term<Int>,
) -> k::Term<Res> {
    if fe + 1 <= CountVoid(ps, e) {
        ROk(EndVoid(c, SetVoidPosts(r, ps), TombReason(fe, GetAnyRelease(r), EpochReasons(ps, e))))
    } else {
        ROk(SetVoidPosts(r, ps))
    }
}

/// RQ-042, RQ-045 (ledger 24): the reasons of the counted posts, the VOID posts of epoch `e`.
#[k::function(total, internal)]
pub fn EpochReasons(ps: k::Term<List<VoidPost>>, e: k::Term<Int>) -> k::Term<List<Reason>> {
    match ps {
        [] => [],
        [VoidPostC::Vp { epoch, reason, .. }, rest @ ..] if epoch == e => [reason, ..EpochReasons(rest, e)],
        [VoidPostC::Vp { epoch, .. }, rest @ ..] if epoch != e => EpochReasons(rest, e),
    }
}

/// RQ-074 (`reasonPosts`): once a RELEASE has committed (`any_release`), STALLED posts are
/// no reason posts.
#[k::function(total, internal)]
pub fn ReasonPosts(anyrel: k::Term<Bool>, counted: k::Term<List<Reason>>) -> k::Term<List<Reason>> {
    if anyrel { DropStalled(counted) } else { counted }
}

/// `counted.filter (· != STALLED)`.
#[k::function(total, internal)]
pub fn DropStalled(l: k::Term<List<Reason>>) -> k::Term<List<Reason>> {
    match l {
        [] => [],
        [x, rest @ ..] if x.eq::<K>(ReasonC::Stalled) => DropStalled(rest),
        [x, rest @ ..] if !x.eq::<K>(ReasonC::Stalled) => [x, ..DropStalled(rest)],
    }
}

/// `countWith (· == x)`.
#[k::function(total, internal)]
pub fn CountReason(l: k::Term<List<Reason>>, x: k::Term<Reason>) -> k::Term<Int> {
    match l {
        [] => 0,
        [y, rest @ ..] if y.eq::<K>(x) => 1 + CountReason(rest, x),
        [y, rest @ ..] if !y.eq::<K>(x) => CountReason(rest, x),
    }
}

/// RQ-045, RQ-072: the first candidate reason that `f + 1` reason posts carry; MIXED when
/// none does.
#[k::function(total, internal)]
pub fn FindReason(f: k::Term<Int>, l: k::Term<List<Reason>>, cands: k::Term<List<Reason>>) -> k::Term<Reason> {
    match cands {
        [] => ReasonC::Mixed,
        [x, ..] if f + 1 <= CountReason(l, x) => x,
        [x, rest @ ..] if CountReason(l, x) < f + 1 => FindReason(f, l, rest),
    }
}

/// RQ-045, RQ-072, RQ-073 (`tombReason`): the post reasons (`postReasons`: every reason
/// but NONE and MIXED, RQ-065) searched in order over the reason posts.
#[k::function(total, internal)]
pub fn TombReason(f: k::Term<Int>, anyrel: k::Term<Bool>, counted: k::Term<List<Reason>>) -> k::Term<Reason> {
    FindReason(
        f,
        ReasonPosts(anyrel, counted),
        [
            ReasonC::ShareComplaint,
            ReasonC::Malformed,
            ReasonC::AuthRefused,
            ReasonC::Revoked,
            ReasonC::ReleaseCheck,
            ReasonC::Contribution,
            ReasonC::DealerFault,
            ReasonC::PinSpent,
            ReasonC::SlotTaken,
            ReasonC::Stalled,
            ReasonC::Restart,
        ],
    )
}

/// RQ-037: one variant per generation; a second RELEASE of another variant is refused.
#[k::function(total, internal)]
pub fn ReleaseRec(r: k::Term<Req>, g: k::Term<Int>, j: k::Term<Int>, prev: k::Term<List<Int>>) -> k::Term<Res> {
    if OrElse(prev, j) != j {
        RErr(r, [RefusalC::NoRule])
    } else {
        ROk(SetReleased(r, list::update(GetReleased(r), g - 1, [j])))
    }
}

/// RQ-037: a RELEASE of generation `g` with variant `j` commits or is acked.
#[k::function(total, internal)]
pub fn StepRelease(_c: k::Term<Ctx>, r: k::Term<Req>, g: k::Term<Int>, j: k::Term<Int>) -> k::Term<Res> {
    if IsTerminal(GetPhase(r)) { RErr(r, [RefusalC::Terminal]) } else { ReleaseAdmitted(r, g, j) }
}

/// RQ-037: only an ADMITTED request releases.
#[k::function(total, internal)]
pub fn ReleaseAdmitted(r: k::Term<Req>, g: k::Term<Int>, j: k::Term<Int>) -> k::Term<Res> {
    if GetPhase(r).eq::<K>(PhaseC::Admitted) { ReleaseInDomain(r, g, j) } else { RErr(r, [RefusalC::NoRule]) }
}

/// RQ-037: `g ∈ 1..G`, `j ∈ 1..K`.
#[k::function(total, internal)]
pub fn ReleaseInDomain(r: k::Term<Req>, g: k::Term<Int>, j: k::Term<Int>) -> k::Term<Res> {
    if 1 <= g && g <= GetGg(r) && 1 <= j && j <= GetKk(r) {
        ReleaseRec(r, g, j, GetD(GetReleased(r), g - 1))
    } else {
        RErr(r, [RefusalC::OutsideCapability])
    }
}

/// RQ-037: `step` on the request `eid` names (RQ-004 when it holds none).
#[k::function(total, internal)]
pub fn TRelease(c: k::Term<Ctx>, rs: k::Term<List<Req>>, eid: k::Term<Int>, g: k::Term<Int>, j: k::Term<Int>) -> k::Term<Res> {
    Targeted(HasReq(eid, rs), StepRelease(c, Find(eid, rs), g, j))
}

// ---------------------------------------------------------------------------
// Board events that change the context.

/// RQ-042, ledger 5: a ROTATE outside RQ-001, or of a registered epoch.
#[k::function(total, internal)]
pub fn RotateCodes(es: k::Term<List<Epoch>>, e: k::Term<Int>, n: k::Term<Int>, f: k::Term<Int>) -> k::Term<List<Refusal>> {
    if !CommitteeOk(n, f) {
        [RefusalC::OutsideCapability]
    } else if list::size(FindEpoch(es, e)) != 0 {
        [RefusalC::NoRule]
    } else {
        []
    }
}

/// A second fee median for one host height must agree with the first.
#[k::function(total, internal)]
pub fn FeeCodes(found: k::Term<List<Int>>, m: k::Term<Int>) -> k::Term<List<Refusal>> {
    match found {
        [] => [],
        [x, ..] if x == m => [],
        [x, ..] if x != m => [RefusalC::NoRule],
    }
}

/// The fee median at a new host height is added; a known one changes nothing.
#[k::function(total, internal)]
pub fn FeeMeds(meds: k::Term<List<Med>>, h: k::Term<Int>, m: k::Term<Int>) -> k::Term<List<Med>> {
    if IsSome(LookupMed(meds, h)) { meds } else { list::concat(meds, [MedC::Md { h, m }]) }
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
    pub height: Int,
    #[k::cell]
    pub cpheight: Int,
    #[k::cell]
    pub epochs: List<Epoch>,
    #[k::cell]
    pub hostmed: List<Med>,
    #[k::cell]
    pub requests: List<Req>,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: board height 0, no checkpoint, no fee median, no request.
    #[k::init]
    pub fn init(params: Params, epochs: List<Epoch>, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            height: 0,
            cpheight: 0,
            epochs,
            hostmed: [],
            requests: [],
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // RQ-003: a request for a new `eid` with `phase = POSTED`.
    #[k::requires(!HasReq(eid, requests))]
    post: {
        k: [Step::Go, ..],
        requests,
        ops: [OpC::Post { eid, epoch, exp, rtype, profile }, ..],
        obs,
    } => {
        requests: list::concat(requests, [NewReq(eid, epoch, exp, rtype, profile)]),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 2: a second post of an `eid` the machine holds.
    #[k::requires(HasReq(eid, requests))]
    post_dup: {
        k: [Step::Go, ..],
        requests,
        ops: [OpC::Post { eid, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // RQ-046: the board reaches height `h`; every live request with `exp < h` expires.
    #[k::requires(h >= height)]
    tick: {
        k: [Step::Go, ..],
        height,
        requests,
        ops: [OpC::Tick { h }, ..],
        obs,
    } => {
        height: h,
        requests: ExpireAll(h, requests),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 4: the board height does not go down.
    #[k::requires(h < height)]
    tick_back: {
        k: [Step::Go, ..],
        height,
        ops: [OpC::Tick { h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // RQ-042: a ROTATE registers epoch `e` with `n_e`, `f_e`.
    #[k::requires(list::size(RotateCodes(epochs, e, n, f)) == 0)]
    rotate: {
        k: [Step::Go, ..],
        epochs,
        ops: [OpC::Rotate { e, n, f }, ..],
        obs,
    } => {
        epochs: list::concat(epochs, [EpochC::Ep { e, n, f }]),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // RQ-001, ledger 5: a ROTATE outside the domain or of a registered epoch.
    #[k::requires(list::size(RotateCodes(epochs, e, n, f)) != 0)]
    rotate_refused: {
        k: [Step::Go, ..],
        epochs,
        ops: [OpC::Rotate { e, n, f }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: RotateCodes(epochs, e, n, f) }],
    };

    // RQ-054, RQ-068: a checkpoint lands at board height `h`.
    #[k::requires(!(h < cpheight || height < h))]
    land_checkpoint: {
        k: [Step::Go, ..],
        height,
        cpheight,
        ops: [OpC::LandCp { h }, ..],
        obs,
    } => {
        cpheight: h,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 4: a checkpoint never goes back and never passes the board height.
    #[k::requires(h < cpheight || height < h)]
    land_checkpoint_refused: {
        k: [Step::Go, ..],
        height,
        cpheight,
        ops: [OpC::LandCp { h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // RQ-027: the host chain's fee median at host height `h`.
    #[k::requires(list::size(FeeCodes(LookupMed(hostmed, h), m)) == 0)]
    host_fee: {
        k: [Step::Go, ..],
        hostmed,
        ops: [OpC::HostFee { h, m }, ..],
        obs,
    } => {
        hostmed: FeeMeds(hostmed, h, m),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // A second, different fee median for one host height.
    #[k::requires(list::size(FeeCodes(LookupMed(hostmed, h), m)) != 0)]
    host_fee_refused: {
        k: [Step::Go, ..],
        hostmed,
        ops: [OpC::HostFee { h, m }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: FeeCodes(LookupMed(hostmed, h), m) }],
    };

    // RQ-006, RQ-007: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TOrder(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, qc, p)))]
    order: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Order { eid, qc, p }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TOrder(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, qc, p)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TOrder(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, qc, p))) }],
    };

    // RQ-006, RQ-007: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TOrder(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, qc, p)))]
    order_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Order { eid, qc, p }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TOrder(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, qc, p)) }],
    };

    // RQ-013, RQ-062: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TOpen(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, kk, ll, collecting, npos, rates)))]
    open_header: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Open { eid, kk, ll, collecting, npos, rates }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TOpen(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, kk, ll, collecting, npos, rates)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TOpen(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, kk, ll, collecting, npos, rates))) }],
    };

    // RQ-013, RQ-062: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TOpen(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, kk, ll, collecting, npos, rates)))]
    open_header_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Open { eid, kk, ll, collecting, npos, rates }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TOpen(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, kk, ll, collecting, npos, rates)) }],
    };

    // RQ-011, RQ-012: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TComplaint(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    complaint: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Complaint { eid }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TComplaint(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TComplaint(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid))) }],
    };

    // RQ-011, RQ-012: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TComplaint(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    complaint_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Complaint { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TComplaint(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)) }],
    };

    // RQ-018 to RQ-021: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TFrame(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, fr)))]
    frame: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::FrameOp { eid, fr }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TFrame(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, fr)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TFrame(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, fr))) }],
    };

    // RQ-018 to RQ-021: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TFrame(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, fr)))]
    frame_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::FrameOp { eid, fr }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TFrame(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, fr)) }],
    };

    // RQ-022: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TDetach(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, position)))]
    detach: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Detach { eid, position }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TDetach(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, position)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TDetach(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, position))) }],
    };

    // RQ-022: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TDetach(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, position)))]
    detach_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Detach { eid, position }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TDetach(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, position)) }],
    };

    // RQ-017: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TVoteOpened(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash)))]
    vote_opened: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::VoteOpened { eid, node, hash }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TVoteOpened(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TVoteOpened(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash))) }],
    };

    // RQ-017: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TVoteOpened(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash)))]
    vote_opened_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::VoteOpened { eid, node, hash }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TVoteOpened(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash)) }],
    };

    // RQ-026, RQ-027: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TVoteAdmit(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash, h)))]
    vote_admit: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::VoteAdmit { eid, node, hash, h }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TVoteAdmit(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash, h)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TVoteAdmit(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash, h))) }],
    };

    // RQ-026, RQ-027: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TVoteAdmit(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash, h)))]
    vote_admit_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::VoteAdmit { eid, node, hash, h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TVoteAdmit(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, node, hash, h)) }],
    };

    // RQ-028, RQ-029: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TObs2(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, gen1_missed, heights)))]
    obs2: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Obs2 { eid, gen1_missed, heights }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TObs2(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, gen1_missed, heights)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TObs2(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, gen1_missed, heights))) }],
    };

    // RQ-028, RQ-029: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TObs2(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, gen1_missed, heights)))]
    obs2_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Obs2 { eid, gen1_missed, heights }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TObs2(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, gen1_missed, heights)) }],
    };

    // RQ-042 to RQ-044, RQ-049: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TPostFinal(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, ct)))]
    post_final: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::PostFinal { eid, epoch, member, ct }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TPostFinal(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, ct)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TPostFinal(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, ct))) }],
    };

    // RQ-042 to RQ-044, RQ-049: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TPostFinal(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, ct)))]
    post_final_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::PostFinal { eid, epoch, member, ct }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TPostFinal(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, ct)) }],
    };

    // RQ-042, RQ-043, RQ-045: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TPostVoid(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, reason)))]
    post_void: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::PostVoid { eid, epoch, member, reason }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TPostVoid(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, reason)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TPostVoid(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, reason))) }],
    };

    // RQ-042, RQ-043, RQ-045: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TPostVoid(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, reason)))]
    post_void_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::PostVoid { eid, epoch, member, reason }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TPostVoid(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, epoch, member, reason)) }],
    };

    // RQ-048, RQ-068, RQ-005, RQ-054: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TRestartBurn(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    restart_burn: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::RestartBurn { eid }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TRestartBurn(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TRestartBurn(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid))) }],
    };

    // RQ-048, RQ-068, RQ-005, RQ-054: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TRestartBurn(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    restart_burn_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::RestartBurn { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TRestartBurn(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)) }],
    };

    // the host chain's confirmation fact: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TConfirm(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    confirm: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Confirm { eid }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TConfirm(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TConfirm(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid))) }],
    };

    // the host chain's confirmation fact: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TConfirm(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    confirm_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Confirm { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TConfirm(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)) }],
    };

    // AU-021, RQ-060: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TCarry(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    carry: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Carry { eid }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TCarry(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TCarry(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid))) }],
    };

    // AU-021, RQ-060: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TCarry(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)))]
    carry_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Carry { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TCarry(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid)) }],
    };

    // RQ-037: the event applies; the request's new phase is observed.
    #[k::requires(ResOk(TRelease(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, g, j)))]
    release: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Release { eid, g, j }, ..],
        obs,
    } => {
        requests: Replace(eid, ResReq(TRelease(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, g, j)), requests),
        ops: [..],
        obs: [..obs, ObsC::PhaseIs { p: GetPhase(ResReq(TRelease(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, g, j))) }],
    };

    // RQ-037: the event is refused with its codes; the state is unchanged.
    #[k::requires(!ResOk(TRelease(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, g, j)))]
    release_refused: {
        k: [Step::Go, ..],
        params,
        height,
        cpheight,
        epochs,
        hostmed,
        requests,
        ops: [OpC::Release { eid, g, j }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ResCodes(TRelease(CtxC::Cx { params, height, cp: cpheight, epochs, host_med: hostmed }, requests, eid, g, j)) }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
