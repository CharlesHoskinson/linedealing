//! Split shard-holder reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/shard-holders/SplitShardHolders/Spec.lean` (`apply`, `runOps`).
//!
//! One rule per behaviour of `apply`: each operation either passes `opRefusals`
//! and runs `exec`, or is refused with every applicable code in code order and
//! leaves the state unchanged (ambiguity ledger 1, 2). The checks are functions
//! with one equation per branch, so each branch and each condition operand is a
//! coverage obligation and a mutation target. Requirement IDs refer to
//! `openspec/changes/add-split-line-dealing/specs/split-shard-holders/spec.md`.
//!
//! Cells are the oracle's `St` fields (`params`, `charters`, `births`, `records`,
//! `dealt`, `used`, `keys`, `slotsused`, `acks`) and its observation list `obs`;
//! `ops` holds the operations still to run and is empty at every end (FLOW.toml
//! omits it). Parameters outside RQ-001 make the oracle answer `could-not-apply`;
//! the corpus stays inside that domain (../gaps.toml).

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, int, list};

k::sorts! {
    Run: KItem;
    Mode;
    Profile;
    Gate;
    Q;
    OptQ;
    MQ;
    OptMQ;
    OptGate;
    Ctx;
    ActorProof;
    BirthCheck;
    RecordReq;
    AckCheck;
    OptRec;
    SlotRef;
    Contrib;
    Params;
    Rec;
    Charter;
    NN;
    NNN;
    CheckedSlot;
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
    #[k::syntax("mTEE")] Tee,
    #[k::syntax("mNONTEE")] NonTee,
}

#[k::constructors(sort = Profile, result = KResult)]
#[rustfmt::skip]
pub enum ProfileC {
    #[k::syntax("pP0")] P0,
    #[k::syntax("pP1")] P1,
    #[k::syntax("pP2")] P2,
}

/// SH-001: a monotone access structure; every gate carries its member id `mid`
/// (SH-002). `primary` is the primary child of an OR gate, `escrow` its escrow child.
#[k::constructors(sort = Gate, result = KResult)]
#[rustfmt::skip]
pub enum GateC {
    #[k::syntax("gLeaf({mid}, {actor})")] Leaf { mid: Int, actor: Int },
    #[k::syntax("gAnd({mid}, {children})")] And { mid: Int, children: List<Gate> },
    #[k::syntax("gGroup({mid}, {kk}, {children})")] Group { mid: Int, kk: Int, children: List<Gate> },
    #[k::syntax("gOr({mid}, {primary}, {escrow})")] Or { mid: Int, primary: Gate, escrow: Gate },
}

/// An exact rational `num / den` (SH-004).
#[k::constructors(sort = Q, result = KResult)]
pub enum QC {
    #[k::syntax("q({num}, {den})")]
    Qv { num: Int, den: Int },
}

#[k::constructors(sort = OptQ, result = KResult)]
#[rustfmt::skip]
pub enum OptQC {
    #[k::syntax("noneQ")] NoneQ,
    #[k::syntax("someQ({w})")] SomeQ { w: Q },
}

/// The member id of the child that holds an actor, with the weight below it.
#[k::constructors(sort = MQ, result = KResult)]
pub enum MQC {
    #[k::syntax("mq({x}, {w})")]
    Mqv { x: Int, w: Q },
}

#[k::constructors(sort = OptMQ, result = KResult)]
#[rustfmt::skip]
pub enum OptMQC {
    #[k::syntax("noneMQ")] NoneMQ,
    #[k::syntax("someMQ({v})")] SomeMQ { v: MQ },
}

#[k::constructors(sort = OptGate, result = KResult)]
#[rustfmt::skip]
pub enum OptGateC {
    #[k::syntax("noneG")] NoneG,
    #[k::syntax("someG({g})")] SomeG { g: Gate },
}

/// The statement a proof of possession was made for: `(X_f, X_a, slot_a, charter_id, chain_id)`.
#[k::constructors(sort = Ctx, result = KResult)]
pub enum CtxC {
    #[k::syntax("ctx({a}, {b}, {c}, {d}, {e})")]
    C5 { a: Int, b: Int, c: Int, d: Int, e: Int },
}

/// SH-007, SH-008: the proof of possession of one actor at birth.
#[k::constructors(sort = ActorProof, result = KResult)]
pub enum ActorProofC {
    #[k::syntax("actorProof({slot}, {x_a}, {ctx}, {valid}, {network_created}, {pop_u}, {delta})")]
    Ap { slot: Int, x_a: Int, ctx: Ctx, valid: Bool, network_created: Bool, pop_u: Bool, delta: Bool },
}

/// SH-009: the checks at one node.
#[k::constructors(sort = BirthCheck, result = KResult)]
pub enum BirthCheckC {
    #[k::syntax("birth({x_f}, {charter_id}, {chain_id}, {actors}, {dealer_ok}, {x_recomputed}, {encoding_ok}, {opening_ok})")]
    Bc {
        x_f: Int,
        charter_id: Int,
        chain_id: Int,
        actors: List<ActorProof>,
        dealer_ok: Bool,
        x_recomputed: Bool,
        encoding_ok: Bool,
        opening_ok: Bool,
    },
}

/// SH-011, SH-012: an address record that arrives at FenrirAssets; `network_created`:
/// the address has a network-created shard (SH-008, ledger 14).
#[k::constructors(sort = RecordReq, result = KResult)]
pub enum RecordReqC {
    #[k::syntax("recordReq({cm_addr}, {profile}, {charter}, {signers}, {owner_reg}, {escrow_acks}, {escrow_quorum}, {guardian_acks}, {q_g}, {network_created})")]
    Rr {
        cm_addr: Int,
        profile: Profile,
        charter: Int,
        signers: List<Int>,
        owner_reg: Bool,
        escrow_acks: Int,
        escrow_quorum: Int,
        guardian_acks: Int,
        q_g: Int,
        network_created: Bool,
    },
}

/// SH-031 (ledger 17): the checks of one ACK envelope at one node: the birth data
/// recompute `X`, the opening of `cm_addr` passes, `pop_u` verifies under `X_u`.
#[k::constructors(sort = AckCheck, result = KResult)]
pub enum AckCheckC {
    #[k::syntax("ack({x_recomputed}, {opening_ok}, {pop_u})")]
    Ac { x_recomputed: Bool, opening_ok: Bool, pop_u: Bool },
}

/// The slot a request names for the actor's half.
#[k::constructors(sort = SlotRef, result = KResult)]
#[rustfmt::skip]
pub enum SlotRefC {
    #[k::syntax("sCommittee")] Committee,
    #[k::syntax("sEcdsa({id}, {leaf_set}, {under_g})")]
    Ecdsa { id: Int, leaf_set: List<Int>, under_g: Bool },
}

/// A request as one actor sees it before it contributes.
#[k::constructors(sort = Contrib, result = KResult)]
pub enum ContribC {
    #[k::syntax("contrib({actor}, {charter}, {s_set}, {initiator}, {weight}, {pairs}, {slot}, {exp_c}, {height}, {policy_ok}, {recompute_ok}, {seizure_settled})")]
    Cr {
        actor: Int,
        charter: Int,
        s_set: List<Int>,
        initiator: Int,
        weight: Q,
        pairs: List<Int>,
        slot: SlotRef,
        exp_c: Int,
        height: Int,
        policy_ok: Bool,
        recompute_ok: Bool,
        seizure_settled: Bool,
    },
}

#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    #[k::syntax("params({n}, {f}, {mode}, {n_h})")]
    Pm { n: Int, f: Int, mode: Mode, n_h: Int },
}

/// An admitted address record with its verified signers, its network-created flag
/// and `acked` (SH-034, SH-037).
#[k::constructors(sort = Rec, result = KResult)]
pub enum RecC {
    #[k::syntax("rec({cm_addr}, {profile}, {charter}, {sigs}, {network_created}, {acked})")]
    Rv { cm_addr: Int, profile: Profile, charter: Int, sigs: List<Int>, network_created: Bool, acked: Bool },
}

/// `findRec`: the record of a `cm_addr`, if any.
#[k::constructors(sort = OptRec, result = KResult)]
#[rustfmt::skip]
pub enum OptRecC {
    #[k::syntax("noneR")] NoneR,
    #[k::syntax("someR({r})")] SomeR { r: Rec },
}

#[k::constructors(sort = Charter, result = KResult)]
pub enum CharterC {
    #[k::syntax("charter({id}, {gamma})")]
    Ch { id: Int, gamma: Gate },
}

#[k::constructors(sort = NN, result = KResult)]
pub enum Pair {
    #[k::syntax("pr({a}, {b})")]
    P { a: Int, b: Int },
}

#[k::constructors(sort = NNN, result = KResult)]
pub enum Triple {
    #[k::syntax("tr({a}, {b}, {c})")]
    T3 { a: Int, b: Int, c: Int },
}

#[k::constructors(sort = CheckedSlot, result = KResult)]
pub enum CheckedSlotC {
    #[k::syntax("cslot({slot}, {check_ok})")]
    Cs { slot: Int, check_ok: Bool },
}

/// The refusal codes, in code order (ledger 1).
#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("rSH001")] Sh001,
    #[k::syntax("rSH002")] Sh002,
    #[k::syntax("rSH013")] Sh013,
    #[k::syntax("rSH015")] Sh015,
    #[k::syntax("rSH018")] Sh018,
    #[k::syntax("rSH019")] Sh019,
    #[k::syntax("rSH021")] Sh021,
    #[k::syntax("rSH026")] Sh026,
    #[k::syntax("rSH035")] Sh035,
    #[k::syntax("rSH036")] Sh036,
    #[k::syntax("rAckRefused")] AckRefused,
    #[k::syntax("rBadRequest")] BadRequest,
    #[k::syntax("rBirthRefused")] BirthRefused,
    #[k::syntax("rNoRule")] NoRule,
    #[k::syntax("rNoAckCertificate")] NoAckCertificate,
    #[k::syntax("rNoBirthCertificate")] NoBirthCertificate,
    #[k::syntax("rNoEscrowCertificate")] NoEscrowCertificate,
    #[k::syntax("rOutsideCapability")] OutsideCapability,
    #[k::syntax("rPolicyRefused")] PolicyRefused,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("fixCharter({id}, {gamma})")] FixCharter { id: Int, gamma: Gate },
    #[k::syntax("birthCheckOp({node}, {cm_addr}, {birth})")] BirthCheckOp { node: Int, cm_addr: Int, birth: BirthCheck },
    #[k::syntax("submitRecord({record})")] SubmitRecord { record: RecordReq },
    #[k::syntax("postPool({actor}, {root}, {key})")] PostPool { actor: Int, root: Int, key: Int },
    #[k::syntax("contribute({request})")] Contribute { request: Contrib },
    #[k::syntax("session({slots})")] Session { slots: List<CheckedSlot> },
    #[k::syntax("putShares({slots})")] PutShares { slots: List<Int> },
    #[k::syntax("holderOpen({cm_addr}, {x_match})")] HolderOpen { cm_addr: Int, x_match: Bool },
    #[k::syntax("ackCheckOp({node}, {cm_addr}, {ack})")] AckCheckOp { node: Int, cm_addr: Int, ack: AckCheck },
    #[k::syntax("acknowledge({cm_addr}, {signers})")] Acknowledge { cm_addr: Int, signers: List<Int> },
    #[k::syntax("pay({cm_addr})")] Pay { cm_addr: Int },
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("oOk")] Ok,
    #[k::syntax("oBirthOk")] BirthOk,
    #[k::syntax("oRefused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("oContributed({refill})")] Contributed { refill: Bool },
    #[k::syntax("oSession({kept}, {complained})")] SessionEnd { kept: List<Int>, complained: List<Int> },
    #[k::syntax("oPuts({entries})")] Puts { entries: List<Int> },
    #[k::syntax("oAckEnvelope")] AckEnvelope,
    #[k::syntax("oAckOk")] AckOk,
    #[k::syntax("oPaid")] Paid,
}

// ---------------------------------------------------------------------------
// List helpers.

/// `nodupB`: no element occurs twice.
#[k::function(total, internal)]
pub fn NodupB(xs: k::Term<List>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => if list::contains(x, rest) { false } else { NodupB(rest) },
    }
}

/// `xs.all ys.contains`.
#[k::function(total, internal)]
pub fn AllIn(xs: k::Term<List<Int>>, ys: k::Term<List<Int>>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => if list::contains(x, ys) { AllIn(rest, ys) } else { false },
    }
}

/// `xs.all (· != 0)`.
#[k::function(total, internal)]
pub fn AllNonzero(xs: k::Term<List<Int>>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => if x != 0 { AllNonzero(rest) } else { false },
    }
}

/// `if b then [r] else []`.
#[k::function(total, internal)]
pub fn Opt(b: k::Term<Bool>, r: k::Term<Refusal>) -> k::Term<List<Refusal>> {
    if b { [r] } else { [] }
}

// ---------------------------------------------------------------------------
// The access structure (SH-001 to SH-004).

/// `Gate.mid`.
#[k::function(total, internal)]
pub fn Mid(g: k::Term<Gate>) -> k::Term<Int> {
    match g {
        GateC::Leaf { mid, .. } => mid,
        GateC::And { mid, .. } => mid,
        GateC::Group { mid, .. } => mid,
        GateC::Or { mid, .. } => mid,
    }
}

/// `cs.map Gate.mid`.
#[k::function(total, internal)]
pub fn Mids(cs: k::Term<List<Gate>>) -> k::Term<List<Int>> {
    match cs {
        [] => [],
        [g, rest @ ..] => [Mid(g), ..Mids(rest)],
    }
}

/// `leaves`: the actors of the leaves, in order.
#[k::function(total, internal)]
pub fn Leaves(g: k::Term<Gate>) -> k::Term<List<Int>> {
    match g {
        GateC::Leaf { actor, .. } => [actor],
        GateC::And { children, .. } => LeavesL(children),
        GateC::Group { children, .. } => LeavesL(children),
        GateC::Or { primary, escrow, .. } => list::concat(Leaves(primary), Leaves(escrow)),
    }
}

#[k::function(total, internal)]
pub fn LeavesL(cs: k::Term<List<Gate>>) -> k::Term<List<Int>> {
    match cs {
        [] => [],
        [g, rest @ ..] => list::concat(Leaves(g), LeavesL(rest)),
    }
}

/// SH-001: every AND and group has a child, a group has `1 ≤ k ≤ m`.
#[k::function(total, internal)]
pub fn ShapeOk(g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { .. } => true,
        GateC::And { children, .. } => list::size(children) > 0 && ShapeOkL(children),
        GateC::Group { kk, children, .. } => 1 <= kk && kk <= list::size(children) && ShapeOkL(children),
        GateC::Or { primary, escrow, .. } => ShapeOk(primary) && ShapeOk(escrow),
    }
}

#[k::function(total, internal)]
pub fn ShapeOkL(cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => true,
        [g, rest @ ..] => ShapeOk(g) && ShapeOkL(rest),
    }
}

/// SH-002: member ids of each group nonzero and distinct.
#[k::function(total, internal)]
pub fn MidsOk(g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { .. } => true,
        GateC::And { children, .. } => MidsOkL(children),
        GateC::Group { children, .. } => {
            AllNonzero(Mids(children)) && NodupB(Mids(children)) && MidsOkL(children)
        }
        GateC::Or { primary, escrow, .. } => MidsOk(primary) && MidsOk(escrow),
    }
}

#[k::function(total, internal)]
pub fn MidsOkL(cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => true,
        [g, rest @ ..] => MidsOk(g) && MidsOkL(rest),
    }
}

/// SH-002: distinct nonzero member ids in every group, and no leaf twice (ledger 11).
#[k::function(total, internal)]
pub fn LeavesOk(g: k::Term<Gate>) -> k::Term<Bool> {
    MidsOk(g) && NodupB(Leaves(g))
}

/// Some leaf of the gate is an actor of `S`.
#[k::function(total, internal)]
pub fn Uses(s: k::Term<List<Int>>, g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { actor, .. } => list::contains(actor, s),
        GateC::And { children, .. } => UsesL(s, children),
        GateC::Group { children, .. } => UsesL(s, children),
        GateC::Or { primary, escrow, .. } => if Uses(s, primary) { true } else { Uses(s, escrow) },
    }
}

#[k::function(total, internal)]
pub fn UsesL(s: k::Term<List<Int>>, cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => false,
        [g, rest @ ..] => if Uses(s, g) { true } else { UsesL(s, rest) },
    }
}

/// SH-003 on one gate: an AND needs every child, a group exactly `k` used
/// children, an OR exactly one used child; every used child is admitted.
#[k::function(total, internal)]
pub fn Adm(s: k::Term<List<Int>>, g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { actor, .. } => list::contains(actor, s),
        GateC::And { children, .. } => AdmAll(s, children),
        GateC::Group { kk, children, .. } => {
            if UsedCount(s, children) == kk { AdmUsed(s, children) } else { false }
        }
        GateC::Or { primary, escrow, .. } => {
            if Uses(s, primary) != Uses(s, escrow) { AdmOr(s, primary, escrow) } else { false }
        }
    }
}

/// `if uses S p then adm S p else adm S e`.
#[k::function(total, internal)]
pub fn AdmOr(s: k::Term<List<Int>>, p: k::Term<Gate>, e: k::Term<Gate>) -> k::Term<Bool> {
    if Uses(s, p) { Adm(s, p) } else { Adm(s, e) }
}

#[k::function(total, internal)]
pub fn AdmAll(s: k::Term<List<Int>>, cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => true,
        [g, rest @ ..] => if Adm(s, g) { AdmAll(s, rest) } else { false },
    }
}

#[k::function(total, internal)]
pub fn AdmUsed(s: k::Term<List<Int>>, cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => true,
        [g, rest @ ..] => AdmUsedStep(s, Uses(s, g), g, rest),
    }
}

/// `(!uses S g || adm S g) && admUsed S gs`, one branch per case.
#[k::function(total, internal)]
pub fn AdmUsedStep(s: k::Term<List<Int>>, used: k::Term<Bool>, g: k::Term<Gate>, rest: k::Term<List<Gate>>) -> k::Term<Bool> {
    if !used { AdmUsed(s, rest) } else { AdmUsedIf(s, Adm(s, g), rest) }
}

/// A used child: admitted, then the rest.
#[k::function(total, internal)]
pub fn AdmUsedIf(s: k::Term<List<Int>>, ok: k::Term<Bool>, rest: k::Term<List<Gate>>) -> k::Term<Bool> {
    if ok { AdmUsed(s, rest) } else { false }
}

#[k::function(total, internal)]
pub fn UsedCount(s: k::Term<List<Int>>, cs: k::Term<List<Gate>>) -> k::Term<Int> {
    match cs {
        [] => 0,
        [g, rest @ ..] => UsedOne(s, g) + UsedCount(s, rest),
    }
}

/// `if uses S g then 1 else 0`.
#[k::function(total, internal)]
pub fn UsedOne(s: k::Term<List<Int>>, g: k::Term<Gate>) -> k::Term<Int> {
    if Uses(s, g) { 1 } else { 0 }
}

/// SH-003: the signing set names the initiator, only actors of `Γ`, each once,
/// and is admitted on `Γ`.
#[k::function(total, internal)]
pub fn Admitted(g: k::Term<Gate>, s: k::Term<List<Int>>, initiator: k::Term<Int>) -> k::Term<Bool> {
    AdmittedNamed(g, s, list::contains(initiator, s))
}

/// The initiator is a member; then `S` names each actor once.
#[k::function(total, internal)]
pub fn AdmittedNamed(g: k::Term<Gate>, s: k::Term<List<Int>>, named: k::Term<Bool>) -> k::Term<Bool> {
    if named { AdmittedOnce(g, s, NodupB(s)) } else { false }
}

/// `S` names each actor once; then only actors of `Γ`.
#[k::function(total, internal)]
pub fn AdmittedOnce(g: k::Term<Gate>, s: k::Term<List<Int>>, once: k::Term<Bool>) -> k::Term<Bool> {
    if once { AdmittedIn(g, s, AllIn(s, Leaves(g))) } else { false }
}

/// `S` names only actors of `Γ`; then `S` is admitted on `Γ`.
#[k::function(total, internal)]
pub fn AdmittedIn(g: k::Term<Gate>, s: k::Term<List<Int>>, inside: k::Term<Bool>) -> k::Term<Bool> {
    if inside { Adm(s, g) } else { false }
}

// Weights (SH-004): exact rationals compared by cross multiplication.

#[k::function(total, internal)]
pub fn QMul(a: k::Term<Q>, b: k::Term<Q>) -> k::Term<Q> {
    match (a, b) {
        (QC::Qv { num: an, den: ad }, QC::Qv { num: bn, den: bd }) => QC::Qv { num: an * bn, den: ad * bd },
    }
}

/// `Q.eqv`.
#[k::function(total, internal)]
pub fn QEqv(a: k::Term<Q>, b: k::Term<Q>) -> k::Term<Bool> {
    match (a, b) {
        (QC::Qv { num: an, den: ad }, QC::Qv { num: bn, den: bd }) => an * bd == bn * ad && ad != 0 && bd != 0,
    }
}

/// `xs.filter (· != x)`.
#[k::function(total, internal)]
pub fn Others(x: k::Term<Int>, xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [y, rest @ ..] => if y != x { [y, ..Others(x, rest)] } else { Others(x, rest) },
    }
}

/// The left fold of `lagrange0`: `acc · Π y / (y − x)`.
#[k::function(total, internal)]
pub fn LagFold(x: k::Term<Int>, ys: k::Term<List<Int>>, acc: k::Term<Q>) -> k::Term<Q> {
    match ys {
        [] => acc,
        [y, rest @ ..] => LagFold(x, rest, QMul(acc, QC::Qv { num: y, den: y - x })),
    }
}

/// `lagrange0 x xs`: the Lagrange coefficient at zero of member `x` in `xs`.
#[k::function(total, internal)]
pub fn Lagrange0(x: k::Term<Int>, xs: k::Term<List<Int>>) -> k::Term<Q> {
    LagFold(x, Others(x, xs), QC::Qv { num: 1, den: 1 })
}

/// `cs.filter (uses S)`.
#[k::function(total, internal)]
pub fn UsedChildren(s: k::Term<List<Int>>, cs: k::Term<List<Gate>>) -> k::Term<List<Gate>> {
    match cs {
        [] => [],
        [g, rest @ ..] => if Uses(s, g) { [g, ..UsedChildren(s, rest)] } else { UsedChildren(s, rest) },
    }
}

/// SH-004: the weight of actor `a` from the signing set alone.
#[k::function(total, internal)]
pub fn Weight(s: k::Term<List<Int>>, a: k::Term<Int>, g: k::Term<Gate>) -> k::Term<OptQ> {
    match g {
        GateC::Leaf { actor, .. } => LeafWeight(a, actor),
        GateC::And { children, .. } => WeightL(s, a, children),
        GateC::Group { children, .. } => GroupWeight(Mids(UsedChildren(s, children)), WeightG(s, a, children)),
        GateC::Or { primary, escrow, .. } => OrWeight(s, a, Weight(s, a, primary), escrow),
    }
}

/// A leaf: weight 1 for its own actor.
#[k::function(total, internal)]
pub fn LeafWeight(a: k::Term<Int>, b: k::Term<Int>) -> k::Term<OptQ> {
    if a == b { OptQC::SomeQ { w: QC::Qv { num: 1, den: 1 } } } else { OptQC::NoneQ }
}

/// A group: the Lagrange coefficient of the child that holds `a`, among the used children.
#[k::function(total, internal)]
pub fn GroupWeight(xs: k::Term<List<Int>>, wg: k::Term<OptMQ>) -> k::Term<OptQ> {
    match wg {
        OptMQC::NoneMQ => OptQC::NoneQ,
        OptMQC::SomeMQ { v: MQC::Mqv { x, w } } => OptQC::SomeQ { w: QMul(Lagrange0(x, xs), w) },
    }
}

/// An OR gate: the primary child's weight, else the escrow child's.
#[k::function(total, internal)]
pub fn OrWeight(s: k::Term<List<Int>>, a: k::Term<Int>, wp: k::Term<OptQ>, e: k::Term<Gate>) -> k::Term<OptQ> {
    match wp {
        OptQC::SomeQ { w } => OptQC::SomeQ { w },
        OptQC::NoneQ => Weight(s, a, e),
    }
}

#[k::function(total, internal)]
pub fn WeightL(s: k::Term<List<Int>>, a: k::Term<Int>, cs: k::Term<List<Gate>>) -> k::Term<OptQ> {
    match cs {
        [] => OptQC::NoneQ,
        [g, rest @ ..] => WeightLStep(s, a, Weight(s, a, g), rest),
    }
}

#[k::function(total, internal)]
pub fn WeightLStep(s: k::Term<List<Int>>, a: k::Term<Int>, w0: k::Term<OptQ>, rest: k::Term<List<Gate>>) -> k::Term<OptQ> {
    match w0 {
        OptQC::SomeQ { w } => OptQC::SomeQ { w },
        OptQC::NoneQ => WeightL(s, a, rest),
    }
}

/// `weightG`: the member id of the child that holds `a`, with the weight below it.
#[k::function(total, internal)]
pub fn WeightG(s: k::Term<List<Int>>, a: k::Term<Int>, cs: k::Term<List<Gate>>) -> k::Term<OptMQ> {
    match cs {
        [] => OptMQC::NoneMQ,
        [g, rest @ ..] => WeightGStep(s, a, Mid(g), Weight(s, a, g), rest),
    }
}

#[k::function(total, internal)]
pub fn WeightGStep(
    s: k::Term<List<Int>>,
    a: k::Term<Int>,
    m: k::Term<Int>,
    w0: k::Term<OptQ>,
    rest: k::Term<List<Gate>>,
) -> k::Term<OptMQ> {
    match w0 {
        OptQC::SomeQ { w } => OptMQC::SomeMQ { v: MQC::Mqv { x: m, w } },
        OptQC::NoneQ => WeightG(s, a, rest),
    }
}

/// SH-019 (ledger 7): actor `a` holds a leaf under the primary child of an OR gate.
#[k::function(total, internal)]
pub fn InPrimary(a: k::Term<Int>, g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { .. } => false,
        GateC::And { children, .. } => InPrimaryL(a, children),
        GateC::Group { children, .. } => InPrimaryL(a, children),
        GateC::Or { primary, escrow, .. } => {
            list::contains(a, Leaves(primary)) || InPrimary(a, primary) || InPrimary(a, escrow)
        }
    }
}

#[k::function(total, internal)]
pub fn InPrimaryL(a: k::Term<Int>, cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => false,
        [g, rest @ ..] => InPrimary(a, g) || InPrimaryL(a, rest),
    }
}

/// SH-026 (ledger 8): actor `a` holds a leaf under the escrow child of an OR gate.
#[k::function(total, internal)]
pub fn InEscrow(a: k::Term<Int>, g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { .. } => false,
        GateC::And { children, .. } => InEscrowL(a, children),
        GateC::Group { children, .. } => InEscrowL(a, children),
        GateC::Or { primary, escrow, .. } => {
            list::contains(a, Leaves(escrow)) || InEscrow(a, primary) || InEscrow(a, escrow)
        }
    }
}

#[k::function(total, internal)]
pub fn InEscrowL(a: k::Term<Int>, cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => false,
        [g, rest @ ..] => InEscrow(a, g) || InEscrowL(a, rest),
    }
}

/// SH-012: `Γ` has an OR gate.
#[k::function(total, internal)]
pub fn HasOr(g: k::Term<Gate>) -> k::Term<Bool> {
    match g {
        GateC::Leaf { .. } => false,
        GateC::And { children, .. } => HasOrL(children),
        GateC::Group { children, .. } => HasOrL(children),
        GateC::Or { .. } => true,
    }
}

#[k::function(total, internal)]
pub fn HasOrL(cs: k::Term<List<Gate>>) -> k::Term<Bool> {
    match cs {
        [] => false,
        [g, rest @ ..] => HasOr(g) || HasOrL(rest),
    }
}

// ---------------------------------------------------------------------------
// State reads.

/// `charterOf`: the first charter with this id.
#[k::function(total, internal)]
pub fn CharterOf(cs: k::Term<List<Charter>>, c: k::Term<Int>) -> k::Term<OptGate> {
    match cs {
        [] => OptGateC::NoneG,
        [CharterC::Ch { id, gamma }, rest @ ..] => if id == c { OptGateC::SomeG { g: gamma } } else { CharterOf(rest, c) },
    }
}

/// `(charterOf s id).isSome`.
#[k::function(total, internal)]
pub fn IsSomeG(o: k::Term<OptGate>) -> k::Term<Bool> {
    match o {
        OptGateC::NoneG => false,
        OptGateC::SomeG { .. } => true,
    }
}

/// The number of `(a, _)` entries of `dealt` that `used` does not hold.
#[k::function(total, internal)]
pub fn UnusedCount(dealt: k::Term<List<NN>>, used: k::Term<List<NN>>, a: k::Term<Int>) -> k::Term<Int> {
    match dealt {
        [] => 0,
        [Pair::P { a: xa, b: xb }, rest @ ..] => {
            if xa == a && !list::contains(Pair::P { a: xa, b: xb }, used) {
                1 + UnusedCount(rest, used, a)
            } else {
                UnusedCount(rest, used, a)
            }
        }
    }
}

/// The number of pairs the actor was dealt.
#[k::function(total, internal)]
pub fn DealtCount(dealt: k::Term<List<NN>>, a: k::Term<Int>) -> k::Term<Int> {
    match dealt {
        [] => 0,
        [Pair::P { a: xa, .. }, rest @ ..] => if xa == a { 1 + DealtCount(rest, a) } else { DealtCount(rest, a) },
    }
}

/// SH-013: `N_pool` new pairs `(a, base + i)`.
#[k::function(total, internal)]
pub fn MkPairs(a: k::Term<Int>, base: k::Term<Int>, n: k::Term<Int>) -> k::Term<List<NN>> {
    if n <= 0 { [] } else { [Pair::P { a, b: base }, ..MkPairs(a, base + 1, n - 1)] }
}

/// `c.pairs.map (fun i => (c.actor, i))`.
#[k::function(total, internal)]
pub fn PairsOf(a: k::Term<Int>, ps: k::Term<List<Int>>) -> k::Term<List<NN>> {
    match ps {
        [] => [],
        [i, rest @ ..] => [Pair::P { a, b: i }, ..PairsOf(a, rest)],
    }
}

/// SH-022: every named pair is dealt to the actor and unused.
#[k::function(total, internal)]
pub fn PairsUnused(a: k::Term<Int>, ps: k::Term<List<Int>>, dealt: k::Term<List<NN>>, used: k::Term<List<NN>>) -> k::Term<Bool> {
    match ps {
        [] => true,
        [i, rest @ ..] => {
            if list::contains(Pair::P { a, b: i }, dealt) && !list::contains(Pair::P { a, b: i }, used) {
                PairsUnused(a, rest, dealt, used)
            } else {
                false
            }
        }
    }
}

/// SH-011: the certificate signers whose BIRTH_OK on `cm` verifies.
#[k::function(total, internal)]
pub fn ValidSigners(signers: k::Term<List<Int>>, births: k::Term<List<NN>>, cm: k::Term<Int>) -> k::Term<List<Int>> {
    match signers {
        [] => [],
        [n, rest @ ..] => {
            if list::contains(Pair::P { a: n, b: cm }, births) {
                [n, ..ValidSigners(rest, births, cm)]
            } else {
                ValidSigners(rest, births, cm)
            }
        }
    }
}

/// `s.records.any (·.cm == cm)`.
#[k::function(total, internal)]
pub fn HasRecord(rs: k::Term<List<Rec>>, cm: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RecC::Rv { cm_addr, .. }, rest @ ..] => if cm_addr == cm { true } else { HasRecord(rest, cm) },
    }
}

/// SH-009: `BIRTH_OK(node, cm)` recorded once (ledger 13).
#[k::function(total, internal)]
pub fn AddOnce(x: k::Term<NN>, xs: k::Term<List<NN>>) -> k::Term<List<NN>> {
    if list::contains(x, xs) { xs } else { [x, ..xs] }
}

// ---------------------------------------------------------------------------
// Birth (SH-007 to SH-010).

/// SH-007: `pop_a` verifies for its own statement; SH-008: a network-created
/// shard carries `pop_U` and the proof of `δ`.
#[k::function(total, internal)]
pub fn ProofOk(x_f: k::Term<Int>, charter_id: k::Term<Int>, chain_id: k::Term<Int>, ap: k::Term<ActorProof>) -> k::Term<Bool> {
    match ap {
        ActorProofC::Ap { slot, x_a, ctx, valid, network_created, pop_u, delta } => {
            valid
                && ctx.eq::<K>(CtxC::C5 { a: x_f, b: x_a, c: slot, d: charter_id, e: chain_id })
                && (!network_created || (pop_u && delta))
        }
    }
}

#[k::function(total, internal)]
pub fn AllProofOk(x_f: k::Term<Int>, charter_id: k::Term<Int>, chain_id: k::Term<Int>, aps: k::Term<List<ActorProof>>) -> k::Term<Bool> {
    match aps {
        [] => true,
        [ap, rest @ ..] => {
            if ProofOk(x_f, charter_id, chain_id, ap) { AllProofOk(x_f, charter_id, chain_id, rest) } else { false }
        }
    }
}

/// SH-009: every check passes.
#[k::function(total, internal)]
pub fn BirthPasses(b: k::Term<BirthCheck>) -> k::Term<Bool> {
    match b {
        BirthCheckC::Bc { x_f, charter_id, chain_id, actors, dealer_ok, x_recomputed, encoding_ok, opening_ok } => {
            AllProofOk(x_f, charter_id, chain_id, actors) && dealer_ok && x_recomputed && encoding_ok && opening_ok
        }
    }
}

// ---------------------------------------------------------------------------
// Records (SH-011, SH-012).

/// RQ-001: `q = ⌈(n + f + 1)/2⌉`.
#[k::function(total, internal)]
pub fn QuorumOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Pm { n, f, .. } => (n + f + 2) / 2,
    }
}

/// SH-011: a P1 or P2 record without `q` BIRTH_OK, a P0 record without the owner's registration.
#[k::function(total, internal)]
pub fn NoBirthCert(p: k::Term<Params>, births: k::Term<List<NN>>, r: k::Term<RecordReq>) -> k::Term<Bool> {
    match r {
        RecordReqC::Rr { cm_addr, profile, signers, owner_reg, .. } => {
            NoBirthCertOf(profile, owner_reg, list::size(ValidSigners(signers, births, cm_addr)), QuorumOf(p))
        }
    }
}

/// `if profile == P0 then !ownerReg else |validSigners| < q`.
#[k::function(total, internal)]
pub fn NoBirthCertOf(profile: k::Term<Profile>, owner_reg: k::Term<Bool>, signed: k::Term<Int>, q: k::Term<Int>) -> k::Term<Bool> {
    if profile.eq::<K>(ProfileC::P0) { !owner_reg } else { signed < q }
}

/// SH-012: an OR gate without an escrow quorum, a P2 record without `q_g` guardian ACKs.
#[k::function(total, internal)]
pub fn NoEscrowCert(g: k::Term<Gate>, r: k::Term<RecordReq>) -> k::Term<Bool> {
    match r {
        RecordReqC::Rr { profile, escrow_acks, escrow_quorum, guardian_acks, q_g, .. } => {
            (HasOr(g) && escrow_acks < escrow_quorum) || (profile.eq::<K>(ProfileC::P2) && guardian_acks < q_g)
        }
    }
}

/// The refusals of `submit_record`, in code order.
#[k::function(total, internal)]
pub fn RecordRefusals(
    p: k::Term<Params>,
    charters: k::Term<List<Charter>>,
    births: k::Term<List<NN>>,
    records: k::Term<List<Rec>>,
    r: k::Term<RecordReq>,
) -> k::Term<List<Refusal>> {
    match r {
        RecordReqC::Rr { charter, .. } => RecordRefusalsG(p, CharterOf(charters, charter), births, records, r),
    }
}

#[k::function(total, internal)]
pub fn RecordRefusalsG(
    p: k::Term<Params>,
    og: k::Term<OptGate>,
    births: k::Term<List<NN>>,
    records: k::Term<List<Rec>>,
    r: k::Term<RecordReq>,
) -> k::Term<List<Refusal>> {
    match (og, r) {
        (OptGateC::NoneG, _) => [RefusalC::NoRule],
        (OptGateC::SomeG { g }, RecordReqC::Rr { cm_addr, signers, .. }) => list::concat(
            Opt(NoBirthCert(p, births, r), RefusalC::NoBirthCertificate),
            list::concat(
                Opt(NoEscrowCert(g, r), RefusalC::NoEscrowCertificate),
                list::concat(
                    Opt(HasRecord(records, cm_addr), RefusalC::NoRule),
                    Opt(!NodupB(signers), RefusalC::OutsideCapability),
                ),
            ),
        ),
    }
}

/// SH-011, SH-012: the admitted record with its verified signers; SH-034: it
/// registers with `acked = false`, also without a network-created shard (ledger 15).
#[k::function(total, internal)]
pub fn RecOf(births: k::Term<List<NN>>, r: k::Term<RecordReq>) -> k::Term<Rec> {
    match r {
        RecordReqC::Rr { cm_addr, profile, charter, signers, network_created, .. } => RecC::Rv {
            cm_addr,
            profile,
            charter,
            sigs: ValidSigners(signers, births, cm_addr),
            network_created,
            acked: false,
        },
    }
}

// ---------------------------------------------------------------------------
// Acknowledgement of a network-created shard (SH-030 to SH-037, DECISIONS 67).

/// `findRec`: the first record of `cm`.
#[k::function(total, internal)]
pub fn FindRec(rs: k::Term<List<Rec>>, cm: k::Term<Int>) -> k::Term<OptRec> {
    match rs {
        [] => OptRecC::NoneR,
        [RecC::Rv { cm_addr, profile, charter, sigs, network_created, acked }, rest @ ..] => {
            if cm_addr == cm {
                OptRecC::SomeR { r: RecC::Rv { cm_addr, profile, charter, sigs, network_created, acked } }
            } else {
                FindRec(rest, cm)
            }
        }
    }
}

/// `holder_open`: SH-036 when `x_u·G ≠ X_u`; no rule for an unknown record or a
/// record without a network-created shard (ledger 14).
#[k::function(total, internal)]
pub fn HolderRefusals(o: k::Term<OptRec>, x_match: k::Term<Bool>) -> k::Term<List<Refusal>> {
    match o {
        OptRecC::NoneR => [RefusalC::NoRule],
        OptRecC::SomeR { r: RecC::Rv { network_created, .. } } => {
            list::concat(Opt(!x_match, RefusalC::Sh036), Opt(!network_created, RefusalC::NoRule))
        }
    }
}

/// SH-031: every check of the ACK envelope passes.
#[k::function(total, internal)]
pub fn AckPasses(a: k::Term<AckCheck>) -> k::Term<Bool> {
    match a {
        AckCheckC::Ac { x_recomputed, opening_ok, pop_u } => x_recomputed && opening_ok && pop_u,
    }
}

/// `ack_check`: SH-032, and a node index `≥ n` (ledger 4). No record is read (ledger 17).
#[k::function(total, internal)]
pub fn AckRefusals(p: k::Term<Params>, node: k::Term<Int>, a: k::Term<AckCheck>) -> k::Term<List<Refusal>> {
    list::concat(Opt(!AckPasses(a), RefusalC::AckRefused), Opt(NOf(p) <= node, RefusalC::OutsideCapability))
}

/// SH-033: the certificate signers whose ACK_OK on `cm` verifies (no deduplication).
#[k::function(total, internal)]
pub fn ValidAckers(signers: k::Term<List<Int>>, acks: k::Term<List<NN>>, cm: k::Term<Int>) -> k::Term<List<Int>> {
    match signers {
        [] => [],
        [n, rest @ ..] => {
            if list::contains(Pair::P { a: n, b: cm }, acks) {
                [n, ..ValidAckers(rest, acks, cm)]
            } else {
                ValidAckers(rest, acks, cm)
            }
        }
    }
}

/// SH-033: an `acknowledge` call without `q` ACK_OK signatures for the record.
#[k::function(total, internal)]
pub fn NoAckCert(p: k::Term<Params>, acks: k::Term<List<NN>>, cm: k::Term<Int>, signers: k::Term<List<Int>>) -> k::Term<Bool> {
    list::size(ValidAckers(signers, acks, cm)) < QuorumOf(p)
}

/// `acknowledge`: no rule for an unknown record (ledger 18), SH-033, and a signer
/// named twice (ledger 4).
#[k::function(total, internal)]
pub fn AcknowledgeRefusals(
    p: k::Term<Params>,
    acks: k::Term<List<NN>>,
    o: k::Term<OptRec>,
    cm: k::Term<Int>,
    signers: k::Term<List<Int>>,
) -> k::Term<List<Refusal>> {
    match o {
        OptRecC::NoneR => [RefusalC::NoRule],
        OptRecC::SomeR { .. } => list::concat(
            Opt(NoAckCert(p, acks, cm, signers), RefusalC::NoAckCertificate),
            Opt(!NodupB(signers), RefusalC::OutsideCapability),
        ),
    }
}

/// SH-037: `acked = true` on the record of `cm`, every other record unchanged.
#[k::function(total, internal)]
pub fn SetAcked(cm: k::Term<Int>, r: k::Term<Rec>) -> k::Term<Rec> {
    match r {
        RecC::Rv { cm_addr, profile, charter, sigs, network_created, acked } => {
            if cm_addr == cm {
                RecC::Rv { cm_addr, profile, charter, sigs, network_created, acked: true }
            } else {
                RecC::Rv { cm_addr, profile, charter, sigs, network_created, acked }
            }
        }
    }
}

/// `records.map (setAcked cm)`.
#[k::function(total, internal)]
pub fn SetAckedL(cm: k::Term<Int>, rs: k::Term<List<Rec>>) -> k::Term<List<Rec>> {
    match rs {
        [] => [],
        [r, rest @ ..] => [SetAcked(cm, r), ..SetAckedL(cm, rest)],
    }
}

/// SH-035: the record has a network-created shard and `acked = false`.
#[k::function(total, internal)]
pub fn PayBlocked(r: k::Term<Rec>) -> k::Term<Bool> {
    match r {
        RecC::Rv { network_created, acked, .. } => network_created && !acked,
    }
}

/// `pay`: no rule for an unknown record; SH-035 while the payment is blocked.
#[k::function(total, internal)]
pub fn PayRefusals(o: k::Term<OptRec>) -> k::Term<List<Refusal>> {
    match o {
        OptRecC::NoneR => [RefusalC::NoRule],
        OptRecC::SomeR { r } => Opt(PayBlocked(r), RefusalC::Sh035),
    }
}

// ---------------------------------------------------------------------------
// Contributions (SH-014 to SH-026).

/// SH-022: the claimed weight does not follow from the signing set.
#[k::function(total, internal)]
pub fn WeightBad(w0: k::Term<OptQ>, claimed: k::Term<Q>) -> k::Term<Bool> {
    match w0 {
        OptQC::SomeQ { w } => !QEqv(w, claimed),
        OptQC::NoneQ => true,
    }
}

/// SH-022: `S` not admitted on `Γ`, a weight that does not follow from it, or a
/// named pair that is not an unused pair of the actor's pool, one per half.
#[k::function(total, internal)]
pub fn BadRequestOf(dealt: k::Term<List<NN>>, used: k::Term<List<NN>>, g: k::Term<Gate>, c: k::Term<Contrib>) -> k::Term<Bool> {
    match c {
        ContribC::Cr { actor, s_set, initiator, weight, pairs, .. } => {
            BadUnlessAdmitted(dealt, used, g, c, Admitted(g, s_set, initiator))
        }
    }
}

/// `S` not admitted on `Γ` is a bad request; otherwise the weight is checked.
#[k::function(total, internal)]
pub fn BadUnlessAdmitted(
    dealt: k::Term<List<NN>>,
    used: k::Term<List<NN>>,
    g: k::Term<Gate>,
    c: k::Term<Contrib>,
    admitted: k::Term<Bool>,
) -> k::Term<Bool> {
    match c {
        ContribC::Cr { actor, s_set, weight, pairs, .. } => {
            if !admitted { true } else { BadUnlessWeight(dealt, used, actor, pairs, WeightBad(Weight(s_set, actor, g), weight)) }
        }
    }
}

/// A weight that does not follow is a bad request; otherwise the pairs are checked.
#[k::function(total, internal)]
pub fn BadUnlessWeight(
    dealt: k::Term<List<NN>>,
    used: k::Term<List<NN>>,
    actor: k::Term<Int>,
    pairs: k::Term<List<Int>>,
    weight_bad: k::Term<Bool>,
) -> k::Term<Bool> {
    if weight_bad { true } else { BadUnlessDistinct(dealt, used, actor, pairs, NodupB(pairs)) }
}

/// A pair named twice is a bad request; otherwise every pair must be unused and dealt.
#[k::function(total, internal)]
pub fn BadUnlessDistinct(
    dealt: k::Term<List<NN>>,
    used: k::Term<List<NN>>,
    actor: k::Term<Int>,
    pairs: k::Term<List<Int>>,
    distinct: k::Term<Bool>,
) -> k::Term<Bool> {
    if !distinct { true } else { !PairsUnused(actor, pairs, dealt, used) }
}

/// SH-018 (ledger 12): an ECDSA slot whose leaf set is not the signing set, or
/// one the actor already contributed on.
#[k::function(total, internal)]
pub fn LeafSetBad(slotsused: k::Term<List<NN>>, c: k::Term<Contrib>) -> k::Term<Bool> {
    match c {
        ContribC::Cr { slot: SlotRefC::Committee, .. } => false,
        ContribC::Cr { actor, s_set, slot: SlotRefC::Ecdsa { id, leaf_set, .. }, .. } => {
            !(NodupB(leaf_set) && list::size(leaf_set) == list::size(s_set) && AllIn(leaf_set, s_set))
                || list::contains(Pair::P { a: actor, b: id }, slotsused)
        }
    }
}

/// SH-019 (ledger 7): the primary holder of an OR gate on a slot under `slr_G`.
#[k::function(total, internal)]
pub fn EscrowSlotBad(g: k::Term<Gate>, c: k::Term<Contrib>) -> k::Term<Bool> {
    match c {
        ContribC::Cr { actor, slot: SlotRefC::Ecdsa { under_g: true, .. }, .. } => InPrimary(actor, g),
        ContribC::Cr { slot: SlotRefC::Ecdsa { under_g: false, .. }, .. } => false,
        ContribC::Cr { slot: SlotRefC::Committee, .. } => false,
    }
}

/// SH-026 (ledger 8): a guardian half outside a settled seizure order that pays `D_reg`.
#[k::function(total, internal)]
pub fn GuardianBad(g: k::Term<Gate>, c: k::Term<Contrib>) -> k::Term<Bool> {
    match c {
        ContribC::Cr { actor, seizure_settled, .. } => InEscrow(actor, g) && !seizure_settled,
    }
}

/// `contribRefusals`: every refusal of a contribution, in code order.
#[k::function(total, internal)]
pub fn ContribRefusals(
    charters: k::Term<List<Charter>>,
    dealt: k::Term<List<NN>>,
    used: k::Term<List<NN>>,
    slotsused: k::Term<List<NN>>,
    c: k::Term<Contrib>,
) -> k::Term<List<Refusal>> {
    match c {
        ContribC::Cr { charter, .. } => ContribRefusalsG(CharterOf(charters, charter), dealt, used, slotsused, c),
    }
}

#[k::function(total, internal)]
pub fn ContribRefusalsG(
    og: k::Term<OptGate>,
    dealt: k::Term<List<NN>>,
    used: k::Term<List<NN>>,
    slotsused: k::Term<List<NN>>,
    c: k::Term<Contrib>,
) -> k::Term<List<Refusal>> {
    match (og, c) {
        (OptGateC::NoneG, _) => [RefusalC::NoRule],
        (OptGateC::SomeG { g }, ContribC::Cr { exp_c, height, recompute_ok, policy_ok, .. }) => list::concat(
            Opt(exp_c < height, RefusalC::Sh015),
            list::concat(
                Opt(LeafSetBad(slotsused, c), RefusalC::Sh018),
                list::concat(
                    Opt(EscrowSlotBad(g, c), RefusalC::Sh019),
                    list::concat(
                        Opt(!recompute_ok, RefusalC::Sh021),
                        list::concat(
                            Opt(GuardianBad(g, c), RefusalC::Sh026),
                            list::concat(
                                Opt(BadRequestOf(dealt, used, g, c), RefusalC::BadRequest),
                                Opt(!policy_ok, RefusalC::PolicyRefused),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    }
}

/// SH-018: the ECDSA slot answered, first in `slotsused`.
#[k::function(total, internal)]
pub fn EcdsaUsedAfter(slotsused: k::Term<List<NN>>, c: k::Term<Contrib>) -> k::Term<List<NN>> {
    match c {
        ContribC::Cr { actor, slot: SlotRefC::Ecdsa { id, .. }, .. } => [Pair::P { a: actor, b: id }, ..slotsused],
        ContribC::Cr { slot: SlotRefC::Committee, .. } => slotsused,
    }
}

/// SH-015: the named pairs marked used, first in `used`.
#[k::function(total, internal)]
pub fn UsedAfter(used: k::Term<List<NN>>, c: k::Term<Contrib>) -> k::Term<List<NN>> {
    match c {
        ContribC::Cr { actor, pairs, .. } => list::concat(PairsOf(actor, pairs), used),
    }
}

/// SH-014: `needsRefill` of the contributing actor on the state after the step.
#[k::function(total, internal)]
pub fn RefillAfter(p: k::Term<Params>, dealt: k::Term<List<NN>>, used: k::Term<List<NN>>, c: k::Term<Contrib>) -> k::Term<Bool> {
    match c {
        ContribC::Cr { actor, .. } => NeedsRefill(p, dealt, used, actor),
    }
}

/// SH-014 (ledger 9): fewer than `N_h` unused pairs remain.
#[k::function(total, internal)]
pub fn NeedsRefill(p: k::Term<Params>, dealt: k::Term<List<NN>>, used: k::Term<List<NN>>, a: k::Term<Int>) -> k::Term<Bool> {
    match p {
        ParamsC::Pm { n_h, .. } => UnusedCount(dealt, used, a) < n_h,
    }
}

// ---------------------------------------------------------------------------
// Sessions (SH-016, SH-017).

/// SH-016: the slots whose public check passes.
#[k::function(total, internal)]
pub fn SessionKeep(xs: k::Term<List<CheckedSlot>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [CheckedSlotC::Cs { slot, check_ok: true }, rest @ ..] => [slot, ..SessionKeep(rest)],
        [CheckedSlotC::Cs { check_ok: false, .. }, rest @ ..] => SessionKeep(rest),
    }
}

/// SH-016: the slots the node complains about.
#[k::function(total, internal)]
pub fn SessionComplain(xs: k::Term<List<CheckedSlot>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [CheckedSlotC::Cs { check_ok: true, .. }, rest @ ..] => SessionComplain(rest),
        [CheckedSlotC::Cs { slot, check_ok: false }, rest @ ..] => [slot, ..SessionComplain(rest)],
    }
}

/// `slots.map (·.1)`.
#[k::function(total, internal)]
pub fn SlotIds(xs: k::Term<List<CheckedSlot>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [CheckedSlotC::Cs { slot, .. }, rest @ ..] => [slot, ..SlotIds(rest)],
    }
}

/// SH-017: one put entry per slot share in TEE mode, none otherwise.
#[k::function(total, internal)]
pub fn PutEntries(p: k::Term<Params>, slots: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match p {
        ParamsC::Pm { mode: ModeC::Tee, .. } => slots,
        ParamsC::Pm { mode: ModeC::NonTee, .. } => [],
    }
}

/// `n` of the parameters.
#[k::function(total, internal)]
pub fn NOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Pm { n, .. } => n,
    }
}

// ---------------------------------------------------------------------------
// Refusals of the other operations.

/// `fix_charter`: SH-001, SH-002, and a charter id fixed twice (ledger 3).
#[k::function(total, internal)]
pub fn CharterRefusals(charters: k::Term<List<Charter>>, id: k::Term<Int>, g: k::Term<Gate>) -> k::Term<List<Refusal>> {
    list::concat(
        Opt(!ShapeOk(g), RefusalC::Sh001),
        list::concat(Opt(!LeavesOk(g), RefusalC::Sh002), Opt(IsSomeG(CharterOf(charters, id)), RefusalC::NoRule)),
    )
}

/// `birth_check`: SH-010, and a node index `≥ n` (ledger 4).
#[k::function(total, internal)]
pub fn BirthRefusals(p: k::Term<Params>, node: k::Term<Int>, b: k::Term<BirthCheck>) -> k::Term<List<Refusal>> {
    list::concat(Opt(!BirthPasses(b), RefusalC::BirthRefused), Opt(NOf(p) <= node, RefusalC::OutsideCapability))
}

/// `post_pool`: SH-013, and a key index `≥ N_pk = 1024` (ledger 4).
#[k::function(total, internal)]
pub fn PoolRefusals(keys: k::Term<List<NNN>>, a: k::Term<Int>, root: k::Term<Int>, key: k::Term<Int>) -> k::Term<List<Refusal>> {
    list::concat(
        Opt(list::contains(Triple::T3 { a, b: root, c: key }, keys), RefusalC::Sh013),
        Opt(1024 <= key, RefusalC::OutsideCapability),
    )
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
    pub births: List<NN>,
    #[k::cell]
    pub records: List<Rec>,
    #[k::cell]
    pub dealt: List<NN>,
    #[k::cell]
    pub used: List<NN>,
    #[k::cell]
    pub keys: List<NNN>,
    #[k::cell]
    pub slotsused: List<NN>,
    #[k::cell]
    pub acks: List<NN>,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: no charter, birth, record, pair or slot yet.
    #[k::init]
    pub fn init(params: Params, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            charters: [],
            births: [],
            records: [],
            dealt: [],
            used: [],
            keys: [],
            slotsused: [],
            acks: [],
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // SH-001, SH-002: a valid charter is fixed, first in `charters`.
    #[k::requires(list::size(CharterRefusals(charters, id, gamma)) == 0)]
    fix_charter: {
        k: [Step::Go, ..],
        charters,
        ops: [OpC::FixCharter { id, gamma }, ..],
        obs,
    } => {
        charters: [CharterC::Ch { id, gamma }, ..charters],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SH-001, SH-002 (ledger 1): the charter is not valid; ledger 3: an id fixed twice.
    #[k::requires(list::size(CharterRefusals(charters, id, gamma)) != 0)]
    fix_charter_refused: {
        k: [Step::Go, ..],
        charters,
        ops: [OpC::FixCharter { id, gamma }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: CharterRefusals(charters, id, gamma) }],
    };

    // SH-009: every check passes; the node signs BIRTH_OK(eid, cm_addr), recorded once (ledger 13).
    #[k::requires(list::size(BirthRefusals(params, node, birth)) == 0)]
    birth_check: {
        k: [Step::Go, ..],
        params,
        births,
        ops: [OpC::BirthCheckOp { node, cm_addr, birth }, ..],
        obs,
    } => {
        births: AddOnce(Pair::P { a: node, b: cm_addr }, births),
        ops: [..],
        obs: [..obs, ObsC::BirthOk],
    };

    // SH-010: a failed check refuses BIRTH_OK; ledger 4: a node index outside `n`.
    #[k::requires(list::size(BirthRefusals(params, node, birth)) != 0)]
    birth_check_refused: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::BirthCheckOp { node, birth, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: BirthRefusals(params, node, birth) }],
    };

    // SH-011, SH-012: the record is admitted with its verified signers, first in `records`.
    #[k::requires(list::size(RecordRefusals(params, charters, births, records, record)) == 0)]
    submit_record: {
        k: [Step::Go, ..],
        params,
        charters,
        births,
        records,
        ops: [OpC::SubmitRecord { record }, ..],
        obs,
    } => {
        records: [RecOf(births, record), ..records],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SH-011, SH-012: no birth or escrow certificate; ledger 3, 4.
    #[k::requires(list::size(RecordRefusals(params, charters, births, records, record)) != 0)]
    submit_record_refused: {
        k: [Step::Go, ..],
        params,
        charters,
        births,
        records,
        ops: [OpC::SubmitRecord { record }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: RecordRefusals(params, charters, births, records, record) }],
    };

    // SH-013: a pool of `N_pool = 64` fresh pairs, numbered after the actor's
    // dealt pairs and appended; the pool key goes first in `keys`.
    #[k::requires(list::size(PoolRefusals(keys, actor, root, key)) == 0)]
    post_pool: {
        k: [Step::Go, ..],
        dealt,
        keys,
        ops: [OpC::PostPool { actor, root, key }, ..],
        obs,
    } => {
        dealt: list::concat(dealt, MkPairs(actor, DealtCount(dealt, actor), 64)),
        keys: [Triple::T3 { a: actor, b: root, c: key }, ..keys],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SH-013: a pool key that is not fresh; ledger 4: a key index outside `N_pk`.
    #[k::requires(list::size(PoolRefusals(keys, actor, root, key)) != 0)]
    post_pool_refused: {
        k: [Step::Go, ..],
        keys,
        ops: [OpC::PostPool { actor, root, key }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: PoolRefusals(keys, actor, root, key) }],
    };

    // SH-015: the actor marks each named pair used in the step that computes the
    // contribution; SH-018: and the ECDSA slot answered; SH-014: `refill` after the step.
    #[k::requires(list::size(ContribRefusals(charters, dealt, used, slotsused, c)) == 0)]
    contribute: {
        k: [Step::Go, ..],
        params,
        charters,
        dealt,
        used,
        slotsused,
        ops: [OpC::Contribute { request: c }, ..],
        obs,
    } => {
        used: UsedAfter(used, c),
        slotsused: EcdsaUsedAfter(slotsused, c),
        ops: [..],
        obs: [..obs, ObsC::Contributed { refill: RefillAfter(params, dealt, UsedAfter(used, c), c) }],
    };

    // SH-015, SH-018, SH-019, SH-021, SH-022, SH-023, SH-026: the actor does not contribute.
    #[k::requires(list::size(ContribRefusals(charters, dealt, used, slotsused, c)) != 0)]
    contribute_refused: {
        k: [Step::Go, ..],
        charters,
        dealt,
        used,
        slotsused,
        ops: [OpC::Contribute { request: c }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ContribRefusals(charters, dealt, used, slotsused, c) }],
    };

    // SH-016: keep the slots whose check passes, complain about the others.
    #[k::requires(NodupB(SlotIds(slots)))]
    session: {
        k: [Step::Go, ..],
        ops: [OpC::Session { slots }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::SessionEnd { kept: SessionKeep(slots), complained: SessionComplain(slots) }],
    };

    // Ledger 4: a session that names a slot twice is outside the capability.
    #[k::requires(!NodupB(SlotIds(slots)))]
    session_dup: {
        k: [Step::Go, ..],
        ops: [OpC::Session { slots }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // SH-017: one put entry per slot share in TEE mode.
    #[k::requires(NodupB(slots))]
    put_shares: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::PutShares { slots }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Puts { entries: PutEntries(params, slots) }],
    };

    // Ledger 4: a put list that names a slot twice is outside the capability.
    #[k::requires(!NodupB(slots))]
    put_shares_dup: {
        k: [Step::Go, ..],
        ops: [OpC::PutShares { slots }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // SH-030: `x_u·G = X_u` on a record with a network-created shard: the holder
    // wallet sends the ACK envelope, on every open (ledger 16).
    #[k::requires(list::size(HolderRefusals(FindRec(records, cm_addr), x_match)) == 0)]
    holder_open: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::HolderOpen { cm_addr, x_match }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::AckEnvelope],
    };

    // SH-036 (ledger 19): no ACK envelope; ledger 14: no rule.
    #[k::requires(list::size(HolderRefusals(FindRec(records, cm_addr), x_match)) != 0)]
    holder_open_refused: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::HolderOpen { cm_addr, x_match }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: HolderRefusals(FindRec(records, cm_addr), x_match) }],
    };

    // SH-031: every check passes; the node signs ACK_OK(eid, cm_addr), recorded once (ledger 17).
    #[k::requires(list::size(AckRefusals(params, node, ack)) == 0)]
    ack_check: {
        k: [Step::Go, ..],
        params,
        acks,
        ops: [OpC::AckCheckOp { node, cm_addr, ack }, ..],
        obs,
    } => {
        acks: AddOnce(Pair::P { a: node, b: cm_addr }, acks),
        ops: [..],
        obs: [..obs, ObsC::AckOk],
    };

    // SH-032: a failed check refuses ACK_OK; ledger 4: a node index outside `n`.
    #[k::requires(list::size(AckRefusals(params, node, ack)) != 0)]
    ack_check_refused: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::AckCheckOp { node, ack, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: AckRefusals(params, node, ack) }],
    };

    // SH-037: the call with `q` ACK_OK signatures lands and sets `acked = true` on the record.
    #[k::requires(list::size(AcknowledgeRefusals(params, acks, FindRec(records, cm_addr), cm_addr, signers)) == 0)]
    acknowledge: {
        k: [Step::Go, ..],
        params,
        records,
        acks,
        ops: [OpC::Acknowledge { cm_addr, signers }, ..],
        obs,
    } => {
        records: SetAckedL(cm_addr, records),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SH-033: no certificate of `q` ACK_OK signatures; ledger 18: no rule, a signer twice.
    #[k::requires(list::size(AcknowledgeRefusals(params, acks, FindRec(records, cm_addr), cm_addr, signers)) != 0)]
    acknowledge_refused: {
        k: [Step::Go, ..],
        params,
        records,
        acks,
        ops: [OpC::Acknowledge { cm_addr, signers }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: AcknowledgeRefusals(params, acks, FindRec(records, cm_addr), cm_addr, signers) }],
    };

    // SH-035: the payer wallet pays to an acknowledged address, or one without a
    // network-created shard (ledger 15).
    #[k::requires(list::size(PayRefusals(FindRec(records, cm_addr))) == 0)]
    pay: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::Pay { cm_addr }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Paid],
    };

    // SH-035 (ledger 19): no payment while `acked = false`; no rule for an unknown record.
    #[k::requires(list::size(PayRefusals(FindRec(records, cm_addr))) != 0)]
    pay_refused: {
        k: [Step::Go, ..],
        records,
        ops: [OpC::Pay { cm_addr }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: PayRefusals(FindRec(records, cm_addr)) }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
