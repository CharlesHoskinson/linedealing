//! Split slots reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/slots/SplitSlots/Spec.lean` (`apply`, `runOps`).
//!
//! One rule per behaviour of `apply`: each operation either passes `opRefusals`
//! and runs `exec` (the slot steps `cstep`, `estep`, `sstep`, the new slots
//! `cnew`, `enew`, `snew` and `metaStep`) with the observation `obsOf` of the
//! state before it, or is refused with its codes and leaves the state unchanged.
//! The per-slot steps are functions with one equation per operation and per
//! branch, so each is a coverage obligation and a mutation target. Requirement
//! IDs refer to `openspec/changes/add-split-line-dealing/specs/split-slots/spec.md`;
//! "ledger N" to `formal/lean-split/slots/ambiguity-ledger.md`.
//!
//! Cells are the oracle's `St` fields and its observation list `obs`; `ops` holds
//! the operations still to run and is empty at every end (FLOW.toml omits it).
//! `Option Nat` is a list of at most one element (`[]` is `none`).

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, int, list};

k::sorts! {
    Run: KItem;
    Mode;
    Suite;
    BStat;
    Root;
    NN;
    CKey;
    EKey;
    CSlot;
    ESlot;
    SeatSt;
    SeatSlot;
    Force;
    Dealer;
    Params;
    Refusal;
    Verdict;
    VoidReason;
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

/// SL-001: the Schnorr suites of the committee pools.
#[k::constructors(sort = Suite, result = KResult)]
#[rustfmt::skip]
pub enum SuiteC {
    #[k::syntax("BIP340")] Bip340,
    #[k::syntax("ED25519")] Ed25519,
}

/// SL-002: `bstat`.
#[k::constructors(sort = BStat, result = KResult)]
#[rustfmt::skip]
pub enum BStatC {
    #[k::syntax("UNNAMED")] Unnamed,
    #[k::syntax("NAMED")] Named,
    #[k::syntax("RESERVED")] Reserved,
    #[k::syntax("CLAIMED")] Claimed,
    #[k::syntax("BURNED")] Burned,
}

/// SL-003: the root an ECDSA slot lies under.
#[k::constructors(sort = Root, result = KResult)]
#[rustfmt::skip]
pub enum RootC {
    #[k::syntax("rootOwn")] Own,
    #[k::syntax("rootG")] Gr,
}

/// A pair of naturals: a namer `(eid, board position)`, a pending entry
/// `(index, eid)`, a covered seat-log entry `(nf, d)`.
#[k::constructors(sort = NN, result = KResult)]
pub enum Pair {
    #[k::syntax("pr({a}, {b})")]
    P { a: Int, b: Int },
}

/// The key `(s, e, ℓ)` of a committee slot.
#[k::constructors(sort = CKey, result = KResult)]
pub enum CKeyC {
    #[k::syntax("ckey({suite}, {epoch}, {idx})")]
    Ck { suite: Suite, epoch: Int, idx: Int },
}

/// The key `(pool, ℓ)` of an ECDSA slot.
#[k::constructors(sort = EKey, result = KResult)]
pub enum EKeyC {
    #[k::syntax("ekey({pool}, {idx})")]
    Ek { pool: Int, idx: Int },
}

/// SL-002: a committee slot.
#[k::constructors(sort = CSlot, result = KResult)]
pub enum CSlotC {
    #[k::syntax("cslot({suite}, {epoch}, {idx}, {bstat}, {prec}, {namers})")]
    Cs { suite: Suite, epoch: Int, idx: Int, bstat: BStat, prec: List<Int>, namers: List<NN> },
}

/// SL-003: an ECDSA slot; `leaf_set` stands for `H(T_ℓ)`.
#[k::constructors(sort = ESlot, result = KResult)]
pub enum ESlotC {
    #[k::syntax("eslot({pool}, {idx}, {leaf_set}, {root}, {bstat}, {prec}, {reserver}, {namers})")]
    Es {
        pool: Int,
        idx: Int,
        leaf_set: Int,
        root: Root,
        bstat: BStat,
        prec: List<Int>,
        reserver: List<Int>,
        namers: List<NN>,
    },
}

/// SL-018: the state of one slot share of the seat.
#[k::constructors(sort = SeatSt, result = KResult)]
#[rustfmt::skip]
pub enum SeatStC {
    #[k::syntax("free")] Free,
    #[k::syntax("bound({d})")] Bound { d: Int },
    #[k::syntax("burnedSeat")] SBurned,
}

/// A slot share of the seat (SL-019, SL-021, SL-027).
#[k::constructors(sort = SeatSlot, result = KResult)]
pub enum SeatSlotC {
    #[k::syntax("seatSlot({key}, {st}, {current}, {signed})")]
    Ss { key: Int, st: SeatSt, current: Bool, signed: List<Int> },
}

/// SL-006: a request in force with the root its source opens.
#[k::constructors(sort = Force, result = KResult)]
pub enum ForceC {
    #[k::syntax("force({eid}, {root})")]
    Frc { eid: Int, root: Root },
}

/// SL-025: a dealer of one slot and whether it has a valid complaint.
#[k::constructors(sort = Dealer, result = KResult)]
pub enum DealerC {
    #[k::syntax("dealer({dealer}, {complained})")]
    Dlr { dealer: Int, complained: Bool },
}

#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    #[k::syntax("params({mode}, {w})")]
    Params { mode: Mode, w: Int },
}

#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("noRule")] NoRule,
    #[k::syntax("outsideCapability")] OutsideCapability,
    #[k::syntax("slotBound")] SlotBound,
}

/// SL-012 to SL-015: the verdict on one committee index of a header.
#[k::constructors(sort = Verdict, result = KResult)]
#[rustfmt::skip]
pub enum VerdictC {
    #[k::syntax("inWindow")] InWindow,
    #[k::syntax("slotTaken")] SlotTaken,
    #[k::syntax("aboveWindow")] AboveWindow,
    #[k::syntax("poolUnlisted")] PoolUnlisted,
}

/// SL-016: the VOID reason SLOT_TAKEN.
#[k::constructors(sort = VoidReason, result = KResult)]
#[rustfmt::skip]
pub enum VoidReasonC {
    #[k::syntax("SLOT_TAKEN")] VSlotTaken,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("dealC({suite}, {epoch}, {kcount})")] DealC { suite: Suite, epoch: Int, kcount: Int },
    #[k::syntax("dealE({pool}, {leaf_set}, {root}, {kcount})")]
    DealE { pool: Int, leaf_set: Int, root: Root, kcount: Int },
    #[k::syntax("openC({eid}, {pos}, {names})")] OpenC { eid: Int, pos: Int, names: List<CKey> },
    #[k::syntax("openE({eid}, {pos}, {names})")] OpenE { eid: Int, pos: Int, names: List<EKey> },
    #[k::syntax("inForce({eid}, {root})")] InForce { eid: Int, root: Root },
    #[k::syntax("lapse({eid})")] Lapse { eid: Int },
    #[k::syntax("reserve({eid})")] Reserve { eid: Int },
    #[k::syntax("claimOp({eid})")] ClaimOp { eid: Int },
    #[k::syntax("endReq({eid})")] EndReq { eid: Int },
    #[k::syntax("burnRange({suite}, {epoch}, {lo}, {hi})")]
    BurnRange { suite: Suite, epoch: Int, lo: Int, hi: Int },
    #[k::syntax("burnPool({pool})")] BurnPool { pool: Int },
    #[k::syntax("seatPut({key})")] SeatPut { key: Int },
    #[k::syntax("seatBind({key}, {d}, {slot_acks}, {sealed_acks})")]
    SeatBind { key: Int, d: Int, slot_acks: Int, sealed_acks: Int },
    #[k::syntax("seatRelease({key}, {d})")] SeatRelease { key: Int, d: Int },
    #[k::syntax("seatBurn({key})")] SeatBurn { key: Int },
    #[k::syntax("judge({listed}, {h}, {pending_min}, {pending}, {bw}, {eid}, {idxs})")]
    Judge { listed: Bool, h: Int, pending_min: Int, pending: List<NN>, bw: Int, eid: Int, idxs: List<Int> },
    #[k::syntax("batch({polys})")] Batch { polys: List<Bool> },
    #[k::syntax("qualify({t}, {dealers})")] Qualify { t: Int, dealers: List<Dealer> },
    #[k::syntax("anchorGate({on}, {covered}, {nf}, {d})")]
    AnchorGate { on: Bool, covered: List<NN>, nf: Int, d: Int },
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("ok")] Ok,
    #[k::syntax("refused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("void({reason})")] Void { reason: VoidReason },
    #[k::syntax("released({d})")] Released { d: Int },
    #[k::syntax("verdicts({vs})")] Verdicts { vs: List<Verdict> },
    #[k::syntax("complaint({failing})")] Complaint { failing: List<Int> },
    #[k::syntax("qualified({ds})")] Qualified { ds: List<List<Int>> },
    #[k::syntax("gate({pass})")] Gate { pass: Bool },
}

// ---------------------------------------------------------------------------
// Helpers (`nodupB`, `maxL`, `lowestPair`, `lowest`, field reads).

/// `nodupB`: no element occurs twice.
#[k::function(total, internal)]
pub fn NodupB(xs: k::Term<List>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => if list::contains(x, rest) { false } else { NodupB(rest) },
    }
}

/// The board position of a namer.
#[k::function(total, internal)]
pub fn PosOf(p: k::Term<NN>) -> k::Term<Int> {
    match p {
        Pair::P { b, .. } => b,
    }
}

/// `lowestPair`, one step: keep the earlier namer unless a later one has a lower position.
#[k::function(total, internal)]
pub fn Pick(a: k::Term<NN>, o: k::Term<List<NN>>) -> k::Term<List<NN>> {
    match o {
        [] => [a],
        [b, ..] => if PosOf(b) < PosOf(a) { [b] } else { [a] },
    }
}

/// `lowestPair`: the namer with the lowest board position (SL-004, SL-006).
#[k::function(total, internal)]
pub fn LowestPair(ns: k::Term<List<NN>>) -> k::Term<List<NN>> {
    match ns {
        [] => [],
        [a, rest @ ..] => Pick(a, LowestPair(rest)),
    }
}

/// `lowest`: the request of the lowest namer.
#[k::function(total, internal)]
pub fn Lowest(ns: k::Term<List<NN>>) -> k::Term<List<Int>> {
    EidOf(LowestPair(ns))
}

/// `Option.map Prod.fst`: the request of a namer, if any.
#[k::function(total, internal)]
pub fn EidOf(o: k::Term<List<NN>>) -> k::Term<List<Int>> {
    match o {
        [] => [],
        [Pair::P { a, .. }, ..] => [a],
    }
}

/// `inForceAny`: some in-force entry is the request `e`.
#[k::function(total, internal)]
pub fn InForceAny(inf: k::Term<List<Force>>, e: k::Term<Int>) -> k::Term<Bool> {
    match inf {
        [] => false,
        [ForceC::Frc { eid, .. }, rest @ ..] => if eid == e { true } else { InForceAny(rest, e) },
    }
}

#[k::function(total, internal)]
pub fn CKeyOf(x: k::Term<CSlot>) -> k::Term<CKey> {
    match x {
        CSlotC::Cs { suite, epoch, idx, .. } => CKeyC::Ck { suite, epoch, idx },
    }
}

#[k::function(total, internal)]
pub fn CPrec(x: k::Term<CSlot>) -> k::Term<List<Int>> {
    match x {
        CSlotC::Cs { prec, .. } => prec,
    }
}

#[k::function(total, internal)]
pub fn CBstat(x: k::Term<CSlot>) -> k::Term<BStat> {
    match x {
        CSlotC::Cs { bstat, .. } => bstat,
    }
}

#[k::function(total, internal)]
pub fn EKeyOf(x: k::Term<ESlot>) -> k::Term<EKey> {
    match x {
        ESlotC::Es { pool, idx, .. } => EKeyC::Ek { pool, idx },
    }
}

#[k::function(total, internal)]
pub fn EPrec(x: k::Term<ESlot>) -> k::Term<List<Int>> {
    match x {
        ESlotC::Es { prec, .. } => prec,
    }
}

#[k::function(total, internal)]
pub fn EReserver(x: k::Term<ESlot>) -> k::Term<List<Int>> {
    match x {
        ESlotC::Es { reserver, .. } => reserver,
    }
}

#[k::function(total, internal)]
pub fn EBstat(x: k::Term<ESlot>) -> k::Term<BStat> {
    match x {
        ESlotC::Es { bstat, .. } => bstat,
    }
}

#[k::function(total, internal)]
pub fn ERoot(x: k::Term<ESlot>) -> k::Term<Root> {
    match x {
        ESlotC::Es { root, .. } => root,
    }
}

#[k::function(total, internal)]
pub fn EPool(x: k::Term<ESlot>) -> k::Term<Int> {
    match x {
        ESlotC::Es { pool, .. } => pool,
    }
}

#[k::function(total, internal)]
pub fn SKey(x: k::Term<SeatSlot>) -> k::Term<Int> {
    match x {
        SeatSlotC::Ss { key, .. } => key,
    }
}

// ---------------------------------------------------------------------------
// Committee slot transitions (`burnC`, `openSlot`, `cstep`, `cnew`).

/// SL-010, SL-011: a burn, used or not.
#[k::function(total, internal)]
pub fn BurnC(x: k::Term<CSlot>) -> k::Term<CSlot> {
    match x {
        CSlotC::Cs { suite, epoch, idx, prec, namers, .. } => {
            CSlotC::Cs { suite, epoch, idx, bstat: BStatC::Burned, prec, namers }
        }
    }
}

/// SL-004: a header opens and names the slot: record the namer; a slot with
/// `prec = none` and `bstat = UNNAMED` gets the namer with the lowest board
/// position and NAMED. SL-017: a BURNED slot, or one with a precedence, gets no
/// new `prec`.
#[k::function(total, internal)]
pub fn OpenSlot(eid: k::Term<Int>, pos: k::Term<Int>, x: k::Term<CSlot>) -> k::Term<CSlot> {
    match x {
        CSlotC::Cs { suite, epoch, idx, bstat, prec, namers } => {
            if list::size(prec) == 0 && bstat.eq::<K>(BStatC::Unnamed) {
                CSlotC::Cs {
                    suite,
                    epoch,
                    idx,
                    bstat: BStatC::Named,
                    prec: Lowest([..namers, Pair::P { a: eid, b: pos }]),
                    namers: [..namers, Pair::P { a: eid, b: pos }],
                }
            } else {
                CSlotC::Cs { suite, epoch, idx, bstat, prec, namers: [..namers, Pair::P { a: eid, b: pos }] }
            }
        }
    }
}

/// `setBstat` of a committee slot.
#[k::function(total, internal)]
pub fn SetBstatC(b: k::Term<BStat>, x: k::Term<CSlot>) -> k::Term<CSlot> {
    match x {
        CSlotC::Cs { suite, epoch, idx, prec, namers, .. } => CSlotC::Cs { suite, epoch, idx, bstat: b, prec, namers },
    }
}

/// SL-005, SL-010 `burnIfLapsed` (DECISIONS 63, ledger 10): a precedence that a
/// lapsed request takes is lapsed at once, so the slot burns.
#[k::function(total, internal)]
pub fn BurnIfLapsed(lapsed: k::Term<List<Int>>, x: k::Term<CSlot>) -> k::Term<CSlot> {
    BurnIfLapsedPrec(lapsed, CPrec(x), x)
}

/// `burnIfLapsed` on the precedence `prec` of the slot `x`.
#[k::function(total, internal)]
pub fn BurnIfLapsedPrec(lapsed: k::Term<List<Int>>, prec: k::Term<List<Int>>, x: k::Term<CSlot>) -> k::Term<CSlot> {
    match prec {
        [] => x,
        [e, ..] => if list::contains(e, lapsed) { BurnC(x) } else { x },
    }
}

/// `cstep`: the committee-slot part of one operation; `lapsed` lists the requests
/// whose precedence is lapsed before it (SL-005).
#[k::function(total, internal)]
pub fn CStep(lapsed: k::Term<List<Int>>, op: k::Term<Op>, x: k::Term<CSlot>) -> k::Term<CSlot> {
    match op {
        // SL-004; SL-005: a header that opens after its lapse takes a lapsed precedence.
        OpC::OpenC { eid, pos, names } => {
            if list::contains(CKeyOf(x), names) { BurnIfLapsed(lapsed, OpenSlot(eid, pos, x)) } else { x }
        }
        // SL-005, SL-010: the lapse burns every slot where the request holds `prec`.
        OpC::Lapse { eid } => if CPrec(x).eq::<K>(list::item(eid)) { BurnC(x) } else { x },
        // SL-008: NAMED with `prec` of the request becomes RESERVED.
        OpC::Reserve { eid } => {
            if CPrec(x).eq::<K>(list::item(eid)) && CBstat(x).eq::<K>(BStatC::Named) {
                SetBstatC(BStatC::Reserved, x)
            } else {
                x
            }
        }
        // SL-009: a reserved slot of the request becomes CLAIMED.
        OpC::ClaimOp { eid } => {
            if CPrec(x).eq::<K>(list::item(eid)) && CBstat(x).eq::<K>(BStatC::Reserved) {
                SetBstatC(BStatC::Claimed, x)
            } else {
                x
            }
        }
        // SL-010: the end of the request with `prec` burns the slot, used or not.
        OpC::EndReq { eid } => if CPrec(x).eq::<K>(list::item(eid)) { BurnC(x) } else { x },
        // CP-020, SL-028: a whole-committee restart burns the indices lo..hi of a pool.
        OpC::BurnRange { suite, epoch, lo, hi } => {
            if InRange(suite, epoch, lo, hi, x) { BurnC(x) } else { x }
        }
        _ => x,
    }
}

/// `burnRange`'s selection: the slot is in pool `(su, e)` with `lo ≤ ℓ ≤ hi`.
#[k::function(total, internal)]
pub fn InRange(su: k::Term<Suite>, e: k::Term<Int>, lo: k::Term<Int>, hi: k::Term<Int>, x: k::Term<CSlot>) -> k::Term<Bool> {
    match x {
        CSlotC::Cs { suite, epoch, idx, .. } => suite.eq::<K>(su) && epoch == e && lo <= idx && idx <= hi,
    }
}

/// `cslots.map (cstep lapsed op)`.
#[k::function(total, internal)]
pub fn MapC(lapsed: k::Term<List<Int>>, op: k::Term<Op>, xs: k::Term<List<CSlot>>) -> k::Term<List<CSlot>> {
    match xs {
        [] => [],
        [x, rest @ ..] => [CStep(lapsed, op, x), ..MapC(lapsed, op, rest)],
    }
}

/// `maxL` of the indices of pool `(su, e)`.
#[k::function(total, internal)]
pub fn MaxIdxC(su: k::Term<Suite>, e: k::Term<Int>, xs: k::Term<List<CSlot>>) -> k::Term<Int> {
    match xs {
        [] => 0,
        [CSlotC::Cs { suite, epoch, idx, .. }, rest @ ..] => {
            if suite.eq::<K>(su) && epoch == e { int::max(idx, MaxIdxC(su, e, rest)) } else { MaxIdxC(su, e, rest) }
        }
    }
}

/// `cnew`: `k − i` fresh UNNAMED slots of pool `(su, e)` from index `top + i + 1`.
#[k::function(total, internal)]
pub fn GenC(su: k::Term<Suite>, e: k::Term<Int>, top: k::Term<Int>, i: k::Term<Int>, k: k::Term<Int>) -> k::Term<List<CSlot>> {
    if i >= k {
        []
    } else {
        [
            CSlotC::Cs { suite: su, epoch: e, idx: top + i + 1, bstat: BStatC::Unnamed, prec: [], namers: [] },
            ..GenC(su, e, top, i + 1, k)
        ]
    }
}

// ---------------------------------------------------------------------------
// ECDSA slot transitions (`burnE`, `earliest`, `assignE`, `estep`, `enew`).

/// SL-011: a burn.
#[k::function(total, internal)]
pub fn BurnE(x: k::Term<ESlot>) -> k::Term<ESlot> {
    match x {
        ESlotC::Es { pool, idx, leaf_set, root, prec, reserver, namers, .. } => {
            ESlotC::Es { pool, idx, leaf_set, root, bstat: BStatC::Burned, prec, reserver, namers }
        }
    }
}

/// The namers of `ns` whose authorization is in force under root `r`.
#[k::function(total, internal)]
pub fn InForceNamers(inf: k::Term<List<Force>>, r: k::Term<Root>, ns: k::Term<List<NN>>) -> k::Term<List<NN>> {
    match ns {
        [] => [],
        [n @ Pair::P { a, .. }, rest @ ..] => {
            if list::contains(ForceC::Frc { eid: a, root: r }, inf) {
                [n, ..InForceNamers(inf, r, rest)]
            } else {
                InForceNamers(inf, r, rest)
            }
        }
    }
}

/// SL-006 `earliest`: the earliest namer in board order whose authorization is in
/// force and whose source opens the slot's root.
#[k::function(total, internal)]
pub fn Earliest(inf: k::Term<List<Force>>, x: k::Term<ESlot>) -> k::Term<List<Int>> {
    match x {
        ESlotC::Es { root, namers, .. } => Lowest(InForceNamers(inf, root, namers)),
    }
}

/// SL-006, ledger 3: give the slot the precedence `e`; UNNAMED moves to NAMED.
#[k::function(total, internal)]
pub fn SetPrecE(e: k::Term<Int>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    match x {
        ESlotC::Es { pool, idx, leaf_set, root, bstat, reserver, namers, .. } => {
            if bstat.eq::<K>(BStatC::Unnamed) {
                ESlotC::Es { pool, idx, leaf_set, root, bstat: BStatC::Named, prec: [e], reserver, namers }
            } else {
                ESlotC::Es { pool, idx, leaf_set, root, bstat, prec: [e], reserver, namers }
            }
        }
    }
}

/// `assignE`, second half: the earliest namer in force, if any.
#[k::function(total, internal)]
pub fn AssignWith(o: k::Term<List<Int>>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    match o {
        [] => x,
        [e, ..] => SetPrecE(e, x),
    }
}

/// SL-006 `assignE`: a slot with `prec = none` and `bstat ≠ BURNED` gets the
/// earliest namer in force.
#[k::function(total, internal)]
pub fn AssignE(inf: k::Term<List<Force>>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    if list::size(EPrec(x)) == 0 && !EBstat(x).eq::<K>(BStatC::Burned) { AssignWith(Earliest(inf, x), x) } else { x }
}

/// Record the namer `(eid, pos)` on an ECDSA slot.
#[k::function(total, internal)]
pub fn AddNamerE(eid: k::Term<Int>, pos: k::Term<Int>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    match x {
        ESlotC::Es { pool, idx, leaf_set, root, bstat, prec, reserver, namers } => ESlotC::Es {
            pool,
            idx,
            leaf_set,
            root,
            bstat,
            prec,
            reserver,
            namers: [..namers, Pair::P { a: eid, b: pos }],
        },
    }
}

/// Some namer of the slot is the request `e`.
#[k::function(total, internal)]
pub fn NamedBy(e: k::Term<Int>, ns: k::Term<List<NN>>) -> k::Term<Bool> {
    match ns {
        [] => false,
        [Pair::P { a, .. }, rest @ ..] => if a == e { true } else { NamedBy(e, rest) },
    }
}

#[k::function(total, internal)]
pub fn ENamers(x: k::Term<ESlot>) -> k::Term<List<NN>> {
    match x {
        ESlotC::Es { namers, .. } => namers,
    }
}

/// SL-008: RESERVED, and `reserver` is the request.
#[k::function(total, internal)]
pub fn ReserveE(eid: k::Term<Int>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    match x {
        ESlotC::Es { pool, idx, leaf_set, root, prec, namers, .. } => {
            ESlotC::Es { pool, idx, leaf_set, root, bstat: BStatC::Reserved, prec, reserver: [eid], namers }
        }
    }
}

/// SL-009: CLAIMED.
#[k::function(total, internal)]
pub fn ClaimE(x: k::Term<ESlot>) -> k::Term<ESlot> {
    match x {
        ESlotC::Es { pool, idx, leaf_set, root, prec, reserver, namers, .. } => {
            ESlotC::Es { pool, idx, leaf_set, root, bstat: BStatC::Claimed, prec, reserver, namers }
        }
    }
}

/// `estep`: the ECDSA-slot part of one operation; `inf` is the in-force list before it.
#[k::function(total, internal)]
pub fn EStep(inf: k::Term<List<Force>>, op: k::Term<Op>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    match op {
        // SL-006, SL-007: record the namer; only a namer in force for the slot's root
        // takes precedence (ledger 2); an unauthorized namer changes nothing else.
        OpC::OpenE { eid, pos, names } => {
            if list::contains(EKeyOf(x), names) {
                OpenE1(inf, eid, pos, x)
            } else {
                x
            }
        }
        // SL-006: the authorization comes into force.
        OpC::InForce { eid, root } => {
            if NamedBy(eid, ENamers(x)) && ERoot(x).eq::<K>(root) {
                AssignE(list::concat(inf, list::item(ForceC::Frc { eid, root })), x)
            } else {
                x
            }
        }
        // SL-008: reserve, and `reserver` is the request.
        OpC::Reserve { eid } => {
            if EPrec(x).eq::<K>(list::item(eid)) && EBstat(x).eq::<K>(BStatC::Named) { ReserveE(eid, x) } else { x }
        }
        // SL-009.
        OpC::ClaimOp { eid } => {
            if EReserver(x).eq::<K>(list::item(eid)) && EBstat(x).eq::<K>(BStatC::Reserved) { ClaimE(x) } else { x }
        }
        // SL-011: the end of the request in `reserver` burns the slot.
        OpC::EndReq { eid } => if EReserver(x).eq::<K>(list::item(eid)) { BurnE(x) } else { x },
        // CP-021, SL-028: a whole-committee restart burns an account pool.
        OpC::BurnPool { pool } => if EPool(x) == pool { BurnE(x) } else { x },
        _ => x,
    }
}

/// SL-006, SL-007: an open that names the slot.
#[k::function(total, internal)]
pub fn OpenE1(inf: k::Term<List<Force>>, eid: k::Term<Int>, pos: k::Term<Int>, x: k::Term<ESlot>) -> k::Term<ESlot> {
    if list::contains(ForceC::Frc { eid, root: ERoot(x) }, inf) {
        AssignE(inf, AddNamerE(eid, pos, x))
    } else {
        AddNamerE(eid, pos, x)
    }
}

/// `eslots.map (estep s op)`.
#[k::function(total, internal)]
pub fn MapE(inf: k::Term<List<Force>>, op: k::Term<Op>, xs: k::Term<List<ESlot>>) -> k::Term<List<ESlot>> {
    match xs {
        [] => [],
        [x, rest @ ..] => [EStep(inf, op, x), ..MapE(inf, op, rest)],
    }
}

/// `maxL` of the indices of account pool `p`.
#[k::function(total, internal)]
pub fn MaxIdxE(p: k::Term<Int>, xs: k::Term<List<ESlot>>) -> k::Term<Int> {
    match xs {
        [] => 0,
        [ESlotC::Es { pool, idx, .. }, rest @ ..] => {
            if pool == p { int::max(idx, MaxIdxE(p, rest)) } else { MaxIdxE(p, rest) }
        }
    }
}

/// `enew`: `k − i` fresh UNNAMED slots of account pool `p` from index `top + i + 1`.
#[k::function(total, internal)]
pub fn GenE(p: k::Term<Int>, ls: k::Term<Int>, r: k::Term<Root>, top: k::Term<Int>, i: k::Term<Int>, k: k::Term<Int>) -> k::Term<List<ESlot>> {
    if i >= k {
        []
    } else {
        [
            ESlotC::Es {
                pool: p,
                idx: top + i + 1,
                leaf_set: ls,
                root: r,
                bstat: BStatC::Unnamed,
                prec: [],
                reserver: [],
                namers: [],
            },
            ..GenE(p, ls, r, top, i + 1, k)
        ]
    }
}

// ---------------------------------------------------------------------------
// Seat slot transitions (TEE; `sstep`, `snew`).

/// SL-018, SL-019: `slot_bind` of a slot share.
#[k::function(total, internal)]
pub fn SBind(w: k::Term<Int>, d: k::Term<Int>, sa: k::Term<Int>, va: k::Term<Int>, x: k::Term<SeatSlot>) -> k::Term<SeatSlot> {
    match x {
        // `free` becomes `bound(d)`; current once the `slot` entries and the sealed
        // version each have `w` acks.
        SeatSlotC::Ss { key, st: SeatStC::Free, signed, .. } => {
            SeatSlotC::Ss { key, st: SeatStC::Bound { d }, current: w <= sa && w <= va, signed }
        }
        // A later ack round for the same digest can make the slot current, never not current.
        SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current, signed } => {
            if d2 == d {
                SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current: current || (w <= sa && w <= va), signed }
            } else {
                SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current, signed }
            }
        }
        SeatSlotC::Ss { key, st: SeatStC::SBurned, current, signed } => {
            SeatSlotC::Ss { key, st: SeatStC::SBurned, current, signed }
        }
    }
}

/// SL-021, SL-027: record the ticket `d` as signed once.
#[k::function(total, internal)]
pub fn AddSigned(d: k::Term<Int>, signed: k::Term<List<Int>>) -> k::Term<List<Int>> {
    if list::contains(d, signed) { signed } else { [d, ..signed] }
}

/// SL-019 to SL-021: a partial only on a current `bound(d)` and only for `d`.
#[k::function(total, internal)]
pub fn SRelease(d: k::Term<Int>, x: k::Term<SeatSlot>) -> k::Term<SeatSlot> {
    match x {
        SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current, signed } => {
            if d2 == d && current {
                SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current, signed: AddSigned(d, signed) }
            } else {
                SeatSlotC::Ss { key, st: SeatStC::Bound { d: d2 }, current, signed }
            }
        }
        SeatSlotC::Ss { key, st: SeatStC::Free, current, signed } => {
            SeatSlotC::Ss { key, st: SeatStC::Free, current, signed }
        }
        SeatSlotC::Ss { key, st: SeatStC::SBurned, current, signed } => {
            SeatSlotC::Ss { key, st: SeatStC::SBurned, current, signed }
        }
    }
}

/// SL-018, SL-030: the slot share moves to `burned`.
#[k::function(total, internal)]
pub fn SBurn(x: k::Term<SeatSlot>) -> k::Term<SeatSlot> {
    match x {
        SeatSlotC::Ss { key, current, signed, .. } => SeatSlotC::Ss { key, st: SeatStC::SBurned, current, signed },
    }
}

/// `sstep`: the seat part of one operation on one slot share.
#[k::function(total, internal)]
pub fn SStep(w: k::Term<Int>, op: k::Term<Op>, x: k::Term<SeatSlot>) -> k::Term<SeatSlot> {
    match op {
        OpC::SeatBind { key, d, slot_acks, sealed_acks } => {
            if SKey(x) == key { SBind(w, d, slot_acks, sealed_acks, x) } else { x }
        }
        OpC::SeatRelease { key, d } => if SKey(x) == key { SRelease(d, x) } else { x },
        OpC::SeatBurn { key } => if SKey(x) == key { SBurn(x) } else { x },
        _ => x,
    }
}

/// `seat.map (sstep w op)`.
#[k::function(total, internal)]
pub fn MapS(w: k::Term<Int>, op: k::Term<Op>, xs: k::Term<List<SeatSlot>>) -> k::Term<List<SeatSlot>> {
    match xs {
        [] => [],
        [x, rest @ ..] => [SStep(w, op, x), ..MapS(w, op, rest)],
    }
}

// ---------------------------------------------------------------------------
// Pure checks (SL-012 to SL-015, SL-023 to SL-026).

/// SL-012 to SL-015: the verdict on one committee index `l`.
#[k::function(total, internal)]
pub fn VerdictOf(
    listed: k::Term<Bool>,
    h: k::Term<Int>,
    pmin: k::Term<Int>,
    pending: k::Term<List<NN>>,
    bw: k::Term<Int>,
    eid: k::Term<Int>,
    l: k::Term<Int>,
) -> k::Term<Verdict> {
    if !listed {
        VerdictC::PoolUnlisted
    } else if h + bw < l {
        VerdictC::AboveWindow
    } else if h < l {
        VerdictC::InWindow
    } else if pmin <= l && list::contains(Pair::P { a: l, b: eid }, pending) {
        VerdictC::InWindow
    } else {
        VerdictC::SlotTaken
    }
}

/// `idxs.map (verdict ...)`.
#[k::function(total, internal)]
pub fn Verdicts(
    listed: k::Term<Bool>,
    h: k::Term<Int>,
    pmin: k::Term<Int>,
    pending: k::Term<List<NN>>,
    bw: k::Term<Int>,
    eid: k::Term<Int>,
    idxs: k::Term<List<Int>>,
) -> k::Term<List<Verdict>> {
    match idxs {
        [] => [],
        [l, rest @ ..] => {
            [VerdictOf(listed, h, pmin, pending, bw, eid, l), ..Verdicts(listed, h, pmin, pending, bw, eid, rest)]
        }
    }
}

/// SL-023, SL-024 `batchCheck`: the failing polynomials, numbered from `i`.
#[k::function(total, internal)]
pub fn BatchFrom(polys: k::Term<List<Bool>>, i: k::Term<Int>) -> k::Term<List<Int>> {
    match polys {
        [] => [],
        [p, rest @ ..] => if p { BatchFrom(rest, i + 1) } else { [i, ..BatchFrom(rest, i + 1)] },
    }
}

/// SL-025: the dealers without a valid complaint, in board order.
#[k::function(total, internal)]
pub fn OkDealers(ds: k::Term<List<Dealer>>) -> k::Term<List<Int>> {
    match ds {
        [] => [],
        [DealerC::Dlr { dealer, complained }, rest @ ..] => {
            if complained { OkDealers(rest) } else { [dealer, ..OkDealers(rest)] }
        }
    }
}

/// `List.take t`.
#[k::function(total, internal)]
pub fn TakeInt(t: k::Term<Int>, xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [x, rest @ ..] => if t > 0 { [x, ..TakeInt(t - 1, rest)] } else { [] },
    }
}

/// SL-025 `qualified`: the first `t` dealers without a valid complaint; none while
/// fewer than `t` exist.
#[k::function(total, internal)]
pub fn QualifiedOf(t: k::Term<Int>, ds: k::Term<List<Dealer>>) -> k::Term<List<List<Int>>> {
    if list::size(OkDealers(ds)) < t { [] } else { [TakeInt(t, OkDealers(ds))] }
}

/// SL-026: some covered entry binds `nf` to another digest than `d`.
#[k::function(total, internal)]
pub fn OtherDigest(nf: k::Term<Int>, d: k::Term<Int>, cov: k::Term<List<NN>>) -> k::Term<Bool> {
    match cov {
        [] => false,
        [Pair::P { a, b }, rest @ ..] => {
            if a == nf {
                if b != d { true } else { OtherDigest(nf, d, rest) }
            } else {
                OtherDigest(nf, d, rest)
            }
        }
    }
}

/// SL-026 `anchorOk`.
#[k::function(total, internal)]
pub fn AnchorOk(on: k::Term<Bool>, cov: k::Term<List<NN>>, nf: k::Term<Int>, d: k::Term<Int>) -> k::Term<Bool> {
    if !on {
        true
    } else if list::contains(Pair::P { a: nf, b: d }, cov) {
        !OtherDigest(nf, d, cov)
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Observations (SL-016, DECISIONS 68): `takenFor` and `slotTakenAt`, read on the
// state after the operation (`obsOf` of the oracle).

/// The request `eid` finds the precedence of another request.
#[k::function(total, internal)]
pub fn TakenC(eid: k::Term<Int>, prec: k::Term<List<Int>>) -> k::Term<Bool> {
    match prec {
        [] => false,
        [p, ..] => p != eid,
    }
}

/// SL-016: the precedence of another request with an authorization in force.
#[k::function(total, internal)]
pub fn TakenE(eid: k::Term<Int>, inf: k::Term<List<Force>>, prec: k::Term<List<Int>>) -> k::Term<Bool> {
    match prec {
        [] => false,
        [p, ..] => if p != eid { InForceAny(inf, p) } else { false },
    }
}

/// SL-016: a committee slot that `eid` names and whose `prec` is another request.
#[k::function(total, internal)]
pub fn CTakenBy(eid: k::Term<Int>, x: k::Term<CSlot>) -> k::Term<Bool> {
    match x {
        CSlotC::Cs { prec, namers, .. } => if NamedBy(eid, namers) { TakenC(eid, prec) } else { false },
    }
}

/// SL-016: an ECDSA slot that `eid` names and whose `prec` is another request in force.
#[k::function(total, internal)]
pub fn ETakenBy(eid: k::Term<Int>, inf: k::Term<List<Force>>, x: k::Term<ESlot>) -> k::Term<Bool> {
    match x {
        ESlotC::Es { prec, namers, .. } => if NamedBy(eid, namers) { TakenE(eid, inf, prec) } else { false },
    }
}

/// SL-016: some committee slot is taken for `eid`.
#[k::function(total, internal)]
pub fn AnyTakenC(eid: k::Term<Int>, xs: k::Term<List<CSlot>>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [x, rest @ ..] => if CTakenBy(eid, x) { true } else { AnyTakenC(eid, rest) },
    }
}

/// SL-016: some ECDSA slot is taken for `eid`.
#[k::function(total, internal)]
pub fn AnyTakenE(eid: k::Term<Int>, inf: k::Term<List<Force>>, xs: k::Term<List<ESlot>>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [x, rest @ ..] => if ETakenBy(eid, inf, x) { true } else { AnyTakenE(eid, inf, rest) },
    }
}

/// SL-016 `takenFor`: a committee slot or an ECDSA slot that `eid` names and another
/// request holds.
#[k::function(total, internal)]
pub fn TakenFor(eid: k::Term<Int>, inf: k::Term<List<Force>>, cs: k::Term<List<CSlot>>, es: k::Term<List<ESlot>>) -> k::Term<Bool> {
    if AnyTakenC(eid, cs) { true } else { AnyTakenE(eid, inf, es) }
}

/// SL-016 `slotTakenAt` (DECISIONS 68), first condition: the authorization of `eid`
/// is in force. A header whose authorization never comes into force gets no SLOT_TAKEN.
#[k::function(total, internal)]
pub fn SlotTakenAt(
    eid: k::Term<Int>,
    inf: k::Term<List<Force>>,
    opened: k::Term<List<Int>>,
    cs: k::Term<List<CSlot>>,
    es: k::Term<List<ESlot>>,
) -> k::Term<Obs> {
    if InForceAny(inf, eid) { SlotTakenOpened(eid, inf, opened, cs, es) } else { ObsC::Ok }
}

/// SL-016 `slotTakenAt`, second condition: the header of `eid` opened.
#[k::function(total, internal)]
pub fn SlotTakenOpened(
    eid: k::Term<Int>,
    inf: k::Term<List<Force>>,
    opened: k::Term<List<Int>>,
    cs: k::Term<List<CSlot>>,
    es: k::Term<List<ESlot>>,
) -> k::Term<Obs> {
    if list::contains(eid, opened) { SlotTakenObs(eid, inf, cs, es) } else { ObsC::Ok }
}

/// SL-016 `slotTakenAt`, third condition: a slot that the header names is taken:
/// VOID SLOT_TAKEN.
#[k::function(total, internal)]
pub fn SlotTakenObs(eid: k::Term<Int>, inf: k::Term<List<Force>>, cs: k::Term<List<CSlot>>, es: k::Term<List<ESlot>>) -> k::Term<Obs> {
    if TakenFor(eid, inf, cs, es) { ObsC::Void { reason: VoidReasonC::VSlotTaken } } else { ObsC::Ok }
}

/// SL-016: the observation of `open_c`, on the state after it (`exec`).
#[k::function(total, internal)]
pub fn ObsOpenC(
    eid: k::Term<Int>,
    inf: k::Term<List<Force>>,
    lapsed: k::Term<List<Int>>,
    opened: k::Term<List<Int>>,
    op: k::Term<Op>,
    cs: k::Term<List<CSlot>>,
    es: k::Term<List<ESlot>>,
) -> k::Term<Obs> {
    SlotTakenAt(eid, inf, [eid, ..opened], MapC(lapsed, op, cs), es)
}

/// SL-016: the observation of `open_e`, on the state after it (`exec`).
#[k::function(total, internal)]
pub fn ObsOpenE(
    eid: k::Term<Int>,
    inf: k::Term<List<Force>>,
    opened: k::Term<List<Int>>,
    op: k::Term<Op>,
    cs: k::Term<List<CSlot>>,
    es: k::Term<List<ESlot>>,
) -> k::Term<Obs> {
    SlotTakenAt(eid, inf, [eid, ..opened], cs, MapE(inf, op, es))
}

/// SL-016: the observation of `in_force`, on the state after it (`exec`).
#[k::function(total, internal)]
pub fn ObsInForce(
    eid: k::Term<Int>,
    root: k::Term<Root>,
    inf: k::Term<List<Force>>,
    opened: k::Term<List<Int>>,
    op: k::Term<Op>,
    cs: k::Term<List<CSlot>>,
    es: k::Term<List<ESlot>>,
) -> k::Term<Obs> {
    SlotTakenAt(eid, [..inf, ForceC::Frc { eid, root }], opened, cs, MapE(inf, op, es))
}

// ---------------------------------------------------------------------------
// Refusals (`opRefusals`).

/// Q-003, ledger 4: the header already opened, or its board position is at or
/// below the last opened header's.
#[k::function(total, internal)]
pub fn HeaderOrder(opened: k::Term<List<Int>>, lastpos: k::Term<List<Int>>, eid: k::Term<Int>, pos: k::Term<Int>) -> k::Term<Bool> {
    match lastpos {
        [] => list::contains(eid, opened),
        [p, ..] => list::contains(eid, opened) || pos <= p,
    }
}

/// Ledger 5: some named committee key was never dealt.
#[k::function(total, internal)]
pub fn UndealtC(names: k::Term<List<CKey>>, xs: k::Term<List<CSlot>>) -> k::Term<Bool> {
    match names {
        [] => false,
        [n, rest @ ..] => if HasCKey(n, xs) { UndealtC(rest, xs) } else { true },
    }
}

#[k::function(total, internal)]
pub fn HasCKey(n: k::Term<CKey>, xs: k::Term<List<CSlot>>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [x, rest @ ..] => if CKeyOf(x).eq::<K>(n) { true } else { HasCKey(n, rest) },
    }
}

/// Ledger 5: some named ECDSA key was never dealt.
#[k::function(total, internal)]
pub fn UndealtE(names: k::Term<List<EKey>>, xs: k::Term<List<ESlot>>) -> k::Term<Bool> {
    match names {
        [] => false,
        [n, rest @ ..] => if HasEKey(n, xs) { UndealtE(rest, xs) } else { true },
    }
}

#[k::function(total, internal)]
pub fn HasEKey(n: k::Term<EKey>, xs: k::Term<List<ESlot>>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [x, rest @ ..] => if EKeyOf(x).eq::<K>(n) { true } else { HasEKey(n, rest) },
    }
}

/// Q-003, ledgers 4, 5: the header is out of board order or names an undealt committee slot.
#[k::function(total, internal)]
pub fn OrderOrUndealtC(
    opened: k::Term<List<Int>>,
    lastpos: k::Term<List<Int>>,
    eid: k::Term<Int>,
    pos: k::Term<Int>,
    names: k::Term<List<CKey>>,
    xs: k::Term<List<CSlot>>,
) -> k::Term<Bool> {
    if HeaderOrder(opened, lastpos, eid, pos) { true } else { UndealtC(names, xs) }
}

/// Q-003, ledgers 4, 5: the header is out of board order or names an undealt ECDSA slot.
#[k::function(total, internal)]
pub fn OrderOrUndealtE(
    opened: k::Term<List<Int>>,
    lastpos: k::Term<List<Int>>,
    eid: k::Term<Int>,
    pos: k::Term<Int>,
    names: k::Term<List<EKey>>,
    xs: k::Term<List<ESlot>>,
) -> k::Term<Bool> {
    if HeaderOrder(opened, lastpos, eid, pos) { true } else { UndealtE(names, xs) }
}

/// `opt b noRule`.
#[k::function(total, internal)]
pub fn NoRuleIf(b: k::Term<Bool>) -> k::Term<List<Refusal>> {
    if b { [RefusalC::NoRule] } else { [] }
}

/// `opt b outsideCapability`.
#[k::function(total, internal)]
pub fn OutsideIf(b: k::Term<Bool>) -> k::Term<List<Refusal>> {
    if b { [RefusalC::OutsideCapability] } else { [] }
}

/// Q-003, ledgers 4, 5, 9: the refusals of `open_c`.
#[k::function(total, internal)]
pub fn OpenCRef(
    opened: k::Term<List<Int>>,
    lastpos: k::Term<List<Int>>,
    xs: k::Term<List<CSlot>>,
    eid: k::Term<Int>,
    pos: k::Term<Int>,
    names: k::Term<List<CKey>>,
) -> k::Term<List<Refusal>> {
    list::concat(
        NoRuleIf(OrderOrUndealtC(opened, lastpos, eid, pos, names, xs)),
        OutsideIf(!NodupB(names)),
    )
}

/// Q-003, ledgers 4, 5, 9: the refusals of `open_e`.
#[k::function(total, internal)]
pub fn OpenERef(
    opened: k::Term<List<Int>>,
    lastpos: k::Term<List<Int>>,
    xs: k::Term<List<ESlot>>,
    eid: k::Term<Int>,
    pos: k::Term<Int>,
    names: k::Term<List<EKey>>,
) -> k::Term<List<Refusal>> {
    list::concat(
        NoRuleIf(OrderOrUndealtE(opened, lastpos, eid, pos, names, xs)),
        OutsideIf(!NodupB(names)),
    )
}

/// Ledger 1: an `in_force` or `lapse` of a request that is in force, lapsed or ended.
#[k::function(total, internal)]
pub fn KnownReq(inf: k::Term<List<Force>>, lapsed: k::Term<List<Int>>, ended: k::Term<List<Int>>, eid: k::Term<Int>) -> k::Term<Bool> {
    InForceAny(inf, eid) || list::contains(eid, lapsed) || list::contains(eid, ended)
}

/// Ledger 1: a reserve of a request not in force, or ended (SL-008).
#[k::function(total, internal)]
pub fn ReserveBad(inf: k::Term<List<Force>>, ended: k::Term<List<Int>>, eid: k::Term<Int>) -> k::Term<Bool> {
    if InForceAny(inf, eid) { list::contains(eid, ended) } else { true }
}

/// Ledgers 6, 8: `seat_put` outside TEE or of a key the seat holds.
#[k::function(total, internal)]
pub fn HasSeat(key: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<Bool> {
    match seat {
        [] => false,
        [x, rest @ ..] => if SKey(x) == key { true } else { HasSeat(key, rest) },
    }
}

/// Ledger 6: a bind of a slot bound to another digest, or burned, or absent.
#[k::function(total, internal)]
pub fn BindBad(key: k::Term<Int>, d: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<Bool> {
    match seat {
        [] => true,
        [x, rest @ ..] => if SKey(x) == key { BindBadSt(d, x) } else { BindBad(key, d, rest) },
    }
}

#[k::function(total, internal)]
pub fn BindBadSt(d: k::Term<Int>, x: k::Term<SeatSlot>) -> k::Term<Bool> {
    match x {
        SeatSlotC::Ss { st: SeatStC::Free, .. } => false,
        SeatSlotC::Ss { st: SeatStC::Bound { d: d2 }, .. } => d2 != d,
        SeatSlotC::Ss { st: SeatStC::SBurned, .. } => true,
    }
}

/// Ledgers 6, 8: the refusal of `seat_bind`: NON_TEE, or the slot is bound to
/// another digest, burned or absent.
#[k::function(total, internal)]
pub fn SeatBindBad(m: k::Term<Mode>, key: k::Term<Int>, d: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<Bool> {
    if m.eq::<K>(ModeC::NonTee) { true } else { BindBad(key, d, seat) }
}

/// Ledgers 6, 8: the refusal of `seat_burn`: NON_TEE, or the slot is burned or absent.
#[k::function(total, internal)]
pub fn SeatBurnBad(m: k::Term<Mode>, key: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<Bool> {
    if m.eq::<K>(ModeC::NonTee) { true } else { BurnBad(key, seat) }
}

/// Ledger 6: a burn of a burned or absent slot.
#[k::function(total, internal)]
pub fn BurnBad(key: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<Bool> {
    match seat {
        [] => true,
        [x, rest @ ..] => if SKey(x) == key { IsBurned(x) } else { BurnBad(key, rest) },
    }
}

#[k::function(total, internal)]
pub fn IsBurned(x: k::Term<SeatSlot>) -> k::Term<Bool> {
    match x {
        SeatSlotC::Ss { st, .. } => st.eq::<K>(SeatStC::SBurned),
    }
}

/// SL-020 and ledger 6: the refusals of a release on a slot the seat holds.
#[k::function(total, internal)]
pub fn ReleaseOn(d: k::Term<Int>, x: k::Term<SeatSlot>) -> k::Term<List<Refusal>> {
    match x {
        SeatSlotC::Ss { st: SeatStC::Bound { d: d2 }, current, .. } => {
            if d2 != d { [RefusalC::SlotBound] } else { NoRuleIf(!current) }
        }
        SeatSlotC::Ss { st: SeatStC::Free, .. } => [RefusalC::NoRule],
        SeatSlotC::Ss { st: SeatStC::SBurned, .. } => [RefusalC::NoRule],
    }
}

/// `seatFind` for a release: the first slot share with the key.
#[k::function(total, internal)]
pub fn ReleaseFind(key: k::Term<Int>, d: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<List<Refusal>> {
    match seat {
        [] => [RefusalC::NoRule],
        [x, rest @ ..] => if SKey(x) == key { ReleaseOn(d, x) } else { ReleaseFind(key, d, rest) },
    }
}

/// SL-020, ledgers 6, 8: the refusals of `seat_release`.
#[k::function(total, internal)]
pub fn ReleaseRef(m: k::Term<Mode>, key: k::Term<Int>, d: k::Term<Int>, seat: k::Term<List<SeatSlot>>) -> k::Term<List<Refusal>> {
    if m.eq::<K>(ModeC::NonTee) { [RefusalC::NoRule] } else { ReleaseFind(key, d, seat) }
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
    pub cslots: List<CSlot>,
    #[k::cell]
    pub eslots: List<ESlot>,
    #[k::cell]
    pub seat: List<SeatSlot>,
    #[k::cell]
    pub forces: List<Force>,
    #[k::cell]
    pub opened: List<Int>,
    #[k::cell]
    pub lastpos: List<Int>,
    #[k::cell]
    pub lapsed: List<Int>,
    #[k::cell]
    pub ended: List<Int>,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: no slot, no request.
    #[k::init]
    pub fn init(params: Params, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            cslots: [],
            eslots: [],
            seat: [],
            forces: [],
            opened: [],
            lastpos: [],
            lapsed: [],
            ended: [],
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // SL-001, SL-022: deal `k` committee slots into pool `(s, e)` above its highest index.
    deal_c: {
        k: [Step::Go, ..],
        cslots,
        ops: [OpC::DealC { suite, epoch, kcount }, ..],
        obs,
    } => {
        cslots: list::concat(cslots, GenC(suite, epoch, MaxIdxC(suite, epoch, cslots), 0, kcount)),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SL-003, SL-022: deal `k` ECDSA slots into account pool `p` above its highest index.
    deal_e: {
        k: [Step::Go, ..],
        eslots,
        ops: [OpC::DealE { pool, leaf_set, root, kcount }, ..],
        obs,
    } => {
        eslots: list::concat(eslots, GenE(pool, leaf_set, root, MaxIdxE(pool, eslots), 0, kcount)),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SL-004, SL-005, SL-016, SL-017: the header opens and names committee slots.
    #[k::requires(list::size(OpenCRef(opened, lastpos, cslots, eid, pos, names)) == 0)]
    open_c: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        opened,
        lastpos,
        lapsed,
        ops: [op @ OpC::OpenC { eid, pos, names }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        opened: [eid, ..opened],
        lastpos: [pos],
        ops: [..],
        obs: [..obs, ObsOpenC(eid, forces, lapsed, opened, op, cslots, eslots)],
    };

    // Q-003, ledgers 4, 5, 9: an open out of board order, of an undealt slot, or
    // naming one slot twice.
    #[k::requires(list::size(OpenCRef(opened, lastpos, cslots, eid, pos, names)) != 0)]
    open_c_refused: {
        k: [Step::Go, ..],
        cslots,
        opened,
        lastpos,
        ops: [OpC::OpenC { eid, pos, names }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: OpenCRef(opened, lastpos, cslots, eid, pos, names) }],
    };

    // SL-006, SL-007, SL-016: the header opens and names ECDSA slots.
    #[k::requires(list::size(OpenERef(opened, lastpos, eslots, eid, pos, names)) == 0)]
    open_e: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        opened,
        lastpos,
        ops: [op @ OpC::OpenE { eid, pos, names }, ..],
        obs,
    } => {
        eslots: MapE(forces, op, eslots),
        opened: [eid, ..opened],
        lastpos: [pos],
        ops: [..],
        obs: [..obs, ObsOpenE(eid, forces, opened, op, cslots, eslots)],
    };

    // Q-003, ledgers 4, 5, 9.
    #[k::requires(list::size(OpenERef(opened, lastpos, eslots, eid, pos, names)) != 0)]
    open_e_refused: {
        k: [Step::Go, ..],
        eslots,
        opened,
        lastpos,
        ops: [OpC::OpenE { eid, pos, names }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: OpenERef(opened, lastpos, eslots, eid, pos, names) }],
    };

    // SL-006, SL-016: the authorization of the request comes into force.
    #[k::requires(!KnownReq(forces, lapsed, ended, eid))]
    authorize: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        opened,
        lapsed,
        ended,
        ops: [op @ OpC::InForce { eid, root }, ..],
        obs,
    } => {
        eslots: MapE(forces, op, eslots),
        forces: [..forces, ForceC::Frc { eid, root }],
        ops: [..],
        obs: [..obs, ObsInForce(eid, root, forces, opened, op, cslots, eslots)],
    };

    // Ledger 1: the request is already in force, lapsed or ended.
    #[k::requires(KnownReq(forces, lapsed, ended, eid))]
    authorize_refused: {
        k: [Step::Go, ..],
        forces,
        lapsed,
        ended,
        ops: [OpC::InForce { eid, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-005, SL-010: the precedence lapses (an input event at `b + Δ_c`, ledgers 9,
    // 10); every committee slot where the request holds `prec` is BURNED.
    #[k::requires(!KnownReq(forces, lapsed, ended, eid))]
    lapse: {
        k: [Step::Go, ..],
        cslots,
        forces,
        lapsed,
        ended,
        ops: [op @ OpC::Lapse { eid }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        lapsed: [eid, ..lapsed],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 1: a lapse of a request that is in force, lapsed or ended.
    #[k::requires(KnownReq(forces, lapsed, ended, eid))]
    lapse_refused: {
        k: [Step::Go, ..],
        forces,
        lapsed,
        ended,
        ops: [OpC::Lapse { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-008: `q` votes with one header hash commit for the request.
    #[k::requires(!ReserveBad(forces, ended, eid))]
    reserve: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        lapsed,
        ended,
        ops: [op @ OpC::Reserve { eid }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        eslots: MapE(forces, op, eslots),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 1: a reserve of a request not in force, or ended.
    #[k::requires(ReserveBad(forces, ended, eid))]
    reserve_refused: {
        k: [Step::Go, ..],
        forces,
        ended,
        ops: [OpC::Reserve { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-009: the request reaches ADMITTED.
    #[k::requires(!list::contains(eid, ended))]
    claim: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        lapsed,
        ended,
        ops: [op @ OpC::ClaimOp { eid }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        eslots: MapE(forces, op, eslots),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 1: a claim of an ended request.
    #[k::requires(list::contains(eid, ended))]
    claim_refused: {
        k: [Step::Go, ..],
        ended,
        ops: [OpC::ClaimOp { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-010, SL-011: the request reaches FINAL, VOID or EXPIRED.
    #[k::requires(!list::contains(eid, ended))]
    end_req: {
        k: [Step::Go, ..],
        cslots,
        eslots,
        forces,
        lapsed,
        ended,
        ops: [op @ OpC::EndReq { eid }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        eslots: MapE(forces, op, eslots),
        ended: [eid, ..ended],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 1: a second end of a request.
    #[k::requires(list::contains(eid, ended))]
    end_req_refused: {
        k: [Step::Go, ..],
        ended,
        ops: [OpC::EndReq { eid }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // CP-020, SL-028: a whole-committee restart burns the indices lo..hi of a pool.
    #[k::requires(lo <= hi)]
    burn_range: {
        k: [Step::Go, ..],
        cslots,
        lapsed,
        ops: [op @ OpC::BurnRange { lo, hi, .. }, ..],
        obs,
    } => {
        cslots: MapC(lapsed, op, cslots),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 9: `lo > hi` is outside the capability.
    #[k::requires(lo > hi)]
    burn_range_refused: {
        k: [Step::Go, ..],
        ops: [OpC::BurnRange { lo, hi, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // CP-021, SL-028: a whole-committee restart burns an account pool.
    burn_pool: {
        k: [Step::Go, ..],
        eslots,
        forces,
        ops: [op @ OpC::BurnPool { .. }, ..],
        obs,
    } => {
        eslots: MapE(forces, op, eslots),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // SL-018: TEE: a slot share enters the seat `free`.
    #[k::requires(!(mode.eq::<K>(ModeC::NonTee) || HasSeat(key, seat)))]
    seat_put: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        seat,
        ops: [OpC::SeatPut { key }, ..],
        obs,
    } => {
        seat: [..seat, SeatSlotC::Ss { key, st: SeatStC::Free, current: false, signed: [] }],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledgers 6, 8: NON_TEE, or a key the seat holds.
    #[k::requires(mode.eq::<K>(ModeC::NonTee) || HasSeat(key, seat))]
    seat_put_refused: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        seat,
        ops: [OpC::SeatPut { key }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-018, SL-019: one batched `slot_bind`.
    #[k::requires(!SeatBindBad(mode, key, d, seat))]
    seat_bind: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, w },
        seat,
        ops: [op @ OpC::SeatBind { key, d, .. }, ..],
        obs,
    } => {
        seat: MapS(w, op, seat),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledgers 6, 8: NON_TEE, or a slot bound to another digest, burned or absent.
    #[k::requires(SeatBindBad(mode, key, d, seat))]
    seat_bind_refused: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        seat,
        ops: [OpC::SeatBind { key, d, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-019, SL-021: a release on a current `bound(d)` leaves a partial for `d`.
    #[k::requires(list::size(ReleaseRef(mode, key, d, seat)) == 0)]
    seat_release: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, w },
        seat,
        ops: [op @ OpC::SeatRelease { key, d }, ..],
        obs,
    } => {
        seat: MapS(w, op, seat),
        ops: [..],
        obs: [..obs, ObsC::Released { d }],
    };

    // SL-020 (`slot_bound`), ledgers 6, 8.
    #[k::requires(list::size(ReleaseRef(mode, key, d, seat)) != 0)]
    seat_release_refused: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        seat,
        ops: [OpC::SeatRelease { key, d }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ReleaseRef(mode, key, d, seat) }],
    };

    // SL-018, SL-030: `slot_burn`.
    #[k::requires(!SeatBurnBad(mode, key, seat))]
    seat_burn: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, w },
        seat,
        ops: [op @ OpC::SeatBurn { key }, ..],
        obs,
    } => {
        seat: MapS(w, op, seat),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledgers 6, 8: NON_TEE, or a burned or absent slot.
    #[k::requires(SeatBurnBad(mode, key, seat))]
    seat_burn_refused: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        seat,
        ops: [OpC::SeatBurn { key }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // SL-012 to SL-015: the window judge keeps no state.
    #[k::requires(bw != 0)]
    judge: {
        k: [Step::Go, ..],
        ops: [OpC::Judge { listed, h, pending_min, pending, bw, eid, idxs }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Verdicts { vs: Verdicts(listed, h, pending_min, pending, bw, eid, idxs) }],
    };

    // Ledger 9: `B = 0` is outside the capability (SL-012: at least 1).
    #[k::requires(bw == 0)]
    judge_refused: {
        k: [Step::Go, ..],
        ops: [OpC::Judge { bw, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // SL-023, SL-024: the batch check keeps no state.
    batch: {
        k: [Step::Go, ..],
        ops: [OpC::Batch { polys }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Complaint { failing: BatchFrom(polys, 1) }],
    };

    // SL-025: the qualified dealers keep no state.
    #[k::requires(t != 0)]
    qualify: {
        k: [Step::Go, ..],
        ops: [OpC::Qualify { t, dealers }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Qualified { ds: QualifiedOf(t, dealers) }],
    };

    // Ledger 9: `t = 0` is outside the capability.
    #[k::requires(t == 0)]
    qualify_refused: {
        k: [Step::Go, ..],
        ops: [OpC::Qualify { t, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // SL-026: the slot-anchor gate keeps no state.
    anchor_gate: {
        k: [Step::Go, ..],
        ops: [OpC::AnchorGate { on, covered, nf, d }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Gate { pass: AnchorOk(on, covered, nf, d) }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
