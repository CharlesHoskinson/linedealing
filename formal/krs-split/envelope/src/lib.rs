//! Split envelope reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/envelope/SplitEnvelope/Spec.lean` (`apply`, `runOps`).
//!
//! One rule per behaviour of `apply`: each operation either passes `opRefusals`
//! and runs `exec`, or is refused with the codes in code order and leaves the
//! state unchanged. The checks themselves are functions with one equation per
//! branch, so each branch and each condition operand is a coverage obligation
//! and a mutation target. Requirement IDs refer to
//! `openspec/changes/add-split-line-dealing/specs/split-envelope/spec.md`.
//!
//! Cells are the oracle's `St` fields (`params`, `height`, `epochs`, `seen`,
//! `accepted`) and its observation list `obs`; `ops` holds the operations still
//! to run and is empty at every end (FLOW.toml omits it).

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, int, list};

k::sorts! {
    Run: KItem;
    Mode;
    Suite;
    RType;
    NN;
    PubPart;
    Envelope;
    Layout;
    Slot;
    Header;
    Partial;
    Refusal;
    Fault;
    Combine;
    Op;
    Obs;
    Params;
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

/// EN-010, SL-001: two Schnorr suites and ECDSA.
#[k::constructors(sort = Suite, result = KResult)]
#[rustfmt::skip]
pub enum SuiteC {
    #[k::syntax("BIP340")] Bip340,
    #[k::syntax("ED25519")] Ed25519,
    #[k::syntax("ECDSA")] Ecdsa,
}

/// RQ-066, EN-018: the request type inside `body_0`; no check before order reads it (EN-022).
#[k::constructors(sort = RType, result = KResult)]
#[rustfmt::skip]
pub enum RTypeC {
    #[k::syntax("SPEND")] Spend,
    #[k::syntax("EXIT")] Exit,
    #[k::syntax("SEIZURE")] Seizure,
    #[k::syntax("BIRTH")] Birth,
    #[k::syntax("REFILL")] Refill,
    #[k::syntax("P0")] P0,
    #[k::syntax("CONTRIB")] Contrib,
}

/// A pair of naturals: `(epoch, keylist_hash)`, `(epoch, dd)`, `eid = (hd, auth_ref)`.
#[k::constructors(sort = NN, result = KResult)]
pub enum Pair {
    #[k::syntax("pr({a}, {b})")]
    P { a: Int, b: Int },
}

#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    /// `mode` and the collection window `Δ_c` of RQ-001 (EN-021, EN-023).
    #[k::syntax("params({mode}, {delta_c})")]
    Params { mode: Mode, delta_c: Int },
}

/// EN-002: the fields of the public part.
#[k::constructors(sort = PubPart, result = KResult)]
pub enum PubPartC {
    #[k::syntax("pub({version}, {epoch}, {keylist_hash}, {exp}, {size_class}, {auth_ref}, {reserved})")]
    Pub {
        version: Int,
        epoch: Int,
        keylist_hash: Int,
        exp: Int,
        size_class: Int,
        auth_ref: Int,
        reserved: Int,
    },
}

/// EN-003 to EN-008: an envelope as a node receives it.
#[k::constructors(sort = Envelope, result = KResult)]
pub enum EnvelopeC {
    #[k::syntax("envelope({size}, {pubpart}, {hd}, {dd}, {proof_ctx}, {proof_valid}, {rtype})")]
    Env {
        size: Int,
        pubpart: PubPart,
        hd: Int,
        dd: Int,
        proof_ctx: NN,
        proof_valid: Bool,
        rtype: RType,
    },
}

/// EN-009: the decoded layout block.
#[k::constructors(sort = Layout, result = KResult)]
pub enum LayoutC {
    #[k::syntax("layout({body_0}, {bodies}, {capsules})")]
    Lay { body_0: Int, bodies: List<Int>, capsules: List<Int> },
}

/// A committee slot `ℓ(g, j)` as `(g, j, ℓ)`.
#[k::constructors(sort = Slot, result = KResult)]
pub enum SlotC {
    #[k::syntax("slot({g}, {j}, {l})")]
    SlotOf { g: Int, j: Int, l: Int },
}

/// An opened header, as far as EN-009 to EN-013 read it.
#[k::constructors(sort = Header, result = KResult)]
pub enum HeaderC {
    #[k::syntax(
        "header({suite}, {kk}, {ll}, {tickets}, {slots}, {r_a}, {r_ecdsa}, {pairs}, {layout}, {n_capsules}, {region_outside}, {length_mismatch}, {has_ic}, {has_r_tkc}, {tkc}, {auth_tkc}, {recompute_mismatch})"
    )]
    Hdr {
        suite: Suite,
        kk: Int,
        ll: Int,
        tickets: Int,
        slots: List<Slot>,
        r_a: List<Int>,
        r_ecdsa: List<Int>,
        pairs: List<Int>,
        layout: Layout,
        n_capsules: Int,
        region_outside: Bool,
        length_mismatch: Bool,
        has_ic: Bool,
        has_r_tkc: Bool,
        tkc: Int,
        auth_tkc: Int,
        recompute_mismatch: Bool,
    },
}

/// A PRF partial of one label (EN-014).
#[k::constructors(sort = Partial, result = KResult)]
pub enum PartialC {
    #[k::syntax("partial({sender}, {proof_ok})")]
    Part { sender: Int, proof_ok: Bool },
}

/// The refusal codes, in code order.
#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("bad_epoch")] BadEpoch,
    #[k::syntax("bad_proof")] BadProof,
    #[k::syntax("bad_shape")] BadShape,
    #[k::syntax("dd_reused")] DdReused,
    #[k::syntax("exp_c_not_below_exp")] ExpCNotBelowExp,
    #[k::syntax("expired")] Expired,
    #[k::syntax("noRule")] NoRule,
    #[k::syntax("outsideCapability")] OutsideCapability,
}

#[k::constructors(sort = Fault, result = KResult)]
#[rustfmt::skip]
pub enum FaultC {
    #[k::syntax("en009")] En009,
    #[k::syntax("en010")] En010,
    #[k::syntax("en011")] En011,
    #[k::syntax("en012")] En012,
    #[k::syntax("en013")] En013,
}

#[k::constructors(sort = Combine, result = KResult)]
#[rustfmt::skip]
pub enum CombineC {
    #[k::syntax("opened")] Opened,
    #[k::syntax("need_more")] NeedMore,
    #[k::syntax("dealer_fault")] DealerFault,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("submit({e})")] Submit { e: Envelope },
    #[k::syntax("tick({h})")] Tick { h: Int },
    #[k::syntax("setEpochs({es})")] SetEpochs { es: List<NN> },
    /// EN-023 again for the ordering block: the envelope with `exp` would be ordered at height `b`.
    #[k::syntax("orderCheck({exp}, {b})")] OrderCheck { exp: Int, b: Int },
    #[k::syntax("header({hdr})")] HeaderOp { hdr: Header },
    #[k::syntax("combine({t}, {dealing_ok}, {partials})")]
    CombineOp { t: Int, dealing_ok: Bool, partials: List<Partial> },
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("accepted({eid})")] Accepted { eid: NN },
    #[k::syntax("refused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("ok")] Ok,
    #[k::syntax("faults({fs})")] Faults { fs: List<Fault> },
    #[k::syntax("combined({c})")] Combined { c: Combine },
}

// ---------------------------------------------------------------------------
// Shared list helpers (Lean `nodupB`, `List.map`, `List.drop`, `List.take`).

/// `nodupB`: no element occurs twice.
#[k::function(total, internal)]
pub fn NodupB(xs: k::Term<List>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => !list::contains(x, rest) && NodupB(rest),
    }
}

/// `es.map (·.1)`: the epochs of the current epoch list.
#[k::function(total, internal)]
pub fn Firsts(es: k::Term<List<NN>>) -> k::Term<List<Int>> {
    match es {
        [] => [],
        [Pair::P { a, .. }, rest @ ..] => [a, ..Firsts(rest)],
    }
}

/// `ps.map (·.sender)`.
#[k::function(total, internal)]
pub fn Senders(ps: k::Term<List<Partial>>) -> k::Term<List<Int>> {
    match ps {
        [] => [],
        [PartialC::Part { sender, .. }, rest @ ..] => [sender, ..Senders(rest)],
    }
}

/// `h.slots.map (·.2.2)`: the slot indices `ℓ`.
#[k::function(total, internal)]
pub fn Ells(xs: k::Term<List<Slot>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [SlotC::SlotOf { l, .. }, rest @ ..] => [l, ..Ells(rest)],
    }
}

/// `List.drop n xs`.
#[k::function(total, internal)]
pub fn DropN(n: k::Term<Int>, xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [_x, rest @ ..] if n > 0 => DropN(n - 1, rest),
        [x, rest @ ..] if n <= 0 => [x, ..rest],
    }
}

/// `xs.any (· != 0)`.
#[k::function(total, internal)]
pub fn AnyNonzero(xs: k::Term<List<Int>>) -> k::Term<Bool> {
    match xs {
        [] => false,
        [x, rest @ ..] => if x == 0 { AnyNonzero(rest) } else { true },
    }
}

// ---------------------------------------------------------------------------
// Public checks before order (EN-004 to EN-008).

/// EN-004: the frame size (16384), `version` (1) and `size_class` (0).
#[k::function(total, internal)]
pub fn BadShapeOf(e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env { size, pubpart: PubPartC::Pub { version, size_class, .. }, .. } => {
            size != 16384 || version != 1 || size_class != 0
        }
    }
}

/// EN-005: `epoch` is a current epoch and `keylist_hash` the hash of its key list.
#[k::function(total, internal)]
pub fn BadEpochOf(epochs: k::Term<List<NN>>, e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { epoch, keylist_hash, .. }, .. } => {
            !list::contains(Pair::P { a: epoch, b: keylist_hash }, epochs)
        }
    }
}

/// EN-006: the board height is above `exp`.
#[k::function(total, internal)]
pub fn ExpiredOf(height: k::Term<Int>, e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { exp, .. }, .. } => exp < height,
    }
}

/// EN-007: `π` verifies for `eid = H(hd ‖ auth_ref)`.
#[k::function(total, internal)]
pub fn BadProofOf(e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env {
            pubpart: PubPartC::Pub { auth_ref, .. },
            hd,
            proof_ctx,
            proof_valid,
            ..
        } => proof_ctx.ne::<K>(Pair::P { a: hd, b: auth_ref }) || !proof_valid,
    }
}

/// EN-008: an earlier accepted envelope of the same epoch has this `dd`.
#[k::function(total, internal)]
pub fn DdReusedOf(seen: k::Term<List<NN>>, e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { epoch, .. }, dd, .. } => {
            list::contains(Pair::P { a: epoch, b: dd }, seen)
        }
    }
}

/// EN-021: `exp_c = b + Δ_c` lies below `exp` (`windowInsideExpiry`).
#[k::function(total, internal)]
pub fn WindowInside(b: k::Term<Int>, delta_c: k::Term<Int>, exp: k::Term<Int>) -> k::Term<Bool> {
    b + delta_c < exp
}

/// EN-023 at acceptance (ledger 10): the earliest block that can order the envelope is
/// the next one, `b = height + 1`; the window must lie inside the expiry (`windowBad`).
#[k::function(total, internal)]
pub fn WindowBadOf(height: k::Term<Int>, delta_c: k::Term<Int>, e: k::Term<Envelope>) -> k::Term<Bool> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { exp, .. }, .. } => !WindowInside(height + 1, delta_c, exp),
    }
}

/// EN-023 refusal code.
#[k::function(total, internal)]
pub fn WindowCode(height: k::Term<Int>, delta_c: k::Term<Int>, e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if WindowBadOf(height, delta_c, e) { [RefusalC::ExpCNotBelowExp] } else { [] }
}

/// EN-005 refusal code.
#[k::function(total, internal)]
pub fn EpochCode(epochs: k::Term<List<NN>>, e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if BadEpochOf(epochs, e) { [RefusalC::BadEpoch] } else { [] }
}

/// EN-007 refusal code.
#[k::function(total, internal)]
pub fn ProofCode(e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if BadProofOf(e) { [RefusalC::BadProof] } else { [] }
}

/// EN-004 refusal code.
#[k::function(total, internal)]
pub fn ShapeCode(e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if BadShapeOf(e) { [RefusalC::BadShape] } else { [] }
}

/// EN-008 refusal code.
#[k::function(total, internal)]
pub fn DdCode(seen: k::Term<List<NN>>, e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if DdReusedOf(seen, e) { [RefusalC::DdReused] } else { [] }
}

/// EN-006 refusal code.
#[k::function(total, internal)]
pub fn ExpiredCode(height: k::Term<Int>, e: k::Term<Envelope>) -> k::Term<List<Refusal>> {
    if ExpiredOf(height, e) { [RefusalC::Expired] } else { [] }
}

/// `publicRefusals`: EN-004 to EN-008 and EN-023, in code order.
#[k::function(total, internal)]
pub fn PublicRefusals(
    epochs: k::Term<List<NN>>,
    height: k::Term<Int>,
    delta_c: k::Term<Int>,
    seen: k::Term<List<NN>>,
    e: k::Term<Envelope>,
) -> k::Term<List<Refusal>> {
    list::concat(
        EpochCode(epochs, e),
        list::concat(
            ProofCode(e),
            list::concat(
                ShapeCode(e),
                list::concat(DdCode(seen, e), list::concat(WindowCode(height, delta_c, e), ExpiredCode(height, e))),
            ),
        ),
    )
}

/// EN-003: `eid = H(hd ‖ auth_ref)`.
#[k::function(total, internal)]
pub fn EidOf(e: k::Term<Envelope>) -> k::Term<NN> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { auth_ref, .. }, hd, .. } => Pair::P { a: hd, b: auth_ref },
    }
}

/// EN-008: `(epoch, dd)` of an accepted envelope.
#[k::function(total, internal)]
pub fn SeenOf(e: k::Term<Envelope>) -> k::Term<NN> {
    match e {
        EnvelopeC::Env { pubpart: PubPartC::Pub { epoch, .. }, dd, .. } => Pair::P { a: epoch, b: dd },
    }
}

// ---------------------------------------------------------------------------
// Header checks after order (EN-009 to EN-013).

/// `Suite.schnorr`.
#[k::function(total, internal)]
pub fn Schnorr(s: k::Term<Suite>) -> k::Term<Bool> {
    match s {
        SuiteC::Ecdsa => false,
        _ => true,
    }
}

/// RQ-001, RQ-067: `G = min(K, G_max)` with `G_max = 2`.
#[k::function(total, internal)]
pub fn GOf(kk: k::Term<Int>) -> k::Term<Int> {
    int::min(kk, 2)
}

/// `Σ_{v=1..i} min(v, g)`.
#[k::function(total, internal)]
pub fn SumMin(i: k::Term<Int>, g: k::Term<Int>) -> k::Term<Int> {
    if i <= 0 { 0 } else { int::min(i, g) + SumMin(i - 1, g) }
}

/// EN-016: the number of variant bodies, `(bodyLabels suite K).length`:
/// `Σ_{v=1..K} min(v, G)` on Schnorr suites, `K` on ECDSA.
#[k::function(total, internal)]
pub fn BodyCount(suite: k::Term<Suite>, kk: k::Term<Int>) -> k::Term<Int> {
    if Schnorr(suite) { SumMin(kk, GOf(kk)) } else { kk }
}

/// EN-010: `N_h = L·Σ_{v=1..K} min(v, G)` on Schnorr suites, `K·L` on ECDSA.
#[k::function(total, internal)]
pub fn TicketCount(suite: k::Term<Suite>, kk: k::Term<Int>, ll: k::Term<Int>) -> k::Term<Int> {
    if Schnorr(suite) { ll * SumMin(kk, GOf(kk)) } else { kk * ll }
}

/// Some slot has grid cell `(g, j)`.
#[k::function(total, internal)]
pub fn HasCell(g: k::Term<Int>, j: k::Term<Int>, slots: k::Term<List<Slot>>) -> k::Term<Bool> {
    match slots {
        [] => false,
        [SlotC::SlotOf { g: sg, j: sj, .. }, rest @ ..] => (sg == g && sj == j) || HasCell(g, j, rest),
    }
}

/// Every `(g, j')` with `1 ≤ j' ≤ j` is some slot's cell.
#[k::function(total, internal)]
pub fn GridRow(g: k::Term<Int>, j: k::Term<Int>, slots: k::Term<List<Slot>>) -> k::Term<Bool> {
    // Branches, not `&&`: see LayoutBad (short-circuit-reading).
    if j <= 0 { true } else if HasCell(g, j, slots) { GridRow(g, j - 1, slots) } else { false }
}

/// EN-010: every grid cell `(g', j)` with `1 ≤ g' ≤ g`, `1 ≤ j ≤ l` is some slot's cell.
#[k::function(total, internal)]
pub fn GridAll(g: k::Term<Int>, l: k::Term<Int>, slots: k::Term<List<Slot>>) -> k::Term<Bool> {
    if g <= 0 { true } else if GridRow(g, l, slots) { GridAll(g - 1, l, slots) } else { false }
}

/// EN-009: a nonzero unused entry, a region outside the frame or over the
/// capsules, or a length that disagrees with the header.
#[k::function(total, internal)]
pub fn LayoutBad(h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr {
            suite,
            kk,
            layout: LayoutC::Lay { bodies, capsules, .. },
            n_capsules,
            region_outside,
            length_mismatch,
            ..
        } => {
            // Branches, not `||`: a short-circuit over the list checks would make kink
            // read the definedness of a skipped operand (short-circuit-reading).
            if AnyNonzero(DropN(BodyCount(suite, kk), bodies)) {
                true
            } else if AnyNonzero(DropN(n_capsules, capsules)) {
                true
            } else {
                region_outside || length_mismatch
            }
        }
    }
}

/// EN-010: the ticket count, and on Schnorr suites exactly `G·L` slots covering the grid.
#[k::function(total, internal)]
pub fn CountBad(h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr { suite, kk, ll, tickets, slots, .. } => {
            tickets != TicketCount(suite, kk, ll)
                || (Schnorr(suite)
                    && (list::size(slots) != GOf(kk) * ll || !GridAll(GOf(kk), ll, slots)))
        }
    }
}

/// EN-011: a repeated `R_A`, ECDSA `R_ℓ` or committee slot, or in TEE mode a
/// repeated actor pool pair.
#[k::function(total, internal)]
pub fn DistinctBad(m: k::Term<Mode>, h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr { r_a, r_ecdsa, slots, pairs, .. } => {
            !NodupB(r_a)
                || !NodupB(r_ecdsa)
                || !NodupB(Ells(slots))
                || (m.eq::<K>(ModeC::Tee) && !NodupB(pairs))
        }
    }
}

/// EN-012: `ic` and `r_tkc` present. The check is structural only (DECISIONS 68): the
/// match of `tkc` with the one `auth` commits is RQ-025's admission check, so `tkc` and
/// `auth_tkc` take no part here.
#[k::function(total, internal)]
pub fn CommitBad(h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr { has_ic, has_r_tkc, .. } => !has_ic || !has_r_tkc,
    }
}

/// EN-013: in TEE mode, a recomputed field differs from a ticket's own.
#[k::function(total, internal)]
pub fn RecomputeBad(m: k::Term<Mode>, h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr { recompute_mismatch, .. } => m.eq::<K>(ModeC::Tee) && recompute_mismatch,
    }
}

#[k::function(total, internal)]
pub fn F009(h: k::Term<Header>) -> k::Term<List<Fault>> {
    if LayoutBad(h) { [FaultC::En009] } else { [] }
}

#[k::function(total, internal)]
pub fn F010(h: k::Term<Header>) -> k::Term<List<Fault>> {
    if CountBad(h) { [FaultC::En010] } else { [] }
}

#[k::function(total, internal)]
pub fn F011(m: k::Term<Mode>, h: k::Term<Header>) -> k::Term<List<Fault>> {
    if DistinctBad(m, h) { [FaultC::En011] } else { [] }
}

#[k::function(total, internal)]
pub fn F012(h: k::Term<Header>) -> k::Term<List<Fault>> {
    if CommitBad(h) { [FaultC::En012] } else { [] }
}

#[k::function(total, internal)]
pub fn F013(m: k::Term<Mode>, h: k::Term<Header>) -> k::Term<List<Fault>> {
    if RecomputeBad(m, h) { [FaultC::En013] } else { [] }
}

/// `headerFaults`: the requirements a header fails, EN-009 to EN-013 in order.
#[k::function(total, internal)]
pub fn HeaderFaults(m: k::Term<Mode>, h: k::Term<Header>) -> k::Term<List<Fault>> {
    list::concat(F009(h), list::concat(F010(h), list::concat(F011(m, h), list::concat(F012(h), F013(m, h)))))
}

/// `headerInDomain`: `K ∈ 1..8`, `L ∈ 1..2`, 15 body and 8 capsule regions,
/// at most 8 capsules (RQ-067, EN-009; ledger 5).
#[k::function(total, internal)]
pub fn HeaderInDomain(h: k::Term<Header>) -> k::Term<Bool> {
    match h {
        HeaderC::Hdr { kk, ll, layout: LayoutC::Lay { bodies, capsules, .. }, n_capsules, .. } => {
            1 <= kk
                && kk <= 8
                && 1 <= ll
                && ll <= 2
                && list::size(bodies) == 15
                && list::size(capsules) == 8
                && n_capsules <= 8
        }
    }
}

// ---------------------------------------------------------------------------
// PRF combination with the proof fallback (EN-014, RQ-015).

/// `ps.all (·.proofOk)`.
#[k::function(total, internal)]
pub fn AllProved(ps: k::Term<List<Partial>>) -> k::Term<Bool> {
    match ps {
        [] => true,
        [PartialC::Part { proof_ok, .. }, rest @ ..] => proof_ok && AllProved(rest),
    }
}

/// `ps.filter (·.proofOk)`.
#[k::function(total, internal)]
pub fn Proved(ps: k::Term<List<Partial>>) -> k::Term<List<Partial>> {
    match ps {
        [] => [],
        [p @ PartialC::Part { proof_ok: true, .. }, rest @ ..] => [p, ..Proved(rest)],
        [PartialC::Part { proof_ok: false, .. }, rest @ ..] => Proved(rest),
    }
}

/// `List.take t ps`.
#[k::function(total, internal)]
pub fn TakeN(t: k::Term<Int>, ps: k::Term<List<Partial>>) -> k::Term<List<Partial>> {
    match ps {
        [] => [],
        [p, rest @ ..] if t > 0 => [p, ..TakeN(t - 1, rest)],
        [_p, ..] if t <= 0 => [],
    }
}

/// `tagOpens`: `t` partials open the tag exactly when the dealing is good and
/// every one of them is correct.
#[k::function(total, internal)]
pub fn TagOpens(dealing_ok: k::Term<Bool>, ps: k::Term<List<Partial>>) -> k::Term<Bool> {
    dealing_ok && AllProved(ps)
}

/// EN-014, second round: the first `t` proved partials.
#[k::function(total, internal)]
pub fn CombineProved(t: k::Term<Int>, dealing_ok: k::Term<Bool>, proved: k::Term<List<Partial>>) -> k::Term<Combine> {
    if list::size(proved) < t {
        CombineC::NeedMore
    } else if TagOpens(dealing_ok, TakeN(t, proved)) {
        CombineC::Opened
    } else {
        CombineC::DealerFault
    }
}

/// EN-014: combine the first `t` partials; if the tag fails, drop each partial
/// whose proof fails and combine the first `t` proved partials again.
#[k::function(total, internal)]
pub fn CombineOf(t: k::Term<Int>, dealing_ok: k::Term<Bool>, ps: k::Term<List<Partial>>) -> k::Term<Combine> {
    if list::size(ps) < t {
        CombineC::NeedMore
    } else if TagOpens(dealing_ok, TakeN(t, ps)) {
        CombineC::Opened
    } else {
        CombineProved(t, dealing_ok, Proved(ps))
    }
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
    pub epochs: List<NN>,
    #[k::cell]
    pub seen: List<NN>,
    #[k::cell]
    pub accepted: List<NN>,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: no envelope seen or accepted yet.
    #[k::init]
    pub fn init(params: Params, height: Int, epochs: List<NN>, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            height,
            epochs,
            seen: [],
            accepted: [],
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // EN-004 to EN-008 and EN-023 pass, EN-003: the node accepts the envelope; `(epoch, dd)`
    // and `eid` go first in `seen` and `accepted` (newest first).
    #[k::requires(list::size(PublicRefusals(epochs, height, delta_c, seen, e)) == 0)]
    submit_accept: {
        k: [Step::Go, ..],
        params: ParamsC::Params { delta_c, .. },
        epochs,
        height,
        seen,
        accepted,
        ops: [OpC::Submit { e }, ..],
        obs,
    } => {
        seen: [SeenOf(e), ..seen],
        accepted: [EidOf(e), ..accepted],
        ops: [..],
        obs: [..obs, ObsC::Accepted { eid: EidOf(e) }],
    };

    // EN-004 to EN-008, EN-023: a failed public check refuses the envelope with every
    // failed check's code, in code order; the state is unchanged.
    #[k::requires(list::size(PublicRefusals(epochs, height, delta_c, seen, e)) != 0)]
    submit_refuse: {
        k: [Step::Go, ..],
        params: ParamsC::Params { delta_c, .. },
        epochs,
        height,
        seen,
        ops: [OpC::Submit { e }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: PublicRefusals(epochs, height, delta_c, seen, e) }],
    };

    // EN-006: the board reaches height `h`.
    #[k::requires(h >= height)]
    tick: {
        k: [Step::Go, ..],
        height,
        ops: [OpC::Tick { h }, ..],
        obs,
    } => {
        height: h,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 4: the board height never goes down; no requirement defines it.
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

    // EN-005: the current epochs and their key-list hashes.
    #[k::requires(NodupB(Firsts(es)))]
    set_epochs: {
        k: [Step::Go, ..],
        epochs: _,
        ops: [OpC::SetEpochs { es }, ..],
        obs,
    } => {
        epochs: es,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 5: an epoch listed twice is outside the capability.
    #[k::requires(!NodupB(Firsts(es)))]
    set_epochs_dup: {
        k: [Step::Go, ..],
        ops: [OpC::SetEpochs { es }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // EN-023 for the ordering block `b`: `exp_c = b + Δ_c` lies below `exp`; the check
    // keeps no state.
    #[k::requires(WindowInside(b, delta_c, exp))]
    order_check: {
        k: [Step::Go, ..],
        params: ParamsC::Params { delta_c, .. },
        ops: [OpC::OrderCheck { exp, b }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // EN-023: `b + Δ_c ≥ exp` is refused with `exp_c_not_below_exp`; the state is unchanged.
    #[k::requires(!WindowInside(b, delta_c, exp))]
    order_check_refused: {
        k: [Step::Go, ..],
        params: ParamsC::Params { delta_c, .. },
        ops: [OpC::OrderCheck { exp, b }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::ExpCNotBelowExp] }],
    };

    // EN-009 to EN-013: the header checks keep no state.
    #[k::requires(HeaderInDomain(hdr))]
    header: {
        k: [Step::Go, ..],
        params: ParamsC::Params { mode, .. },
        ops: [OpC::HeaderOp { hdr }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Faults { fs: HeaderFaults(mode, hdr) }],
    };

    // Ledger 5: a header outside `K ∈ 1..8`, `L ∈ 1..2` or the layout domain.
    #[k::requires(!HeaderInDomain(hdr))]
    header_outside: {
        k: [Step::Go, ..],
        ops: [OpC::HeaderOp { hdr }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // EN-014, RQ-015: the combination keeps no state.
    #[k::requires(!(t == 0 || !NodupB(Senders(partials))))]
    combine: {
        k: [Step::Go, ..],
        ops: [OpC::CombineOp { t, dealing_ok, partials }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Combined { c: CombineOf(t, dealing_ok, partials) }],
    };

    // Ledger 5: `t = 0` or a sender twice is outside the capability.
    #[k::requires(t == 0 || !NodupB(Senders(partials)))]
    combine_outside: {
        k: [Step::Go, ..],
        ops: [OpC::CombineOp { t, partials, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
