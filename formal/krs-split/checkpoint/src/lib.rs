//! Split checkpoint reference definition in KRS, ported from the Lean oracle
//! `formal/lean-split/checkpoint/SplitCheckpoint/Spec.lean` (`apply`, `runOps`).
//!
//! One rule per behaviour of `apply`: each operation either passes `opRefusals`
//! and runs `exec`, or is refused with the codes in code order and leaves the
//! state unchanged. The checks are functions with one equation per branch, so
//! each branch and each condition operand is a coverage obligation and a
//! mutation target. Requirement IDs refer to
//! `openspec/changes/add-split-line-dealing/specs/split-checkpoint/spec.md`.
//!
//! Cells are the oracle's `St` fields and its observation list `obs`; `ops`
//! holds the operations still to run and is empty at every end (FLOW.toml
//! omits it). The cell `burn` is the oracle's `burnC`, `accounts` its `accts`.

use k::{KItem, KResult};
use k::builtin::{Bool, Int, KSequence, List, int, list};

k::sorts! {
    Run: KItem;
    Mode;
    Outcome;
    NN;
    Params;
    Pool;
    Restore;
    Leaf;
    Entry;
    SeatRoot;
    Cp;
    ASlot;
    Acct;
    Write;
    Range;
    Session;
    Cov;
    RSlot;
    Refusal;
    Op;
    Obs;
}

#[k::constructors(sort = Run, result = KResult)]
pub enum Step {
    #[k::syntax("#run")]
    Go,
    /// `landNode s c`: the node's part of a landing (CP-025, CP-027).
    #[k::syntax("#landNode({c})")]
    LandNode { c: Cp },
    /// `readLedger s c tk cov` on the latest landed checkpoint (CP-018).
    #[k::syntax("#readNode({tk}, {cov})")]
    ReadNode { tk: List<NN>, cov: List<Cov> },
}

#[k::constructors(sort = Mode, result = KResult)]
#[rustfmt::skip]
pub enum ModeC {
    #[k::syntax("TEE")] Tee,
    #[k::syntax("NON_TEE")] NonTee,
}

#[k::constructors(sort = Outcome, result = KResult)]
#[rustfmt::skip]
pub enum OutcomeC {
    #[k::syntax("FINAL")] Final,
    #[k::syntax("VOID")] Void,
    #[k::syntax("RELEASED")] Released,
}

/// A pair of naturals: `(seat, boot counter)`, `(auth, nf)`, `(seat, slot)`.
#[k::constructors(sort = NN, result = KResult)]
pub enum Pair {
    #[k::syntax("pr({a}, {b})")]
    P { a: Int, b: Int },
}

/// RQ-001, SL-012, CP-034: `n`, `f`, the mode, the window `B`, slot anchors, `Δ_rec`.
#[k::constructors(sort = Params, result = KResult)]
pub enum ParamsC {
    #[k::syntax("params({n}, {f}, {mode}, {bb}, {slot_anchor}, {d_rec})")]
    Params { n: Int, f: Int, mode: Mode, bb: Int, slot_anchor: Bool, d_rec: Int },
}

/// CP-002: the fields of one committee pool of a checkpoint.
#[k::constructors(sort = Pool, result = KResult)]
pub enum PoolC {
    #[k::syntax("pool({pool}, {h}, {pending_min}, {pending}, {pending_count})")]
    PoolOf { pool: Int, h: Int, pending_min: Int, pending: List<Int>, pending_count: Int },
}

/// CP-016: `RestoreDone(committee, node_index, boot_ctr, cp.seq, whole_restart)`.
/// `seat` is the node index (JSON `node_index`, DECISIONS 69 item 8).
#[k::constructors(sort = Restore, result = KResult)]
pub enum RestoreC {
    #[k::syntax("rd({seat}, {boot_ctr}, {cp_seq}, {whole})")]
    Rd { seat: Int, boot_ctr: Int, cp_seq: Int, whole: Bool },
}

/// A `settle_root` leaf `(auth, outcome)`.
#[k::constructors(sort = Leaf, result = KResult)]
pub enum LeafC {
    #[k::syntax("lf({auth}, {out})")]
    Lf { auth: Int, out: Outcome },
}

/// CP-015, CP-016: seat-log entries; a binding entry is `(nf, e)`, the slot nullifier
/// and the hidden digest (DECISIONS 69 item 1).
#[k::constructors(sort = Entry, result = KResult)]
#[rustfmt::skip]
pub enum EntryC {
    #[k::syntax("bind({nf}, {e})")] Bind { nf: Int, e: Int },
    #[k::syntax("put({digest})")] Put { digest: Int },
    #[k::syntax("restoreEntry({r})")] RestoreE { r: Restore },
    #[k::syntax("releaseEntry({eid}, {g})")] ReleaseE { eid: Int, g: Int },
}

#[k::constructors(sort = SeatRoot, result = KResult)]
pub enum SeatRootC {
    #[k::syntax("sr({seat}, {log})")]
    Sr { seat: Int, log: List<Entry> },
}

/// CP-001: the fields of a checkpoint.
#[k::constructors(sort = Cp, result = KResult)]
pub enum CpC {
    #[k::syntax(
        "cp({seq}, {epoch}, {board_height}, {board_root}, {witness_root}, {pools}, {settle}, {bf}, {boot_counters}, {restart_seq}, {seat_roots}, {restores})"
    )]
    CpOf {
        seq: Int,
        epoch: Int,
        board_height: Int,
        board_root: Int,
        witness_root: Int,
        pools: List<Pool>,
        settle: List<Leaf>,
        bf: List<NN>,
        boot_counters: List<NN>,
        restart_seq: Int,
        seat_roots: List<SeatRoot>,
        restores: List<Restore>,
    },
}

/// An account-pool slot as a node holds it.
#[k::constructors(sort = ASlot, result = KResult)]
#[rustfmt::skip]
pub enum ASlotC {
    #[k::syntax("free")] Free,
    #[k::syntax("burnedSlot")] Burned,
    #[k::syntax("bound({d})")] Bound { d: Int },
}

#[k::constructors(sort = Acct, result = KResult)]
pub enum AcctC {
    #[k::syntax("acct({id}, {slots}, {mark}, {refill})")]
    AcctOf { id: Int, slots: List<ASlot>, mark: Int, refill: Bool },
}

#[k::constructors(sort = Write, result = KResult)]
#[rustfmt::skip]
pub enum WriteC {
    #[k::syntax("wCheckpoint")] WCheckpoint,
    #[k::syntax("wEvent")] WEvent,
    #[k::syntax("wEks({e})")] WEks { e: Int },
}

/// A committee-pool burn range `(pool, lo, hi)`, both ends included.
#[k::constructors(sort = Range, result = KResult)]
pub enum RangeC {
    #[k::syntax("rg({pool}, {lo}, {hi})")]
    Rg { pool: Int, lo: Int, hi: Int },
}

#[k::constructors(sort = Session, result = KResult)]
pub enum SessionC {
    #[k::syntax("sess({pool}, {burned})")]
    Sess { pool: Int, burned: List<Range> },
}

/// A covered binding `(account, slot, digest)` (CP-029).
#[k::constructors(sort = Cov, result = KResult)]
pub enum CovC {
    #[k::syntax("cov({account}, {slot}, {d})")]
    CovOf { account: Int, slot: Int, d: Int },
}

/// CP-031: `(seat, slot, covered binding, seat log read in full)`.
#[k::constructors(sort = RSlot, result = KResult)]
pub enum RSlotC {
    #[k::syntax("rslot({seat}, {slot}, {covered}, {log_read})")]
    RSlotOf { seat: Int, slot: Int, covered: Bool, log_read: Bool },
}

/// The refusal codes, in code order.
#[k::constructors(sort = Refusal, result = KResult)]
#[rustfmt::skip]
pub enum RefusalC {
    #[k::syntax("belowFloor")] BelowFloor,
    #[k::syntax("hLowered")] HLowered,
    #[k::syntax("ledgerUnverified")] LedgerUnverified,
    #[k::syntax("noRule")] NoRule,
    #[k::syntax("noRestoreStatement")] NoRestoreStatement,
    #[k::syntax("outsideCapability")] OutsideCapability,
    #[k::syntax("pendingGap")] PendingGap,
    #[k::syntax("pendingMinLowered")] PendingMinLowered,
    #[k::syntax("recoveryEarly")] RecoveryEarly,
    #[k::syntax("restartJump")] RestartJump,
}

#[k::constructors(sort = Op, result = KResult)]
#[rustfmt::skip]
pub enum OpC {
    #[k::syntax("land({c}, {mh})")] Land { c: Cp, mh: Int },
    #[k::syntax("boot")] Boot,
    #[k::syntax("readLedger({ok}, {tickets}, {cov})")]
    ReadLedger { ok: Bool, tickets: List<NN>, cov: List<Cov> },
    #[k::syntax("openSession({pool})")] OpenSession { pool: Int },
    #[k::syntax("openAcct({a})")] OpenAcct { a: Acct },
    #[k::syntax("bindAcct({aid}, {i}, {d})")] BindAcct { aid: Int, i: Int, d: Int },
    #[k::syntax("restoreDone({r})")] RestoreDone { r: Restore },
    #[k::syntax("recover({mh})")] Recover { mh: Int },
    #[k::syntax("coldStart({intact}, {signers})")] ColdStart { intact: Int, signers: Int },
    #[k::syntax("eks({e}, {acks}, {sigs})")] Eks { e: Int, acks: List<Int>, sigs: Int },
    #[k::syntax("nonTeeRestart")] NonTeeRestart,
    #[k::syntax("signBf({leaves})")] SignBf { leaves: List<NN> },
    #[k::syntax("signSettle({leaves}, {ended}, {mv})")]
    SignSettle { leaves: List<Leaf>, ended: List<Leaf>, mv: List<Int> },
    #[k::syntax("signPending({p}, {live})")] SignPending { p: Pool, live: List<Int> },
    #[k::syntax("signSeatRoot({log})")] SignSeatRoot { log: List<Entry> },
    #[k::syntax("orderReq({order_h}, {peers}, {proof})")]
    OrderReq { order_h: Int, peers: List<Int>, proof: Bool },
    #[k::syntax("coveredQ({h})")] CoveredQ { h: Int },
    #[k::syntax("releaseAnchor({anchor}, {entry_h})")] ReleaseAnchor { anchor: Bool, entry_h: Int },
    #[k::syntax("reshare({slots})")] Reshare { slots: List<RSlot> },
    #[k::syntax("due({last}, {now})")] Due { last: Int, now: Int },
    #[k::syntax("mayReboot")] MayReboot,
    #[k::syntax("loseTail")] LoseTail,
}

#[k::constructors(sort = Obs, result = KResult)]
#[rustfmt::skip]
pub enum ObsC {
    #[k::syntax("ok")] Ok,
    #[k::syntax("refused({codes})")] Refused { codes: List<Refusal> },
    #[k::syntax("answer({b})")] BoolObs { b: Bool },
    #[k::syntax("reshared({xs})")] SlotsObs { xs: List<NN> },
}

// ---------------------------------------------------------------------------
// Parameters (RQ-001).

/// `w = n − 1 − f`.
#[k::function(total, internal)]
pub fn WOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { n, f, .. } => n - 1 - f,
    }
}

/// `t = n − f`.
#[k::function(total, internal)]
pub fn TOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { n, f, .. } => n - f,
    }
}

/// `q = ⌈(n + f + 1)/2⌉ = (n + f + 2) / 2`.
#[k::function(total, internal)]
pub fn QOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { n, f, .. } => (n + f + 2) / 2,
    }
}

#[k::function(total, internal)]
pub fn NOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { n, .. } => n,
    }
}

#[k::function(total, internal)]
pub fn BOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { bb, .. } => bb,
    }
}

#[k::function(total, internal)]
pub fn AnchorOf(p: k::Term<Params>) -> k::Term<Bool> {
    match p {
        ParamsC::Params { slot_anchor, .. } => slot_anchor,
    }
}

#[k::function(total, internal)]
pub fn NonTeeOf(p: k::Term<Params>) -> k::Term<Bool> {
    match p {
        ParamsC::Params { mode, .. } => mode.eq::<K>(ModeC::NonTee),
    }
}

#[k::function(total, internal)]
pub fn DRecOf(p: k::Term<Params>) -> k::Term<Int> {
    match p {
        ParamsC::Params { d_rec, .. } => d_rec,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (Lean `opt`, `lookup`, `nodupB`).

/// `opt b r`: the code `r` when `b` holds.
#[k::function(total, internal)]
pub fn Opt(b: k::Term<Bool>, r: k::Term<Refusal>) -> k::Term<List<Refusal>> {
    if b { [r] } else { [] }
}

/// `nodupB`: no element occurs twice.
#[k::function(total, internal)]
pub fn NodupB(xs: k::Term<List>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => {
            if list::contains(x, rest) { false } else { NodupB(rest) }
        }
    }
}

/// `lookup xs k`: the second part of the first pair with first part `key`, else 0.
#[k::function(total, internal)]
pub fn Lookup(xs: k::Term<List<NN>>, key: k::Term<Int>) -> k::Term<Int> {
    match xs {
        [] => 0,
        [Pair::P { a, b }, rest @ ..] => {
            if a == key { b } else { Lookup(rest, key) }
        }
    }
}

/// `xs.map (·.1)`.
#[k::function(total, internal)]
pub fn Firsts(xs: k::Term<List<NN>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [Pair::P { a, .. }, rest @ ..] => [a, ..Firsts(rest)],
    }
}

/// `xs.map (·.2)`.
#[k::function(total, internal)]
pub fn Seconds(xs: k::Term<List<NN>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [Pair::P { b, .. }, rest @ ..] => [b, ..Seconds(rest)],
    }
}

/// The seats `s ∈ [from, n)` on which the two counter lists agree (`kept`, `continuous`).
#[k::function(total, internal)]
pub fn CountEq(from: k::Term<Int>, n: k::Term<Int>, xs: k::Term<List<NN>>, ys: k::Term<List<NN>>) -> k::Term<Int> {
    if n <= from { 0 } else { CountAt(from, n, xs, ys) }
}

/// One seat `from < n` of `CountEq`: it counts when the two counters agree.
#[k::function(total, internal)]
pub fn CountAt(from: k::Term<Int>, n: k::Term<Int>, xs: k::Term<List<NN>>, ys: k::Term<List<NN>>) -> k::Term<Int> {
    if Lookup(xs, from) == Lookup(ys, from) { 1 + CountEq(from + 1, n, xs, ys) } else { CountEq(from + 1, n, xs, ys) }
}

// ---------------------------------------------------------------------------
// Checkpoint field access.

#[k::function(total, internal)]
pub fn CpSeq(c: k::Term<Cp>) -> k::Term<Int> {
    match c {
        CpC::CpOf { seq, .. } => seq,
    }
}

#[k::function(total, internal)]
pub fn CpPools(c: k::Term<Cp>) -> k::Term<List<Pool>> {
    match c {
        CpC::CpOf { pools, .. } => pools,
    }
}

#[k::function(total, internal)]
pub fn CpCounters(c: k::Term<Cp>) -> k::Term<List<NN>> {
    match c {
        CpC::CpOf { boot_counters, .. } => boot_counters,
    }
}

#[k::function(total, internal)]
pub fn CpRestores(c: k::Term<Cp>) -> k::Term<List<Restore>> {
    match c {
        CpC::CpOf { restores, .. } => restores,
    }
}

#[k::function(total, internal)]
pub fn CpRestartSeq(c: k::Term<Cp>) -> k::Term<Int> {
    match c {
        CpC::CpOf { restart_seq, .. } => restart_seq,
    }
}

/// `{ c with restartSeq := v }`.
#[k::function(total, internal)]
pub fn WithRestartSeq(c: k::Term<Cp>, v: k::Term<Int>) -> k::Term<Cp> {
    match c {
        CpC::CpOf {
            seq,
            epoch,
            board_height,
            board_root,
            witness_root,
            pools,
            settle,
            bf,
            boot_counters,
            seat_roots,
            restores,
            ..
        } => CpC::CpOf {
            seq,
            epoch,
            board_height,
            board_root,
            witness_root,
            pools,
            settle,
            bf,
            boot_counters,
            restart_seq: v,
            seat_roots,
            restores,
        },
    }
}

/// `latestRestartSeq`: `restart_seq` of the latest landed checkpoint, or 0.
#[k::function(total, internal)]
pub fn LatestRestartSeq(chain: k::Term<List<Cp>>) -> k::Term<Int> {
    match chain {
        [] => 0,
        [c, ..] => CpRestartSeq(c),
    }
}

// ---------------------------------------------------------------------------
// Landing rules of the committee contract (CP-007 to CP-011).

/// `poolOf c1 pid` then `h < p1.h`; false when `c1` has no such pool.
#[k::function(total, internal)]
pub fn BelowPrev(prev: k::Term<List<Pool>>, pid: k::Term<Int>, h: k::Term<Int>) -> k::Term<Bool> {
    match prev {
        [] => false,
        [PoolC::PoolOf { pool, h: h1, .. }, rest @ ..] => {
            if pool == pid { h < h1 } else { BelowPrev(rest, pid, h) }
        }
    }
}

/// CP-007: `h` below the previous `h` for a pool of both checkpoints.
#[k::function(total, internal)]
pub fn Lowered(prev: k::Term<List<Pool>>, pools: k::Term<List<Pool>>) -> k::Term<Bool> {
    match pools {
        [] => false,
        [PoolC::PoolOf { pool, h, .. }, rest @ ..] => {
            if BelowPrev(prev, pool, h) { true } else { Lowered(prev, rest) }
        }
    }
}

/// CP-008: `pending_min > h + 1` for a pool.
#[k::function(total, internal)]
pub fn Gap(pools: k::Term<List<Pool>>) -> k::Term<Bool> {
    match pools {
        [] => false,
        [PoolC::PoolOf { h, pending_min, .. }, rest @ ..] => {
            if h + 1 < pending_min { true } else { Gap(rest) }
        }
    }
}

/// CP-009, for one pool of `c2`: `cp2.h < cp1.h + B` or `cp2.pending_min ≤ cp1.h + B`
/// against the first pool of `c1` with the same id; false when there is none.
#[k::function(total, internal)]
pub fn JumpPool(
    prev: k::Term<List<Pool>>,
    pid: k::Term<Int>,
    h: k::Term<Int>,
    pm: k::Term<Int>,
    bb: k::Term<Int>,
) -> k::Term<Bool> {
    match prev {
        [] => false,
        [PoolC::PoolOf { pool, h: h1, .. }, rest @ ..] => {
            if pool == pid { h < h1 + bb || pm <= h1 + bb } else { JumpPool(rest, pid, h, pm, bb) }
        }
    }
}

#[k::function(total, internal)]
pub fn JumpAny(prev: k::Term<List<Pool>>, pools: k::Term<List<Pool>>, bb: k::Term<Int>) -> k::Term<Bool> {
    match pools {
        [] => false,
        [PoolC::PoolOf { pool, h, pending_min, .. }, rest @ ..] => {
            if JumpPool(prev, pool, h, pending_min, bb) { true } else { JumpAny(prev, rest, bb) }
        }
    }
}

/// CP-009: with `slot_anchor` off, fewer than `w + 1` kept counters and a pool
/// of both whose floor moved by less than `B`.
#[k::function(total, internal)]
pub fn JumpBad(p: k::Term<Params>, c1: k::Term<Cp>, c2: k::Term<Cp>) -> k::Term<Bool> {
    !AnchorOf(p)
        && CountEq(0, NOf(p), CpCounters(c1), CpCounters(c2)) < WOf(p) + 1
        && JumpAny(CpPools(c1), CpPools(c2), BOf(p))
}

/// CP-041 (DECISIONS 69 item 6): with `slot_anchor` off, a `restart_seq` that the
/// contract sets (ledger 4) other than that of `c1`, and no jump (`noJump` is `JumpAny`).
#[k::function(total, internal)]
/// One condition per function (BT-109): the anchor check never skips a reading of
/// `NextRestartSeq`, so a mutation of the CP-011 helpers has a verdict.
pub fn MovedJump(p: k::Term<Params>, chain: k::Term<List<Cp>>, c1: k::Term<Cp>, c2: k::Term<Cp>) -> k::Term<Bool> {
    if AnchorOf(p) { false } else { MovedOff(p, chain, c1, c2) }
}

/// CP-041 with `slot_anchor` off: the contract's `restart_seq` for `c2` differs from
/// that of `c1`, and no jump.
#[k::function(total, internal)]
pub fn MovedOff(p: k::Term<Params>, chain: k::Term<List<Cp>>, c1: k::Term<Cp>, c2: k::Term<Cp>) -> k::Term<Bool> {
    if NextRestartSeq(chain, c2) != CpRestartSeq(c1) { JumpAny(CpPools(c1), CpPools(c2), BOf(p)) } else { false }
}

/// CP-009, CP-041, ledger 1: `jumpBad || movedJump`, one `restart_jump` code for both.
#[k::function(total, internal)]
pub fn JumpCode(p: k::Term<Params>, chain: k::Term<List<Cp>>, c1: k::Term<Cp>, c2: k::Term<Cp>) -> k::Term<Bool> {
    if JumpBad(p, c1, c2) { true } else { MovedJump(p, chain, c1, c2) }
}

/// `poolOf c1 pid` then `pending_min < p1.pending_min`; false when `c1` has no such pool.
#[k::function(total, internal)]
pub fn BelowPrevMin(prev: k::Term<List<Pool>>, pid: k::Term<Int>, pm: k::Term<Int>) -> k::Term<Bool> {
    match prev {
        [] => false,
        [PoolC::PoolOf { pool, pending_min: pm1, .. }, rest @ ..] => {
            if pool == pid { pm < pm1 } else { BelowPrevMin(rest, pid, pm) }
        }
    }
}

/// CP-040 (DECISIONS 69 item 6, ledger 11): `pending_min` below the previous
/// `pending_min` for a pool of both checkpoints.
#[k::function(total, internal)]
pub fn PminLowered(prev: k::Term<List<Pool>>, pools: k::Term<List<Pool>>) -> k::Term<Bool> {
    match pools {
        [] => false,
        [PoolC::PoolOf { pool, pending_min, .. }, rest @ ..] => {
            if BelowPrevMin(prev, pool, pending_min) { true } else { PminLowered(prev, rest) }
        }
    }
}

/// `chain.flatMap (·.restores)`.
#[k::function(total, internal)]
pub fn AllRestores(chain: k::Term<List<Cp>>) -> k::Term<List<Restore>> {
    match chain {
        [] => [],
        [c, rest @ ..] => list::concat(CpRestores(c), AllRestores(rest)),
    }
}

/// Some `RestoreDone` of seat `s` for counter `ctr`.
#[k::function(total, internal)]
pub fn HasRestore(rs: k::Term<List<Restore>>, s: k::Term<Int>, ctr: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RestoreC::Rd { seat, boot_ctr, .. }, rest @ ..] => {
            if seat == s && boot_ctr == ctr { true } else { HasRestore(rest, s, ctr) }
        }
    }
}

/// A boot counter without its seat's `RestoreDone`.
#[k::function(total, internal)]
pub fn MissingRestore(counters: k::Term<List<NN>>, rs: k::Term<List<Restore>>) -> k::Term<Bool> {
    match counters {
        [] => false,
        [Pair::P { a, b }, rest @ ..] => {
            if HasRestore(rs, a, b) { MissingRestore(rest, rs) } else { true }
        }
    }
}

/// CP-010: a boot counter without the seat's `RestoreDone` for that counter in
/// this or an earlier landed checkpoint.
#[k::function(total, internal)]
pub fn NoStatement(chain: k::Term<List<Cp>>, c2: k::Term<Cp>) -> k::Term<Bool> {
    MissingRestore(CpCounters(c2), list::concat(CpRestores(c2), AllRestores(chain)))
}

/// `landRefusals`: the refusals of a candidate checkpoint, in code order. The
/// first checkpoint has `seq` 0; a later one follows the latest by one (ledger 2).
/// `latest` and `chain` are the same list: the match reads `latest` and the
/// statement check reads `chain`, because K cannot parse a list pattern `ListItem(C1) _`
/// with an `#as` alias of the whole list.
#[k::function(total, internal)]
pub fn LandRefusals(p: k::Term<Params>, latest: k::Term<List<Cp>>, chain: k::Term<List<Cp>>, c2: k::Term<Cp>) -> k::Term<List<Refusal>> {
    match latest {
        [] => list::concat(
            Opt(CpSeq(c2) != 0, RefusalC::NoRule),
            list::concat(
                Opt(NoStatement(chain, c2), RefusalC::NoRestoreStatement),
                Opt(Gap(CpPools(c2)), RefusalC::PendingGap),
            ),
        ),
        [c1, ..] => list::concat(
            Opt(Lowered(CpPools(c1), CpPools(c2)), RefusalC::HLowered),
            list::concat(
                Opt(CpSeq(c2) != CpSeq(c1) + 1, RefusalC::NoRule),
                list::concat(
                    Opt(NoStatement(chain, c2), RefusalC::NoRestoreStatement),
                    list::concat(
                        Opt(Gap(CpPools(c2)), RefusalC::PendingGap),
                        list::concat(
                            Opt(PminLowered(CpPools(c1), CpPools(c2)), RefusalC::PendingMinLowered),
                            Opt(JumpCode(p, chain, c1, c2), RefusalC::RestartJump),
                        ),
                    ),
                ),
            ),
        ),
    }
}

/// A `RestoreDone` with `whole_restart` that names a checkpoint at or above `cur`.
#[k::function(total, internal)]
pub fn AnyWhole(rs: k::Term<List<Restore>>, cur: k::Term<Int>) -> k::Term<Bool> {
    match rs {
        [] => false,
        [RestoreC::Rd { cp_seq, whole, .. }, rest @ ..] => {
            if whole && cur <= cp_seq { true } else { AnyWhole(rest, cur) }
        }
    }
}

/// CP-011 (DECISIONS 69 item 6): the `restart_seq` the contract sets: the seq of
/// `c2` when `c2` or a landed checkpoint carries a qualifying `RestoreDone`, else the
/// current value.
#[k::function(total, internal)]
pub fn NextRestartSeq(chain: k::Term<List<Cp>>, c2: k::Term<Cp>) -> k::Term<Int> {
    NextFrom(chain, c2, LatestRestartSeq(chain))
}

/// `nextRestartSeq` with the current value `cur`: the carriers are `c2 :: chain`.
#[k::function(total, internal)]
pub fn NextFrom(chain: k::Term<List<Cp>>, c2: k::Term<Cp>, cur: k::Term<Int>) -> k::Term<Int> {
    if CarrierQual(c2, cur) { CpSeq(c2) } else { ChainMoves(chain, c2, cur) }
}

/// A landed checkpoint of `chain` is a qualifying carrier (ledger 15).
#[k::function(total, internal)]
pub fn ChainMoves(chain: k::Term<List<Cp>>, c2: k::Term<Cp>, cur: k::Term<Int>) -> k::Term<Int> {
    if ChainCarries(chain, cur) { CpSeq(c2) } else { cur }
}

/// Some checkpoint of `chain` is a qualifying carrier.
#[k::function(total, internal)]
pub fn ChainCarries(chain: k::Term<List<Cp>>, cur: k::Term<Int>) -> k::Term<Bool> {
    match chain {
        [] => false,
        [c, rest @ ..] => {
            if CarrierQual(c, cur) { true } else { ChainCarries(rest, cur) }
        }
    }
}

/// CP-011, ledger 15: a carrier counts only while its `seq` is above `cur`, and then
/// when it carries a `RestoreDone` with `whole_restart` naming a checkpoint at or above `cur`.
#[k::function(total, internal)]
pub fn CarrierQual(c: k::Term<Cp>, cur: k::Term<Int>) -> k::Term<Bool> {
    if cur < CpSeq(c) { AnyWhole(CpRestores(c), cur) } else { false }
}

/// CP-004: the pending statements that the landed checkpoint does not carry.
#[k::function(total, internal)]
pub fn NotCarried(rs: k::Term<List<Restore>>, carried: k::Term<List<Restore>>) -> k::Term<List<Restore>> {
    match rs {
        [] => [],
        [r, rest @ ..] => {
            if list::contains(r, carried) { NotCarried(rest, carried) } else { [r, ..NotCarried(rest, carried)] }
        }
    }
}

// ---------------------------------------------------------------------------
// Signer rules (CP-012 to CP-015).

/// `chain.flatMap (fun c => c.bf.map (·.2))`.
#[k::function(total, internal)]
pub fn LandedNfs(chain: k::Term<List<Cp>>) -> k::Term<List<Int>> {
    match chain {
        [] => [],
        [CpC::CpOf { bf, .. }, rest @ ..] => list::concat(Seconds(bf), LandedNfs(rest)),
    }
}

/// No element of `xs` is in `ys`.
#[k::function(total, internal)]
pub fn NoneIn(xs: k::Term<List<Int>>, ys: k::Term<List<Int>>) -> k::Term<Bool> {
    match xs {
        [] => true,
        [x, rest @ ..] => {
            if list::contains(x, ys) { false } else { NoneIn(rest, ys) }
        }
    }
}

/// CP-012: no two leaves hold one `nf`, and none holds an `nf` of a landed `bf_root`.
#[k::function(total, internal)]
pub fn SignBfOk(chain: k::Term<List<Cp>>, leaves: k::Term<List<NN>>) -> k::Term<Bool> {
    if NodupB(Seconds(leaves)) { NoneIn(Seconds(leaves), LandedNfs(chain)) } else { false }
}

/// Every leaf is one of `ended`.
#[k::function(total, internal)]
pub fn AllIn(leaves: k::Term<List<Leaf>>, ended: k::Term<List<Leaf>>) -> k::Term<Bool> {
    match leaves {
        [] => true,
        [l, rest @ ..] => {
            if list::contains(l, ended) { AllIn(rest, ended) } else { false }
        }
    }
}

/// No leaf gives an `auth` that Midnight records as VOID another outcome.
#[k::function(total, internal)]
pub fn VoidKept(leaves: k::Term<List<Leaf>>, mv: k::Term<List<Int>>) -> k::Term<Bool> {
    match leaves {
        [] => true,
        [LeafC::Lf { auth, out }, rest @ ..] => {
            if list::contains(auth, mv) { VoidLeafKept(out, rest, mv) } else { VoidKept(rest, mv) }
        }
    }
}

/// A leaf whose `auth` Midnight records as VOID keeps the outcome VOID.
#[k::function(total, internal)]
pub fn VoidLeafKept(out: k::Term<Outcome>, rest: k::Term<List<Leaf>>, mv: k::Term<List<Int>>) -> k::Term<Bool> {
    if out.ne::<K>(OutcomeC::Void) { false } else { VoidKept(rest, mv) }
}

/// CP-013: exactly the leaves of the requests that ended in the interval, each
/// with its board outcome, and no VOID overridden.
#[k::function(total, internal)]
pub fn SignSettleOk(leaves: k::Term<List<Leaf>>, ended: k::Term<List<Leaf>>, mv: k::Term<List<Int>>) -> k::Term<Bool> {
    if NodupB(leaves) { SettleSized(leaves, ended, mv) } else { false }
}

/// CP-013: as many leaves as requests that ended.
#[k::function(total, internal)]
pub fn SettleSized(leaves: k::Term<List<Leaf>>, ended: k::Term<List<Leaf>>, mv: k::Term<List<Int>>) -> k::Term<Bool> {
    if list::size(leaves) == list::size(ended) { SettleLeavesOk(leaves, ended, mv) } else { false }
}

/// CP-013: every leaf ended with its outcome, and no VOID overridden.
#[k::function(total, internal)]
pub fn SettleLeavesOk(leaves: k::Term<List<Leaf>>, ended: k::Term<List<Leaf>>, mv: k::Term<List<Int>>) -> k::Term<Bool> {
    if AllIn(leaves, ended) { VoidKept(leaves, mv) } else { false }
}

/// `insertSorted`.
#[k::function(total, internal)]
pub fn InsertSorted(x: k::Term<Int>, ys: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match ys {
        [] => [x],
        [y, rest @ ..] => {
            if x <= y { [x, y, ..rest] } else { [y, ..InsertSorted(x, rest)] }
        }
    }
}

/// `sortNat`: insertion sort.
#[k::function(total, internal)]
pub fn SortNat(xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [x, rest @ ..] => InsertSorted(x, SortNat(rest)),
    }
}

/// `l.head?.getD d`.
#[k::function(total, internal)]
pub fn HeadOr(xs: k::Term<List<Int>>, d: k::Term<Int>) -> k::Term<Int> {
    match xs {
        [] => d,
        [x, ..] => x,
    }
}

/// CP-014 (DECISIONS 71): `poolOf c pid`'s `pending_min`, 0 when `c` does not list the pool.
#[k::function(total, internal)]
pub fn PoolFloor(pools: k::Term<List<Pool>>, pid: k::Term<Int>) -> k::Term<Int> {
    match pools {
        [] => 0,
        [PoolC::PoolOf { pool, pending_min, .. }, rest @ ..] => {
            if pool == pid { pending_min } else { PoolFloor(rest, pid) }
        }
    }
}

/// CP-014 (DECISIONS 71, ledger 19): `floorOf`: the `pending_min` of the latest landed
/// checkpoint (the head of the chain) for the pool; no landed checkpoint gives no floor (0).
#[k::function(total, internal)]
pub fn FloorOf(chain: k::Term<List<Cp>>, pid: k::Term<Int>) -> k::Term<Int> {
    match chain {
        [] => 0,
        [c, ..] => PoolFloor(CpPools(c), pid),
    }
}

/// CP-014 (DECISIONS 71): the live indices at or above the floor `lo`.
#[k::function(total, internal)]
pub fn AtOrAbove(lo: k::Term<Int>, xs: k::Term<List<Int>>) -> k::Term<List<Int>> {
    match xs {
        [] => [],
        [x, rest @ ..] => {
            if lo <= x { [x, ..AtOrAbove(lo, rest)] } else { AtOrAbove(lo, rest) }
        }
    }
}

/// CP-014, CP-002 (DECISIONS 71): the pending fields over the sorted live indices at or
/// above the floor `lo`: the lowest entry or `h + 1`, the list, its length.
#[k::function(total, internal)]
pub fn PendingFieldsOk(lo: k::Term<Int>, p: k::Term<Pool>, live: k::Term<List<Int>>) -> k::Term<Bool> {
    match p {
        PoolC::PoolOf { h, pending_min, pending, pending_count, .. } => {
            HeadOr(SortNat(AtOrAbove(lo, live)), h + 1) == pending_min
                && SortNat(AtOrAbove(lo, live)).eq::<K>(pending)
                && list::size(AtOrAbove(lo, live)) == pending_count
        }
    }
}

/// CP-014 (DECISIONS 71): `signPending chain p live`: the fields over the list above the
/// floor of the latest landed checkpoint for the pool.
#[k::function(total, internal)]
pub fn SignPendingOk(chain: k::Term<List<Cp>>, p: k::Term<Pool>, live: k::Term<List<Int>>) -> k::Term<Bool> {
    match p {
        PoolC::PoolOf { pool, .. } => PendingFieldsOk(FloorOf(chain, pool), p, live),
    }
}

/// The slot nullifiers `nf` of the `bind` entries `(nf, e)` (CP-015, CP-016).
#[k::function(total, internal)]
pub fn BindKeys(log: k::Term<List<Entry>>) -> k::Term<List<Int>> {
    match log {
        [] => [],
        [EntryC::Bind { nf, .. }, rest @ ..] => [nf, ..BindKeys(rest)],
        [EntryC::Put { .. }, rest @ ..] => BindKeys(rest),
        [EntryC::RestoreE { .. }, rest @ ..] => BindKeys(rest),
        [EntryC::ReleaseE { .. }, rest @ ..] => BindKeys(rest),
    }
}

/// The digests of the `put` entries.
#[k::function(total, internal)]
pub fn PutDigests(log: k::Term<List<Entry>>) -> k::Term<List<Int>> {
    match log {
        [] => [],
        [EntryC::Put { digest }, rest @ ..] => [digest, ..PutDigests(rest)],
        [EntryC::Bind { .. }, rest @ ..] => PutDigests(rest),
        [EntryC::RestoreE { .. }, rest @ ..] => PutDigests(rest),
        [EntryC::ReleaseE { .. }, rest @ ..] => PutDigests(rest),
    }
}

/// CP-015: no second binding for one slot key and no second put of one digest.
#[k::function(total, internal)]
pub fn SignSeatRootOk(log: k::Term<List<Entry>>) -> k::Term<Bool> {
    NodupB(BindKeys(log)) && NodupB(PutDigests(log))
}

// ---------------------------------------------------------------------------
// The node: classification and burns (CP-017 to CP-029, CP-033).

/// CP-017, CP-018: fewer than `w + 1` continuous seats is a whole-committee restart.
#[k::function(total, internal)]
pub fn WholeRestart(p: k::Term<Params>, tickets: k::Term<List<NN>>, c: k::Term<Cp>) -> k::Term<Bool> {
    CountEq(0, NOf(p), tickets, CpCounters(c)) < WOf(p) + 1
}

/// CP-027: the restart stays open until the landed checkpoint shows `w + 1` continuous seats.
#[k::function(total, internal)]
pub fn StillOpen(p: k::Term<Params>, tickets: k::Term<List<NN>>, c: k::Term<Cp>) -> k::Term<Bool> {
    !(WOf(p) + 1 <= CountEq(0, NOf(p), tickets, CpCounters(c)))
}

/// CP-020: the burn range `[pending_min, h + B]` of each pool.
#[k::function(total, internal)]
pub fn BurnRanges(bb: k::Term<Int>, pools: k::Term<List<Pool>>) -> k::Term<List<Range>> {
    match pools {
        [] => [],
        [PoolC::PoolOf { pool, h, pending_min, .. }, rest @ ..] => {
            [RangeC::Rg { pool, lo: pending_min, hi: h + bb }, ..BurnRanges(bb, rest)]
        }
    }
}

/// CP-020, CP-023, CP-029: the union of the ranges of every checkpoint read;
/// with slot anchors nothing burns.
#[k::function(total, internal)]
pub fn NewBurn(p: k::Term<Params>, c: k::Term<Cp>, burn: k::Term<List<Range>>) -> k::Term<List<Range>> {
    if AnchorOf(p) { burn } else { list::concat(BurnRanges(BOf(p), CpPools(c)), burn) }
}

/// CP-021: every slot burns.
#[k::function(total, internal)]
pub fn BurnSlots(slots: k::Term<List<ASlot>>) -> k::Term<List<ASlot>> {
    match slots {
        [] => [],
        [_x, rest @ ..] => [ASlotC::Burned, ..BurnSlots(rest)],
    }
}

/// CP-021: burn every `free` and `bound` slot of each account pool.
#[k::function(total, internal)]
pub fn BurnAccts(accts: k::Term<List<Acct>>) -> k::Term<List<Acct>> {
    match accts {
        [] => [],
        [AcctC::AcctOf { id, slots, mark, refill }, rest @ ..] => {
            [AcctC::AcctOf { id, slots: BurnSlots(slots), mark, refill }, ..BurnAccts(rest)]
        }
    }
}

/// CP-029: the slot a covered binding `(aid, i, d)` gives, else `free`.
#[k::function(total, internal)]
pub fn CoveredSlot(cov: k::Term<List<Cov>>, aid: k::Term<Int>, i: k::Term<Int>) -> k::Term<ASlot> {
    match cov {
        [] => ASlotC::Free,
        [CovC::CovOf { account, slot, d }, rest @ ..] => {
            if account == aid && slot == i { ASlotC::Bound { d } } else { CoveredSlot(rest, aid, i) }
        }
    }
}

/// CP-029: a `free` slot with a covered binding becomes `bound` to its digest.
#[k::function(total, internal)]
pub fn AnchorSlots(cov: k::Term<List<Cov>>, aid: k::Term<Int>, i: k::Term<Int>, slots: k::Term<List<ASlot>>) -> k::Term<List<ASlot>> {
    match slots {
        [] => [],
        [ASlotC::Free, rest @ ..] => [CoveredSlot(cov, aid, i), ..AnchorSlots(cov, aid, i + 1, rest)],
        [ASlotC::Bound { d }, rest @ ..] => [ASlotC::Bound { d }, ..AnchorSlots(cov, aid, i + 1, rest)],
        [ASlotC::Burned, rest @ ..] => [ASlotC::Burned, ..AnchorSlots(cov, aid, i + 1, rest)],
    }
}

#[k::function(total, internal)]
pub fn AnchorAccts(cov: k::Term<List<Cov>>, accts: k::Term<List<Acct>>) -> k::Term<List<Acct>> {
    match accts {
        [] => [],
        [AcctC::AcctOf { id, slots, mark, refill }, rest @ ..] => {
            [AcctC::AcctOf { id, slots: AnchorSlots(cov, id, 0, slots), mark, refill }, ..AnchorAccts(cov, rest)]
        }
    }
}

/// CP-021, CP-029: the account pools after a whole-committee restart.
#[k::function(total, internal)]
pub fn RestartAccts(p: k::Term<Params>, cov: k::Term<List<Cov>>, accts: k::Term<List<Acct>>, open: k::Term<Bool>) -> k::Term<List<Acct>> {
    if AnchorOf(p) { AnchorAccts(cov, accts) } else { GenBurn(open, accts) }
}

/// CP-021, CP-027 (DECISIONS 69 item 7, ledger 12): the account pools burn once per
/// restart generation; a read inside an open restart burns them no second time.
#[k::function(total, internal)]
pub fn GenBurn(open: k::Term<Bool>, accts: k::Term<List<Acct>>) -> k::Term<List<Acct>> {
    if open { accts } else { BurnAccts(accts) }
}

/// CP-022 (DECISIONS 69 item 7, ledger 16): each open session takes the burn ranges
/// of its pool at once; with slot anchors nothing burns (CP-029).
#[k::function(total, internal)]
pub fn NewSessions(p: k::Term<Params>, c: k::Term<Cp>, sessions: k::Term<List<Session>>) -> k::Term<List<Session>> {
    if AnchorOf(p) { sessions } else { BurnSessions(BurnRanges(BOf(p), CpPools(c)), sessions) }
}

/// `burnSessions`: `(pool, rs.filter (·.1 == pool) ++ burned)` for each session.
#[k::function(total, internal)]
pub fn BurnSessions(rs: k::Term<List<Range>>, sessions: k::Term<List<Session>>) -> k::Term<List<Session>> {
    match sessions {
        [] => [],
        [SessionC::Sess { pool, burned }, rest @ ..] => {
            [SessionC::Sess { pool, burned: list::concat(PoolBurns(rs, pool), burned) }, ..BurnSessions(rs, rest)]
        }
    }
}

/// CP-042 (DECISIONS 69 item 4): at a verified ledger read the node appends again
/// each statement it keeps in RAM that the board lost (`reappend`).
#[k::function(total, internal)]
pub fn Reappend(board: k::Term<List<Restore>>, waiting: k::Term<List<Restore>>) -> k::Term<List<Restore>> {
    list::concat(board, NotCarried(waiting, board))
}

/// CP-025: the landed checkpoint carries a `restart_seq` above the marker of the open restart.
#[k::function(total, internal)]
pub fn IsMarker(open: k::Term<Bool>, prev: k::Term<Int>, c: k::Term<Cp>) -> k::Term<Bool> {
    open && prev < CpRestartSeq(c)
}

/// The marker read keeps an open restart's marker.
#[k::function(total, internal)]
pub fn KeepInt(open: k::Term<Bool>, old: k::Term<Int>, new: k::Term<Int>) -> k::Term<Int> {
    if open { old } else { new }
}

#[k::function(total, internal)]
pub fn KeepLanded(open: k::Term<Bool>, old: k::Term<Bool>) -> k::Term<Bool> {
    if open { old } else { false }
}

/// CP-025: the marker checkpoint writes its `restart_seq` into each account pool.
#[k::function(total, internal)]
pub fn MarkAccts(accts: k::Term<List<Acct>>, m: k::Term<Int>) -> k::Term<List<Acct>> {
    match accts {
        [] => [],
        [AcctC::AcctOf { id, slots, refill, .. }, rest @ ..] => {
            [AcctC::AcctOf { id, slots, mark: m, refill }, ..MarkAccts(rest, m)]
        }
    }
}

/// CP-033: no slot share is kept and every address refills.
#[k::function(total, internal)]
pub fn RefillAccts(accts: k::Term<List<Acct>>) -> k::Term<List<Acct>> {
    match accts {
        [] => [],
        [AcctC::AcctOf { id, slots, mark, .. }, rest @ ..] => {
            [AcctC::AcctOf { id, slots: BurnSlots(slots), mark, refill: true }, ..RefillAccts(rest)]
        }
    }
}

/// `readLedger` refusals: CP-019 and ledger 3, then tickets outside the seats.
#[k::function(total, internal)]
pub fn SeatOutside(tickets: k::Term<List<NN>>, n: k::Term<Int>) -> k::Term<Bool> {
    match tickets {
        [] => false,
        [Pair::P { a, .. }, rest @ ..] => {
            if n <= a { true } else { SeatOutside(rest, n) }
        }
    }
}

/// CP-019: a node with no verified view stays not ready; CP-043: on a ready node an
/// unverified read is no refusal (ledger 6).
#[k::function(total, internal)]
pub fn ReadRefusals(
    p: k::Term<Params>,
    chain: k::Term<List<Cp>>,
    ok: k::Term<Bool>,
    tickets: k::Term<List<NN>>,
    ready: k::Term<Bool>,
) -> k::Term<List<Refusal>> {
    list::concat(
        Opt(!ok && !ready, RefusalC::LedgerUnverified),
        list::concat(
            Opt(NonTeeOf(p) || list::size(chain) == 0, RefusalC::NoRule),
            Opt(SeatOutside(tickets, NOf(p)) || !NodupB(Firsts(tickets)), RefusalC::OutsideCapability),
        ),
    )
}

/// CP-024: a session created while the restart is open opens with its pool's burns.
#[k::function(total, internal)]
pub fn PoolBurns(burn: k::Term<List<Range>>, pid: k::Term<Int>) -> k::Term<List<Range>> {
    match burn {
        [] => [],
        [r @ RangeC::Rg { pool, .. }, rest @ ..] => {
            if pool == pid { [r, ..PoolBurns(rest, pid)] } else { PoolBurns(rest, pid) }
        }
    }
}

#[k::function(total, internal)]
pub fn SessionBurns(open: k::Term<Bool>, burn: k::Term<List<Range>>, pid: k::Term<Int>) -> k::Term<List<Range>> {
    if open { PoolBurns(burn, pid) } else { [] }
}

#[k::function(total, internal)]
pub fn HasSession(sessions: k::Term<List<Session>>, pid: k::Term<Int>) -> k::Term<Bool> {
    match sessions {
        [] => false,
        [SessionC::Sess { pool, .. }, rest @ ..] => {
            if pool == pid { true } else { HasSession(rest, pid) }
        }
    }
}

#[k::function(total, internal)]
pub fn SessionRefusals(ready: k::Term<Bool>, sessions: k::Term<List<Session>>, pid: k::Term<Int>) -> k::Term<List<Refusal>> {
    list::concat(Opt(!ready, RefusalC::LedgerUnverified), Opt(HasSession(sessions, pid), RefusalC::NoRule))
}

#[k::function(total, internal)]
pub fn HasAcct(accts: k::Term<List<Acct>>, aid: k::Term<Int>) -> k::Term<Bool> {
    match accts {
        [] => false,
        [AcctC::AcctOf { id, .. }, rest @ ..] => {
            if id == aid { true } else { HasAcct(rest, aid) }
        }
    }
}

#[k::function(total, internal)]
pub fn AcctId(a: k::Term<Acct>) -> k::Term<Int> {
    match a {
        AcctC::AcctOf { id, .. } => id,
    }
}

#[k::function(total, internal)]
pub fn AcctRefusals(ready: k::Term<Bool>, accts: k::Term<List<Acct>>, a: k::Term<Acct>) -> k::Term<List<Refusal>> {
    list::concat(Opt(!ready, RefusalC::LedgerUnverified), Opt(HasAcct(accts, AcctId(a)), RefusalC::NoRule))
}

/// CP-026: a pool with a mark below `restart_seq` burns before any bind.
#[k::function(total, internal)]
pub fn OpenedAcct(a: k::Term<Acct>, rsq: k::Term<Int>, pre: k::Term<Bool>) -> k::Term<Acct> {
    match a {
        AcctC::AcctOf { id, slots, mark, refill } => {
            if mark < rsq {
                AcctC::AcctOf { id, slots: BurnSlots(slots), mark: rsq, refill }
            } else {
                PreBurn(pre, id, slots, mark, refill)
            }
        }
    }
}

/// CP-021 (DECISIONS 69 item 7): before the marker lands every pool predates the
/// restart and burns in this generation; its mark stays.
#[k::function(total, internal)]
pub fn PreBurn(pre: k::Term<Bool>, id: k::Term<Int>, slots: k::Term<List<ASlot>>, mark: k::Term<Int>, refill: k::Term<Bool>) -> k::Term<Acct> {
    if pre { AcctC::AcctOf { id, slots: BurnSlots(slots), mark, refill } } else { AcctC::AcctOf { id, slots, mark, refill } }
}

/// CP-021: the restart is open, its marker has not landed, and slot anchors are off.
#[k::function(total, internal)]
pub fn PreMarker(open: k::Term<Bool>, landed: k::Term<Bool>, p: k::Term<Params>) -> k::Term<Bool> {
    open && !landed && !AnchorOf(p)
}

/// `a.slots[i]? == some .free`.
#[k::function(total, internal)]
pub fn FreeAt(slots: k::Term<List<ASlot>>, i: k::Term<Int>) -> k::Term<Bool> {
    match slots {
        [] => false,
        [x, rest @ ..] => {
            if i == 0 { x.eq::<K>(ASlotC::Free) } else { FreeAt(rest, i - 1) }
        }
    }
}

/// `slotFree` at an account pool with id `aid`: its slot `i` is free, or a later pool's.
#[k::function(total, internal)]
pub fn SlotFreeIn(slots: k::Term<List<ASlot>>, rest: k::Term<List<Acct>>, aid: k::Term<Int>, i: k::Term<Int>) -> k::Term<Bool> {
    if FreeAt(slots, i) { true } else { SlotFree(rest, aid, i) }
}

/// `slotFree`: some account pool `aid` has a `free` slot `i`.
#[k::function(total, internal)]
pub fn SlotFree(accts: k::Term<List<Acct>>, aid: k::Term<Int>, i: k::Term<Int>) -> k::Term<Bool> {
    match accts {
        [] => false,
        [AcctC::AcctOf { id, slots, .. }, rest @ ..] => {
            if id == aid { SlotFreeIn(slots, rest, aid, i) } else { SlotFree(rest, aid, i) }
        }
    }
}

/// CP-025 (ledger 5): no bind while the restart is open and no marker landed,
/// and none on a slot that is not free.
#[k::function(total, internal)]
pub fn BindRefusals(
    ready: k::Term<Bool>,
    open: k::Term<Bool>,
    landed: k::Term<Bool>,
    accts: k::Term<List<Acct>>,
    aid: k::Term<Int>,
    i: k::Term<Int>,
) -> k::Term<List<Refusal>> {
    list::concat(
        Opt(!ready, RefusalC::LedgerUnverified),
        Opt((open && !landed) || !SlotFree(accts, aid, i), RefusalC::NoRule),
    )
}

/// `slots.set i (.bound d)`; past the end nothing changes.
#[k::function(total, internal)]
pub fn SetBound(slots: k::Term<List<ASlot>>, i: k::Term<Int>, d: k::Term<Int>) -> k::Term<List<ASlot>> {
    match slots {
        [] => [],
        [x, rest @ ..] => {
            if i == 0 { [ASlotC::Bound { d }, ..rest] } else { [x, ..SetBound(rest, i - 1, d)] }
        }
    }
}

#[k::function(total, internal)]
pub fn BindAccts(accts: k::Term<List<Acct>>, aid: k::Term<Int>, i: k::Term<Int>, d: k::Term<Int>) -> k::Term<List<Acct>> {
    match accts {
        [] => [],
        [AcctC::AcctOf { id, slots, mark, refill }, rest @ ..] => {
            if id == aid {
                [AcctC::AcctOf { id, slots: SetBound(slots, i, d), mark, refill }, ..BindAccts(rest, aid, i, d)]
            } else {
                [AcctC::AcctOf { id, slots, mark, refill }, ..BindAccts(rest, aid, i, d)]
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery (CP-030 to CP-035) and the stateless node rules.

/// CP-034, CP-035: `recover` needs a landed checkpoint, once, `Δ_rec` blocks after the latest landing.
#[k::function(total, internal)]
pub fn RecoverRefusals(
    p: k::Term<Params>,
    chain: k::Term<List<Cp>>,
    recovered: k::Term<Bool>,
    last: k::Term<Int>,
    mh: k::Term<Int>,
) -> k::Term<List<Refusal>> {
    match chain {
        [] => [RefusalC::NoRule],
        [_c, ..] => list::concat(
            Opt(recovered, RefusalC::NoRule),
            Opt(mh < last + DRecOf(p), RefusalC::RecoveryEarly),
        ),
    }
}

/// CP-006: some node acknowledged fewer than `w` keys.
#[k::function(total, internal)]
pub fn AnyBelow(acks: k::Term<List<Int>>, w: k::Term<Int>) -> k::Term<Bool> {
    match acks {
        [] => false,
        [x, rest @ ..] => {
            if x < w { true } else { AnyBelow(rest, w) }
        }
    }
}

/// `peers.foldl max acc`.
#[k::function(total, internal)]
pub fn FoldMax(xs: k::Term<List<Int>>, acc: k::Term<Int>) -> k::Term<Int> {
    match xs {
        [] => acc,
        [x, rest @ ..] => FoldMax(rest, int::max(acc, x)),
    }
}

/// The board height of the latest landed checkpoint, or 0.
#[k::function(total, internal)]
pub fn HeadHeight(chain: k::Term<List<Cp>>) -> k::Term<Int> {
    match chain {
        [] => 0,
        [CpC::CpOf { board_height, .. }, ..] => board_height,
    }
}

/// CP-036: ordered below `max(peer heights, latest checkpoint height)` with no
/// proof of non-service.
#[k::function(total, internal)]
pub fn BelowFloorOf(chain: k::Term<List<Cp>>, order_h: k::Term<Int>, peers: k::Term<List<Int>>, proof: k::Term<Bool>) -> k::Term<Bool> {
    order_h < int::max(FoldMax(peers, 0), HeadHeight(chain)) && !proof
}

/// CP-016: a seat-log entry at board height `h` counts once a landed root covers it.
#[k::function(total, internal)]
pub fn CoveredAt(chain: k::Term<List<Cp>>, h: k::Term<Int>) -> k::Term<Bool> {
    match chain {
        [] => false,
        [CpC::CpOf { board_height, .. }, ..] => h <= board_height,
    }
}

/// CP-043, CP-037 (ledger 6): an anchored release waits while the node is not ready.
#[k::function(total, internal)]
pub fn ReleaseWaits(anchor: k::Term<Bool>, ready: k::Term<Bool>) -> k::Term<Bool> {
    anchor && !ready
}

/// CP-037: release under an `anchor_before_release` charter waits for coverage.
#[k::function(total, internal)]
pub fn ReleaseOk(chain: k::Term<List<Cp>>, anchor: k::Term<Bool>, entry_h: k::Term<Int>) -> k::Term<Bool> {
    if anchor { CoveredAt(chain, entry_h) } else { true }
}

/// CP-031: the slots without a covered binding whose seat log was read in full.
#[k::function(total, internal)]
pub fn ReshareList(slots: k::Term<List<RSlot>>) -> k::Term<List<NN>> {
    match slots {
        [] => [],
        [RSlotC::RSlotOf { seat, slot, covered, log_read }, rest @ ..] => {
            if !covered && log_read { [Pair::P { a: seat, b: slot }, ..ReshareList(rest)] } else { ReshareList(rest) }
        }
    }
}

/// CP-031, CP-032: without slot anchors the recovery group reshares no ECDSA slot.
#[k::function(total, internal)]
pub fn ReshareOf(p: k::Term<Params>, slots: k::Term<List<RSlot>>) -> k::Term<List<NN>> {
    if AnchorOf(p) { ReshareList(slots) } else { [] }
}

/// CP-003: a checkpoint is due when 60 s of board time passed.
#[k::function(total, internal)]
pub fn DueAt(last: k::Term<Int>, now: k::Term<Int>) -> k::Term<Bool> {
    last + 60 <= now
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
    pub chain: List<Cp>,
    #[k::cell]
    pub landmh: Int,
    #[k::cell]
    pub recovered: Bool,
    #[k::cell]
    pub writes: List<Write>,
    #[k::cell]
    pub ready: Bool,
    #[k::cell]
    pub tickets: List<NN>,
    #[k::cell]
    pub burn: List<Range>,
    #[k::cell]
    pub accounts: List<Acct>,
    #[k::cell]
    pub sessions: List<Session>,
    #[k::cell]
    pub restarting: Bool,
    #[k::cell]
    pub marker: Int,
    #[k::cell]
    pub landed: Bool,
    #[k::cell]
    pub waiting: List<Restore>,
    #[k::cell]
    pub board: List<Restore>,
    #[k::cell]
    pub cold: Bool,
    #[k::cell]
    pub newpool: Bool,
    #[k::cell]
    pub ops: List<Op>,
    #[k::cell]
    pub obs: List<Obs>,
}

impl Machine {
    /// `init`: no checkpoint landed, the node not ready, nothing burned.
    #[k::init]
    pub fn init(params: Params, ops: List<Op>) -> Self {
        Self {
            k: k::k![Step::Go],
            params,
            chain: [],
            landmh: 0,
            recovered: false,
            writes: [],
            ready: false,
            tickets: [],
            burn: [],
            accounts: [],
            sessions: [],
            restarting: false,
            marker: 0,
            landed: false,
            waiting: [],
            board: [],
            cold: false,
            newpool: false,
            ops,
            obs: [],
        }
    }
}

k::rules! {
    for Machine;

    // CP-007 to CP-011, CP-040, CP-041, CP-003, CP-005: the checkpoint lands with the
    // `restart_seq` the contract sets (CP-011) and one checkpoint write; CP-004,
    // CP-042: the statements it carries leave the pending list and the board. The
    // node's part follows.
    #[k::requires(list::size(LandRefusals(params, chain, chain, c)) == 0)]
    land: {
        k: [Step::Go, ..],
        params,
        chain,
        writes,
        waiting,
        board,
        ops: [OpC::Land { c, mh }, ..],
        obs,
    } => {
        k: [Step::LandNode { c: WithRestartSeq(c, NextRestartSeq(chain, c)) }, ..],
        chain: [WithRestartSeq(c, NextRestartSeq(chain, c)), ..chain],
        landmh: mh,
        writes: [WriteC::WCheckpoint, ..writes],
        waiting: NotCarried(waiting, CpRestores(c)),
        board: NotCarried(board, CpRestores(c)),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-025, CP-027: the landed checkpoint is the marker of the open restart: it
    // marks every account pool, and the restart ends with `w + 1` continuous seats.
    #[k::requires(IsMarker(restarting, marker, c))]
    land_marker: {
        k: [Step::LandNode { c }, ..],
        params,
        tickets,
        accounts,
        restarting,
        marker,
    } => {
        k: [Step::Go, ..],
        landed: true,
        accounts: MarkAccts(accounts, CpRestartSeq(c)),
        restarting: StillOpen(params, tickets, c),
    };

    // A landing that is no marker of an open restart leaves the node as it is.
    #[k::requires(!IsMarker(restarting, marker, c))]
    land_plain: {
        k: [Step::LandNode { c }, ..],
        restarting,
        marker,
    } => {
        k: [Step::Go, ..],
    };

    // CP-007 to CP-010, CP-040, CP-041, ledger 1, ledger 2: the contract refuses the
    // candidate with every failing code.
    #[k::requires(list::size(LandRefusals(params, chain, chain, c)) != 0)]
    land_refuse: {
        k: [Step::Go, ..],
        params,
        chain,
        ops: [OpC::Land { c, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: LandRefusals(params, chain, chain, c) }],
    };

    // CP-019: the node boots and is not ready.
    boot: {
        k: [Step::Go, ..],
        ops: [OpC::Boot, ..],
        obs,
    } => {
        ready: false,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-018: a verified snapshot with a landed checkpoint; the node classifies
    // the boot on the latest landed checkpoint. CP-042: first it appends again each
    // statement it keeps in RAM that the board lost.
    #[k::requires(list::size(ReadRefusals(params, chain, ok, tk, ready)) == 0 && ok)]
    read_ledger: {
        k: [Step::Go, ..],
        params,
        chain,
        ready,
        waiting,
        board,
        ops: [OpC::ReadLedger { ok, tickets: tk, cov }, ..],
        obs,
    } => {
        k: [Step::ReadNode { tk, cov }, ..],
        board: Reappend(board, waiting),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-043 (ledger 6): a later view that does not verify on a ready node: the
    // node keeps the last verified view and is not ready.
    #[k::requires(list::size(ReadRefusals(params, chain, ok, tk, ready)) == 0 && !ok)]
    read_unverified: {
        k: [Step::Go, ..],
        params,
        chain,
        ready,
        ops: [OpC::ReadLedger { ok, tickets: tk, .. }, ..],
        obs,
    } => {
        ready: false,
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-018, CP-020 to CP-023, CP-029: a whole-committee restart. The marker of
    // an open restart stays; the burns grow by the ranges of `c`, and each open
    // session takes them at once (CP-022).
    #[k::requires(WholeRestart(params, tk, c))]
    read_whole: {
        k: [Step::ReadNode { tk, cov }, ..],
        params,
        chain: [c, ..],
        burn,
        accounts,
        sessions,
        restarting,
        marker,
        landed,
    } => {
        k: [Step::Go, ..],
        ready: true,
        tickets: tk,
        restarting: true,
        marker: KeepInt(restarting, marker, CpRestartSeq(c)),
        landed: KeepLanded(restarting, landed),
        burn: NewBurn(params, c, burn),
        sessions: NewSessions(params, c, sessions),
        accounts: RestartAccts(params, cov, accounts, restarting),
    };

    // CP-028: a partial restart burns nothing; the node is ready.
    #[k::requires(!WholeRestart(params, tk, c))]
    read_partial: {
        k: [Step::ReadNode { tk, .. }, ..],
        params,
        chain: [c, ..],
    } => {
        k: [Step::Go, ..],
        ready: true,
        tickets: tk,
    };

    // CP-019, ledger 3: an unverified snapshot, a non-TEE committee or no landed
    // checkpoint; tickets outside the seats.
    #[k::requires(list::size(ReadRefusals(params, chain, ok, tk, ready)) != 0)]
    read_refuse: {
        k: [Step::Go, ..],
        params,
        chain,
        ready,
        ops: [OpC::ReadLedger { ok, tickets: tk, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: ReadRefusals(params, chain, ok, tk, ready) }],
    };

    // CP-024: a session created while the restart is open opens with the burns.
    #[k::requires(list::size(SessionRefusals(ready, sessions, pool)) == 0)]
    open_session: {
        k: [Step::Go, ..],
        ready,
        burn,
        sessions,
        restarting,
        ops: [OpC::OpenSession { pool }, ..],
        obs,
    } => {
        sessions: [SessionC::Sess { pool, burned: SessionBurns(restarting, burn, pool) }, ..sessions],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 6: a node that is not ready; a second session for one pool.
    #[k::requires(list::size(SessionRefusals(ready, sessions, pool)) != 0)]
    open_session_refuse: {
        k: [Step::Go, ..],
        ready,
        sessions,
        ops: [OpC::OpenSession { pool }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: SessionRefusals(ready, sessions, pool) }],
    };

    // CP-026: a restored account pool with a mark below `restart_seq` burns first;
    // CP-021: one opened in an open restart before its marker lands burns too.
    #[k::requires(list::size(AcctRefusals(ready, accounts, a)) == 0)]
    open_acct: {
        k: [Step::Go, ..],
        params,
        chain,
        ready,
        accounts,
        restarting,
        landed,
        ops: [OpC::OpenAcct { a }, ..],
        obs,
    } => {
        accounts: [OpenedAcct(a, LatestRestartSeq(chain), PreMarker(restarting, landed, params)), ..accounts],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 6: a node that is not ready; an account pool opened twice.
    #[k::requires(list::size(AcctRefusals(ready, accounts, a)) != 0)]
    open_acct_refuse: {
        k: [Step::Go, ..],
        ready,
        accounts,
        ops: [OpC::OpenAcct { a }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: AcctRefusals(ready, accounts, a) }],
    };

    // CP-025: the node binds a free slot of an account pool.
    #[k::requires(list::size(BindRefusals(ready, restarting, landed, accounts, aid, i)) == 0)]
    bind_acct: {
        k: [Step::Go, ..],
        ready,
        accounts,
        restarting,
        landed,
        ops: [OpC::BindAcct { aid, i, d }, ..],
        obs,
    } => {
        accounts: BindAccts(accounts, aid, i, d),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-025, ledger 5, ledger 6: no bind before the marker lands, on a slot that
    // is not free, or on a node that is not ready.
    #[k::requires(list::size(BindRefusals(ready, restarting, landed, accounts, aid, i)) != 0)]
    bind_acct_refuse: {
        k: [Step::Go, ..],
        ready,
        accounts,
        restarting,
        landed,
        ops: [OpC::BindAcct { aid, i, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: BindRefusals(ready, restarting, landed, accounts, aid, i) }],
    };

    // CP-004, CP-016: the statement waits for a checkpoint that carries it, in RAM
    // and on the board's uncovered tail (CP-042).
    #[k::requires(seat < NOf(params))]
    restore_done: {
        k: [Step::Go, ..],
        params,
        waiting,
        board,
        ops: [OpC::RestoreDone { r: r @ RestoreC::Rd { seat, .. } }, ..],
        obs,
    } => {
        waiting: [r, ..waiting],
        board: [..board, r],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // A seat outside the committee.
    #[k::requires(NOf(params) <= seat)]
    restore_done_outside: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::RestoreDone { r: RestoreC::Rd { seat, .. } }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::OutsideCapability] }],
    };

    // CP-042: the board loses its uncovered tail; the RAM copies stay.
    lose_tail: {
        k: [Step::Go, ..],
        board,
        ops: [OpC::LoseTail, ..],
        obs,
    } => {
        board: [],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-034: the recovery transition, one record.
    #[k::requires(list::size(RecoverRefusals(params, chain, recovered, landmh, mh)) == 0)]
    recover: {
        k: [Step::Go, ..],
        params,
        chain,
        recovered,
        landmh,
        writes,
        ops: [OpC::Recover { mh }, ..],
        obs,
    } => {
        recovered: true,
        writes: [WriteC::WEvent, ..writes],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-035, ledger 9: before `Δ_rec`, a second time, or with no landed checkpoint.
    #[k::requires(list::size(RecoverRefusals(params, chain, recovered, landmh, mh)) != 0)]
    recover_refuse: {
        k: [Step::Go, ..],
        params,
        chain,
        recovered,
        landmh,
        ops: [OpC::Recover { mh }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: RecoverRefusals(params, chain, recovered, landmh, mh) }],
    };

    // CP-030: the cold start record, below `t` intact nodes with `q` signatures, once.
    #[k::requires(!(TOf(params) <= intact || signers < QOf(params) || cold))]
    cold_start: {
        k: [Step::Go, ..],
        params,
        writes,
        cold,
        ops: [OpC::ColdStart { intact, signers }, ..],
        obs,
    } => {
        cold: true,
        newpool: true,
        writes: [WriteC::WEvent, ..writes],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 7: no cold start with `t` intact nodes, below `q` signatures, or twice.
    #[k::requires(TOf(params) <= intact || signers < QOf(params) || cold)]
    cold_start_refuse: {
        k: [Step::Go, ..],
        params,
        cold,
        ops: [OpC::ColdStart { intact, signers }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // CP-006: one `EKS_e` record with `n` acks of at least `w` keys and `q` signatures.
    #[k::requires(!(list::size(acks) != NOf(params) || AnyBelow(acks, WOf(params)) || sigs < QOf(params)))]
    eks: {
        k: [Step::Go, ..],
        params,
        writes,
        ops: [OpC::Eks { e, acks, sigs }, ..],
        obs,
    } => {
        writes: [WriteC::WEks { e }, ..writes],
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // Ledger 8: a key set without `n` acks of `w` keys or without `q` signatures.
    #[k::requires(list::size(acks) != NOf(params) || AnyBelow(acks, WOf(params)) || sigs < QOf(params))]
    eks_refuse: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::Eks { acks, sigs, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // CP-033: a non-TEE committee keeps no slot share, deals a new nonce pool and
    // every address refills.
    #[k::requires(NonTeeOf(params))]
    non_tee_restart: {
        k: [Step::Go, ..],
        params,
        accounts,
        ops: [OpC::NonTeeRestart, ..],
        obs,
    } => {
        newpool: true,
        accounts: RefillAccts(accounts),
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-033 is a non-TEE rule.
    #[k::requires(!NonTeeOf(params))]
    non_tee_restart_refuse: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::NonTeeRestart, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::NoRule] }],
    };

    // CP-012.
    sign_bf: {
        k: [Step::Go, ..],
        chain,
        ops: [OpC::SignBf { leaves }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: SignBfOk(chain, leaves) }],
    };

    // CP-013.
    sign_settle: {
        k: [Step::Go, ..],
        ops: [OpC::SignSettle { leaves, ended, mv }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: SignSettleOk(leaves, ended, mv) }],
    };

    // CP-014 (DECISIONS 71: the floor is read from the landed chain).
    sign_pending: {
        k: [Step::Go, ..],
        chain,
        ops: [OpC::SignPending { p, live }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: SignPendingOk(chain, p, live) }],
    };

    // CP-015.
    sign_seat_root: {
        k: [Step::Go, ..],
        ops: [OpC::SignSeatRoot { log }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: SignSeatRootOk(log) }],
    };

    // CP-036: an order at or above the replay floor, or with a proof of non-service.
    #[k::requires(!BelowFloorOf(chain, order_h, peers, proof))]
    order_req: {
        k: [Step::Go, ..],
        chain,
        ops: [OpC::OrderReq { order_h, peers, proof }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Ok],
    };

    // CP-036: below the replay floor.
    #[k::requires(BelowFloorOf(chain, order_h, peers, proof))]
    order_req_refuse: {
        k: [Step::Go, ..],
        chain,
        ops: [OpC::OrderReq { order_h, peers, proof }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::BelowFloor] }],
    };

    // CP-016.
    covered: {
        k: [Step::Go, ..],
        chain,
        ops: [OpC::CoveredQ { h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: CoveredAt(chain, h) }],
    };

    // CP-037.
    #[k::requires(!ReleaseWaits(anchor, ready))]
    release_anchor: {
        k: [Step::Go, ..],
        chain,
        ready,
        ops: [OpC::ReleaseAnchor { anchor, entry_h }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: ReleaseOk(chain, anchor, entry_h) }],
    };

    // CP-043, CP-037 (ledger 6): an anchored release waits while the node is not ready.
    #[k::requires(ReleaseWaits(anchor, ready))]
    release_anchor_refuse: {
        k: [Step::Go, ..],
        ready,
        ops: [OpC::ReleaseAnchor { anchor, .. }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::Refused { codes: [RefusalC::LedgerUnverified] }],
    };

    // CP-031, CP-032.
    reshare: {
        k: [Step::Go, ..],
        params,
        ops: [OpC::Reshare { slots }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::SlotsObs { xs: ReshareOf(params, slots) }],
    };

    // CP-003.
    due: {
        k: [Step::Go, ..],
        ops: [OpC::Due { last, now }, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: DueAt(last, now) }],
    };

    // CP-004: a seat may reboot once every statement it appended is carried.
    may_reboot: {
        k: [Step::Go, ..],
        waiting,
        ops: [OpC::MayReboot, ..],
        obs,
    } => {
        ops: [..],
        obs: [..obs, ObsC::BoolObs { b: list::size(waiting) == 0 }],
    };

    // `runOps`: the run ends when no operation is left.
    done: {
        k: [Step::Go, ..],
        ops: [],
    } => {
        k: [..],
    };
}
