// -*- mode: Bluespec; -*-
// Split-line dealing: Quint model written from the specification only.
//
// Sources (the only inputs of this model, LOOP item 14):
//   openspec/changes/add-split-line-dealing/specs/split-request/spec.md        (RQ-*)
//     sha256 fc3252556560d321e5ff39868a5039595b0bd70007e4de0bf482fc4b46839d91
//   openspec/changes/add-split-line-dealing/specs/split-slots/spec.md          (SL-*)
//     sha256 e72063544baab6a87e4a99570eb438fae571d01c84fbe66cdd0514ef7a75a557
//   openspec/changes/add-split-line-dealing/specs/split-authorization/spec.md  (AU-*)
//     sha256 df0592d3f44be537dcd6caa53873e586f3714bf72a6f3af0f45eb67c0a2a9526
//   openspec/changes/add-split-line-dealing/specs/split-checkpoint/spec.md     (CP-*)
//     sha256 aa3a134ae2bb9f0d1f8e97ca02a2bb1ece075f7a555eebbaa49390d2ea887e6a
//   openspec/changes/add-split-line-dealing/specs/split-envelope/spec.md       (EN-*)
//     sha256 6961d44acc4e9fe7cbf1d9ffaddd76b2142c9768b45177c364fa5c01cf5c87d0
//   openspec/changes/add-split-line-dealing/specs/split-shard-holders/spec.md  (SH-*)
//     sha256 39adcd7c5d63c364bf2c0e23e4b7165dd9423a24eff845e5a0bbbe2716222733
//     (SH-038, DECISIONS 72, is the input of a hash and has no artifact here: REQMAP.md)
//   specs/refinement/baseline.yaml revision 6 with D-065 to D-072 (claims C1-C21 as INV-*, D items, Q-001..Q-008)
//     sha256 8f52752fc1a097e4da6236b06d4a7762cdaed5ec322ee1afa52a814e27f3c53d
//
// The model abstracts the committee to one honest board view (every honest node
// reads one board) plus explicit FINAL/VOID posts per member and epoch, so the
// counting rules of RQ-042..RQ-045 run over real members. Quorum votes (OPENED,
// ADMIT) commit as one event. Cryptographic failures are nondeterministic faults
// chosen at post time and recorded in the request (`fault`).
//
// Field names follow the spec (RQ-002, SL-002, SL-003, AU-001, AU-002, CP-001,
// CP-002). Model-only fields are listed in README.md. Ghost (history) state is
// in the variable `g` and is not part of the replay contract.
module splitspec {
  // ---------------------------------------------------------------- constants
  const MODE: str      // "TEE" | "NON_TEE" (RQ-001 mode)
  const PROFILE: str   // "P1" | "P2"  (charter profile of the one record)
  const MUT: str       // "none", or the name of one planted rule change (README)

  // RQ-001 committee parameters, small instance n = 4, f = 1.
  pure def qOf(n: int, f: int): int = (n + f + 2) / 2      // ceil((n+f+1)/2)
  pure def tOf(n: int, f: int): int = n - f
  pure def wOf(n: int, f: int): int = n - 1 - f
  pure val N = 4
  pure val F = 1
  pure val Q = qOf(N, F)
  pure val T = tOf(N, F)
  pure val W = wOf(N, F)
  pure val G_MAX = 2
  pure val DELTA_C = 4         // collection window and precedence lapse, in board blocks
  pure val DELTA_HOLD = 1      // RQ-033 hold wait, Midnight blocks
  pure val B = 2               // SL-012 reservation window
  pure val EIDS = 1.to(3)
  pure val CSLOTS = 1.to(4)    // one committee pool (BIP340, epoch 1), SL-001
  pure val ESLOTS = 1.to(3)    // one account pool, SL-003
  pure val EROOT = Map(1 -> "OWN", 2 -> "OWN", 3 -> "G")
  pure val MEMBERS = 1.to(N)
  pure val CORRUPT = Set(1)    // |C| = 1 <= f in every epoch
  pure val MAX_H = 22
  pure val MAX_MH = 10
  pure val MAX_CP = 6
  pure val REASONS = Set("SHARE_COMPLAINT", "MALFORMED", "AUTH_REFUSED", "REVOKED", "RELEASE_CHECK",
                         "CONTRIBUTION", "DEALER_FAULT", "PIN_SPENT", "SLOT_TAKEN", "STALLED", "RESTART")
  // RQ-065 domain: the post reasons plus MIXED, the reason of a tombstone with no common reason (RQ-072).
  pure val REASON_DOM = REASONS.union(Set("MIXED"))
  pure val FAULTS = Set("bad_share", "malformed", "dealer_fault", "auth_refused", "release_check", "contribution")

  pure def mut(x: str): bool = MUT == x

  // ------------------------------------------------------------------- types
  type Req = {
    eid: int, epoch: int, exp: int, req_type: str, profile: str, order_pos: int, exp_c: int,
    phase: str, reason: str, collecting: bool, K: int, L: int, G: int,
    anchor: int -> int, released: int -> int, any_release: bool, restart_end: bool, outcome: str,
    // model fields (README "Model-only fields")
    suite: str, source: str, cslot: int -> int, eslot: int -> int, fault: str,
    filled: bool, frame_held: bool, hdr_open: bool, complaint: str, dealer_fault_recorded: bool,
    end_height: int, lapsed: bool, release_height: int,
  }
  type Auth = { auth: int, nf: int, status: str, final_height: int, settled: str, coin: int, pin: int }
  type AssetRec = { rstate: str, nf: int, nf_used: bool, coin: int, pin: int, hold_set: bool,
               next_nf: int, next_pin: int, pending_auth: int }
  type CSlot = { bstat: str, prec: int, namers: Set[int], rsv: bool }
  type ESlot = { root: str, bstat: str, prec: int, reserver: int, namers: Set[int] }
  type Cp = { seq: int, board_height: int, h: int, pending_min: int, pending: Set[(int, int)],
              pending_count: int, settle_root: Set[(int, str)], restart_seq: int }
  type Post = { eid: int, epoch: int, member: int, kind: str, reason: str }
  // SH-030 to SH-037 (DECISIONS 67): the asset record of one address with a network-created shard.
  // `ec_ok`: the E_c of the record is the one behind delta (x_u·G = X_u for the holder);
  // `ack_env`: the ACK envelope that opened ("NONE", "HOLDER" with a valid pop_u, "CREATOR" without);
  // `ack_ok`: the members that signed ACK_OK; `acked`: the contract flag; `paid`: a payer paid.
  type Addr = { registered: bool, ec_ok: bool, ack_env: str, ack_ok: Set[int], acked: bool, paid: bool }
  type State = {
    requests: int -> Req, auths: int -> Auth, record: AssetRec,
    cslots: int -> CSlot, eslots: int -> ESlot,
    board_height: int, midnight_height: int,
    cp: Cp, held: int -> str, signed_leaf: int -> str,
    committee_txs: int, checkpoints: int, eks_writes: int,
    posts: Set[Post], epochs: Set[int],
    host_spent: Set[(int, int, int)],   // (coin, pin, eid): host-chain confirmations
    restart_open: bool, restarts: int,
    addr: Addr,
  }
  type Ghost = {
    sent: Set[(int, int, int)],          // (eid, g, j): release partials that left the nodes
    slot_tickets: Set[(str, int, int, int)], // (pool kind, index, eid, variant) honest partials per slot
    sent_revoked: Set[int],
    admitted: Set[int],
    hdr_sent: Set[int],
    honest_void: Set[(int, str)],
    taken_by: Set[(int, int, str)],      // (victim, blocker, pool kind) of honest SLOT_TAKEN posts
    restart_hit: Set[int],               // ended after the latest landed cp and holding a burned slot
    held_changed: bool,
    cp_prev: Cp,
    first_after_restart: bool,
    burn_lo: int, burn_hi: int, burned_usable: int, burned_pending: int,
    eburn_restart: Set[int],
    rel_seen: Set[(int, int, int)],      // (eid, g, j): every released[g] = j that RQ-037 set (RQ-076)
    adm_posts: Set[(int, str, bool)],    // (eid, reason, in force) of honest AUTH_REFUSED and SL-016 SLOT_TAKEN posts
  }
  type Op = { kind: str, eid: int, arg: int, code: str }

  // ------------------------------------------------------------- helpers
  pure def has(m: a -> b, k: a): bool = m.keys().contains(k)
  pure def terminal(p: str): bool = p == "FINAL" or p == "VOID" or p == "EXPIRED"
  pure def maxOf(s: Set[int], d: int): int = s.fold(d, (acc, x) => if (x > acc) x else acc)
  pure def minOf(s: Set[int], d: int): int = s.fold(d, (acc, x) => if (x < acc) x else acc)
  pure def gens(r: Req): Set[int] = 1.to(r.G)
  pure def variants(r: Req): Set[int] = 1.to(r.K)
  pure def cIdx(r: Req): Set[int] = if (r.suite == "SCHNORR") gens(r).map(g => r.cslot.get(g)) else Set()
  pure def eIdx(r: Req): Set[int] = if (r.suite == "ECDSA") variants(r).map(v => r.eslot.get(v)) else Set()
  pure def srcRoot(src: str): str = if (src == "SEIZURE") "G" else "OWN"   // AU-006

  // No checkpoint has landed: board_height -1, so an end at board height 0 is in the first interval.
  pure val cpZero: Cp = { seq: 0, board_height: -1, h: 0, pending_min: 1, pending: Set(),
                          pending_count: 0, settle_root: Set(), restart_seq: 0 }

  // AU-010: in force from the Midnight block at which authorize is final.
  pure def inForce(s: State, e: int): bool = has(s.auths, e) and s.auths.get(e).final_height >= 0
  pure def revoked(s: State, e: int): bool = has(s.auths, e) and s.auths.get(e).status == "REVOKED"
  pure def settledAuth(s: State, e: int): bool = has(s.auths, e) and s.auths.get(e).settled != "NONE"
  pure def live(s: State, e: int): bool = has(s.requests, e) and not(terminal(s.requests.get(e).phase))
  pure def spentBy(s: State, e: int): bool = s.host_spent.exists(x => x._3 == e)
  pure def pinSpent(s: State, e: int): bool =
    has(s.auths, e) and s.host_spent.exists(x => x._2 == s.auths.get(e).pin)

  // SL-012 window of the latest landed checkpoint.
  pure def inWindow(s: State, idx: int, e: int): bool =
    (s.cp.h < idx and idx <= s.cp.h + B) or
    (s.cp.pending_min <= idx and idx <= s.cp.h and s.cp.pending.contains((idx, e)))
  // SL-013 below the window.
  pure def belowWindow(s: State, idx: int, e: int): bool =
    idx < s.cp.pending_min or
    (s.cp.pending_min <= idx and idx <= s.cp.h and not(s.cp.pending.contains((idx, e))))
  // SL-014 above the window.
  pure def aboveWindow(s: State, idx: int): bool = idx > s.cp.h + B

  // SL-016: committee slot under another precedence; ECDSA slot under another in-force
  // precedence. SL-013: a committee index below the window. The planted rule
  // "ecdsa_prec_at_open" treats ECDSA slots as committee slots.
  pure def precTakenC(s: State, e: int, idx: int): bool =
    val c = s.cslots.get(idx)
    c.prec != 0 and c.prec != e
  pure def takenC(s: State, e: int, idx: int): bool = precTakenC(s, e, idx) or belowWindow(s, idx, e)
  pure def takenE(s: State, e: int, idx: int): bool =
    val x = s.eslots.get(idx)
    if (mut("ecdsa_prec_at_open")) x.prec != 0 and x.prec != e
    else x.prec != 0 and x.prec != e and inForce(s, x.prec)
  pure def blockersOf(s: State, e: int): Set[(int, str)] =
    val r = s.requests.get(e)
    cIdx(r).filter(i => s.cslots.get(i).prec != 0 and s.cslots.get(i).prec != e).map(i => (s.cslots.get(i).prec, "C"))
      .union(eIdx(r).filter(i => takenE(s, e, i)).map(i => (s.eslots.get(i).prec, "E")))
  pure def slotTaken(s: State, e: int): bool =
    val r = s.requests.get(e)
    cIdx(r).exists(i => takenC(s, e, i)) or eIdx(r).exists(i => takenE(s, e, i))
  // SL-013: "If a header names a committee index below cp.pending_min, or an index in
  // [cp.pending_min, cp.h] that the pending list does not hold for its own request" (no in-force clause).
  pure def belowTaken(s: State, e: int): bool =
    val r = s.requests.get(e)
    cIdx(r).exists(i => belowWindow(s, i, e))
  // SL-016 (DECISIONS 68): "While the authorization of an opened request is in force, if its header
  // names a committee slot whose prec is another request, or an ECDSA slot whose prec is another
  // request with an authorization in force". The planted "taken_before_force" drops the clause.
  pure def precTaken(s: State, e: int): bool =
    val r = s.requests.get(e)
    (inForce(s, e) or mut("taken_before_force")) and
    (cIdx(r).exists(i => precTakenC(s, e, i)) or eIdx(r).exists(i => takenE(s, e, i)))

  // Admission and OPENED-vote slot checks (RQ-016, RQ-023: SL-004, SL-006, SL-012).
  pure def slotsOk(s: State, e: int): bool =
    val r = s.requests.get(e)
    cIdx(r).forall(i => s.cslots.get(i).prec == e and s.cslots.get(i).bstat != "BURNED" and inWindow(s, i, e))
    and eIdx(r).forall(i => s.eslots.get(i).prec == e and s.eslots.get(i).bstat != "BURNED")

  // RQ-049..RQ-052 outcome of an end. The planted "restart_void_unspent" is the rule that
  // DECISIONS 53 replaced: a restart end with an unspent pin and no visible release is VOID.
  pure def outcomeOf(s: State, r: Req): str =
    if (r.phase == "FINAL") "FINAL"
    else if (r.restart_end)
      (if (spentBy(s, r.eid)) "FINAL"
       else if (mut("restart_void_unspent") and not(pinSpent(s, r.eid)) and not(r.any_release)) "VOID"
       else "RELEASED")
    else if (r.any_release) "RELEASED"
    else "VOID"

  // SL-010: a committee slot burns when the request with prec ends or lapses, used or not.
  pure def burnC(c: CSlot, e: int): CSlot =
    if (c.prec == e and (not(mut("committee_burn_reserved_only")) or c.rsv)) { ...c, bstat: "BURNED" } else c
  // SL-011: an ECDSA slot burns when the request in `reserver` ends.
  pure def burnE(x: ESlot, e: int): ESlot =
    val hit = if (mut("ecdsa_burn_by_namer")) x.reserver == e or x.namers.contains(e)
              else if (mut("ecdsa_prec_at_open")) x.reserver == e or x.prec == e
              else x.reserver == e
    if (hit) { ...x, bstat: "BURNED" } else x

  // SL-005 (DECISIONS 63), state-driven: while the board height is at least b + DELTA_C and the
  // authorization was not in force at b + DELTA_C, the precedence of the request is lapsed, and
  // SL-010 burns every committee slot where it holds prec. Evaluated after every event that
  // raises the board height (tick, order, checkpoint), so it fires at b + DELTA_C exactly; a
  // header that opens later burns its slots in openHeaderNow. The planted "lapse_once" is the
  // event rule of revision 2: lapse only on tick, burn only the slots held at that event.
  pure def applyLapse(s: State, onTick: bool): State =
    val h = s.board_height
    val lapse = EIDS.filter(x => has(s.requests, x) and live(s, x) and s.requests.get(x).order_pos >= 0 and
                                 not(s.requests.get(x).lapsed) and h >= s.requests.get(x).order_pos + DELTA_C and
                                 not(inForce(s, x)))
    val reqs = s.requests.keys().mapBy(x => if (lapse.contains(x)) { ...s.requests.get(x), lapsed: true } else s.requests.get(x))
    val burnSet = if (mut("lapse_once")) lapse
                  else EIDS.filter(x => has(reqs, x) and reqs.get(x).lapsed and live(s, x))
    if (mut("lapse_once") and not(onTick)) s
    else { ...s, requests: reqs, cslots: CSLOTS.mapBy(i => burnSet.fold(s.cslots.get(i), (c, x) => burnC(c, x))) }

  // End of a request (RQ-044..RQ-053, SL-010, SL-011).
  pure def endReq(s: State, e: int, ph: str, rs: str): State =
    val r1 = { ...s.requests.get(e), phase: ph, reason: rs, end_height: s.board_height }
    val r2 = { ...r1, outcome: outcomeOf(s, r1) }
    val leaf = if (has(s.auths, e)) s.signed_leaf.put(e, r2.outcome) else s.signed_leaf
    { ...s,
      requests: s.requests.set(e, r2),
      signed_leaf: leaf,
      cslots: CSLOTS.mapBy(i => burnC(s.cslots.get(i), e)),
      eslots: ESLOTS.mapBy(i => burnE(s.eslots.get(i), e)),
      committee_txs: if (mut("settle_per_request") and has(s.auths, e)) s.committee_txs + 1 else s.committee_txs,
    }

  // RQ-046 "When the board height passes exp of a request whose phase is not FINAL or VOID, the
  // request state machine SHALL set phase = EXPIRED" (lead ruling A: expiry is urgent). Applied
  // inside every event that raises the board height (tick, order, checkpoint), so no event lands
  // on a live request whose exp the board height has passed. The planted "late_expiry" is the
  // rule of item 14: a separate `expire` event that may come any number of steps later.
  pure def applyExpiry(s: State): State =
    if (mut("late_expiry")) s
    else EIDS.fold(s, (acc, x) =>
      if (live(acc, x) and acc.board_height > acc.requests.get(x).exp)
        endReq(acc, x, "EXPIRED", acc.requests.get(x).reason)
      else acc)
  // Every event that raises the board height: RQ-046 expiry first, then the SL-005 lapse.
  pure def advance(s: State, onTick: bool): State = applyLapse(applyExpiry(s), onTick)

  // RQ-005: events other than settlement signatures and the RQ-068 re-end are refused on a
  // terminal request; every node event below requires `live`.

  // Honest VOID conditions (RQ-011, RQ-014, RQ-015, RQ-025, RQ-031, RQ-034, RQ-038, RQ-041,
  // RQ-047, RQ-048, SL-013, SL-016, AU-028).
  pure def voidCond(s: State, e: int, rs: str): bool =
    val r = s.requests.get(e)
    val pre = r.phase == "ORDERED" or r.phase == "OPENED" or r.phase == "COLLECTING"
    val opn = r.phase == "OPENED" or r.phase == "COLLECTING"
    if (rs == "SHARE_COMPLAINT") r.complaint == "early"
    else if (rs == "MALFORMED") r.fault == "malformed" and r.hdr_open and r.phase == "ORDERED"
    else if (rs == "DEALER_FAULT") r.fault == "dealer_fault" and r.phase == "ORDERED"
    // RQ-025 (DECISIONS 68): "the authorization of auth_ref is in force and its record does not open
    // to the hd and the tkc of the header". The model's authorize never fails, so the "Midnight
    // refused the authorize call" branch has no event. The planted "auth_refused_before_force"
    // drops the in-force clause (the RQ-025 of revision 5).
    else if (rs == "AUTH_REFUSED") r.fault == "auth_refused" and opn and (inForce(s, e) or mut("auth_refused_before_force"))
    else if (rs == "REVOKED") revoked(s, e) and not(r.any_release)
    else if (rs == "RELEASE_CHECK") r.fault == "release_check" and r.phase == "ADMITTED"
    else if (rs == "CONTRIBUTION") r.fault == "contribution" and r.phase == "ADMITTED" and r.anchor.get(1) != 0
    else if (rs == "PIN_SPENT") MODE == "TEE" and not(r.any_release) and pinSpent(s, e) and not(spentBy(s, e))
    else if (rs == "SLOT_TAKEN") opn and (belowTaken(s, e) or precTaken(s, e))
    else if (rs == "STALLED") r.collecting and opn and s.board_height >= r.exp_c
    else if (rs == "RESTART") r.restart_end
    else false

  // ------------------------------------------------------------------ state
  var st: State
  var g: Ghost
  var lastOp: Op

  pure val ghost0: Ghost = {
    sent: Set(), slot_tickets: Set(), sent_revoked: Set(), admitted: Set(), hdr_sent: Set(),
    honest_void: Set(), taken_by: Set(), restart_hit: Set(), held_changed: false,
    cp_prev: cpZero, first_after_restart: false,
    burn_lo: 0, burn_hi: -1, burned_usable: 0, burned_pending: 0, eburn_restart: Set(),
    rel_seen: Set(), adm_posts: Set(),
  }

  pure val st0: State = {
    requests: Map(), auths: Map(),
    record: { rstate: "UNSPENT", nf: 1, nf_used: false, coin: 1, pin: -1, hold_set: false,
              next_nf: 2, next_pin: 1, pending_auth: 0 },
    cslots: CSLOTS.mapBy(_ => { bstat: "UNNAMED", prec: 0, namers: Set(), rsv: false }),
    eslots: ESLOTS.mapBy(i => { root: EROOT.get(i), bstat: "UNNAMED", prec: 0, reserver: 0, namers: Set() }),
    board_height: 0, midnight_height: 0,
    cp: cpZero, held: Map(), signed_leaf: Map(),
    committee_txs: 0, checkpoints: 0, eks_writes: 0,
    posts: Set(), epochs: Set(1),
    host_spent: Set(),
    restart_open: false, restarts: 0,
    addr: addrNone,
  }
  pure val addrNone: Addr = { registered: false, ec_ok: false, ack_env: "NONE", ack_ok: Set(), acked: false, paid: false }
  action init = all {
    st' = st0,
    g' = ghost0,
    lastOp' = { kind: "init", eid: 0, arg: 0, code: "" },
  }
  // initArmed (practice 20 of the formal kit, "start from any valid state"): the state after
  // post(1) by the owner, authorize(1), finalizeAuth(1) and one Midnight block, with the grid
  // of request 1 picked at random. Every later event is sampled as from init.
  action initArmed = {
    nondet sh = SHAPES.oneOf()
    val Kx = if (sh._1 == "ECDSA") (if (sh._2 > 2) 2 else sh._2) else sh._2
    val r1: Req = { ...reqNone, eid: 1, epoch: 1, exp: 16, profile: PROFILE, source: "OWNER",
                    suite: sh._1, K: Kx, G: (if (Kx < G_MAX) Kx else G_MAX), collecting: sh._3 }
    all {
      st' = { ...st0, requests: Map(1 -> r1), midnight_height: 1,
              auths: Map(1 -> { auth: 1, nf: 1, status: "FINAL", final_height: 0, settled: "NONE", coin: 1, pin: 1 }),
              record: { ...st0.record, rstate: "PENDING", nf_used: true, next_pin: 2, pending_auth: 1 } },
      g' = ghost0,
      lastOp' = { kind: "init_armed", eid: 1, arg: 0, code: "" },
    }
  }

  // Absent eids read as a placeholder so that let-bindings before a guard stay defined.
  pure val reqNone: Req = {
    eid: 0, epoch: 0, exp: -1, req_type: "SPEND", profile: "P1", order_pos: -1, exp_c: -1,
    phase: "POSTED", reason: "NONE", collecting: false, K: 1, L: 1, G: 1,
    anchor: Map(1 -> 0, 2 -> 0), released: Map(1 -> 0, 2 -> 0), any_release: false, restart_end: false, outcome: "NONE",
    suite: "SCHNORR", source: "NONE", cslot: Map(1 -> 1, 2 -> 2), eslot: Map(1 -> 1, 2 -> 2), fault: "none",
    filled: false, frame_held: false, hdr_open: false, complaint: "none", dealer_fault_recorded: false,
    end_height: -1, lapsed: false, release_height: -1,
  }
  pure val authNone: Auth = { auth: 0, nf: -1, status: "NONE", final_height: -1, settled: "NONE", coin: 0, pin: -1 }
  def req(e: int): Req = if (has(st.requests, e)) st.requests.get(e) else reqNone
  action done(k: str, e: int, a: int): bool = lastOp' = { kind: k, eid: e, arg: a, code: "" }

  // --------------------------------------------------------------- actions
  // RQ-003 (EN-004..EN-008 passed): a request is added with phase POSTED.
  // RQ-002 fields; RQ-066 type/profile; RQ-067 grid; EN-021 exp.
  // Nondeterministic post: one pick per independent choice, drawn only once the guard holds.
  pure val SHAPES = tuples(Set("SCHNORR", "ECDSA"), 1.to(3), Set(false, true))
  pure val CPAIRS = tuples(CSLOTS, CSLOTS).filter(p => p._1 != p._2)
  pure val EPAIRS = tuples(ESLOTS, ESLOTS).filter(p => p._1 != p._2)
  pure val SRCS = List("OWNER", "OWNER", "SEIZURE", "NONE")
  pure val FAULTL = List("none", "none", "none", "none", "bad_share", "malformed", "dealer_fault",
                         "auth_refused", "release_check", "contribution")
  action post(e: int): bool = all { not(has(st.requests, e)), EIDS.contains(e), st.board_height < MAX_H, postPick(e) }
  action postPick(e: int): bool = {
    nondet sh = SHAPES.oneOf()
    nondet cpAny = CPAIRS.oneOf()
    nondet wi = 0.to(3).oneOf()
    // Sampling bias: three times in four the committee slots come from the current window.
    val winPairs = CPAIRS.filter(p => p._1 > st.cp.h and p._1 <= st.cp.h + B and
                                      (sh._2 == 1 or (p._2 > st.cp.h and p._2 <= st.cp.h + B)))
    nondet cpWin = (if (winPairs == Set()) CPAIRS else winPairs).oneOf()
    val cp2 = if (wi < 3) cpWin else cpAny
    nondet ep2 = EPAIRS.oneOf()
    nondet si = 0.to(3).oneOf()
    nondet fi = 0.to(9).oneOf()
    nondet expOff = Set(10, 13, 16).oneOf()
    val src0 = SRCS.nth(si)
    val src = if (src0 == "SEIZURE" and PROFILE != "P2") "OWNER" else src0
    postWith(e, sh._1, src, sh._2, sh._3, cp2._1, cp2._2, ep2._1, ep2._2, FAULTL.nth(fi), expOff)
  }
  action postWith(e: int, suite: str, src: str, K: int, collecting: bool, c1: int, c2: int,
                  e1: int, e2: int, fault: str, expOff: int): bool = {
    val Kx = if (suite == "ECDSA") (if (K > 2) 2 else K) else K
    val Gx = if (Kx < G_MAX) Kx else G_MAX
    all {
      not(has(st.requests, e)), EIDS.contains(e),
      st.board_height < MAX_H,
      c1 != c2, e1 != e2,
      src != "SEIZURE" or PROFILE == "P2",
      en023Ok(st.board_height + 1, st.board_height + expOff),   // EN-023 at acceptance
      st' = { ...st, requests: st.requests.put(e, {
        eid: e, epoch: 1, exp: st.board_height + expOff,
        req_type: if (src == "SEIZURE") "SEIZURE" else "SPEND", profile: PROFILE,
        order_pos: -1, exp_c: -1, phase: "POSTED", reason: "NONE", collecting: collecting,
        K: Kx, L: 1, G: Gx,
        anchor: Map(1 -> 0, 2 -> 0), released: Map(1 -> 0, 2 -> 0),
        any_release: false, restart_end: false, outcome: "NONE",
        suite: suite, source: src, cslot: Map(1 -> c1, 2 -> c2), eslot: Map(1 -> e1, 2 -> e2),
        fault: fault,
        filled: false, frame_held: false, hdr_open: false, complaint: "none", dealer_fault_recorded: false,
        end_height: -1, lapsed: false, release_height: -1,
      }) },
      g' = g,
      done("post", e, 0),
    }
  }

  // EN-023 (DECISIONS 62): the board height b that would order the envelope gives b + DELTA_C < exp.
  // The planted "exp_c_unchecked" drops the check (EN-021 as a wallet duty only).
  pure def en023Ok(b: int, exp: int): bool = mut("exp_c_unchecked") or b + DELTA_C < exp

  // AU-004, AU-005, AU-006, AU-007, AU-009: authorize on Midnight (Midnight-first).
  action authorize(e: int): bool = {
    val r = req(e)
    val rc = st.record
    val pin = if (rc.rstate == "LOCKED") rc.pin else rc.next_pin
    all {
      has(st.requests, e), not(has(st.auths, e)), r.source != "NONE",
      live(st, e),            // model choice: the wallet authorizes only a live request (README)
      rc.rstate != "PENDING", not(rc.nf_used),
      not(rc.hold_set) or r.source == "SEIZURE",                       // AU-007 hold accumulator
      eIdx(r).forall(i => EROOT.get(i) == srcRoot(r.source)),          // AU-005 item 4, AU-006
      st' = { ...st,
        auths: st.auths.put(e, { auth: e, nf: rc.nf, status: "SUBMITTED", final_height: -1,
                                 settled: "NONE", coin: rc.coin, pin: pin }),
        record: { ...rc, rstate: "PENDING", nf_used: true, pending_auth: e,
                  next_pin: if (rc.rstate == "LOCKED") rc.next_pin else rc.next_pin + 1 } },
      g' = g,
      done("authorize", e, pin),
    }
  }

  // AU-010 (AU-002 status FINAL): the authorize transaction becomes final on Midnight.
  action finalizeAuth(e: int): bool = all {
    has(st.auths, e), st.auths.get(e).status == "SUBMITTED",
    st' = { ...st, auths: st.auths.set(e, { ...st.auths.get(e), status: "FINAL", final_height: st.midnight_height }) },
    g' = g,
    done("finalize_auth", e, st.midnight_height),
  }

  // AU-018: the hold authority revokes a P2 authorization and sets the hold tag.
  action revoke(e: int): bool = {
    val a = if (has(st.auths, e)) st.auths.get(e) else authNone
    all {
      PROFILE == "P2", has(st.auths, e),
      a.status == "SUBMITTED" or a.status == "FINAL", a.settled == "NONE",
      st' = { ...st, auths: st.auths.set(e, { ...a, status: "REVOKED" }),
                     record: { ...st.record, hold_set: true } },
      g' = g,
      done("revoke", e, 0),
    }
  }

  // ECDSA precedence when the authorization is in force and the header is open (SL-006),
  // earliest in board order among the eligible in-force requests. SL-007: no authorization,
  // no change.
  pure def ecdsaEligible(s: State, e: int): Set[int] =
    if (not(has(s.requests, e))) Set() else {
      val r = s.requests.get(e)
      if (r.hdr_open and live(s, e) and inForce(s, e) and r.phase != "ORDERED")
        eIdx(r).filter(i => EROOT.get(i) == srcRoot(r.source) and s.eslots.get(i).prec == 0
                            and s.eslots.get(i).bstat != "BURNED")
      else Set()
    }
  action ecdsaPrec(e: int): bool = {
    val sl = ecdsaEligible(st, e)
    val earlier = EIDS.filter(x => x != e and has(st.requests, x) and
                                   ecdsaEligible(st, x).intersect(sl) != Set() and
                                   st.requests.get(x).order_pos < req(e).order_pos)
    all {
      not(mut("ecdsa_prec_at_open")),
      sl != Set(), earlier == Set(),
      st' = { ...st, eslots: ESLOTS.mapBy(i =>
        if (sl.contains(i)) { ...st.eslots.get(i), prec: e, bstat: "NAMED" } else st.eslots.get(i)) },
      g' = g,
      done("ecdsa_prec", e, 0),
    }
  }

  // RQ-006 order (QC at board position p = height b); RQ-009 header partials leave only now.
  // EN-023 again for the ordering block; SL-005 lapse at the new height.
  action order(e: int): bool = all {
    has(st.requests, e), req(e).phase == "POSTED", st.board_height < MAX_H,
    en023Ok(st.board_height + 1, req(e).exp),
    st' = advance({ ...st, board_height: st.board_height + 1,
            requests: st.requests.set(e, { ...req(e), phase: "ORDERED", order_pos: st.board_height + 1,
                                           exp_c: st.board_height + 1 + DELTA_C }) }, false),
    g' = { ...g, hdr_sent: if (req(e).fault == "bad_share") g.hdr_sent else g.hdr_sent.union(Set(e)) },
    done("order", e, st.board_height + 1),
  }

  // RQ-010/RQ-011/RQ-012: a verified share complaint is ordered.
  action complain(e: int): bool = {
    val r = req(e)
    val early = r.phase == "ORDERED" or r.phase == "OPENED" or r.phase == "COLLECTING"
    all {
      has(st.requests, e), live(st, e), r.fault == "bad_share", r.complaint == "none", r.phase != "POSTED",
      st' = { ...st, requests: st.requests.set(e,
        if (early) { ...r, complaint: "early" } else { ...r, complaint: "late", dealer_fault_recorded: true }) },
      g' = g,
      done("complain", e, if (early) 1 else 2),
    }
  }

  // RQ-013 open; RQ-014 malformed header stays ORDERED with VOID MALFORMED pending;
  // RQ-015 dealer fault never opens. SL-004 committee precedence (Q-003: judged only after
  // every earlier-ordered live envelope opened or ended, provisional). RQ-062 is out of scope:
  // every modelled type signs.
  action openHeader(e: int): bool = all {
    has(st.requests, e), req(e).phase == "ORDERED", not(req(e).hdr_open), openHeaderNow(e) }
  action openHeaderNow(e: int): bool = {
    val r = req(e)
    val earlierWait = EIDS.exists(x => has(st.requests, x) and x != e and
      st.requests.get(x).order_pos >= 0 and st.requests.get(x).order_pos < r.order_pos and
      not(st.requests.get(x).hdr_open) and live(st, x))
    val ok = r.fault != "malformed"
    val cs = CSLOTS.mapBy(i => {
      val c = st.cslots.get(i)
      if (ok and cIdx(r).contains(i))
        (if (c.prec == 0 and c.bstat == "UNNAMED") { ...c, prec: e, bstat: "NAMED", namers: c.namers.union(Set(e)) }
         else { ...c, namers: c.namers.union(Set(e)) })
      else c })
    val es = ESLOTS.mapBy(i => {
      val x = st.eslots.get(i)
      if (ok and eIdx(r).contains(i))
        (if (mut("ecdsa_prec_at_open") and x.prec == 0 and x.bstat == "UNNAMED")
           { ...x, prec: e, bstat: "NAMED", namers: x.namers.union(Set(e)) }
         else { ...x, namers: x.namers.union(Set(e)) })
      else x })
    // SL-005 (DECISIONS 63): a lapsed request takes a lapsed precedence; SL-010 burns the slot.
    val cs2 = if (r.lapsed and not(mut("lapse_once"))) CSLOTS.mapBy(i => burnC(cs.get(i), e)) else cs
    all {
      has(st.requests, e), r.phase == "ORDERED", not(r.hdr_open), r.fault != "dealer_fault",
      not(earlierWait),
      st' = { ...st,
        requests: st.requests.set(e, if (ok) { ...r, phase: "OPENED", hdr_open: true } else { ...r, hdr_open: true }),
        cslots: cs2, eslots: es },
      g' = g,
      done("open", e, if (ok) 1 else 0),
    }
  }

  // SL-008 reserve on q votes.
  pure def reserve(s: State, e: int, claim: bool): State =
    val r = s.requests.get(e)
    val bs = if (claim) "CLAIMED" else "RESERVED"
    { ...s,
      cslots: CSLOTS.mapBy(i => if (cIdx(r).contains(i)) { ...s.cslots.get(i), bstat: bs, rsv: true } else s.cslots.get(i)),
      eslots: ESLOTS.mapBy(i => if (eIdx(r).contains(i)) { ...s.eslots.get(i), bstat: bs, reserver: e } else s.eslots.get(i)) }

  // RQ-016, RQ-017, SL-008, RQ-021 (held frames attach): q OPENED votes commit.
  action openedVote(e: int): bool = {
    val r = req(e)
    all {
      has(st.requests, e), r.phase == "OPENED", r.collecting, inForce(st, e),
      not(settledAuth(st, e)), slotsOk(st, e), r.fault != "auth_refused",
      val s1 = reserve(st, e, false)
      st' = { ...s1, requests: s1.requests.set(e, { ...r, phase: "COLLECTING", filled: r.filled or r.frame_held }) },
      g' = g,
      done("opened_vote", e, 0),
    }
  }

  // RQ-018 attach ("a contribution frame ordered at a board height at most exp_c ... phase =
  // COLLECTING"); RQ-021 hold ("While the target request ... has phase POSTED or ORDERED ... hold
  // the frame"). RQ-020 ("ordered at a board height above exp_c of its target request ... refuse")
  // names no phase, so the ORDERED hold carries the height guard too (lead ruling B); POSTED has no
  // exp_c yet. RQ-075 (DECISIONS 70, lead ruling C): OPENED and ADMITTED targets are refused.
  action frame(e: int): bool = {
    val r = req(e)
    all {
      has(st.requests, e), r.collecting,
      or {
        r.phase == "COLLECTING" and not(r.filled) and st.board_height <= r.exp_c,
        r.phase == "POSTED" and not(r.frame_held),
        r.phase == "ORDERED" and not(r.frame_held) and st.board_height <= r.exp_c,
      },
      st' = { ...st, requests: st.requests.set(e,
        if (r.phase == "COLLECTING") { ...r, filled: true } else { ...r, frame_held: true }) },
      g' = g,
      done("frame", e, st.board_height),
    }
  }

  // RQ-022: a verified complaint against an attached frame detaches it.
  action frameComplaint(e: int): bool = {
    val r = req(e)
    all {
      has(st.requests, e), r.phase == "COLLECTING", r.filled,
      st' = { ...st, requests: st.requests.set(e, { ...r, filled: false }) },
      g' = g,
      done("frame_complaint", e, 0),
    }
  }

  // RQ-023, RQ-026, RQ-027, SL-008, SL-009: the first q ADMIT votes commit.
  action admit(e: int): bool = {
    nondet j = variants(req(e)).oneOf()
    admitWith(e, j)
  }
  action admitWith(e: int, j: int): bool = {
    val r = req(e)
    all {
      variants(r).contains(j),
      has(st.requests, e),
      (r.phase == "OPENED" and not(r.collecting)) or (r.phase == "COLLECTING" and r.filled),
      inForce(st, e), not(revoked(st, e)), not(settledAuth(st, e)),
      slotsOk(st, e), r.fault != "auth_refused",
      val s1 = reserve(st, e, true)
      st' = { ...s1, requests: s1.requests.set(e, { ...r, phase: "ADMITTED", anchor: r.anchor.set(1, j) }) },
      g' = { ...g, admitted: g.admitted.union(Set(e)) },
      done("admit", e, j),
    }
  }

  // RQ-028: generation 2 anchor after generation 1 did not confirm by its deadline.
  action anchor2(e: int): bool = {
    nondet j = variants(req(e)).oneOf()
    anchor2With(e, j)
  }
  action anchor2With(e: int, j: int): bool = {
    val r = req(e)
    all {
      has(st.requests, e), r.phase == "ADMITTED", r.G == 2, r.anchor.get(2) == 0,
      not(spentBy(st, e)), j > r.anchor.get(1),
      st' = { ...st, requests: st.requests.set(e, { ...r, anchor: r.anchor.set(2, j) }) },
      g' = g,
      done("anchor2", e, j),
    }
  }

  // RQ-030..RQ-036, RQ-058, RQ-059, SL-019, SL-021: release partials for (anchor[g], g).
  // In TEE mode the w acks of RQ-035 come first and RQ-037 records the release at the ack.
  // In NON_TEE mode RQ-069 (DECISIONS 59): no partial before the node's RELEASE for (g, j) has
  // committed (released[g] = j). The planted "send_before_record" is the order of revision 2.
  action sendRelease(e: int, gg: int): bool = {
    nondet jAny = variants(req(e)).oneOf()
    sendReleaseWith(e, gg, if (mut("any_variant")) jAny else req(e).anchor.get(gg))
  }
  action sendReleaseWith(e: int, gg: int, j: int): bool = {
    val r = req(e)
    val a = if (has(st.auths, e)) st.auths.get(e) else authNone
    val tk = if (r.suite == "SCHNORR") ("C", r.cslot.get(gg), e, j) else ("E", r.eslot.get(j), e, j)
    val tee = MODE == "TEE"
    all {
      has(st.requests, e), r.phase == "ADMITTED", gens(r).contains(gg), r.anchor.get(gg) != 0, j != 0,
      not(g.sent.contains((e, gg, j))),
      has(st.auths, e), inForce(st, e),
      mut("ignore_revoke") or a.status != "REVOKED",                    // RQ-030, RQ-032, RQ-059
      r.fault != "release_check",                                       // RQ-031
      PROFILE != "P2" or gg != 1 or st.midnight_height >= a.final_height + DELTA_HOLD,  // RQ-033
      tee or mut("send_before_record") or r.released.get(gg) == j,      // RQ-069
      st' = if (tee) { ...st, requests: st.requests.set(e, { ...r, released: r.released.set(gg, j),
                                                                  any_release: true, release_height: st.board_height }) }
            else st,
      g' = { ...g, sent: g.sent.union(Set((e, gg, j))), slot_tickets: g.slot_tickets.union(Set(tk)),
                   sent_revoked: if (a.status == "REVOKED") g.sent_revoked.union(Set(e)) else g.sent_revoked,
                   rel_seen: if (tee) g.rel_seen.union(Set((e, gg, j))) else g.rel_seen },
      done("send_release", e, gg * 10 + j),
    }
  }

  // RQ-037, RQ-069 (NON_TEE): the node's RELEASE for (g, anchor[g]) commits in a board vote while
  // the request is ADMITTED and the release checks of RQ-030 hold; only then may it send (RQ-069).
  // Refused on a terminal request (RQ-005). Under "send_before_record" the RELEASE follows a send.
  action recordRelease(e: int, gg: int): bool = {
    val r = req(e)
    val a = if (has(st.auths, e)) st.auths.get(e) else authNone
    val js = 1.to(3).filter(j => g.sent.contains((e, gg, j)))
    val j = if (mut("send_before_record")) minOf(js, 0) else r.anchor.get(gg)
    all {
      MODE == "NON_TEE", has(st.requests, e), live(st, e), r.released.get(gg) == 0, j != 0,
      if (mut("send_before_record")) js != Set()
      else and {
        r.phase == "ADMITTED", gens(r).contains(gg), has(st.auths, e), inForce(st, e),
        a.status != "REVOKED", r.fault != "release_check",
        PROFILE != "P2" or gg != 1 or st.midnight_height >= a.final_height + DELTA_HOLD,
      },
      st' = { ...st, requests: st.requests.set(e, { ...r, released: r.released.set(gg, j),
                                                       any_release: true, release_height: st.board_height }) },
      g' = { ...g, rel_seen: g.rel_seen.union(Set((e, gg, j))) },
      done("record_release", e, gg),
    }
  }

  // Host chain: a combined signature of a released variant confirms if its pin is unspent.
  action hostConfirm(e: int): bool = {
    val r = req(e)
    val a = if (has(st.auths, e)) st.auths.get(e) else authNone
    all {
      has(st.requests, e), has(st.auths, e), g.sent.exists(x => x._1 == e),
      r.fault != "contribution", not(pinSpent(st, e)),
      st' = { ...st, host_spent: st.host_spent.union(Set((a.coin, a.pin, e))) },
      g' = g,
      done("host_confirm", e, a.pin),
    }
  }

  // RQ-042/RQ-043 serving epochs: epoch 1 binds; epoch 2 serves after its ROTATE.
  def serving(ep: int): bool = st.epochs.contains(ep)
  pure def countIn(ps: Set[Post], e: int, k: str, ep: int): int =
    ps.filter(p => p.eid == e and p.kind == k and p.epoch == ep).map(p => p.member).size()
  pure def countAll(ps: Set[Post], e: int, k: str): int =
    ps.filter(p => p.eid == e and p.kind == k).map(p => (p.epoch, p.member)).size()

  // RQ-040, RQ-044, RQ-049: FINAL posts; q in one serving epoch form the tombstone.
  action postFinal(e: int, ep: int, m: int): bool = all { live(st, e), serving(ep), postFinalNow(e, ep, m) }
  action postFinalNow(e: int, ep: int, m: int): bool = {
    val p = { eid: e, epoch: ep, member: m, kind: "FINAL", reason: "NONE" }
    val ps = st.posts.union(Set(p))
    val cnt = if (mut("cross_epoch")) countAll(ps, e, "FINAL") else countIn(ps, e, "FINAL", ep)
    all {
      has(st.requests, e), live(st, e), serving(ep), not(st.posts.contains(p)),
      CORRUPT.contains(m) or spentBy(st, e),
      val s1 = { ...st, posts: ps }
      st' = if (cnt >= Q) endReq(s1, e, "FINAL", "NONE") else s1,
      g' = g,
      done("post_final", e, ep * 10 + m),
    }
  }

  // RQ-042, RQ-045, RQ-072, RQ-050, RQ-051, RQ-052, RQ-053: VOID posts; f + 1 distinct members of
  // one serving epoch form the tombstone. Its reason is the reason of at least f + 1 counted posts,
  // or MIXED (DECISIONS 61, Q-002 resolved). The planted "completing_reason" takes the reason of
  // the completing post (revision 2). RQ-073, RQ-074 (DECISIONS 64, owner ruling): once
  // any_release = true, STALLED posts count toward the tombstone but are no reason posts, so the
  // reason is the reason of f + 1 remaining posts or MIXED. The planted "stalled_after_release"
  // counts them again (revision 3).
  pure def tombReason(counted: Set[Post], rs: str, rel: bool): str =
    val reasonPosts = if (rel and not(mut("stalled_after_release"))) counted.filter(p => p.reason != "STALLED") else counted
    if (mut("completing_reason")) rs
    else REASONS.filter(x => reasonPosts.filter(p => p.reason == x).size() >= F + 1).fold("MIXED", (acc, x) => x)
  action postVoid(e: int, ep: int, m: int, rs: str): bool = all { live(st, e), serving(ep), postVoidNow(e, ep, m, rs) }
  action postVoidNow(e: int, ep: int, m: int, rs: str): bool = {
    val p = { eid: e, epoch: ep, member: m, kind: "VOID", reason: rs }
    val ps = st.posts.union(Set(p))
    val cnt = if (mut("cross_epoch")) countAll(ps, e, "VOID") else countIn(ps, e, "VOID", ep)
    val counted = ps.filter(q => q.eid == e and q.kind == "VOID" and (mut("cross_epoch") or q.epoch == ep))
    val honest = not(CORRUPT.contains(m))
    all {
      has(st.requests, e), live(st, e), serving(ep),
      not(st.posts.exists(q => q.eid == e and q.kind == "VOID" and q.epoch == ep and q.member == m)),
      not(honest) or voidCond(st, e, rs),
      val s1 = { ...st, posts: ps }
      st' = if (cnt >= F + 1) endReq(s1, e, "VOID", tombReason(counted, rs, st.requests.get(e).any_release)) else s1,
      g' = { ...g,
        honest_void: if (honest) g.honest_void.union(Set((e, rs))) else g.honest_void,
        adm_posts: if (honest and (rs == "AUTH_REFUSED" or (rs == "SLOT_TAKEN" and not(belowTaken(st, e)))))
                     g.adm_posts.union(Set((e, rs, inForce(st, e)))) else g.adm_posts,
        taken_by: if (honest and rs == "SLOT_TAKEN") g.taken_by.union(blockersOf(st, e).map(b => (e, b._1, b._2)))
                  else g.taken_by },
      done("post_void", e, ep * 10 + m),
    }
  }

  // RQ-046 expiry is part of every height-raising event (applyExpiry, lead ruling A). The separate
  // `expire` event exists only under the planted "late_expiry" (the item 14 rule).
  action expire(e: int): bool = {
    val r = req(e)
    all {
      mut("late_expiry"),
      has(st.requests, e), r.phase != "FINAL", r.phase != "VOID", r.phase != "EXPIRED",
      st.board_height > r.exp,
      st' = endReq(st, e, "EXPIRED", r.reason),
      g' = g,
      done("expire", e, 0),
    }
  }

  // Board block; SL-005 lapse (state-driven, applyLapse) burns the committee slots of a lapsed request.
  action tick: bool = all { st.board_height < MAX_H, tickNow }
  action tickNow: bool = {
    val h = st.board_height + 1
    all {
      st.board_height < MAX_H,
      st' = advance({ ...st, board_height: h }, true),
      g' = g,
      done("tick", 0, h),
    }
  }

  action tickMidnight: bool = all {
    st.midnight_height < MAX_MH,
    st' = { ...st, midnight_height: st.midnight_height + 1 },
    g' = g,
    done("tick_midnight", 0, st.midnight_height + 1),
  }

  // ------------------------------------------------------------ checkpoint
  // CP-002, CP-013, CP-014: the honest checkpoint that the signers compute now.
  pure def leavesOf(s: State): Set[(int, str)] =
    s.requests.keys().filter(e => {
      val r = s.requests.get(e)
      terminal(r.phase) and has(s.auths, e) and r.end_height > s.cp.board_height and
      (if (mut("root_omit")) r.end_height < s.board_height else r.end_height <= s.board_height) and
      (not(has(s.held, e)) or s.held.get(e) == s.signed_leaf.get(e))       // CP-013 last clause
    }).map(e => (e, s.signed_leaf.get(e)))
  // CP-014 (DECISIONS 71): "the sorted list of the committee slots that live requests hold on the
  // board at or above the pending_min of the previous landed checkpoint for that pool". The model
  // has one pool; before the first checkpoint s.cp is cpZero with pending_min 1, the lowest index,
  // so the first list has no floor ("A pool that the previous landed checkpoint does not list has
  // no floor"). The planted "pending_unwindowed" restores the listing of revision 6 (finding F7).
  pure def pendingOf(s: State): Set[(int, int)] =
    tuples(CSLOTS, EIDS).filter(((i, e)) => s.cslots.get(i).prec == e and s.cslots.get(i).bstat != "BURNED" and live(s, e) and
      (mut("pending_unwindowed") or i >= s.cp.pending_min))
  pure def nextCp(s: State, gh: Ghost): Cp =
    val pend = pendingOf(s)
    val hRes = maxOf(CSLOTS.filter(i => s.cslots.get(i).rsv), 0)
    val hBurn = if (s.restart_open and not(mut("no_jump"))) gh.burn_hi else 0
    val h = maxOf(Set(s.cp.h, hRes, hBurn), 0)
    val pm = if (pend == Set()) h + 1 else minOf(pend.map(x => x._1), 1000)
    { seq: s.cp.seq + 1, board_height: s.board_height, h: h, pending_min: pm, pending: pend,
      pending_count: pend.size(), settle_root: leavesOf(s),
      restart_seq: if (s.restart_open) s.cp.seq + 1 else s.cp.restart_seq }
  // CP-007, CP-040, CP-008, CP-009/CP-041 contract checks. CP-040 (DECISIONS 69): "If a checkpoint
  // has pending_min below the pending_min of the previous landed checkpoint ... refuse ... with the
  // code pending_min_lowered"; the planted "pending_min_unchecked" drops it. CP-041: "a restart_seq
  // other than that of cp1 and ... cp2.h < cp1.h + B or cp2.pending_min <= cp1.h + B ... restart_jump".
  // In the model restart_seq moves exactly at the first checkpoint after the classification, where
  // CP-009 fires too (one checkpoint read, no seat-by-seat sync).
  pure def cpCode(old: Cp, c: Cp, restartOpen: bool): str =
    if (c.h < old.h) "h_lowered"
    else if (c.pending_min < old.pending_min and not(mut("pending_min_unchecked"))) "pending_min_lowered"
    else if (c.pending_min > c.h + 1) "pending_gap"
    else if ((restartOpen or c.restart_seq != old.restart_seq) and not(mut("no_jump")) and
             (c.h < old.h + B or c.pending_min <= old.h + B)) "restart_jump"
    else ""

  // AU-020, AU-023: apply one landed leaf.
  pure def applyLeaf(s: State, leaf: (int, str)): State =
    val a = s.auths.get(leaf._1)
    val o = leaf._2
    val rc = s.record
    val onRecord = rc.rstate == "PENDING" and rc.pending_auth == leaf._1
    val rc2 = if (not(onRecord) or a.settled != "NONE") rc
              else if (o == "FINAL") { ...rc, rstate: "UNSPENT", coin: rc.coin + 1, nf: rc.next_nf, next_nf: rc.next_nf + 1,
                                       nf_used: false, pin: -1, pending_auth: 0 }
              // AU-023, AU-029 (DECISIONS 60): a VOID successor of an authorization accepted on a
              // LOCKED record (pin bound, rc.pin != -1) stays LOCKED to that pin. The planted
              // "locked_void_unlocks" is the AU-023 of revision 2.
              else if (o == "VOID" and rc.pin != -1 and not(mut("locked_void_unlocks")))
                { ...rc, rstate: "LOCKED", nf: rc.next_nf, next_nf: rc.next_nf + 1, nf_used: false, pending_auth: 0 }
              else if (o == "VOID") { ...rc, rstate: "UNSPENT", nf: rc.next_nf, next_nf: rc.next_nf + 1,
                                      nf_used: false, pin: -1, pending_auth: 0 }
              else { ...rc, rstate: "LOCKED", nf: rc.next_nf, next_nf: rc.next_nf + 1, nf_used: false,
                     pin: a.pin, pending_auth: 0 }
    { ...s,
      auths: if (a.settled == "NONE") s.auths.set(leaf._1, { ...a, settled: o }) else s.auths,
      held: s.held.put(leaf._1, o),
      record: rc2 }

  // CP-003, CP-005, CP-011, AU-020, AU-023, CP-027: one checkpoint transaction lands.
  action landCheckpoint: bool = all { st.checkpoints < MAX_CP, landCheckpointNow }
  action landCheckpointNow: bool = {
    val c = nextCp(st, g)
    val code = cpCode(st.cp, c, st.restart_open)
    val s1 = c.settle_root.fold(st, (acc, lf) => applyLeaf(acc, lf))
    val changed = c.settle_root.exists(lf => has(st.held, lf._1) and st.held.get(lf._1) != lf._2)
    all {
      code == "",
      st' = advance({ ...s1, cp: c, board_height: st.board_height + 1,
              committee_txs: st.committee_txs + 1, checkpoints: st.checkpoints + 1,
              restart_open: false }, false),
      g' = { ...g, cp_prev: st.cp, held_changed: g.held_changed or changed, first_after_restart: st.restart_open },
      done("checkpoint", 0, c.seq),
    }
  }

  // ----------------------------------------------------------------- restart
  // CP-018 classification (fewer than w + 1 continuous seats) is the precondition of this
  // event. CP-020, CP-021, CP-022, CP-023 (one checkpoint read), RQ-048, RQ-068, RQ-054 carve-out.
  // `lose`: the board entries after the latest landed checkpoint are lost with the board tail
  // and the rolled-back acks (RQ-052 note, DECISIONS 53). RQ-076 (DECISIONS 70, lead ruling D):
  // "the request state machine SHALL keep any_release and every released[g] of each request as
  // they were before the restart", so `lose` changes no request field; it stays in lastOp.arg as
  // the event label. The planted "restart_clears_release" is the item 14 rule that cleared them.
  // RQ-068 re-ends only requests whose leaf Midnight does not hold: DECISIONS 58 "a leaf that
  // Midnight holds is never replaced" and "the restart gives it no second outcome" (lead ruling E;
  // a carried VOID leaf of AU-021 is held). The planted "replace_held" re-ends a held request and
  // replaces its leaf.
  pure def holdsSlot(s: State, e: int, lo: int, hi: int): bool =
    val r = s.requests.get(e)
    cIdx(r).exists(i => s.cslots.get(i).prec == e and lo <= i and i <= hi) or
    eIdx(r).exists(i => s.eslots.get(i).prec == e or s.eslots.get(i).reserver == e)
  action wholeRestart: bool = {
    nondet lose = Set(false, true).oneOf()
    all { st.restarts < 1, restartWith(lose) }
  }
  action restartWith(lose: bool): bool = {
    val lo = st.cp.pending_min
    val hi = st.cp.h + B
    val usable = CSLOTS.filter(i => lo <= i and i <= hi and st.cslots.get(i).prec == 0 and st.cslots.get(i).bstat == "UNNAMED")
    val pend = CSLOTS.filter(i => lo <= i and i <= hi and st.cp.pending.exists(x => x._1 == i))
    val liveHit = EIDS.filter(e => has(st.requests, e) and live(st, e) and holdsSlot(st, e, lo, hi))
    val endedHit = EIDS.filter(e => has(st.requests, e) and not(live(st, e)) and
                                    st.requests.get(e).end_height > st.cp.board_height and holdsSlot(st, e, lo, hi))
    val unsettled = endedHit.filter(e => mut("replace_held") or not(has(st.held, e)))
    val reEnd = unsettled.filter(e => not(mut("d058_b") and has(st.signed_leaf, e)))
    def lost(r: Req): Req =
      if (mut("restart_clears_release") and lose and r.release_height > st.cp.board_height)
        { ...r, any_release: false, released: Map(1 -> 0, 2 -> 0), release_height: -1 } else r
    val reqs1 = st.requests.keys().mapBy(e => {
      val r = lost(st.requests.get(e))
      if (liveHit.contains(e)) { ...r, restart_end: true }
      else if (reEnd.contains(e)) { ...r, restart_end: true, outcome: (if (spentBy(st, e)) "FINAL" else "RELEASED") }
      else r })
    val leaf1 = st.signed_leaf.keys().mapBy(e =>
      if (reEnd.contains(e) and (not(has(st.held, e)) or mut("replace_held")))
        reqs1.get(e).outcome else st.signed_leaf.get(e))
    all {
      st.restarts < 1,
      st' = { ...st, requests: reqs1, signed_leaf: leaf1,
              cslots: CSLOTS.mapBy(i => if (lo <= i and i <= hi) { ...st.cslots.get(i), bstat: "BURNED" } else st.cslots.get(i)),
              eslots: ESLOTS.mapBy(i => { ...st.eslots.get(i), bstat: "BURNED" }),
              restart_open: true, restarts: st.restarts + 1 },
      g' = { ...g, restart_hit: g.restart_hit.union(endedHit.filter(e => not(has(st.held, e)))), burn_lo: lo, burn_hi: hi,
                   burned_usable: usable.size(), burned_pending: pend.size(),
                   eburn_restart: ESLOTS.filter(i => st.eslots.get(i).bstat != "BURNED") },
      done("restart", 0, if (lose) 1 else 0),
    }
  }

  // SH-034: a payer registers the record of an address with a network-created shard, acked = false.
  // ec_ok is the creator's choice: the E_c behind delta or another point (SH-036 scenario).
  action registerAddr(ecOk: bool): bool = all {
    not(st.addr.registered),
    st' = { ...st, addr: { ...addrNone, registered: true, ec_ok: ecOk } },
    g' = g,
    done("register_addr", 0, if (ecOk) 1 else 0),
  }
  // SH-030, SH-036: the holder wallet sends the ACK envelope with pop_u only when x_u·G = X_u.
  action holderAck: bool = all {
    st.addr.registered, st.addr.ec_ok, st.addr.ack_env == "NONE",
    st' = { ...st, addr: { ...st.addr, ack_env: "HOLDER" } },
    g' = g,
    done("holder_ack", 0, 0),
  }
  // SH-032 scenario: the creator sends an ACK envelope without a valid pop_u.
  action creatorAck: bool = all {
    st.addr.registered, st.addr.ack_env == "NONE",
    st' = { ...st, addr: { ...st.addr, ack_env: "CREATOR" } },
    g' = g,
    done("creator_ack", 0, 0),
  }
  // SH-031, SH-032: an honest member signs ACK_OK only for an envelope whose pop_u verifies (the
  // holder's); a corrupt member signs anything. The planted "ack_without_pop" lets honest members
  // sign the creator's envelope.
  action ackOk(m: int): bool = all {
    st.addr.registered, st.addr.ack_env != "NONE", not(st.addr.ack_ok.contains(m)), MEMBERS.contains(m),
    CORRUPT.contains(m) or st.addr.ack_env == "HOLDER" or mut("ack_without_pop"),
    st' = { ...st, addr: { ...st.addr, ack_ok: st.addr.ack_ok.union(Set(m)) } },
    g' = g,
    done("ack_ok", 0, m),
  }
  // SH-033, SH-037: acknowledge lands only with q ACK_OK signatures and sets acked = true. The
  // planted "ack_cert_short" accepts f signatures.
  action acknowledge: bool = all {
    st.addr.registered, not(st.addr.acked),
    st.addr.ack_ok.size() >= (if (mut("ack_cert_short")) F else Q),
    st' = { ...st, addr: { ...st.addr, acked: true } },
    g' = g,
    done("acknowledge", 0, st.addr.ack_ok.size()),
  }
  // SH-035: the payer wallet pays only to an acknowledged address. The planted "pay_before_ack"
  // pays to any registered address.
  action payAddr: bool = all {
    st.addr.registered, not(st.addr.paid), st.addr.acked or mut("pay_before_ack"),
    st' = { ...st, addr: { ...st.addr, paid: true } },
    g' = g,
    done("pay_addr", 0, 0),
  }
  action ackStep: bool = {
    nondet ecOk = Set(true, false).oneOf()
    nondet m = MEMBERS.oneOf()
    any { registerAddr(ecOk), holderAck, creatorAck, ackOk(m), acknowledge, payAddr }
  }

  // RQ-042 rotation: ROTATE registers epoch 2; CP-006 one EKS record.
  action rotate: bool = all {
    not(st.epochs.contains(2)),
    st' = { ...st, epochs: st.epochs.union(Set(2)), eks_writes: st.eks_writes + 1, committee_txs: st.committee_txs + 1 },
    g' = g,
    done("rotate", 0, 2),
  }

  // AU-021, RQ-060: a reissue's authorize carries the signed VOID leaf of its stalled request.
  action reissue(e0: int, e1: int): bool = {
    val r0 = req(e0)
    val rc = st.record
    all {
      e0 != e1, has(st.requests, e0), has(st.requests, e1), has(st.auths, e0), not(has(st.auths, e1)),
      r0.phase == "VOID", r0.reason == "STALLED", r0.outcome == "VOID",
      has(st.signed_leaf, e0), st.signed_leaf.get(e0) == "VOID", not(has(st.held, e0)),
      rc.rstate == "PENDING", rc.pending_auth == e0,
      req(e1).source != "NONE", req(e1).phase == "POSTED", not(rc.hold_set) or req(e1).source == "SEIZURE",
      eIdx(req(e1)).forall(i => EROOT.get(i) == srcRoot(req(e1).source)),
      val s1 = applyLeaf(st, (e0, "VOID"))
      val rc1 = s1.record
      st' = { ...s1,
        auths: s1.auths.put(e1, { auth: e1, nf: rc1.nf, status: "SUBMITTED", final_height: -1, settled: "NONE",
                                  coin: rc1.coin, pin: if (rc1.rstate == "LOCKED") rc1.pin else rc1.next_pin }),
        record: { ...rc1, rstate: "PENDING", nf_used: true, pending_auth: e1,
                  next_pin: if (rc1.rstate == "LOCKED") rc1.next_pin else rc1.next_pin + 1 } },
      g' = g,
      done("reissue", e0, e1),
    }
  }

  // ---------------------------------------------------------------- refusals
  // Each refusal leaves st unchanged and records the spec's code (exported separately: the
  // replayer counts an oracle refusal as a disagreement).
  action refuse(k: str, e: int, code: str): bool = all { st' = st, g' = g, lastOp' = { kind: k, eid: e, arg: 0, code: code } }
  action refusals: bool = {
    nondet e = EIDS.oneOf()
    val r = req(e)
    any {
      all { not(has(st.requests, e)), refuse("admit", e, "unknown_request") },                       // RQ-004
      all { has(st.requests, e), terminal(r.phase), refuse("admit", e, "terminal") },                 // RQ-005
      all { has(st.requests, e), r.phase == "POSTED", refuse("order", e, "no_qc") },                  // RQ-007
      all { has(st.requests, e), r.phase == "POSTED", not(en023Ok(st.board_height + 1, r.exp)),
            refuse("order", e, "exp_c_not_below_exp") },                                              // EN-023
      all { has(st.requests, e), r.phase == "COLLECTING", r.filled, refuse("frame", e, "position_filled") }, // RQ-019
      all { has(st.requests, e), r.collecting, r.exp_c >= 0, st.board_height > r.exp_c, live(st, e),
            refuse("frame", e, "late_contribution") },                                                // RQ-020
      all { has(st.requests, e), (r.phase == "OPENED" or r.phase == "ADMITTED"),
            refuse("frame", e, "late_contribution") },                                                // RQ-075
      all { has(st.requests, e), r.phase == "OPENED", not(inForce(st, e)), refuse("admit", e, "not_in_force") }, // RQ-024
      all { has(st.requests, e), r.phase == "OPENED", cIdx(r).exists(i => aboveWindow(st, i)),
            refuse("admit", e, "above_window") },                                                     // SL-014
      all { has(st.requests, e), r.phase == "OPENED", settledAuth(st, e), refuse("admit", e, "settled") }, // RQ-061
      all { has(st.requests, e), not(has(st.auths, e)), st.record.nf_used, r.source != "NONE",
            refuse("authorize", e, "nf_used") },                                                      // AU-008
      all { has(st.requests, e), PROFILE == "P1", has(st.auths, e), refuse("revoke", e, "not_revocable") }, // AU-019
      all { has(st.requests, e), settledAuth(st, e), refuse("revoke", e, "not_revocable") },          // AU-019
      all { not(st.epochs.contains(2)), has(st.requests, e), live(st, e), refuse("post_void", e, "unknown_epoch") }, // RQ-043
      all { st.checkpoints < MAX_CP, cpCode(st.cp, nextCp(st, g), st.restart_open) != "",
            refuse("checkpoint", 0, cpCode(st.cp, nextCp(st, g), st.restart_open)) },                 // CP-007..CP-009
      all { has(st.requests, e), refuse("reissue", e, "bad_carry") },                                 // AU-022 (carried FINAL)
      all { st.addr.ack_env == "CREATOR", { nondet m = MEMBERS.exclude(CORRUPT).oneOf()
            all { not(st.addr.ack_ok.contains(m)), refuse("ack_ok", m, "ack_refused") } } },          // SH-032
      all { st.addr.registered, not(st.addr.acked), st.addr.ack_ok.size() < Q,
            refuse("acknowledge", 0, "no_ack_certificate") },                                         // SH-033
    }
  }

  // -------------------------------------------------------------------- step
  // `coin(k)` holds with probability 1/k in a sampled run; it only biases the sampler.
  action coin(k: int): bool = { nondet c = 1.to(k).oneOf() c == 1 }
  action step: bool = {
    nondet e = EIDS.oneOf()
    any {
      post(e), authorize(e), finalizeAuth(e), ecdsaPrec(e), order(e),
      openHeader(e), openedVote(e), frame(e), admit(e), anchor2(e),
      // Coin-gated branches: rarer adversarial or background events (sampling bias only).
      all { coin(4), revoke(e) }, all { coin(2), complain(e) }, all { coin(4), frameComplaint(e) },
      all { has(st.requests, e), req(e).phase == "ADMITTED", { nondet gg = 1.to(2).oneOf() sendRelease(e, gg) } },
      all { MODE == "NON_TEE", live(st, e), { nondet gg = 1.to(2).oneOf() recordRelease(e, gg) } },
      hostConfirm(e),
      all { live(st, e), { nondet ep = st.epochs.oneOf()
                           val ms = MEMBERS.filter(x => not(st.posts.contains({ eid: e, epoch: ep, member: x, kind: "FINAL", reason: "NONE" })))
                           all { ms != Set(), { nondet m = ms.oneOf() postFinal(e, ep, m) } } } },
      all { live(st, e), { nondet ep = st.epochs.oneOf() nondet m = MEMBERS.oneOf() nondet rs = REASONS.oneOf()
                           postVoid(e, ep, m, rs) } },
      expire(e),
      all { coin(2), tick }, all { coin(2), tickMidnight }, all { coin(2), landCheckpoint }, all { coin(4), rotate },
      all { coin(4), ackStep },
      all { has(st.requests, e), req(e).phase == "VOID", { nondet e2 = EIDS.oneOf() reissue(e, e2) } },
    }
  }
  // Test helper: a step that changes nothing (used after `.fail()` in scripted runs).
  action keep: bool = all { st' = st, g' = g, lastOp' = lastOp }
  // Restart exploration: the whole-committee restart is enabled once some request released or ended.
  action stepRestart: bool = any {
    step,
    all { st.board_height >= 4, g.sent != Set() or st.requests.keys().exists(x => terminal(req(x).phase)), wholeRestart },
  }
  action stepAll: bool = any { stepRestart, refusals }

  // -------------------------------------------------------------- invariants
  // Domains: RQ-064, RQ-065, RQ-066, RQ-067; AU-002; SL-002.
  val inv_RQ064_RQ065_RQ066_domains: bool = st.requests.keys().forall(e => {
    val r = st.requests.get(e)
    Set("POSTED", "ORDERED", "OPENED", "COLLECTING", "ADMITTED", "FINAL", "VOID", "EXPIRED").contains(r.phase) and
    Set("NONE", "FINAL", "VOID", "RELEASED").contains(r.outcome) and
    (r.reason == "NONE" or REASON_DOM.contains(r.reason)) and
    Set("SPEND", "EXIT", "SEIZURE", "BIRTH", "REFILL", "P0", "CONTRIB").contains(r.req_type) and
    Set("P0", "P1", "P2").contains(r.profile) })
  // RQ-065 scenario: a live request has reason NONE.
  val inv_RQ065_liveReasonNone: bool = st.requests.keys().forall(e => live(st, e) implies req(e).reason == "NONE")
  // RQ-067 grid domains.
  val inv_RQ067_grid: bool = st.requests.keys().forall(e => {
    val r = req(e)
    1 <= r.K and r.K <= 8 and 1 <= r.L and r.L <= 2 and r.G == (if (r.K < G_MAX) r.K else G_MAX) and
    gens(r).forall(x => 0 <= r.anchor.get(x) and r.anchor.get(x) <= r.K and 0 <= r.released.get(x) and r.released.get(x) <= r.K) })
  // RQ-029 selection domain.
  val inv_RQ029_selection: bool = st.requests.keys().forall(e => {
    val r = req(e)
    gens(r).forall(x => r.anchor.get(x) != 0 implies x <= r.anchor.get(x)) and
    (r.anchor.get(2) != 0 implies r.anchor.get(1) < r.anchor.get(2)) })
  // RQ-008, claim C8 (INV-008): nothing leaves before order.
  val inv_RQ008_C8_sealedUntilOrder: bool =
    g.hdr_sent.forall(e => req(e).phase != "POSTED") and g.sent.forall(x => req(x._1).order_pos >= 0)
  // RQ-057, claims C6 and C20 (INV-006, INV-020): no release before ADMITTED with an authorization
  // in force.
  val inv_RQ057_C6_C20_noReleaseBeforeAdmission: bool = g.sent.forall(x =>
    g.admitted.contains(x._1) and inForce(st, x._1))
  // Claim C20 (INV-020), first half: "a stalled request releases nothing", read on the tombstone
  // reason. Revision 2 broke it by a corrupt completing post (finding F2); RQ-045 and RQ-072
  // (DECISIONS 61) need f + 1 STALLED posts, one of them honest. In the gate.
  val inv_C20_stalledReleasedNothing: bool = g.sent.forall(x => req(x._1).reason != "STALLED")
  // F2 witness: a request that released carries the reason STALLED.
  // RQ-073, RQ-074, claim C20 (DECISIONS 64, finding F6; the witness w_stalled_after_release before):
  // a request with a committed RELEASE never has reason STALLED.
  val inv_RQ073_C20_noStalledAfterRelease: bool =
    st.requests.keys().forall(e => req(e).reason == "STALLED" implies not(req(e).any_release))
  // RQ-058, claim C9 (INV-009): one variant per generation, only the anchor.
  val inv_RQ058_C9_oneVariantPerGeneration: bool = g.sent.forall(x =>
    x._3 == req(x._1).anchor.get(x._2) and g.sent.forall(y => (y._1 == x._1 and y._2 == x._2) implies y._3 == x._3))
  // RQ-059, claim C7 (INV-007): no partial after revocation.
  val inv_RQ059_C7_noReleaseAfterRevoke: bool = g.sent_revoked == Set()
  // SL-021, SL-027, claim C12 (INV-012): no slot collects honest partials for two tickets.
  val inv_SL027_C12_oneTicketPerSlot: bool = g.slot_tickets.forall(x => g.slot_tickets.forall(y =>
    (x._1 == y._1 and x._2 == y._2) implies (x._3 == y._3 and x._4 == y._4)))
  // AU-024, AU-008, RQ-054, RQ-068, claim C11 (INV-011): at most one host spend per record state.
  val inv_AU024_C11_oneSpendPerRecordState: bool = st.host_spent.forall(x => st.host_spent.forall(y =>
    x._1 == y._1 implies x == y))
  // AU-008, claim C11: one authorization per nullifier.
  val inv_AU008_C11_oneAuthPerNf: bool = st.auths.keys().forall(a => st.auths.keys().forall(b =>
    st.auths.get(a).nf == st.auths.get(b).nf implies a == b))
  // RQ-054, claim C11 (D-058): no node signs, and no root lands, another outcome for a leaf that
  // Midnight holds.
  val inv_RQ054_C11_heldLeafNeverReplaced: bool =
    not(g.held_changed) and st.held.keys().forall(a => has(st.signed_leaf, a) implies st.signed_leaf.get(a) == st.held.get(a))
  // AU-025, RQ-052, claim C11 (D-053): a RELEASED settlement keeps the record locked to its pin:
  // no later authorization on the same record state uses another pin.
  val inv_AU025_C11_releasedNeverUnspent: bool = st.auths.keys().forall(a => st.auths.keys().forall(b => {
    val x = st.auths.get(a)
    val y = st.auths.get(b)
    (x.settled == "RELEASED" and y.coin == x.coin and y.nf > x.nf) implies y.pin == x.pin }))
  // RQ-069, RQ-051, claim C11 (D-059): a request whose partials left a node never settles VOID.
  val inv_RQ069_C11_sentNeverVoid: bool = g.sent.forall(x => req(x._1).outcome != "VOID")
  // RQ-045, RQ-072, RQ-071, claims C13 and C20 (D-061): a named tombstone reason has an honest post
  // with that reason; only MIXED has none.
  val inv_RQ045_RQ072_C13_C20_reasonHasHonestPost: bool = st.requests.keys().forall(e =>
    (req(e).phase == "VOID" and req(e).reason != "MIXED") implies g.honest_void.contains((e, req(e).reason)))
  // EN-023, RQ-006 (D-062): every ordered request has exp_c < exp (finding F3 witness before).
  val inv_EN023_expCBelowExp: bool = st.requests.keys().forall(e => req(e).exp_c >= 0 implies req(e).exp_c < req(e).exp)
  // SL-005, SL-010, claim C13 (D-063): a committee slot whose prec request is lapsed is BURNED,
  // also when the header opened after b + DELTA_C (finding F4 witness before).
  val inv_SL005_SL010_lapsedPrecBurned: bool = CSLOTS.forall(i => {
    val c = st.cslots.get(i)
    (c.prec != 0 and req(c.prec).lapsed) implies c.bstat == "BURNED" })
  // RQ-052, RQ-068 (D-053, D-058), claim C11: a restart end never settles VOID.
  val inv_RQ052_RQ068_C11_restartEndNeverVoid: bool = st.requests.keys().forall(e =>
    (req(e).restart_end and req(e).outcome != "NONE") implies req(e).outcome != "VOID")
  // RQ-068, claim C11 (D-058): every request that ended after the latest landed checkpoint and
  // held a slot the restart burned is re-ended with the restart outcome.
  val inv_RQ068_C11_reEnded: bool = g.restart_hit.forall(e =>
    req(e).restart_end and (has(st.signed_leaf, e) implies (st.signed_leaf.get(e) == req(e).outcome or has(st.held, e))))
  // RQ-049, RQ-050, RQ-051: outcome of an end.
  val inv_RQ049_RQ050_RQ051_outcome: bool = st.requests.keys().forall(e => {
    val r = req(e)
    if (not(terminal(r.phase))) r.outcome == "NONE"
    else if (r.phase == "FINAL") r.outcome == "FINAL"
    else if (r.restart_end) r.outcome != "NONE"
    else r.outcome == (if (r.any_release) "RELEASED" else "VOID") })
  // RQ-053: every end with an authorization has a signed leaf (auth, outcome).
  val inv_RQ053_leafSigned: bool = st.requests.keys().forall(e =>
    (terminal(req(e).phase) and has(st.auths, e)) implies has(st.signed_leaf, e))
  // SL-010, the committee half of the one burn rule: a committee slot whose prec request ended is
  // BURNED, used or not. The lapse half is inv_SL005_SL010_lapsedPrecBurned.
  val inv_SL010_committeeBurnAtPrecEnd: bool = CSLOTS.forall(i => {
    val c = st.cslots.get(i)
    (c.prec != 0 and not(live(st, c.prec))) implies c.bstat == "BURNED" })
  // SL-011, SL-028, the ECDSA half: an ECDSA slot burns outside a restart only at the end of its
  // reserver, and always then.
  val inv_SL011_SL028_ecdsaBurnOnlyByReserver: bool = ESLOTS.forall(i => {
    val x = st.eslots.get(i)
    (x.bstat == "BURNED" and not(g.eburn_restart.contains(i))) implies (x.reserver != 0 and not(live(st, x.reserver)))
    and ((x.reserver != 0 and not(live(st, x.reserver))) implies x.bstat == "BURNED") })
  // SL-006, SL-007, claim C13 (INV-013, D-054): ECDSA precedence only for an in-force request.
  val inv_SL007_C13_ecdsaPrecOnlyInForce: bool = ESLOTS.forall(i => {
    val x = st.eslots.get(i)
    x.prec != 0 implies inForce(st, x.prec) })
  // RQ-063 safety half, SL-016, claim C13: an honest SLOT_TAKEN on an ECDSA slot names a blocker
  // whose authorization came into force.
  val inv_RQ063_C13_ecdsaTakenOnlyByInForce: bool = g.taken_by.forall(x => x._3 == "E" implies inForce(st, x._2))
  // RQ-042, RQ-045, claim C13: a VOID tombstone not formed by the restart has an honest VOID post.
  val inv_RQ042_C13_voidNeedsHonestPost: bool = st.requests.keys().forall(e =>
    (req(e).phase == "VOID") implies g.honest_void.exists(x => x._1 == e))
  // RQ-044, RQ-040: a FINAL tombstone has a host confirmation of one of its variants.
  val inv_RQ044_finalNeedsConfirmation: bool = st.requests.keys().forall(e =>
    req(e).phase == "FINAL" implies spentBy(st, e))
  // CP-005 (D-052, owner rule): committee Midnight writes are one per checkpoint and one per epoch.
  val inv_CP005_batchedWrites: bool = st.committee_txs == st.checkpoints + st.eks_writes
  // CP-013, AU-020: every request with an authorization that ended at or before the latest landed
  // checkpoint height is settled on Midnight (root or carried VOID).
  val inv_CP013_AU020_settledByRoot: bool = st.requests.keys().forall(e => {
    val r = req(e)
    (terminal(r.phase) and has(st.auths, e) and r.end_height <= st.cp.board_height) implies has(st.held, e) })
  // CP-007, CP-008, CP-009 on the landed chain.
  val inv_CP007_CP008_CP009_landedChain: bool =
    st.cp.h >= g.cp_prev.h and st.cp.pending_min <= st.cp.h + 1 and
    (g.first_after_restart implies (st.cp.h >= g.cp_prev.h + B and st.cp.pending_min > g.cp_prev.h + B))
  // CP-014: pending fields agree.
  val inv_CP014_pendingFields: bool =
    st.cp.pending_count == st.cp.pending.size() and
    (st.cp.pending == Set() implies st.cp.pending_min == st.cp.h + 1) and
    st.cp.pending.forall(x => st.cp.pending_min <= x._1)
  // CP-020, claim C16 (INV-016): after a restart every index of [pending_min, h + B] is BURNED.
  val inv_CP020_C16_burnCovers: bool = CSLOTS.forall(i => (g.burn_lo <= i and i <= g.burn_hi) implies st.cslots.get(i).bstat == "BURNED")
  // CP-039, claim C16: at most B usable indices plus the pending indices burn per checkpoint read.
  val inv_CP039_C16_boundedLoss: bool = g.burned_usable <= B + g.burned_pending
  // SL-017: a BURNED committee slot is never reserved again, and precedence never moves.
  val inv_SL017_precForward: bool = CSLOTS.forall(i => {
    val c = st.cslots.get(i)
    (c.prec == 0 implies (c.bstat == "UNNAMED" or c.bstat == "BURNED")) and
    (c.prec != 0 implies c.namers.contains(c.prec)) })
  // RQ-046 (lead ruling A): no live request has a board height past its exp.
  val inv_RQ046_urgentExpiry: bool = st.requests.keys().forall(e => live(st, e) implies st.board_height <= req(e).exp)
  // RQ-076, RQ-037, claim C11 (DECISIONS 70): every released[g] = j that RQ-037 set stays set, and
  // any_release with it, through every later event, a restart that loses the board tail included.
  val inv_RQ076_C11_releaseMonotone: bool = g.rel_seen.forall(x =>
    req(x._1).any_release and req(x._1).released.get(x._2) == x._3)
  // AU-006: the seizure source only in P2.
  val inv_AU006_sources: bool = st.requests.keys().forall(e => req(e).source == "SEIZURE" implies PROFILE == "P2")
  // RQ-025, SL-016 (DECISIONS 68): an honest AUTH_REFUSED post, and an honest SLOT_TAKEN post that
  // SL-013 (below the window) does not cover, name a request whose authorization was in force.
  val inv_RQ025_SL016_admissionChecksInForce: bool = g.adm_posts.forall(x => x._3)
  // CP-040 (DECISIONS 69) on the landed chain: pending_min never falls.
  val inv_CP040_pendingMinForward: bool = st.cp.pending_min >= g.cp_prev.pending_min
  // CP-014, CP-040 (DECISIONS 71, finding F7): the checkpoint that the signers compute now never has
  // pending_min below the landed one, so CP-040 never refuses an honest checkpoint. A landed-chain
  // invariant cannot see the old listing, because CP-040 refuses its checkpoint before it lands.
  val inv_CP014_CP040_honestFloorKept: bool = nextCp(st, g).pending_min >= st.cp.pending_min
  // SH-034, SH-037, SH-033 (DECISIONS 67): a record is acked only with q ACK_OK signatures.
  val inv_SH033_SH037_ackedNeedsCertificate: bool = st.addr.acked implies st.addr.ack_ok.size() >= Q
  // SH-030, SH-031, SH-036, claim C1 for a network-created shard (DECISIONS 67): an acked record
  // carries the right E_c, so its holder can sign.
  val inv_SH031_SH036_C1_ackedOnlyRightEc: bool = st.addr.acked implies (st.addr.ec_ok and st.addr.ack_env == "HOLDER")
  // SH-035: no payment to an address before its record is acked.
  val inv_SH035_payOnlyAcked: bool = st.addr.paid implies st.addr.acked

  val inv: bool = and {
    inv_RQ064_RQ065_RQ066_domains, inv_RQ065_liveReasonNone, inv_RQ067_grid, inv_RQ029_selection,
    inv_RQ008_C8_sealedUntilOrder, inv_RQ057_C6_C20_noReleaseBeforeAdmission,
    inv_RQ058_C9_oneVariantPerGeneration, inv_RQ059_C7_noReleaseAfterRevoke,
    inv_SL027_C12_oneTicketPerSlot, inv_AU024_C11_oneSpendPerRecordState, inv_AU008_C11_oneAuthPerNf,
    inv_RQ054_C11_heldLeafNeverReplaced, inv_AU025_C11_releasedNeverUnspent,
    inv_RQ052_RQ068_C11_restartEndNeverVoid, inv_RQ068_C11_reEnded, inv_RQ049_RQ050_RQ051_outcome,
    inv_RQ053_leafSigned, inv_SL010_committeeBurnAtPrecEnd, inv_SL011_SL028_ecdsaBurnOnlyByReserver,
    inv_SL007_C13_ecdsaPrecOnlyInForce, inv_RQ063_C13_ecdsaTakenOnlyByInForce,
    inv_RQ042_C13_voidNeedsHonestPost, inv_RQ044_finalNeedsConfirmation, inv_CP005_batchedWrites,
    inv_CP013_AU020_settledByRoot, inv_CP007_CP008_CP009_landedChain, inv_CP014_pendingFields,
    inv_CP020_C16_burnCovers, inv_CP039_C16_boundedLoss, inv_SL017_precForward, inv_AU006_sources,
    inv_C20_stalledReleasedNothing,
    inv_RQ069_C11_sentNeverVoid, inv_RQ045_RQ072_C13_C20_reasonHasHonestPost,
    inv_EN023_expCBelowExp, inv_SL005_SL010_lapsedPrecBurned,
    inv_RQ073_C20_noStalledAfterRelease,
    inv_RQ046_urgentExpiry, inv_RQ076_C11_releaseMonotone,
    inv_RQ025_SL016_admissionChecksInForce, inv_CP040_pendingMinForward, inv_CP014_CP040_honestFloorKept,
    inv_SH033_SH037_ackedNeedsCertificate, inv_SH031_SH036_C1_ackedOnlyRightEc, inv_SH035_payOnlyAcked,
  }

  // Revision 3 (DECISIONS 59 to 63): the C11 spend invariants (findings F1, F5) and the C20 reason
  // invariant (finding F2) hold on the fixed spec, so the gate checks every invariant. Revision 4
  // (DECISIONS 64) adds inv_RQ073_C20_noStalledAfterRelease for finding F6.
  val inv_C11_spend: bool = inv_AU024_C11_oneSpendPerRecordState and inv_AU025_C11_releasedNeverUnspent
  val inv_gate: bool = inv

  // --------------------------------------------------------------- witnesses
  val w_final: bool = st.requests.keys().exists(e => req(e).phase == "FINAL")
  val w_void_slot_taken: bool = st.requests.keys().exists(e => req(e).reason == "SLOT_TAKEN")
  val w_stalled: bool = st.requests.keys().exists(e => req(e).reason == "STALLED")
  val w_collecting_admitted: bool = st.requests.keys().exists(e => req(e).collecting and req(e).phase == "ADMITTED")
  val w_released_outcome: bool = st.requests.keys().exists(e => req(e).outcome == "RELEASED")
  val w_anchor2: bool = st.requests.keys().exists(e => req(e).anchor.get(2) != 0)
  val w_ecdsa_prec: bool = ESLOTS.exists(i => st.eslots.get(i).prec != 0)
  val w_ecdsa_reserved: bool = ESLOTS.exists(i => st.eslots.get(i).reserver != 0)
  val w_settled_by_root: bool = st.auths.keys().exists(a => st.auths.get(a).settled != "NONE")
  val w_locked: bool = st.record.rstate == "LOCKED"
  val w_restart_live_hit: bool = st.requests.keys().exists(e => req(e).restart_end and req(e).phase == "VOID" and req(e).reason == "RESTART")
  val w_restart_reend: bool = g.restart_hit != Set()
  val w_restart_cp_landed: bool = st.cp.restart_seq > 0
  val w_two_coins: bool = st.record.coin >= 2
  val w_revoked_void: bool = st.requests.keys().exists(e => req(e).reason == "REVOKED")
  val w_lapsed: bool = st.requests.keys().exists(e => req(e).lapsed)
  val w_reissue: bool = st.auths.keys().exists(a => st.auths.get(a).settled == "VOID" and has(st.held, a))
  val w_rotate_post: bool = st.posts.exists(p => p.epoch == 2)
  val w_sent: bool = g.sent != Set()
  val w_host_spend: bool = st.host_spent != Set()
  // Revision 3: the fixed paths are reached.
  val w_mixed: bool = st.requests.keys().exists(e => req(e).reason == "MIXED")
  val w_locked_after_void: bool = st.record.rstate == "LOCKED" and st.auths.keys().exists(a =>
    st.auths.get(a).settled == "VOID" and st.auths.get(a).pin == st.record.pin)
  val w_open_lapsed: bool = st.requests.keys().exists(e => req(e).lapsed and req(e).hdr_open)
  // Revision 6 (DECISIONS 67 to 69).
  val w_paid_acked: bool = st.addr.paid
  val w_creator_ack: bool = st.addr.ack_env == "CREATOR" and st.addr.ack_ok != Set()
  val w_cp_pending_min_lowered: bool = st.checkpoints < MAX_CP and cpCode(st.cp, nextCp(st, g), st.restart_open) == "pending_min_lowered"
  // Revision 7 (DECISIONS 71): the F7 precondition, a live request that holds precedence on a
  // committee slot below the landed pending_min.
  val w_prec_below_floor: bool = CSLOTS.exists(i => {
    val c = st.cslots.get(i)
    c.prec != 0 and c.bstat != "BURNED" and live(st, c.prec) and i < st.cp.pending_min })
  val w_auth_refused: bool = st.requests.keys().exists(e => req(e).reason == "AUTH_REFUSED")
  val w_nontee_released_unconfirmed: bool = MODE == "NON_TEE" and
    st.requests.keys().exists(e => req(e).outcome == "RELEASED" and not(spentBy(st, e)) and not(req(e).restart_end))
}

// ------------------------------------------------------------------ instances
module tee_p2 { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "none").* }
module tee_p1 { import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "none").* }
module nontee_p2 { import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "none").* }
module nontee_p1 { import splitspec(MODE = "NON_TEE", PROFILE = "P1", MUT = "none").* }
// Planted rule changes (README "Mutants").
module m_ecdsa_prec_at_open { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ecdsa_prec_at_open").* }
module m_committee_burn_reserved_only { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "committee_burn_reserved_only").* }
module m_ecdsa_burn_by_namer { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ecdsa_burn_by_namer").* }
module m_d058_b_nontee { import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "d058_b").* }
module m_d058_b { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "d058_b").* }
module m_replace_held { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "replace_held").* }
module m_restart_void_unspent { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "restart_void_unspent").* }
module m_settle_per_request { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "settle_per_request").* }
module m_root_omit { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "root_omit").* }
module m_no_jump { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "no_jump").* }
module m_cross_epoch { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "cross_epoch").* }
module m_ignore_revoke { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ignore_revoke").* }
module m_any_variant { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "any_variant").* }
// Revision 3: each fix of DECISIONS 59 to 63 with the old rule planted back.
module m_send_before_record { import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "send_before_record").* }
module m_locked_void_unlocks { import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "locked_void_unlocks").* }
module m_completing_reason { import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "completing_reason").* }
module m_exp_c_unchecked { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "exp_c_unchecked").* }
module m_lapse_once { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "lapse_once").* }
// Revision 4: the fix of DECISIONS 64 with the old rule planted back (TEE P1 for the scripted
// schedule, NON_TEE P1 for random runs, where revision 3 reached F6).
module m_stalled_after_release { import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "stalled_after_release").* }
// Item 14 replay rulings: the late expiry event (ruling A) and the restart that clears the release
// record (ruling D) planted back.
module m_late_expiry { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "late_expiry").* }
// Revision 6: DECISIONS 67 to 69 with the old rule planted back, or the new rule dropped.
module m_auth_refused_before_force { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "auth_refused_before_force").* }
module m_taken_before_force { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "taken_before_force").* }
module m_pending_min_unchecked { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pending_min_unchecked").* }
module m_ack_without_pop { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ack_without_pop").* }
module m_ack_cert_short { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ack_cert_short").* }
module m_pay_before_ack { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pay_before_ack").* }
module m_restart_clears_release { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "restart_clears_release").* }
module m_stalled_after_release_nontee { import splitspec(MODE = "NON_TEE", PROFILE = "P1", MUT = "stalled_after_release").* }
// Revision 7: DECISIONS 71 with the CP-014 listing of revision 6 planted back (finding F7).
module m_pending_unwindowed { import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pending_unwindowed").* }
