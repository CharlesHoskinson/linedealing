// -*- mode: Bluespec; -*-
// Quint model of the batched Midnight writes of split-line dealing.
// Source: design/enhancement/DESIGN.md §4.1 (reservation window, pending_min, pending_root),
// §5.3 (board-first authorization, bf_root), §5.6 (settlement leaf, settle_root,
// carried VOID settlement), §5.9 items 6 and 7 (reissue), §7.11 (restart burn),
// §7.13 (checkpoint record, contract rule on h and pending_min, signer rules).
// Written from the DESIGN text only.
//
// Three parts share one state machine:
//   A. Committee pool, restart burn [pending_min, h + B], contract rule (claims C12, C13, C16).
//   B. Settlement by root path and carried VOID, restart replay (claim C11).
//   C. Board-first calls batched under bf_root, duplicate-nf refusal (claim C11, O29).
//
// MUT selects one mutant (0 = the design). BOARD_LOSS lets part C lose the board
// tail past the latest landed checkpoint (whole-committee restart, every disk rolled back).

module batched_checkpoint {
  const MUT: int
  const BOARD_LOSS: bool

  // ---------------------------------------------------------------- part A
  pure val B: int = 2
  pure val IDX: Set[int] = 1.to(7)
  pure val REQ: Set[int] = 1.to(4)

  type Cp = { h: int, pendingMin: int, pend: Set[int], forged: Set[int] }

  var a_res: int -> int            // request -> reserved index (0: none)
  var a_status: int -> str         // "idle" | "live" | "ended"   (board record)
  var a_maxRes: int                // highest reserved index on the board
  var a_cps: List[Cp]              // landed checkpoints (Midnight)
  var a_disk: int -> str           // seat sessions: "free" | "bound" | "burned"
  var a_snaps: List[{ disk: int -> str, res: int -> int, status: int -> str, maxRes: int }]
  var a_burned: Set[int]           // burned by restart (slot_stale), from Midnight fields
  var a_uses: int -> Set[int]      // tickets ever bound per index (ground truth)
  var a_era: int                   // board era: a lost board tail can change a request's anchor
  var a_restartOpen: bool
  var a_lastOld: Set[int]          // burn set of the list rule at the last restart
  var a_lastNew: Set[int]          // burn set [pending_min, h + B] at the last restart
  var a_listRuleOk: bool           // every landed cp2 after a restart meets the list rule
  var a_refusedHonest: bool        // the contract refused an honest checkpoint

  pure def lastCp(cps: List[Cp]): Cp = cps[cps.length() - 1]
  pure def minOr(s: Set[int], d: int): int = s.fold(d, (m, x) => if (x < m) x else m)
  pure def rangeSet(lo: int, hi: int): Set[int] = IDX.filter(i => i >= lo and i <= hi)

  // Burn set of a restart, read from the latest landed checkpoint only.
  pure def burnNew(cp: Cp): Set[int] =
    if (MUT == 1) rangeSet(cp.h + 1, cp.h + B)                              // window only
    else if (MUT == 2) rangeSet(cp.pend.fold(0, (m, x) => if (x > m) x else m), cp.h + B) // highest pending
    else rangeSet(cp.pendingMin, cp.h + B)
  pure def burnList(cp: Cp): Set[int] = rangeSet(cp.h + 1, cp.h + B).union(cp.pend)

  // Vote and slot_bind rule of §4.1 against the latest checkpoint.
  // An index in [pending_min, h] needs a membership proof under pending_root (cp.pend);
  // a proof for an index below pending_min never counts (QI-24). Mutant 11 drops that check.
  pure def windowOk(cp: Cp, i: int, own: bool): bool =
    (i > cp.h and i <= cp.h + B) or (own and (MUT == 11 or i >= cp.pendingMin) and cp.pend.union(cp.forged).contains(i))

  action a_init = all {
    a_res' = REQ.mapBy(r => 0),
    a_status' = REQ.mapBy(r => "idle"),
    a_maxRes' = 0,
    a_cps' = [{ h: 0, pendingMin: 1, pend: Set(), forged: Set() }],
    a_disk' = IDX.mapBy(i => "free"),
    a_snaps' = [{ disk: IDX.mapBy(i => "free"), res: REQ.mapBy(r => 0), status: REQ.mapBy(r => "idle"), maxRes: 0 }],
    a_burned' = Set(),
    a_uses' = IDX.mapBy(i => Set()),
    a_era' = 0,
    a_restartOpen' = false,
    a_lastOld' = Set(),
    a_lastNew' = Set(),
    a_listRuleOk' = true,
    a_refusedHonest' = false,
  }

  action a_unchanged = all {
    a_res' = a_res, a_status' = a_status, a_maxRes' = a_maxRes, a_cps' = a_cps,
    a_disk' = a_disk, a_snaps' = a_snaps, a_burned' = a_burned, a_uses' = a_uses,
    a_era' = a_era, a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld,
    a_lastNew' = a_lastNew, a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
  }

  // A request reserves one index, in increasing order, inside the window.
  action a_reserve(r: int, i: int): bool = all {
    a_status.get(r) == "idle",
    i > a_maxRes,
    windowOk(lastCp(a_cps), i, false),
    not(a_burned.contains(i)),
    a_res' = a_res.set(r, i),
    a_status' = a_status.set(r, "live"),
    a_maxRes' = i,
    a_cps' = a_cps, a_disk' = a_disk, a_snaps' = a_snaps, a_burned' = a_burned, a_uses' = a_uses,
    a_era' = a_era, a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld,
    a_lastNew' = a_lastNew, a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
  }

  // slot_bind: the session must show the slot free, the slot must not be stale,
  // and the index must meet the window rule of the latest checkpoint.
  action a_bind(r: int): bool = {
    val i = a_res.get(r)
    all {
      Set("live", "named").contains(a_status.get(r)),
      i > 0,
      a_disk.get(i) == "free",
      not(a_burned.contains(i)),
      windowOk(lastCp(a_cps), i, true),
      a_disk' = a_disk.set(i, "bound"),
      a_uses' = a_uses.set(i, a_uses.get(i).union(Set(r * 100 + a_era))),
      a_res' = a_res, a_status' = a_status, a_maxRes' = a_maxRes, a_cps' = a_cps,
      a_snaps' = a_snaps, a_burned' = a_burned, a_era' = a_era,
      a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld, a_lastNew' = a_lastNew,
      a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
    }
  }

  // FINAL, VOID or EXPIRED: slot_burn.
  action a_end(r: int): bool = all {
    a_status.get(r) == "live",
    a_status' = a_status.set(r, "ended"),
    a_disk' = if (a_res.get(r) > 0) a_disk.set(a_res.get(r), "burned") else a_disk,
    a_res' = a_res, a_maxRes' = a_maxRes, a_cps' = a_cps, a_snaps' = a_snaps,
    a_burned' = a_burned, a_uses' = a_uses, a_era' = a_era,
    a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld, a_lastNew' = a_lastNew,
    a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
  }

  // Honest checkpoint and the contract rule of §7.13.
  action a_checkpoint = {
    val prev = lastCp(a_cps)
    val pend = REQ.filter(r => a_status.get(r) == "live" and a_res.get(r) > 0).map(r => a_res.get(r))
    val hMin = if (a_restartOpen) prev.h + B else prev.h
    val h = if (a_maxRes > hMin) a_maxRes else hMin
    val cp = { h: h, pendingMin: minOr(pend, h + 1), pend: pend, forged: Set() }
    // §7.13 contract rules: h never falls, pending_min never falls (DECISIONS 69, D-039, SS-146),
    // and the first checkpoint after a restart jumps past the window.
    val accepted =
      cp.h >= prev.h and cp.pendingMin >= prev.pendingMin and cp.pendingMin <= cp.h + 1
      and (not(a_restartOpen) or (cp.h >= prev.h + B and cp.pendingMin > prev.h + B))
    val listOk =
      not(a_restartOpen) or (cp.h >= prev.h + B and cp.pend.intersect(burnList(prev)).size() == 0)
    all {
      a_cps' = if (accepted) a_cps.append(cp) else a_cps,
      a_snaps' = if (accepted) a_snaps.append({ disk: a_disk, res: a_res, status: a_status, maxRes: a_maxRes }) else a_snaps,
      a_restartOpen' = if (accepted) false else a_restartOpen,
      a_listRuleOk' = and { a_listRuleOk, or { not(accepted), listOk } },
      a_refusedHonest' = or { a_refusedHonest, not(accepted) },
      a_res' = a_res, a_status' = a_status, a_maxRes' = a_maxRes, a_disk' = a_disk,
      a_burned' = a_burned, a_uses' = a_uses, a_era' = a_era,
      a_lastOld' = a_lastOld, a_lastNew' = a_lastNew,
    }
  }

  // Whole-committee restart. Every disk may roll back to the state at any landed
  // checkpoint, and the board tail past the latest landed checkpoint may be lost.
  // Nodes read the latest landed checkpoint from Midnight and burn from it.
  action a_restart(snap: int, loseBoard: bool): bool = {
    val cp = lastCp(a_cps)
    val s = a_snaps[snap]
    val top = a_snaps[a_snaps.length() - 1]
    val disk0 = s.disk
    val status0 = if (loseBoard) top.status else a_status
    val res0 = if (loseBoard) top.res else a_res
    val burn = burnNew(cp)
    all {
      snap >= 0, snap < a_snaps.length(),
      a_disk' = IDX.mapBy(i => if (burn.contains(i)) "burned" else disk0.get(i)),
      a_burned' = a_burned.union(burn),
      a_status' = REQ.mapBy(r =>
        if (status0.get(r) == "live" and burn.contains(res0.get(r))) "ended" else status0.get(r)),
      a_res' = res0,
      a_maxRes' = if (loseBoard) top.maxRes else a_maxRes,
      a_era' = if (loseBoard) a_era + 1 else a_era,
      a_restartOpen' = true,
      a_lastOld' = burnList(cp),
      a_lastNew' = burn,
      a_cps' = a_cps, a_snaps' = a_snaps, a_uses' = a_uses,
      a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
    }
  }

  // A Byzantine signer set puts a dead index below pending_min into the list behind
  // pending_root of the latest checkpoint. The contract reads only h and pending_min.
  action a_byzRoot(i: int): bool = {
    val cp = lastCp(a_cps)
    val n = a_cps.length()
    all {
      i < cp.pendingMin,
      a_cps' = a_cps.replaceAt(n - 1, { ...cp, forged: cp.forged.union(Set(i)) }),
      a_res' = a_res, a_status' = a_status, a_maxRes' = a_maxRes, a_disk' = a_disk,
      a_snaps' = a_snaps, a_burned' = a_burned, a_uses' = a_uses, a_era' = a_era,
      a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld, a_lastNew' = a_lastNew,
      a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
    }
  }

  // A Byzantine initiator posts a header that names a dead index at or below h. It gets
  // no honest reservation ("named", never "live"), so no honest checkpoint lists it.
  // Only the vote and slot_bind rule of §4.1 stands between it and a second use.
  action a_nameDead(r: int, i: int): bool = all {
    a_status.get(r) == "idle",
    i <= lastCp(a_cps).h,
    a_res' = a_res.set(r, i),
    a_status' = a_status.set(r, "named"),
    a_maxRes' = a_maxRes, a_cps' = a_cps, a_disk' = a_disk, a_snaps' = a_snaps,
    a_burned' = a_burned, a_uses' = a_uses, a_era' = a_era,
    a_restartOpen' = a_restartOpen, a_lastOld' = a_lastOld, a_lastNew' = a_lastNew,
    a_listRuleOk' = a_listRuleOk, a_refusedHonest' = a_refusedHonest,
  }

  action a_step = any {
    nondet r = REQ.oneOf()
    nondet i = IDX.oneOf()
    a_reserve(r, i),
    nondet r = REQ.oneOf()
    a_bind(r),
    nondet r = REQ.oneOf()
    a_end(r),
    a_checkpoint,
    nondet snap = 0.to(5).oneOf()
    nondet lose = Bool.oneOf()
    a_restart(snap, lose),
    nondet i = IDX.oneOf()
    a_byzRoot(i),
    nondet r = REQ.oneOf()
    nondet i = IDX.oneOf()
    a_nameDead(r, i),
  }

  // C12 and C16 (QI-24): no committee slot binds two tickets, also after a rollback of every disk.
  val C12_C16_oneTicketPerSlot = IDX.forall(i => a_uses.get(i).size() <= 1)
  // C16: the burn [pending_min, h + B] covers the window and the pending list of the checkpoint.
  val C16_burnCoversList = a_lastOld.subseteq(a_lastNew)
  // C16: every checkpoint the contract accepts after a restart meets the list rule.
  val C16_pendingMinRuleImpliesListRule = a_listRuleOk
  // C13: the contract accepts every honest checkpoint.
  val C13_honestCheckpointLands = not(a_refusedHonest)

  // ---------------------------------------------------------------- part B
  pure val AUTH: Set[int] = 1.to(4)
  pure val OUT: Set[str] = Set("FINAL", "VOID", "RELEASED")
  pure def code(o: str): int = if (o == "FINAL") 1 else if (o == "VOID") 2 else 3
  pure def succ(a: int, o: str): int = a * 10 + code(o)
  // Host input of a record state: a VOID or RELEASED successor keeps the pinned input,
  // a FINAL successor is the change record with a new input.
  pure def inputOf(nf: int): int = if (nf < 10) nf else if (nf % 10 == 1) nf else -1

  var b_auth: int -> int           // auth -> nf it spends (0 = initial record state)
  var b_input: int -> int          // auth -> host input it spends
  var b_nextAuth: int
  var b_spent: int -> int          // nf -> number of accepted authorize calls
  var b_status: int -> str         // auth -> "none" | "live" | "ended" (board)
  var b_released: Set[int]
  var b_inputSpentBy: int -> int   // host input -> auth whose transaction confirmed (0: unspent)
  var b_signed: Set[(int, str)]    // leaves with q signatures, held by wallets
  var b_boardLeaves: Set[(int, str)] // leaves on the board, not yet under a landed root
  var b_root: Set[(int, str)]      // leaves under landed settle_root values
  var b_carried: Set[int]          // auths that Midnight records as settled VOID by a carry
  var b_cpEnded: Set[int]          // auths ended when the latest checkpoint was signed
  var b_reissueEarly: bool         // a reissue landed before any root covered its VOID leaf

  pure def counted(root: Set[(int, str)], carried: Set[int], a: int): Set[str] =
    root.filter(l => l._1 == a).map(l => l._2).union(if (carried.contains(a)) Set("VOID") else Set())

  def recExists(nf: int): bool =
    nf == 0 or AUTH.exists(a => OUT.exists(o => succ(a, o) == nf and counted(b_root, b_carried, a).contains(o)))

  // Host input of the record state nf, followed back through VOID and RELEASED successors.
  def hostInputOf(nf: int): int =
    if (nf == 0) 0 else if (nf % 10 == 1) nf
    else { val p = nf / 10  if (p >= 1 and p <= 4) b_input.get(p) else 0 }

  action b_init = all {
    b_auth' = AUTH.mapBy(a => -1),
    b_input' = AUTH.mapBy(a => -1),
    b_nextAuth' = 1,
    b_spent' = Set(0, 11, 12, 13, 21, 22, 23, 31, 32, 33, 41, 42, 43).mapBy(x => 0),
    b_status' = AUTH.mapBy(a => "none"),
    b_released' = Set(),
    b_inputSpentBy' = Set(0, 11, 21, 31, 41).mapBy(x => 0),
    b_signed' = Set(),
    b_boardLeaves' = Set(),
    b_root' = Set(),
    b_carried' = Set(),
    b_cpEnded' = Set(),
    b_reissueEarly' = false,
  }

  action b_unchanged = all {
    b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
    b_status' = b_status, b_released' = b_released, b_inputSpentBy' = b_inputSpentBy,
    b_signed' = b_signed, b_boardLeaves' = b_boardLeaves, b_root' = b_root,
    b_carried' = b_carried, b_cpEnded' = b_cpEnded, b_reissueEarly' = b_reissueEarly,
  }

  // authorize on an existing record state; Midnight refuses a spent nullifier.
  // A reissue carries the VOID leaf of the stalled request with q signatures.
  action b_authorize(nf: int, carry: int): bool = {
    val a = b_nextAuth
    val carryOk = and { carry > 0, b_signed.contains((carry, "VOID")), nf == succ(carry, "VOID") }
    val early = and { carryOk, not(b_root.contains((carry, "VOID"))) }
    all {
      a <= 4,
      b_spent.keys().contains(nf),
      recExists(nf) or carryOk,
      MUT == 5 or b_spent.get(nf) == 0,
      b_auth' = b_auth.set(a, nf),
      b_input' = b_input.set(a, hostInputOf(nf)),
      b_nextAuth' = a + 1,
      b_spent' = b_spent.set(nf, b_spent.get(nf) + 1),
      b_status' = b_status.set(a, "live"),
      b_carried' = if (carryOk) b_carried.union(Set(carry)) else b_carried,
      b_reissueEarly' = or { b_reissueEarly, early },
      b_released' = b_released, b_inputSpentBy' = b_inputSpentBy, b_signed' = b_signed,
      b_boardLeaves' = b_boardLeaves, b_root' = b_root, b_cpEnded' = b_cpEnded,
    }
  }

  // Release of a partial; the host transaction may then confirm if its input is unspent.
  action b_release(a: int): bool = all {
    b_status.get(a) == "live",
    b_released' = b_released.union(Set(a)),
    b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
    b_status' = b_status, b_inputSpentBy' = b_inputSpentBy, b_signed' = b_signed,
    b_boardLeaves' = b_boardLeaves, b_root' = b_root, b_carried' = b_carried,
    b_cpEnded' = b_cpEnded, b_reissueEarly' = b_reissueEarly,
  }

  action b_hostConfirm(a: int): bool = {
    val inp = b_input.get(a)
    all {
      b_status.get(a) == "live",
      b_released.contains(a),
      b_inputSpentBy.keys().contains(inp),
      b_inputSpentBy.get(inp) == 0,
      b_inputSpentBy' = b_inputSpentBy.set(inp, a),
      b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
      b_status' = b_status, b_released' = b_released, b_signed' = b_signed,
      b_boardLeaves' = b_boardLeaves, b_root' = b_root, b_carried' = b_carried,
      b_cpEnded' = b_cpEnded, b_reissueEarly' = b_reissueEarly,
    }
  }

  // Outcome of an ending request, from the board record and the host chain (§5.6).
  def outcomeOf(a: int): str =
    if (b_inputSpentBy.get(b_input.get(a)) == a) "FINAL"
    else if (b_released.contains(a)) "RELEASED"
    else "VOID"

  action b_end(a: int): bool = {
    val o = outcomeOf(a)
    all {
      b_status.get(a) == "live",
      b_inputSpentBy.keys().contains(b_input.get(a)),
      b_status' = b_status.set(a, "ended"),
      b_signed' = b_signed.union(Set((a, o))),
      b_boardLeaves' = b_boardLeaves.union(Set((a, o))),
      b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
      b_released' = b_released, b_inputSpentBy' = b_inputSpentBy, b_root' = b_root,
      b_carried' = b_carried, b_cpEnded' = b_cpEnded, b_reissueEarly' = b_reissueEarly,
    }
  }

  // Mutant 4: a quorum signs a second outcome for one auth (no honest overlap).
  action b_byzSign(a: int, o: str): bool = all {
    MUT == 4,
    b_status.get(a) == "ended",
    b_signed' = b_signed.union(Set((a, o))),
    b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
    b_status' = b_status, b_released' = b_released, b_inputSpentBy' = b_inputSpentBy,
    b_boardLeaves' = b_boardLeaves, b_root' = b_root, b_carried' = b_carried,
    b_cpEnded' = b_cpEnded, b_reissueEarly' = b_reissueEarly,
  }

  // Checkpoint signers: settle_root covers every leaf of the interval, and no leaf
  // gives an auth an outcome other than the VOID that Midnight records for it.
  action b_checkpoint = {
    val conflictFree = b_boardLeaves.filter(l => MUT == 3 or not(b_carried.contains(l._1)) or l._2 == "VOID")
    val covered = if (MUT == 6) conflictFree.filter(l => l._1 % 2 == 0) else conflictFree
    all {
      b_root' = b_root.union(covered),
      b_boardLeaves' = Set(),
      b_cpEnded' = AUTH.filter(a => b_status.get(a) == "ended"),
      b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
      b_status' = b_status, b_released' = b_released, b_inputSpentBy' = b_inputSpentBy,
      b_signed' = b_signed, b_carried' = b_carried, b_reissueEarly' = b_reissueEarly,
    }
  }

  // Whole-committee restart with the board tail lost: the leaves that no landed root
  // covers are gone, and the restart burn ends those requests again. A node refuses a
  // request whose auth Midnight shows settled. Otherwise it settles FINAL when the host
  // shows the request's own transaction, VOID when the pinned input is unspent, and
  // RELEASED otherwise (§5.6, Availability).
  action b_restartLoseBoard = {
    val lost = b_boardLeaves.map(l => l._1)
    val again = lost.filter(a => MUT == 3 or not(b_carried.contains(a)))
    def replay(a: int): str =
      if (MUT == 7) "VOID"
      else if (b_inputSpentBy.get(b_input.get(a)) == a) "FINAL"
      else if (b_inputSpentBy.get(b_input.get(a)) == 0) "VOID"
      else "RELEASED"
    val newLeaves = again.map(a => (a, replay(a)))
    all {
      b_boardLeaves' = newLeaves,
      b_signed' = b_signed.union(newLeaves),
      b_auth' = b_auth, b_input' = b_input, b_nextAuth' = b_nextAuth, b_spent' = b_spent,
      b_status' = b_status, b_released' = b_released, b_inputSpentBy' = b_inputSpentBy,
      b_root' = b_root, b_carried' = b_carried, b_cpEnded' = b_cpEnded,
      b_reissueEarly' = b_reissueEarly,
    }
  }

  action b_step = any {
    nondet nf = Set(0, 11, 12, 13, 21, 22, 23, 31, 32, 33).oneOf()
    nondet carry = 0.to(3).oneOf()
    b_authorize(nf, carry),
    nondet a = AUTH.oneOf()
    b_release(a),
    nondet a = AUTH.oneOf()
    b_hostConfirm(a),
    nondet a = AUTH.oneOf()
    b_end(a),
    nondet a = AUTH.oneOf()
    nondet o = OUT.oneOf()
    b_byzSign(a, o),
    b_checkpoint,
    b_restartLoseBoard,
  }

  // C11: no auth settles with two outcomes on Midnight.
  val C11_oneOutcomePerAuth = AUTH.forall(a => counted(b_root, b_carried, a).size() <= 1)
  // C11: Midnight accepts one authorize per record state, on either settlement path.
  val C11_oneAuthorizePerState = b_spent.keys().forall(nf => b_spent.get(nf) <= 1)
  // C11: a request whose own transaction confirmed settles FINAL, so its change record
  // exists, and no FINAL settlement names a request whose transaction did not confirm.
  val C11_noLostSuccessor = AUTH.forall(a => {
    val c = counted(b_root, b_carried, a)
    val inp = b_input.get(a)
    val own = and { inp >= 0, b_inputSpentBy.keys().contains(inp), b_inputSpentBy.get(inp) == a }
    and { (own and c.size() > 0) implies c == Set("FINAL"), c.contains("FINAL") implies own }
  })
  // C11: every request that ended before a checkpoint is settled once it lands.
  val C11_settledByCheckpoint = b_cpEnded.forall(a => counted(b_root, b_carried, a).size() > 0)
  // Witness (expected to be violated): a reissue lands before any root covers its VOID leaf.
  val W_reissueWaitsForRoot = not(b_reissueEarly)

  // ---------------------------------------------------------------- part C
  pure val NF: Set[int] = 1.to(3)

  var c_inForce: List[int]         // nf of every call in force, in board order
  var c_pend: Set[int]             // board pending set since the latest landed checkpoint
  var c_batch: List[int]           // calls of the interval, as the proposer lists them
  var c_landed: List[List[int]]    // nf leaves of each landed bf_root
  var c_hostSpent: int -> int      // nf -> number of host spends of its pinned input

  pure def flat(ls: List[List[int]]): List[int] = ls.foldl([], (acc, l) => acc.concat(l))
  pure def listSet(l: List[int]): Set[int] = l.indices().map(i => l[i])
  pure def noDup(l: List[int]): bool =
    l.indices().forall(i => l.indices().forall(j => i == j or l[i] != l[j]))

  action c_init = all {
    c_inForce' = [], c_pend' = Set(), c_batch' = [], c_landed' = [],
    c_hostSpent' = NF.mapBy(x => 0),
  }
  action c_unchanged = all {
    c_inForce' = c_inForce, c_pend' = c_pend, c_batch' = c_batch,
    c_landed' = c_landed, c_hostSpent' = c_hostSpent,
  }

  // §5.3 steps 2 to 4: the node checks nf against every landed bf_root, the board
  // refuses a second call on one nf, and the call is in force at its order.
  action c_post(nf: int): bool = all {
    c_inForce.length() < 4,
    MUT == 9 or not(listSet(flat(c_landed)).contains(nf)),
    MUT == 8 or not(c_pend.contains(nf)),
    c_inForce' = c_inForce.append(nf),
    c_pend' = c_pend.union(Set(nf)),
    c_batch' = c_batch.append(nf),
    c_landed' = c_landed, c_hostSpent' = c_hostSpent,
  }

  // A Byzantine checkpoint proposer lists a call with a repeated nf in the batch.
  action c_byzInject(nf: int): bool = all {
    c_batch.length() < 4,
    c_batch' = c_batch.append(nf),
    c_inForce' = c_inForce, c_pend' = c_pend, c_landed' = c_landed, c_hostSpent' = c_hostSpent,
  }

  // Checkpoint signers sign bf_root only over leaves with no repeated nf, in the batch
  // or against earlier landed roots. Honest signers drop the repeated leaves.
  action c_checkpoint = {
    val earlier = listSet(flat(c_landed))
    val kept = c_batch.indices().filter(i =>
      MUT == 10 or (not(earlier.contains(c_batch[i]))
        and c_batch.indices().forall(j => j >= i or c_batch[j] != c_batch[i])))
    all {
      c_landed' = c_landed.append(range(0, c_batch.length()).foldl([], (acc, i) => if (kept.contains(i)) acc.append(c_batch[i]) else acc)),
      c_pend' = Set(),
      c_batch' = [],
      c_inForce' = c_inForce, c_hostSpent' = c_hostSpent,
    }
  }

  // The pinned host input of a record state confirms at most once.
  action c_hostSpend(nf: int): bool = all {
    listSet(c_inForce).contains(nf),
    c_hostSpent.get(nf) == 0,
    c_hostSpent' = c_hostSpent.set(nf, 1),
    c_inForce' = c_inForce, c_pend' = c_pend, c_batch' = c_batch, c_landed' = c_landed,
  }

  // Whole-committee restart with every disk rolled back: the board tail past the
  // latest landed checkpoint is lost, with its pending set and its batch.
  action c_boardLoss = all {
    BOARD_LOSS,
    c_pend' = Set(), c_batch' = [],
    c_inForce' = c_inForce, c_landed' = c_landed, c_hostSpent' = c_hostSpent,
  }

  action c_step = any {
    nondet nf = NF.oneOf()
    c_post(nf),
    nondet nf = NF.oneOf()
    c_byzInject(nf),
    c_checkpoint,
    nondet nf = NF.oneOf()
    c_hostSpend(nf),
    c_boardLoss,
  }

  // C11 (board-first): no two calls in force share one nf.
  val C11_bfNoDupInForce = noDup(c_inForce)
  // C11 (board-first): the landed bf_root values hold each nf once.
  val C11_bfLandedDisjoint = noDup(flat(c_landed))
  // C11 (board-first): the pinned host input bounds the host chain to one spend.
  val C11_bfOneHostSpend = NF.forall(x => c_hostSpent.get(x) <= 1)

  // ---------------------------------------------------------------- composition
  action init = all { a_init, b_init, c_init }
  action step = any {
    all { a_step, b_unchanged, c_unchanged },
    all { a_unchanged, b_step, c_unchanged },
    all { a_unchanged, b_unchanged, c_step },
  }

  val allInvariants = and {
    C12_C16_oneTicketPerSlot, C16_burnCoversList, C16_pendingMinRuleImpliesListRule,
    C13_honestCheckpointLands, C11_oneOutcomePerAuth, C11_oneAuthorizePerState,
    C11_noLostSuccessor, C11_settledByCheckpoint, C11_bfNoDupInForce,
    C11_bfLandedDisjoint, C11_bfOneHostSpend,
  }
}

module design { import batched_checkpoint(MUT = 0, BOARD_LOSS = false).* }
module boardLoss { import batched_checkpoint(MUT = 0, BOARD_LOSS = true).* }
module mut1_windowOnly { import batched_checkpoint(MUT = 1, BOARD_LOSS = false).* }
module mut2_highestPending { import batched_checkpoint(MUT = 2, BOARD_LOSS = false).* }
module mut3_noCarryCheck { import batched_checkpoint(MUT = 3, BOARD_LOSS = false).* }
module mut4_doubleSign { import batched_checkpoint(MUT = 4, BOARD_LOSS = false).* }
module mut5_spentNf { import batched_checkpoint(MUT = 5, BOARD_LOSS = false).* }
module mut6_partialRoot { import batched_checkpoint(MUT = 6, BOARD_LOSS = false).* }
module mut7_replayVoid { import batched_checkpoint(MUT = 7, BOARD_LOSS = false).* }
module mut8_boardDupNf { import batched_checkpoint(MUT = 8, BOARD_LOSS = false).* }
module mut9_noLandedCheck { import batched_checkpoint(MUT = 9, BOARD_LOSS = false).* }
module mut10_noSignerCheck { import batched_checkpoint(MUT = 10, BOARD_LOSS = false).* }
module mut11_proofBelowPendingMin { import batched_checkpoint(MUT = 11, BOARD_LOSS = false).* }

// Reachability witnesses: each val is expected to be VIOLATED by `quint run`,
// which shows that the invariants above are not vacuous.
module witnesses {
  import batched_checkpoint(MUT = 0, BOARD_LOSS = false).*
  // A restart burns while a request holds a pending index below h, after a disk rollback.
  val W_restartWithPending = not(a_lastOld.exists(i => i <= lastCp(a_cps).h) and a_era > 0)
  // A slot bound after a rollback of every disk and a lost board tail.
  val W_bindAfterLoss = not(IDX.exists(i => a_uses.get(i).exists(t => t % 100 > 0)))
  // A reissue lands with its carried VOID settlement before any root covers the leaf.
  val W_reissueEarly = W_reissueWaitsForRoot
  // A FINAL settlement lands and its successor is spent on the root path.
  val W_spendAfterFinal = not(AUTH.exists(a => b_root.contains((a, "FINAL")) and b_spent.get(succ(a, "FINAL")) > 0))
  // The signers drop a repeated nf that a Byzantine proposer listed.
  val W_dupDropped = not(c_landed.length() > 0 and flat(c_landed).length() < c_inForce.length())
}

module tests {
  import batched_checkpoint(MUT = 0, BOARD_LOSS = false).*

  action stepB(act: bool): bool = all { a_unchanged, act, c_unchanged }
  action stepA(act: bool): bool = all { act, b_unchanged, c_unchanged }
  action stepC(act: bool): bool = all { a_unchanged, b_unchanged, act }

  // §5.9 item 7: a reissue carries the VOID settlement and waits for no checkpoint.
  run reissueCarriesVoidTest = init
    .then(stepB(b_authorize(0, 0)))
    .then(all { assert(b_status.get(1) == "live"), stepB(b_end(1)) })
    .then(all { assert(b_signed == Set((1, "VOID"))), stepB(b_authorize(12, 1)) })
    .then(all { assert(b_nextAuth == 3), stepB(b_unchanged) })
    .then(all { assert(b_carried == Set(1)), stepB(b_unchanged) })
    .then(all { assert(b_reissueEarly), stepB(b_checkpoint) })
    .then(all { assert(counted(b_root, b_carried, 1) == Set("VOID")), assert(C11_oneAuthorizePerState), stepB(b_checkpoint) })

  // §7.11 and §7.13: request 1 holds index 1 below h at the checkpoint, binds it after,
  // ends, and every disk rolls back with the board tail lost. The burn [pending_min, h + B]
  // covers index 1, so the replayed request cannot bind it to a new ticket.
  run pendingMinBurnAfterRollbackTest = init
    .then(stepA(a_reserve(1, 1)))
    .then(stepA(a_reserve(2, 2)))
    .then(stepA(a_end(2)))
    .then(stepA(a_checkpoint))
    .then(all { assert(lastCp(a_cps) == { h: 2, pendingMin: 1, pend: Set(1), forged: Set() }), stepA(a_bind(1)) })
    .then(stepA(a_end(1)))
    .then(stepA(a_restart(0, true)))
    .then(all {
      assert(a_lastNew == Set(1, 2, 3, 4)),
      assert(a_lastOld == Set(1, 3, 4)),
      assert(a_status.get(1) == "ended"),
      assert(a_burned.contains(1)),
      stepA(a_checkpoint),
    })
    .then(all {
      assert(lastCp(a_cps).h == 4), assert(lastCp(a_cps).pendingMin == 5),
      assert(C13_honestCheckpointLands), assert(C16_pendingMinRuleImpliesListRule),
      assert(C12_C16_oneTicketPerSlot),
      stepA(a_unchanged),
    })

  // §5.6: a FINAL settlement counts by the root path only, and its successor is spent once.
  run finalByRootTest = init
    .then(stepB(b_authorize(0, 0)))
    .then(stepB(b_release(1)))
    .then(stepB(b_hostConfirm(1)))
    .then(stepB(b_end(1)))
    .then(all { assert(b_signed == Set((1, "FINAL"))), assert(not(recExists(11))), stepB(b_checkpoint) })
    .then(all { assert(recExists(11)), stepB(b_authorize(11, 0)) })
    .then(all { assert(C11_noLostSuccessor), assert(C11_oneAuthorizePerState), stepB(b_unchanged) })

  // §5.3: the board refuses a second call on one nf, and the signers drop a repeated nf
  // that a Byzantine proposer lists.
  run bfDuplicateRefusedTest = init
    .then(stepC(c_post(1)))
    .then(all { assert(c_pend.contains(1)), stepC(c_byzInject(1)) })
    .then(stepC(c_checkpoint))
    .then(all { assert(c_landed == [[1]]), assert(listSet(flat(c_landed)).contains(1)), stepC(c_unchanged) })
}
