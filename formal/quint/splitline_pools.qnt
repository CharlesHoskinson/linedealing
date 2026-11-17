// -*- mode: Bluespec; -*-
// Committee pools, the reservation window, slot states, the batched bind, the whole-committee
// restart and the recovery reshare of split-line dealing (DESIGN.md §4.1, §5.8, §7.4, §7.7,
// §7.11, §7.13 as of main 0736ed6, with DECISIONS 54). The request machine of splitline.qnt abstracts these into
// SlotSt; this module models them on their own, so the sampler reaches restarts and
// recoveries in a few steps. The rules come from the DESIGN text only.
//
// Scope. Nodes are the honest seats of a TEE committee whose seald enforces slot states; the
// board is safe (|C| <= f), so every honest node reads one order and one anchor per request.
// A whole-committee restart rolls every disk back to genesis (the worst case of §7.11) and
// loses the board tail past the checkpoint it reads. Recovery hands the committee to a
// successor through E (§5.8). A ticket is rid * 10 + variant; a request whose board tail is
// lost may be anchored again with another variant, which is the reuse that the pending burn
// stops.
//
// Pools: 1 = Schnorr committee pool, 2 = Ed25519 committee pool, 3 = one ECDSA account pool.
// With one shared committee index space (mutant m_shared_pool) both suites use pool 1:
// odd indices were dealt for Schnorr, even ones for Ed25519.
//
// Burns: a committee slot burns at the end of the request that had precedence on it (§4.1,
// §4.5 item 4). An account-pool slot burns at the end of the request that reserved it, and
// only a reserved slot takes precedence (DECISIONS 54). Every request here is authorized:
// splitline.qnt models the authorization and the G5 rule. A restart burns [pending_min, h + B]
// of the checkpoint it reads (§7.11 item 1). The contract rules on h and pending_min, the
// settle_root and bf_root are checked in design/enhancement/quint/batched_checkpoint.qnt.
//
// Invariants carry the DESIGN claim ids C12, C13, C15 and C16.

module splitline_pools_types {
  type SlotSt = Free | Bound(int) | Burned

  type PRules = {
    windowVote: bool,        // §4.1: an honest node votes only for a header inside the window
    windowBind: bool,        // §4.1, §7.7: seald checks the same bounds at slot_bind
    poolPerSuite: bool,      // §4.1: one committee pool per suite and epoch
    batchBind: bool,         // §7.7: one bind round per pool session and board height (O36)
    bindBeforePartial: bool, // §5.6 item 6: no partial before slot_bind
    burnWindow: bool,        // §7.11 item 1: burn (h, h + B] of the checkpoint read
    burnPending: bool,       // §7.11 item 1: burn the pending indices of the checkpoint read
    burnAccounts: bool,      // §7.11 item 1: burn every free and bound account-pool slot
    acctBurnAll: bool,       // §7.11 item 1 (PR4): the burn reaches every slot of each account pool
                             // that the node finds among its sessions; off, only the slots that a
                             // request on the readable board named (the prototype reducer)
    reshareCoveredOnly: bool,// §7.11 item 2, §5.8: E reshares only slots no covered seat log binds
    reshareNoAnchor: bool,   // mutant switch: E reshares from the checkpoint's board view without anchors
    acctPrec: bool,          // §4.1, DECISIONS 54: the earliest live request in board order takes an account-pool slot
    voteStale: bool,         // §7.11 item 1: after a restart an honest node votes for no burned index, and
                             // the request that names it ends VOID; off, only seald's bind checks remain
  }

  pure val POOL_RULES: PRules = {
    windowVote: true, windowBind: true, poolPerSuite: true, batchBind: true, bindBeforePartial: true,
    burnWindow: true, burnPending: true, burnAccounts: true, acctBurnAll: true, reshareCoveredOnly: true,
    reshareNoAnchor: false, acctPrec: true, voteStale: true,
  }

  type PReq = {
    suite: int,          // 1 Schnorr, 2 Ed25519, 3 ECDSA
    pool: int,
    idx: int,
    st: str,             // U unposted, P posted, O ordered, A admitted, K anchored, F final, V void, L lost
    reason: str,
    order: int,
    votes: Set[int],
    variant: int,
    anchorH: int,
    held: bool,          // the request reserved its slot (ADMIT)
    prec: bool,          // the request had precedence on its slot at ordering
    succ: bool,          // posted to the successor committee after recovery
  }

  type Cp = {
    seq: int,
    h: int -> int,                    // floor per committee pool
    pending: int -> Set[(int, int)],  // (index, rid) per committee pool
    roots: int -> Set[(int, int, int)], // seat -> covered bindings (pool, index, ticket)
    boardSeq: int,
    reqSnap: int -> PReq,
  }

  type PNode = {
    sl: (int, int) -> SlotSt,
    log: Set[(int, int, int)],        // seat log on the board: bindings (pool, index, ticket)
    acctOk: bool,                     // no account-pool bind between a restart and the next checkpoint
  }

  type PS = {
    reqs: int -> PReq,
    seq: int,
    bh: int,
    cp: Cp,
    needRaise: bool,
    retired: int -> int,              // pool -> highest index a restart burn retired
    burnedAtRestart: Set[(int, int)],
    nodes: int -> PNode,
    rounds: Set[(int, int, int, int)],// (node, pool, board height, round number)
    bindHist: Set[(int, int, int, int, bool)], // (node, pool, index, ticket, inside window at bind)
    voteLog: Set[(int, int, bool)],   // (node, rid, inside window at vote)
    partials: Set[(int, int, int, int)], // (node, pool, index, ticket)
    everHeld: Set[(int, int, int)],   // (pool, index, suite) reserved by some request
    restarts: int,
    recovered: bool,
    reshared: Set[int],
    usedAtRecovery: Set[int],
    oldCovered: Set[(int, int, int)],
    batchRefusal: bool,
    partialAfterRestart: bool,
    partialOnReshared: bool,
    lastAction: str,
  }
}

module splitline_pools {
  import splitline_pools_types.*

  const NN: int        // honest seats
  const QQ: int        // votes to admit, partials to finish
  const B: int         // window width
  const ANCHOR: bool   // seald anchor_before_release / slot_anchor on (§7.7, O32)
  const PR: PRules

  pure val PNODES: Set[int] = 1.to(NN)
  pure val PRIDS: Set[int] = 1.to(4)
  pure val MAXI: int = 6
  pure val ACCT: Set[int] = 1.to(3)
  pure val MAXBH: int = 6
  pure val MAXCP: int = 6
  pure val COMMITTEE_POOLS: Set[int] = if (PR.poolPerSuite) Set(1, 2) else Set(1)
  pure val POOLS: Set[int] = COMMITTEE_POOLS.union(Set(3))

  pure def poolOf(su: int): int = if (su == 3) 3 else if (PR.poolPerSuite) su else 1
  pure def isCommittee(pl: int): bool = pl != 3
  // the suite an index of a committee pool was dealt for
  pure def dealtFor(pl: int, i: int): int = if (PR.poolPerSuite) pl else (if (i % 2 == 1) 1 else 2)
  pure def idxOf(su: int): Set[int] =
    if (su == 3) ACCT else 1.to(MAXI).filter(i => dealtFor(poolOf(su), i) == su)
  pure def tkOf(r: int, v: int): int = r * 10 + v
  pure def allSlots: Set[(int, int)] =
    tuples(COMMITTEE_POOLS, 1.to(MAXI)).union(tuples(Set(3), ACCT))

  pure val emptyReq: PReq = {
    suite: 0, pool: 0, idx: 0, st: "U", reason: "", order: 0, votes: Set(), variant: 0,
    anchorH: -1, held: false, prec: false, succ: false,
  }
  pure val freshNode: PNode = { sl: allSlots.mapBy(_ => Free), log: Set(), acctOk: true }

  var p: PS

  // §4.1 window rule against the latest checkpoint.
  pure def inWindow(st: PS, pl: int, i: int, r: int): bool =
    not(isCommittee(pl))
    or (st.cp.h.get(pl) < i and i <= st.cp.h.get(pl) + B)
    or st.cp.pending.get(pl).contains((i, r))

  // §7.13: the lowest pending index, or h + 1 when no request holds one.
  pure def pendingMin(cp: Cp, pl: int): int =
    cp.pending.get(pl).fold(cp.h.get(pl) + 1, (m, e) => if (e._1 < m) e._1 else m)

  pure def isEnded(x: str): bool = Set("F", "V", "L").contains(x)
  pure def isLive(x: str): bool = Set("O", "A", "K").contains(x)
  pure def slotKey(rq: PReq): (int, int) = (rq.pool, rq.idx)

  // a binding (pool, index, ticket) that a covered seat log holds for another ticket
  pure def coveredConflict(st: PS, pl: int, i: int, tk: int): bool =
    // a successor's seats read their own seat logs; the old seats' bindings reach them only
    // through the reshare rule of E (§7.11 item 2)
    PNODES.exists(n => st.cp.roots.get(n).exists(e => e._1 == pl and e._2 == i and e._3 != tk))

  pure def heldMax(st: PS, pl: int): int =
    PRIDS.filter(r => st.reqs.get(r).held and st.reqs.get(r).pool == pl and not(st.reqs.get(r).succ))
         .fold(0, (m, r) => if (st.reqs.get(r).idx > m) st.reqs.get(r).idx else m)

  // a seat after the restart: rolled back to genesis, then the burns, or with anchors the
  // covered bindings of its seat log
  pure def restoreNode(covered: Set[(int, int, int)], burned: Set[(int, int)]): PNode = {
    sl: allSlots.mapBy(sk => {
      val c = covered.filter(e => e._1 == sk._1 and e._2 == sk._2)
      if (burned.contains(sk)) Burned
      else if (ANCHOR and c.size() > 0) Bound(c.fold(0, (m, e) => e._3))
      else Free }),
    log: covered, acctOk: ANCHOR,
  }

  action pinit: bool = all {
    p' = {
      reqs: PRIDS.mapBy(_ => emptyReq), seq: 0, bh: 0,
      cp: { seq: 0, h: COMMITTEE_POOLS.mapBy(_ => 0), pending: COMMITTEE_POOLS.mapBy(_ => Set()),
            roots: PNODES.mapBy(_ => Set()), boardSeq: 0, reqSnap: PRIDS.mapBy(_ => emptyReq) },
      needRaise: false, retired: COMMITTEE_POOLS.mapBy(_ => 0), burnedAtRestart: Set(),
      nodes: PNODES.mapBy(_ => freshNode), rounds: Set(), bindHist: Set(), voteLog: Set(),
      partials: Set(), everHeld: Set(), restarts: 0, recovered: false, reshared: Set(),
      usedAtRecovery: Set(), oldCovered: Set(), batchRefusal: false, partialAfterRestart: false,
      partialOnReshared: false, lastAction: "init",
    }
  }

  action doPost(r: int, su: int, i: int): bool = {
    val rq = p.reqs.get(r)
    all {
      rq.st == "U", idxOf(su).contains(i),
      not(p.recovered) or su == 3,            // the successor's charter admits exits only
      p' = { ...p, reqs: p.reqs.set(r, { ...emptyReq, suite: su, pool: poolOf(su), idx: i, st: "P",
                                          succ: p.recovered }),
             lastAction: "post" },
    }
  }

  // Precedence by board order (§4.1): an earlier request that named the slot takes it.
  action doOrder(r: int): bool = {
    val rq = p.reqs.get(r)
    // committee pool: the earlier namer has precedence; account pool: only a request that
    // reserved the slot holds it (DECISIONS 54)
    val taken = PRIDS.exists(q => q != r and p.reqs.get(q).order > 0 and p.reqs.get(q).succ == rq.succ
      and slotKey(p.reqs.get(q)) == slotKey(rq) and p.reqs.get(q).st != "L"
      and (if (isCommittee(rq.pool)) p.reqs.get(q).prec else p.reqs.get(q).held))
    all {
      rq.st == "P",
      p' = { ...p, seq: p.seq + 1,
             reqs: p.reqs.set(r, if (taken) { ...rq, order: p.seq + 1, st: "V", reason: "SLOT_TAKEN" }
                                 else { ...rq, order: p.seq + 1, st: "O", prec: isCommittee(rq.pool) }),
             lastAction: "order" },
    }
  }

  action doVote(i: int, r: int): bool = {
    val rq = p.reqs.get(r)
    // §7.11 item 1: slot_stale refuses a burned committee index, and a burned account pool
    // takes no vote (the model has no refill session).
    val ok = inWindow(p, rq.pool, rq.idx, r) and not(PR.voteStale and p.burnedAtRestart.contains(slotKey(rq)))
    all {
      rq.st == "O", not(rq.votes.contains(i)),
      not(PR.windowVote) or ok,
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, votes: rq.votes.union(Set(i)) }),
             voteLog: p.voteLog.union(Set((i, r, ok))), lastAction: "vote" },
    }
  }

  // §4.1: an index at or below h that the checkpoint does not list as pending for this
  // request never gets an honest vote; the request ends VOID with SLOT_TAKEN.
  action doVoidBelowFloor(r: int): bool = {
    val rq = p.reqs.get(r)
    all {
      PR.windowVote, rq.st == "O", isCommittee(rq.pool),
      rq.idx <= p.cp.h.get(rq.pool), not(p.cp.pending.get(rq.pool).contains((rq.idx, r))),
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "V", reason: "SLOT_TAKEN" }), lastAction: "voidBelowFloor" },
    }
  }

  pure def acctHeldByOther(st: PS, r: int): bool = {
    val rq = st.reqs.get(r)
    PRIDS.exists(q => q != r and st.reqs.get(q).held and st.reqs.get(q).succ == rq.succ
      and slotKey(st.reqs.get(q)) == slotKey(rq) and st.reqs.get(q).st != "L")
  }

  // §4.1, DECISIONS 54: every request of this model is authorized, so of the live requests
  // that name an account-pool slot the earliest in board order has precedence.
  pure def acctEarlierLive(st: PS, r: int): bool = {
    val rq = st.reqs.get(r)
    PRIDS.exists(q => q != r and st.reqs.get(q).succ == rq.succ and slotKey(st.reqs.get(q)) == slotKey(rq)
      and isLive(st.reqs.get(q).st) and st.reqs.get(q).order > 0 and st.reqs.get(q).order < rq.order)
  }

  // §7.11 item 1: a request that names a burned slot ends VOID; the owner re-posts it.
  action doVoidBurned(r: int): bool = {
    val rq = p.reqs.get(r)
    all {
      PR.voteStale, rq.st == "O", p.burnedAtRestart.contains(slotKey(rq)),
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "V", reason: "BURNED" }), lastAction: "voidBurned" },
    }
  }

  // DECISIONS 54: an ordered ECDSA request whose slot another request reserved ends SLOT_TAKEN.
  action doVoidAcctTaken(r: int): bool = {
    val rq = p.reqs.get(r)
    all {
      rq.st == "O", not(isCommittee(rq.pool)), acctHeldByOther(p, r),
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "V", reason: "SLOT_TAKEN" }), lastAction: "voidAcctTaken" },
    }
  }

  action doAdmit(r: int): bool = {
    val rq = p.reqs.get(r)
    all {
      rq.st == "O", rq.votes.size() >= QQ,
      isCommittee(rq.pool) or not(acctHeldByOther(p, r) or (PR.acctPrec and acctEarlierLive(p, r))),
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "A", held: true }),
             everHeld: p.everHeld.union(Set((rq.pool, rq.idx, rq.suite))), lastAction: "admit" },
    }
  }

  action doAnchor(r: int, v: int): bool = {
    val rq = p.reqs.get(r)
    all {
      rq.st == "A", Set(1, 2).contains(v),
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "K", variant: v, anchorH: p.bh }), lastAction: "anchor" },
    }
  }

  // §7.4, §7.7 with anchors: the node appends its bindings of one pool to its seat log.
  action doLog(i: int, pl: int): bool = {
    val nd = p.nodes.get(i)
    // slot_bind appends the binding, so seald's window and marker checks apply here too
    val es = PRIDS.filter(r => p.reqs.get(r).st == "K" and p.reqs.get(r).pool == pl
                               and nd.sl.get((pl, p.reqs.get(r).idx)) == Free
                               and (if (pl == 3) nd.acctOk else (not(PR.windowBind) or inWindow(p, pl, p.reqs.get(r).idx, r))))
                  .map(r => (pl, p.reqs.get(r).idx, tkOf(r, p.reqs.get(r).variant)))
    all {
      ANCHOR, not(es.subseteq(nd.log)),
      p' = { ...p, nodes: p.nodes.set(i, { ...nd, log: nd.log.union(es) }), lastAction: "log" },
    }
  }

  // §7.7: one bind round per pool session and board height binds every slot that the
  // anchors fix; seald refuses a slot by its own rules and binds the others (O36, G2).
  action doBindBatch(i: int, pl: int, one: int): bool = {
    val nd = p.nodes.get(i)
    val cand = PRIDS.filter(r => p.reqs.get(r).st == "K" and p.reqs.get(r).pool == pl
                                 and nd.sl.get((pl, p.reqs.get(r).idx)) == Free)
    val k = p.rounds.filter(x => x._1 == i and x._2 == pl and x._3 == p.bh).size()
    // a per-slot bind (mutant) takes one candidate per round
    val batch = if (PR.batchBind) cand else cand.filter(r => r == one)
    val accept = batch.filter(r => {
      val rq = p.reqs.get(r)
      val tk = tkOf(r, rq.variant)
      and {
        if (rq.pool == 3) nd.acctOk else (not(PR.windowBind) or inWindow(p, rq.pool, rq.idx, r)),
        not(ANCHOR) or (p.cp.roots.get(i).contains((rq.pool, rq.idx, tk)) and not(coveredConflict(p, rq.pool, rq.idx, tk))),
      } })
    all {
      batch.size() > 0, not(PR.batchBind) or k == 0,
      p' = { ...p,
        nodes: p.nodes.set(i, { ...nd, sl: accept.fold(nd.sl, (m, r) =>
                 m.set((pl, p.reqs.get(r).idx), Bound(tkOf(r, p.reqs.get(r).variant)))) }),
        bindHist: p.bindHist.union(accept.map(r => {
          val rq = p.reqs.get(r)
          (i, pl, rq.idx, tkOf(r, rq.variant), inWindow(p, rq.pool, rq.idx, r)) })),
        rounds: p.rounds.union(Set((i, pl, p.bh, k))),
        batchRefusal: p.batchRefusal or (accept.size() > 0 and accept.size() < batch.size()),
        lastAction: "bindBatch" },
    }
  }

  action doRelease(i: int, r: int): bool = {
    val rq = p.reqs.get(r)
    val tk = tkOf(r, rq.variant)
    val st0 = p.nodes.get(i).sl.get((rq.pool, rq.idx))
    all {
      rq.st == "K",
      if (PR.bindBeforePartial) st0 == Bound(tk) else st0 != Burned,
      not(p.partials.contains((i, rq.pool, rq.idx, tk))),
      p' = { ...p, partials: p.partials.union(Set((i, rq.pool, rq.idx, tk))),
             partialAfterRestart: p.partialAfterRestart or p.restarts > 0,
             partialOnReshared: p.partialOnReshared or (rq.pool == 3 and p.reshared.contains(rq.idx)),
             lastAction: "release" },
    }
  }

  action doFinal(r: int): bool = {
    val rq = p.reqs.get(r)
    val tk = tkOf(r, rq.variant)
    all {
      rq.st == "K", p.partials.filter(x => x._2 == rq.pool and x._3 == rq.idx and x._4 == tk).size() >= QQ,
      p' = { ...p, reqs: p.reqs.set(r, { ...rq, st: "F", reason: "FINAL" }), lastAction: "final" },
    }
  }

  // §4.5: a slot burns at the end of its request.
  action doBurnEnd(i: int, r: int): bool = {
    val rq = p.reqs.get(r)
    val nd = p.nodes.get(i)
    all {
      Set("F", "V").contains(rq.st), if (isCommittee(rq.pool)) rq.prec else rq.held,
      nd.sl.get(slotKey(rq)) != Burned,
      p' = { ...p, nodes: p.nodes.set(i, { ...nd, sl: nd.sl.set(slotKey(rq), Burned) }), lastAction: "burnEnd" },
    }
  }

  action doHeight: bool = all { p.bh < MAXBH, p' = { ...p, bh: p.bh + 1, lastAction: "height" } }

  // §4.1, §7.13: floor, pending indices and seat roots. After a restart the next checkpoint
  // raises h to at least h + B and drops the burned indices from the pending set.
  action doCheckpoint: bool = {
    val newH = COMMITTEE_POOLS.mapBy(pl => {
      val base = Set(p.cp.h.get(pl), heldMax(p, pl), p.retired.get(pl)).fold(0, (m, x) => if (x > m) x else m)
      if (p.needRaise and base < p.cp.h.get(pl) + B) p.cp.h.get(pl) + B else base })
    val pend = COMMITTEE_POOLS.mapBy(pl =>
      PRIDS.filter(r => Set("A", "K").contains(p.reqs.get(r).st) and p.reqs.get(r).pool == pl)
           .map(r => (p.reqs.get(r).idx, r))
           .filter(e => not(p.burnedAtRestart.contains((pl, e._1)))))
    val roots = PNODES.mapBy(n => p.nodes.get(n).log)
    all {
      p.cp.seq < MAXCP, not(p.recovered),
      newH != p.cp.h or pend != p.cp.pending or roots != p.cp.roots or p.needRaise or p.cp.seq == 0,
      p' = { ...p,
        cp: { seq: p.cp.seq + 1, h: newH, pending: pend, roots: PNODES.mapBy(n => p.nodes.get(n).log),
              boardSeq: p.seq, reqSnap: p.reqs },
        needRaise: false,
        nodes: PNODES.mapBy(n => { ...p.nodes.get(n), acctOk: true }),
        lastAction: "checkpoint" },
    }
  }

  // §7.11 item 1: whole-committee restart. Every disk rolls back to genesis and the board
  // tail past the checkpoint is lost. Burns: the window (h, h + B] and the pending indices
  // of every committee pool, and every free and bound account-pool slot. With anchors
  // nothing burns: a slot with a covered binding becomes bound to that digest.
  action doWholeRestart: bool = {
    val cp = p.cp
    // design: [pending_min, h + B]; the mutants keep one half of the list rule
    val burnC: Set[(int, int)] = COMMITTEE_POOLS.fold(Set(), (acc, pl) => {
      val h = cp.h.get(pl)
      val pmin = pendingMin(cp, pl)
      acc.union(
        if (PR.burnWindow and PR.burnPending) 1.to(MAXI).filter(i => pmin <= i and i <= h + B).map(i => (pl, i))
        else if (PR.burnWindow) 1.to(MAXI).filter(i => h < i and i <= h + B).map(i => (pl, i))
        else if (PR.burnPending) cp.pending.get(pl).map(e => (pl, e._1))
        else Set()) })
    val boardNamed: Set[int] = ACCT.filter(i => PRIDS.exists(r => cp.reqSnap.get(r).order > 0
                                                         and cp.reqSnap.get(r).pool == 3 and cp.reqSnap.get(r).idx == i))
    val burnA: Set[(int, int)] =
      if (not(PR.burnAccounts)) Set()
      else if (PR.acctBurnAll) ACCT.map(i => (3, i))
      else boardNamed.map(i => (3, i))
    val burned = if (ANCHOR) Set() else burnC.union(burnA)
    all {
      p.restarts < 1, not(p.recovered), p.cp.seq >= 1,
      p' = { ...p,
        reqs: PRIDS.mapBy(r => {
          val snap = cp.reqSnap.get(r)
          val cur = p.reqs.get(r)
          if (cur.order == 0) cur
          else if (cur.order > cp.boardSeq) { ...cur, st: "L", reason: "BOARD_TAIL" }
          // §7.11 item 1: every live request on a burned slot ends VOID, also one that
          // holds its index by precedence only or has no reservation yet
          else if (isLive(snap.st) and burned.contains(slotKey(snap))) { ...snap, st: "V", reason: "BURNED" }
          else snap }),
        seq: cp.boardSeq,
        nodes: PNODES.mapBy(n => restoreNode(cp.roots.get(n), burned)),
        needRaise: not(ANCHOR),
        retired: COMMITTEE_POOLS.mapBy(pl => if (ANCHOR or not(PR.burnWindow)) p.retired.get(pl) else cp.h.get(pl) + B),
        burnedAtRestart: burned,
        // a covered binding restores the bound state: it counts as the bind (§7.11)
        bindHist: p.bindHist.union(if (ANCHOR) PNODES.fold(Set(), (acc, n) =>
          acc.union(cp.roots.get(n).map(e => (n, e._1, e._2, e._3, true)))) else Set()),
        restarts: p.restarts + 1,
        lastAction: "wholeRestart" },
    }
  }

  // §5.8, §7.11 item 2: E reshares x_f and the ECDSA slot shares that no covered seat log
  // binds, only on a committee with anchors. Committee nonce slots are not backed up.
  action doRecover: bool = {
    val cp = p.cp
    val coveredBound = ACCT.filter(i => PNODES.exists(n => cp.roots.get(n).exists(e => e._1 == 3 and e._2 == i)))
    val boardClaimed = ACCT.filter(i => PRIDS.exists(r => cp.reqSnap.get(r).held and cp.reqSnap.get(r).pool == 3
                                                           and cp.reqSnap.get(r).idx == i))
    val rs =
      if (ANCHOR) (if (PR.reshareCoveredOnly) ACCT.exclude(coveredBound) else ACCT)
      else if (PR.reshareNoAnchor) ACCT.exclude(boardClaimed)
      else Set()
    all {
      not(p.recovered), p.cp.seq >= 1,
      p' = { ...p,
        reqs: PRIDS.mapBy(r => if (isLive(p.reqs.get(r).st) or p.reqs.get(r).st == "P")
                                 { ...p.reqs.get(r), st: "L", reason: "RECOVERY" } else p.reqs.get(r)),
        nodes: PNODES.mapBy(n => { sl: allSlots.mapBy(sk => if (sk._1 == 3 and rs.contains(sk._2)) Free else Burned),
                                   log: Set(), acctOk: true }),
        oldCovered: PNODES.fold(Set(), (acc, n) => acc.union(cp.roots.get(n))),
        cp: { ...cp, roots: PNODES.mapBy(_ => Set()) },
        recovered: true, reshared: rs, needRaise: false,
        usedAtRecovery: p.partials.filter(x => x._2 == 3).map(x => x._3),
        lastAction: "recover" },
    }
  }

  // Checkpoints of the successor cover its seat logs (pool fields unchanged: exits use ECDSA).
  action doSuccCheckpoint: bool = all {
    p.recovered, p.cp.seq < MAXCP + 3, PNODES.mapBy(n => p.nodes.get(n).log) != p.cp.roots,
    p' = { ...p, cp: { ...p.cp, seq: p.cp.seq + 1, roots: PNODES.mapBy(n => p.nodes.get(n).log) },
           lastAction: "succCheckpoint" },
  }

  action doIdle: bool = all { p' = { ...p, lastAction: "idle" } }

  action pprog: bool = {
    nondet r = PRIDS.oneOf()
    nondet i = PNODES.oneOf()
    nondet su = Set(1, 2, 3).oneOf()
    nondet ix = 1.to(MAXI).oneOf()
    nondet v = Set(1, 2).oneOf()
    nondet pl = POOLS.oneOf()
    any {
      doPost(r, su, ix), doOrder(r), doVote(i, r), doVote(i, r), doVoidBelowFloor(r), doVoidAcctTaken(r), doVoidBurned(r), doAdmit(r),
      doAnchor(r, v), doLog(i, pl), doBindBatch(i, pl, r), doBindBatch(i, pl, r), doRelease(i, r), doRelease(i, r),
      doFinal(r), doBurnEnd(i, r), doHeight, doCheckpoint, doSuccCheckpoint, doIdle,
    }
  }
  action pfault: bool = any { doWholeRestart, doRecover }
  // Progress about 16 times as often as a restart or a recovery.
  action p4: bool = any { pprog, pprog, pprog, pprog }
  action pstep: bool = any { p4, p4, p4, p4, pfault }
  action pstepRestart: bool = any { p4, p4, p4, p4, p4, p4, p4, p4, doWholeRestart }
  action pstepRecover: bool = any { p4, p4, p4, p4, p4, p4, p4, p4, doRecover }

  // ---------------------------------------------------------------- invariants
  // C12, C16: honest partials on one slot name one ticket, across restarts and recovery.
  val C16_NoSlotTwice: bool =
    p.partials.forall(a => p.partials.forall(b => not(a._2 == b._2 and a._3 == b._3) or a._4 == b._4))

  // C13 (§4.1): every honest OPENED/ADMIT vote met the window rule at the time of the vote.
  val C13_VoteInWindow: bool = p.voteLog.forall(e => e._3)

  // C13 (§4.1, §7.7): seald binds a committee slot only inside the window or for its own pending index.
  val C13_BindInWindow: bool = p.bindHist.forall(e => e._5)

  // C12 (§5.6 item 6): no partial before slot_bind fixed the slot to that ticket.
  val C12_NoPartialBeforeBind: bool =
    p.partials.forall(x => p.bindHist.exists(b => b._1 == x._1 and b._2 == x._2 and b._3 == x._3 and b._4 == x._4))

  // C13 (§7.7, O36): one bind round per pool session and board height.
  val C13_OneBindRound: bool = p.rounds.forall(x => x._4 == 0)

  // C12 (G2 with a batch): a node never binds one slot to two tickets, also when a batch
  // holds a refused slot and across restarts.
  val C12_BindOneTicket: bool =
    p.bindHist.forall(a => p.bindHist.forall(b => not(a._1 == b._1 and a._2 == b._2 and a._3 == b._3) or a._4 == b._4))

  // C13 (§4.1): an index is lost only to its own suite: an unreserved index of suite s below
  // the floor lies below an index that a request of suite s reserved, or a restart retired it.
  val C13_LostOnlyOwnSuite: bool =
    COMMITTEE_POOLS.forall(pl => 1.to(MAXI).forall(i => {
      val su = dealtFor(pl, i)
      not(i <= p.cp.h.get(pl) and not(p.everHeld.exists(e => e._1 == pl and e._2 == i)) and i > p.retired.get(pl))
      or p.everHeld.exists(e => e._1 == pl and e._2 > i and e._3 == su)
    }))

  // C15 (§5.8, §7.11 item 2): without anchors E reshares no ECDSA slot.
  val C15_NoEcdsaReshareWithoutAnchor: bool = ANCHOR or p.reshared == Set()

  // C15, C16: E never reshares an ECDSA slot that signed before the recovery.
  val C15_ReshareOnlyUnused: bool = p.reshared.intersect(p.usedAtRecovery) == Set()

  // C16 (§7.13): an honest checkpoint has pending_min <= h + 1 for every pool, so the
  // contract never refuses it on that rule (the refusal is checked in batched_checkpoint.qnt).
  val C16_PendingMinAtMostFloorPlusOne: bool =
    COMMITTEE_POOLS.forall(pl => pendingMin(p.cp, pl) <= p.cp.h.get(pl) + 1)

  // C12, C13 (DECISIONS 54): no two requests reserve one account-pool slot in one committee.
  // C13 (§4.1, DECISIONS 54): no later request holds an account-pool slot that an earlier
  // live request names, and SLOT_TAKEN on the account pool names an earlier request.
  val C13_AcctEarliestHolds: bool = and {
    PRIDS.forall(x => { val xq = p.reqs.get(x)
      (xq.pool == 3 and xq.held and isLive(xq.st)) implies not(acctEarlierLive(p, x)) }),
    PRIDS.forall(r => { val rq = p.reqs.get(r)
      (rq.pool == 3 and rq.reason == "SLOT_TAKEN") implies PRIDS.exists(z => { val zq = p.reqs.get(z)
        z != r and zq.succ == rq.succ and slotKey(zq) == slotKey(rq) and zq.order > 0 and zq.order < rq.order }) }),
  }

  // C16 (§7.11 item 1): no live request holds a slot that the restart burned.
  val C16_NoLiveOnBurned: bool =
    not(PR.voteStale) or PRIDS.forall(r => { val rq = p.reqs.get(r)
      not(isLive(rq.st) and rq.held and p.burnedAtRestart.contains(slotKey(rq))) })

  val C13_AcctOneReservation: bool =
    PRIDS.forall(a => PRIDS.forall(b => not(a != b and p.reqs.get(a).held and p.reqs.get(b).held
      and p.reqs.get(a).pool == 3 and slotKey(p.reqs.get(a)) == slotKey(p.reqs.get(b))
      and p.reqs.get(a).succ == p.reqs.get(b).succ and p.reqs.get(a).st != "L" and p.reqs.get(b).st != "L")))

  val PoolInvariants: bool = and {
    C16_PendingMinAtMostFloorPlusOne, C13_AcctOneReservation,
    C13_AcctEarliestHolds, C16_NoLiveOnBurned,
    C16_NoSlotTwice, C13_VoteInWindow, C13_BindInWindow, C12_NoPartialBeforeBind, C13_OneBindRound,
    C12_BindOneTicket, C13_LostOnlyOwnSuite, C15_NoEcdsaReshareWithoutAnchor, C15_ReshareOnlyUnused,
  }

  // ---------------------------------------------------------------- reachability
  val PoolPartialReached: bool = p.partials.size() > 0
  val PoolFinalReached: bool = PRIDS.exists(r => p.reqs.get(r).st == "F")
  val RestartReached: bool = p.restarts > 0
  val PartialAfterRestartReached: bool = p.partialAfterRestart
  val BurnedVoidReached: bool = PRIDS.exists(r => p.reqs.get(r).reason == "BURNED")
  val SlotTakenFloorReached: bool = PRIDS.exists(r => p.reqs.get(r).reason == "SLOT_TAKEN" and p.reqs.get(r).votes.size() == 0 and p.lastAction == "voidBelowFloor")
  val LostIndexReached: bool = COMMITTEE_POOLS.exists(pl => 1.to(MAXI).exists(i =>
    i <= p.cp.h.get(pl) and not(p.everHeld.exists(e => e._1 == pl and e._2 == i))))
  val BatchRefusalReached: bool = p.batchRefusal
  val RecoveryReached: bool = p.recovered
  val ReshareSignReached: bool = p.partialOnReshared
  val CoveredRestoreReached: bool = p.restarts > 0 and PNODES.exists(n => allSlots.exists(sk =>
    match p.nodes.get(n).sl.get(sk) { | Bound(_) => true | _ => false }))
}

// ---------------------------------------------------------------- instances
module pl_design {     // no anchors: restart burns, no ECDSA reshare
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = POOL_RULES).* from "./splitline_pools"
}
module pl_anchor {     // seald anchor_before_release / slot_anchor: nothing burns, E reshares unbound ECDSA slots
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = true, PR = POOL_RULES).* from "./splitline_pools"
}
module pm_window {     // honest votes and seald ignore the window
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, windowVote: false, windowBind: false }).* from "./splitline_pools"
}
module pm_shared_pool {  // one committee index space for both suites
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, poolPerSuite: false }).* from "./splitline_pools"
}
module pm_bind_per_slot {  // one bind round per slot
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, batchBind: false }).* from "./splitline_pools"
}
module pm_partial_before_bind {
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, bindBeforePartial: false }).* from "./splitline_pools"
}
module pm_no_window_burn {
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, burnWindow: false }).* from "./splitline_pools"
}
module pm_no_pending_burn {
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, burnPending: false }).* from "./splitline_pools"
}
module pm_no_account_burn {
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, burnAccounts: false }).* from "./splitline_pools"
}
module pm_acct_named {  // PR4: the restart burns only the account-pool slots that the readable board named
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, acctBurnAll: false }).* from "./splitline_pools"
}
module pm_reshare_no_anchor {  // E reshares ECDSA slots from the checkpoint's board view
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = false, PR = { ...POOL_RULES, reshareNoAnchor: true }).* from "./splitline_pools"
}
module pm_reshare_all {  // anchors on, E reshares without reading the seat logs
  import splitline_pools_types.* from "./splitline_pools"
  import splitline_pools(NN = 3, QQ = 2, B = 2, ANCHOR = true, PR = { ...POOL_RULES, reshareCoveredOnly: false }).* from "./splitline_pools"
}
