// -*- mode: Bluespec; -*-
// Conformance wrapper for model-based testing of impl/ against linedealing.qnt.
//
// This file adds no protocol behaviour. It imports linedealing_protocol and adds
// one observation variable `proj`. Every wrapped step runs the original step and
// sets proj' to the projection of the PRE-state, so the projection of state k
// appears in state k + 1 of an ITF trace (the last state has no projection).
// The projection holds the values that the model derives from the board and that
// the Rust board stores: binding, status, ACK quorum, ROTATE, HANDOVER, Q, and per
// generation the active epoch, the freeze decision, lock or release, the lock
// digest and the anchor and failure of each attempt of each epoch.

module linedealing_mbt_protocol {
  const CN: int
  const CF: int
  const C_ONE_PREVOTE: bool
  const C_RULE4: bool

  import linedealing_protocol(
    N = CN,
    F = CF,
    ENFORCE_ONE_PREVOTE = C_ONE_PREVOTE,
    ENFORCE_RULE4 = C_RULE4
  ).* from "../linedealing"

  type AttProj = { done: bool, h: int, failed: bool }
  type GenProj = {
    active: int,
    inFlight: bool,
    lockOrRel: bool,
    lockDg: int,
    lockA: int,
    att: (int, int) -> AttProj
  }
  type Proj = {
    valid: bool,
    bound: bool,
    status: ReqStatus,
    armed: bool,
    rotated: bool,
    handover: bool,
    q: Set[int],
    gens: int -> GenProj
  }

  var proj: Proj

  pure val noAtt: AttProj = { done: false, h: 0, failed: false }

  // Anchor and failure of attempts 1 and 2 of (e, g), as the model's attemptWindow
  // and obsAnchorInRange see them (attempt 2 starts after the cut of a failed attempt 1).
  pure def attemptsOf(b: List[Post], blocks: List[ChainBlock], mIdx: int, e: int, g: int): int -> AttProj = {
    val rng = validRangeForGen(b, blocks, mIdx, e, g)
    if (not(rng.ok)) Map(1 -> noAtt, 2 -> noAtt) else {
      val o1 = obsAnchorInRange(b, rng.startIdx, rng.endIdx, e, g, 1)
      val f1 = o1.done and attemptFailedInRange(b, o1.cutIdx, rng.endIdx, e, g, 1)
      val o2 =
        if (f1) obsAnchorInRange(b, o1.cutIdx + 1, rng.endIdx, e, g, 2)
        else { done: false, cutIdx: -1, anchorH: 0 }
      val f2 = o2.done and attemptFailedInRange(b, o2.cutIdx, rng.endIdx, e, g, 2)
      Map(
        1 -> { done: o1.done, h: o1.anchorH, failed: f1 },
        2 -> { done: o2.done, h: o2.anchorH, failed: f2 }
      )
    }
  }

  // Digest and attempt of the first PREVOTE (board order) whose candidate has a lock certificate.
  pure def lockOf(b: List[Post], blocks: List[ChainBlock], mIdx: int, g: int): { dg: int, a: int } =
    EPOCHS.fold({ dg: 0, a: 0 }, (acc, e) =>
      if (acc.dg > 0) acc else {
        val rng = validRangeForGen(b, blocks, mIdx, e, g)
        if (not(rng.ok) or rng.endIdx <= rng.startIdx) acc else {
          safeSlicePosts(b, rng.startIdx, rng.endIdx).foldl(acc, (found, p) =>
            if (found.dg > 0) found
            else if (p.kind == P_PREVOTE and p.epoch == e and p.g == g
                     and prevoteSignersInRange(b, rng.startIdx, rng.endIdx, e, g, p.a, p.h, p.dg).size() >= QUORUM) {
              { dg: p.dg, a: p.a }
            } else found
          )
        }
      }
    )

  val projNow: Proj = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    {
      valid: true,
      bound: mIdx >= 0,
      status: reqStatus,
      armed: mIdx >= 0 and armedIdx(board, mIdx) >= 0,
      rotated: mIdx >= 0 and rotateIdx(board, mIdx) >= 0,
      handover: mIdx >= 0 and handoverIdx(board, chainBlocks, mIdx) >= 0,
      q: reshareCandidateDealers(board, chainBlocks, mIdx),
      gens: GENS.mapBy(g => {
        val lk = if (msg.mode == OpenMode) lockOf(board, chainBlocks, mIdx, g) else { dg: 0, a: 0 }
        val a1 = attemptsOf(board, chainBlocks, mIdx, 1, g)
        val a2 = attemptsOf(board, chainBlocks, mIdx, 2, g)
        {
          active: activeEpochForGen(board, chainBlocks, mIdx, g),
          inFlight: isGenInFlightAtRotate(board, chainBlocks, mIdx, g),
          lockOrRel: genHasLockOrRelease(board, chainBlocks, mIdx, g),
          lockDg: lk.dg,
          lockA: lk.a,
          att: Map(
            (1, 1) -> a1.get(1), (1, 2) -> a1.get(2),
            (2, 1) -> a2.get(1), (2, 2) -> a2.get(2)
          )
        }
      })
    }
  }

  pure val emptyProj: Proj = {
    valid: false, bound: false, status: StUnbound, armed: false, rotated: false,
    handover: false, q: Set(), gens: GENS.mapBy(g => {
      active: 0, inFlight: false, lockOrRel: false, lockDg: 0, lockA: 0,
      att: Map((1, 1) -> noAtt, (1, 2) -> noAtt, (2, 1) -> noAtt, (2, 2) -> noAtt)
    })
  }

  // The five safety invariants of linedealing_protocol, re-exported for --invariants.
  val cNoNonceReuse: bool = NoNonceReuse
  val cAtMostOneExecution: bool = AtMostOneExecution
  val cLockBeforeShare: bool = LockBeforeShare
  val cNoTransientTombstone: bool = NoTransientTombstone
  val cFreezeSafety: bool = FreezeSafety

  // Witness negations of linedealing_protocol: a violation is a directed trace to the state.
  val cNoLockCert: bool = NoLockCert
  val cNoGen2: bool = NoGen2
  val cNoGen2Spend: bool = NoGen2Spend
  val cNoReshareDone: bool = NoReshareDone
  val cNoEpoch2Partial: bool = NoEpoch2Partial
  val cNoRollbackAfterPartial: bool = NoRollbackAfterPartial
  val cNoRollbackAfterPrevote: bool = NoRollbackAfterPrevote
  val cNoHandoverWithOldPartial: bool = not(HandoverWithOldPartialReached)
  val cNoFinal: bool = NoFinal
  val cNoVoid: bool = NoVoid
  val cNoExpired: bool = NoExpired
  val cNoSpendExecuted: bool = NoSpendExecuted
  // Wrapper witnesses: an attempt failed by f + 1 NACKs, and an anchored attempt 2.
  val cNoFailedAttempt: bool = {
    val mIdx = boundMsgIdx(board)
    not(EPOCHS.exists(e => GENS.exists(g => attemptsOf(board, chainBlocks, mIdx, e, g).get(1).failed)))
  }
  val cNoAttempt2Anchor: bool = {
    val mIdx = boundMsgIdx(board)
    not(EPOCHS.exists(e => GENS.exists(g => attemptsOf(board, chainBlocks, mIdx, e, g).get(2).done)))
  }

  action cInit = all { init, proj' = emptyProj }
  action cInitArmed = all { initArmed, proj' = emptyProj }
  action cInitArmedOpen = all { initArmedOpen, proj' = emptyProj }
  action cInitArmedOpenReshare = all { initArmedOpenReshare, proj' = emptyProj }

  action cStep = all { step, proj' = projNow }
  action cStepHonestProgress = all { stepHonestProgress, proj' = projNow }
  action cStepProgressFaults = all { stepProgressFaults, proj' = projNow }
  action cStepAdversarial = all { stepAdversarial, proj' = projNow }
  action cStepWeighted = all { stepWeighted, proj' = projNow }

  // Scripted trace for the replay: a failed attempt and a second attempt. The
  // sampled runs never reach a failed attempt (an honest NACK needs an anchor
  // that is not eligible while every honest reporter was eligible at its tip).
  // Instance n = 4 only (mbt_n4). Byzantine node 4 reports height 2 (trigger
  // false) between honest reports at heights 1 and 3, so the anchor is 2; two
  // honest NACKs fail attempt 1;
  // attempt 2 anchors at 3, locks and gets a partial. Export the trace with
  // quint test --main=mbt_n4 --match=failedAttemptScenarioN4 --out-itf=...
  run failedAttemptScenario =
    all { initWithParams(Set(4), Set(4), true, 10, NODES.mapBy(_ => 1), NODES.mapBy(_ => 1)), proj' = emptyProj }
      .then(all { postOwnerMsg(1, OpenMode, ProfileT1, RotFinish, 1, 10, Set()), proj' = projNow })
      .then(all { honestStepA(1), proj' = projNow })
      .then(all { honestStepA(2), proj' = projNow })
      .then(all { honestStepA(3), proj' = projNow })
      .then(all { advanceChainEmpty(false, 10), proj' = projNow })
      .then(all { advanceChainEmpty(true, 10), proj' = projNow })
      .then(all { syncNodeChainTip(1, 2, 3), proj' = projNow })
      .then(all { honestObs(1, 1, 1, 1), proj' = projNow })
      .then(all { honestObs(1, 2, 1, 1), proj' = projNow })
      .then(all { byzPost({ ...emptyPost(P_OBS, boardHeight), epoch: 1, node: 4, g: 1, a: 1, h: 2 }), proj' = projNow })
      .then(all { syncNodeChainTip(1, 1, 2), proj' = projNow })
      .then(all { honestNack(1, 1, 1, 1), proj' = projNow })
      .then(all { honestNack(1, 2, 1, 1), proj' = projNow })
      .then(all { syncNodeChainTip(1, 1, 3), proj' = projNow })
      .then(all { syncNodeChainTip(1, 3, 3), proj' = projNow })
      .then(all { honestObs(1, 1, 1, 2), proj' = projNow })
      .then(all { honestObs(1, 2, 1, 2), proj' = projNow })
      .then(all { honestObs(1, 3, 1, 2), proj' = projNow })
      .then(all { honestPrevote(1, 1, 1, 2), proj' = projNow })
      .then(all { honestPrevote(1, 2, 1, 2), proj' = projNow })
      .then(all { honestPrevote(1, 3, 1, 2), proj' = projNow })
      .then(all { honestOpenPartial(1, 1, 1, 2), proj' = projNow })
      .then(all {
        assert(attemptFailedInRange(board, 0, board.length(), 1, 1, 1)),
        assert(LockCertReached),
        proj' = projNow,
        keepUnchanged,
      })
}

module mbt_n4 {
  import linedealing_mbt_protocol(CN = 4, CF = 1, C_ONE_PREVOTE = true, C_RULE4 = true).*

  run failedAttemptScenarioN4 = failedAttemptScenario
}

module mbt_n7 {
  import linedealing_mbt_protocol(CN = 7, CF = 2, C_ONE_PREVOTE = true, C_RULE4 = true).*
}

module mbt_broken_prevote {
  import linedealing_mbt_protocol(CN = 4, CF = 1, C_ONE_PREVOTE = false, C_RULE4 = true).*
}

module mbt_broken_rule4 {
  import linedealing_mbt_protocol(CN = 4, CF = 1, C_ONE_PREVOTE = true, C_RULE4 = false).*
}
