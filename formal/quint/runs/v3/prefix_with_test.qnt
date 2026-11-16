// -*- mode: Bluespec; -*-
// Quint formal specification of the Line-Dealing Committee Protocol
// Source specification: design/SCHEME.md (sections 3.3-3.10, 4, and 5)
//
// Models:
// - Committee of N >= 3F + 1 nodes per epoch (quorum q = ceil((N + F + 1) / 2)) with static Byzantine subset |byz| <= F
// - Open mode and Sealed mode, profiles T1 (t = F + 1) and T2 (t = N - F)
// - Rotation policies: finish, reshare (freeze + handover to new committee), void
// - Totally ordered board log and board height window [nb, exp]
// - Step A: owner MSG acceptance, ACK quorum (q = ceil((N + F + 1) / 2); 2F + 1 when N = 3F + 1), verified DLEQ complaints
// - Step B: height-only OBS reports, anchor rule (entry F + 1 of the q sorted reports),
//           flickering eligibility, NACKs (F + 1 fails attempt, consumes nothing),
//           anchor replacement within a generation, board cut for multi-generation
// - Step C (Sealed): deterministic variant selection and partial release
// - Step C (Open): Build, durable slot ledger, one PREVOTE per (rid, g),
//                  q-PREVOTE lock certificate, PARTIAL only after lock for own digest
// - Rule 4: node crash/disk-rollback action, clean restart action, and board replay
// - Generations g = 1..G and fee-bump rule across target-chain blocks (delta)
// - Target chain where every request transaction (and optional foreign tx) spends
//   the conflict pin, plus FINAL / VOID / EXPIRED tombstones.

module linedealing_protocol {
  // =========================================================================
  // Protocol parameters
  // =========================================================================
  const N: int
  const F: int
  const ENFORCE_ONE_PREVOTE: bool
  const ENFORCE_RULE4: bool

  // Quorum size for N >= 3F + 1 nodes (SCHEME 2, LOOP item 4b): q = ceil((N + F + 1) / 2).
  // Two quorums share 2q - N >= F + 1 nodes; q <= N - F; q >= 2F + 1. For N = 3F + 1, q = 2F + 1.
  pure def quorumOf(n: int, f: int): int = (n + f + 2) / 2
  pure val QUORUM: int = quorumOf(N, F)
  pure val MAX_GEN: int = 2
  pure val MAX_VARIANTS: int = 2
  pure val MAX_ATTEMPTS: int = 2
  pure val DELTA: int = 1
  pure val BUMP_INC: int = 5
  pure val FEE_CEILING: int = 25
  pure val MAX_BOARD_HEIGHT: int = 5
  pure val MAX_CHAIN_HEIGHT: int = 4

  pure val NODES: Set[int] = 1.to(N)
  pure val GENS: Set[int] = 1.to(MAX_GEN)
  pure val ATTEMPTS: Set[int] = 1.to(MAX_ATTEMPTS)
  pure val EPOCHS: Set[int] = Set(1, 2)

  // =========================================================================
  // Data types
  // =========================================================================
  type Mode = OpenMode | SealedMode
  type ThresholdProfile = ProfileT1 | ProfileT2
  type RotPolicy = RotFinish | RotReshare | RotVoid

  type ReqStatus =
    | StUnbound
    | StBound
    | StArmed
    | StFinal
    | StVoid
    | StExpired

  type PostKind =
    | P_MSG
    | P_ACK
    | P_COMPLAINT
    | P_OBS
    | P_NACK
    | P_PREVOTE
    | P_PARTIAL
    | P_SEALED_PARTIAL
    | P_ROTATE
    | P_RS_DEAL
    | P_RS_COMPLAINT
    | P_READY
    | P_FINAL
    | P_VOID

  type Post = {
    kind: PostKind,
    epoch: int,
    node: int,
    mid: int,
    mode: Mode,
    tProfile: ThresholdProfile,
    rotPolicy: RotPolicy,
    nb: int,
    exp: int,
    badNodes: Set[int],
    g: int,
    a: int,
    h: int,
    dg: int,
    variant: int,
    dealers: Set[int],
    gens: Set[int],
    targetDealer: int,
    bheight: int
  }

  type ChainTxKind = TxNone | TxReq | TxForeign

  type ChainBlock = {
    height: int,
    triggerOk: bool,
    marketFee: int,
    txKind: ChainTxKind,
    txGen: int,
    txVal: int
  }

  type NodeState = {
    chainTip: int,
    ledger: int -> int,
    abstained: Set[int],
    erased: Set[int],
    builderImpl: int
  }

  // =========================================================================
  // State variables
  // =========================================================================
  var byz1: Set[int]
  var byz2: Set[int]
  var boardHeight: int
  var board: List[Post]
  var chainBlocks: List[ChainBlock]
  var nodes1: int -> NodeState
  var nodes2: int -> NodeState

  // =========================================================================
  // Total pure helpers: safe slicing, sorting, median anchor (SCHEME.md §3.6)
  // =========================================================================
  pure def maxInt(x: int, y: int): int =
    if (x >= y) x else y

  pure def emptyPost(k: PostKind, bh: int): Post = {
    kind: k,
    epoch: 0,
    node: 0,
    mid: 0,
    mode: OpenMode,
    tProfile: ProfileT1,
    rotPolicy: RotFinish,
    nb: 1,
    exp: 4,
    badNodes: Set(),
    g: 0,
    a: 0,
    h: 0,
    dg: 0,
    variant: 0,
    dealers: Set(),
    gens: Set(),
    targetDealer: 0,
    bheight: bh
  }

  pure def safeSlicePosts(b: List[Post], s: int, e: int): List[Post] = {
    val lo = if (s < 0) 0 else s
    val hi = if (e > b.length()) b.length() else e
    if (lo >= hi or lo >= b.length()) List()
    else b.slice(lo, hi)
  }

  pure def safeSliceBlocks(blocks: List[ChainBlock], s: int, e: int): List[ChainBlock] = {
    val lo = if (s < 0) 0 else s
    val hi = if (e > blocks.length()) blocks.length() else e
    if (lo >= hi or lo >= blocks.length()) List()
    else blocks.slice(lo, hi)
  }

  pure def msgAt(b: List[Post], mIdx: int): Post =
    if (mIdx >= 0 and mIdx < b.length()) b.nth(mIdx)
    else emptyPost(P_MSG, 0)

  pure def insertDesc(xs: List[int], x: int): List[int] = {
    val res = xs.foldl(
      { placed: false, acc: List() },
      (st, y) =>
        if (not(st.placed) and x >= y) {
          { placed: true, acc: st.acc.append(x).append(y) }
        } else {
          { placed: st.placed, acc: st.acc.append(y) }
        }
    )
    if (res.placed) res.acc else res.acc.append(x)
  }

  pure def sortDesc(xs: List[int]): List[int] =
    xs.foldl(List(), (acc, x) => insertDesc(acc, x))

  // Given the first q reported heights (q >= 2f+1) and Byzantine bound fVal,
  // sort descending and return entry fVal + 1 (0-indexed fVal). At least fVal + 1
  // reports are at or above it and at least q - fVal >= fVal + 1 at or below it.
  pure def selectAnchorHeightForF(heights: List[int], fVal: int): int = {
    val sorted = sortDesc(heights)
    if (fVal >= 0 and fVal < sorted.length()) sorted.nth(fVal) else 0
  }

  pure def selectAnchorHeight(heights: List[int]): int =
    selectAnchorHeightForF(heights, F)

  pure def thresholdOf(prof: ThresholdProfile): int =
    if (prof == ProfileT1) F + 1 else N - F

  // Sealed mode fee grid: variant 1 pays 15, variant 2 pays 25 (= FEE_CEILING).
  pure def sealedGridFee(v: int): int =
    if (v == 1) 15 else FEE_CEILING

  // Injective lock-digest encoding (LD1/dg in SCHEME.md §3.1, §3.8).
  // 0 is reserved for "no ledger entry".
  pure def encodeDigest(e: int, g: int, a: int, hStar: int, fee: int, bImpl: int): int =
    e * 100000 + g * 10000 + a * 1000 + hStar * 100 + fee * 2 + (bImpl - 1)

  // =========================================================================
  // Pure helpers: Target chain queries (SCHEME.md §3.6, §4)
  // =========================================================================
  pure def blockAt(blocks: List[ChainBlock], h: int): ChainBlock =
    if (h >= 1 and h <= blocks.length()) blocks.nth(h - 1)
    else { height: 0, triggerOk: false, marketFee: 0, txKind: TxNone, txGen: 0, txVal: 0 }

  pure def pinSpentAt(blocks: List[ChainBlock], h: int): bool =
    safeSliceBlocks(blocks, 0, h).foldl(false, (spent, blk) => spent or (blk.txKind != TxNone))

  pure def pinSpentByReqAt(blocks: List[ChainBlock], h: int): bool =
    safeSliceBlocks(blocks, 0, h).foldl(false, (spent, blk) => spent or (blk.txKind == TxReq))

  pure def reqSpentValAt(blocks: List[ChainBlock], h: int): int =
    safeSliceBlocks(blocks, 0, h).foldl(0, (acc, blk) =>
      if (blk.txKind == TxReq) blk.txVal else acc
    )

  pure def pinSpentByForeignAt(blocks: List[ChainBlock], h: int): bool =
    safeSliceBlocks(blocks, 0, h).foldl(false, (spent, blk) => spent or (blk.txKind == TxForeign))

  // Sealed mode Select(intent, S(hStar), prevVariant): returns 0 for bottom (⊥)
  pure def selectSealedVariant(
    blocks: List[ChainBlock],
    hStar: int,
    g: int,
    prevAnchorH: int,
    prevVariant: int
  ): int =
    if (hStar < 1 or hStar > blocks.length()) 0 else {
      val blk = blockAt(blocks, hStar)
      val deltaOk = (g == 1) or (prevAnchorH >= 1 and hStar >= prevAnchorH + DELTA)
      if (not(blk.triggerOk) or pinSpentAt(blocks, hStar) or not(deltaOk)) 0
      else if (prevVariant < 1 and sealedGridFee(1) >= blk.marketFee) 1
      else if (prevVariant < 2 and MAX_VARIANTS >= 2 and sealedGridFee(2) >= blk.marketFee) 2
      else 0
    }

  // Open mode Build(intent, S(hStar), g, prevFee): returns 0 for bottom (⊥), else tx fee
  pure def buildOpenTxFee(
    blocks: List[ChainBlock],
    hStar: int,
    g: int,
    prevAnchorH: int,
    prevFee: int
  ): int =
    if (hStar < 1 or hStar > blocks.length()) 0 else {
      val blk = blockAt(blocks, hStar)
      val deltaOk = (g == 1) or (prevAnchorH >= 1 and hStar >= prevAnchorH + DELTA)
      if (not(blk.triggerOk) or pinSpentAt(blocks, hStar) or not(deltaOk)) 0 else {
        val fee =
          if (g == 1) blk.marketFee
          else maxInt(blk.marketFee, prevFee + BUMP_INC)
        if (fee <= FEE_CEILING and fee > 0) fee else 0
      }
    }

  // =========================================================================
  // Pure helpers: Board log interpretation (SCHEME.md §3.4 - §3.10, §5)
  // =========================================================================

  // Step A public checks (§3.4 checks 1-9)
  pure def stepAPasses(p: Post): bool =
    p.kind == P_MSG
      and p.mid > 0
      and p.nb >= 1
      and p.nb <= p.exp
      and p.bheight <= p.exp
      and ((p.rotPolicy == RotReshare) implies (p.tProfile == ProfileT1))

  // Index of first MSG passing Step A public checks (-1 if unbound)
  pure def boundMsgIdx(b: List[Post]): int = {
    val scan = b.foldl(
      { idx: 0, found: -1 },
      (st, p) =>
        if (st.found == -1 and stepAPasses(p)) {
          { idx: st.idx + 1, found: st.idx }
        } else {
          { idx: st.idx + 1, found: st.found }
        }
    )
    scan.found
  }

  // Verified complaint index (§3.4): complaint is cryptographically valid iff
  // dealer ciphertext for c.node was actually bad (c.node in msg.badNodes).
  pure def firstValidComplaintIdx(b: List[Post], mIdx: int): int =
    if (mIdx < 0) -1 else {
      val msg = msgAt(b, mIdx)
      val scan = b.foldl(
        { idx: 0, found: -1 },
        (st, p) =>
          if (st.found == -1 and st.idx > mIdx and p.kind == P_COMPLAINT
              and p.epoch == 1 and p.node.in(NODES) and p.mid == msg.mid
              and p.node.in(msg.badNodes)) {
            { idx: st.idx + 1, found: st.idx }
          } else {
            { idx: st.idx + 1, found: st.found }
          }
      )
      scan.found
    }

  // Board index where the q-th distinct Epoch-1 ACK arrives (q = QUORUM) (-1 if not armed)
  pure def armedIdx(b: List[Post], mIdx: int): int =
    if (mIdx < 0) -1 else {
      val msg = msgAt(b, mIdx)
      val cIdx = firstValidComplaintIdx(b, mIdx)
      val scan = b.foldl(
        { idx: 0, seen: Set(), found: -1 },
        (st, p) =>
          if (st.found == -1 and st.idx > mIdx
              and (cIdx == -1 or st.idx < cIdx)
              and p.kind == P_ACK and p.epoch == 1
              and p.node.in(NODES) and p.mid == msg.mid) {
            val seenNext = st.seen.union(Set(p.node))
            val foundNext = if (seenNext.size() >= QUORUM) st.idx else -1
            { idx: st.idx + 1, seen: seenNext, found: foundNext }
          } else {
            { idx: st.idx + 1, seen: st.seen, found: st.found }
          }
      )
      scan.found
    }

  // Index of first ROTATE(1 -> 2) after MSG binding (-1 if not rotated)
  pure def rotateIdx(b: List[Post], mIdx: int): int =
    if (mIdx < 0) -1 else {
      val scan = b.foldl(
        { idx: 0, found: -1 },
        (st, p) =>
          if (st.found == -1 and st.idx > mIdx and p.kind == P_ROTATE) {
            { idx: st.idx + 1, found: st.idx }
          } else {
            { idx: st.idx + 1, found: st.found }
          }
      )
      scan.found
    }

  // Distinct nodes that posted PREVOTE(epoch=e, g, a, hStar, dg) in b[startIdx..endIdx)
  pure def prevoteSignersInRange(
    b: List[Post],
    startIdx: int,
    endIdx: int,
    e: int,
    g: int,
    a: int,
    hStar: int,
    dg: int
  ): Set[int] = {
    val scan = b.foldl(
      { idx: 0, signers: Set() },
      (st, p) =>
        if (st.idx >= startIdx and st.idx < endIdx
            and p.kind == P_PREVOTE and p.epoch == e and p.node.in(NODES)
            and p.g == g and p.a == a and p.h == hStar and p.dg == dg) {
          { idx: st.idx + 1, signers: st.signers.union(Set(p.node)) }
        } else {
          { idx: st.idx + 1, signers: st.signers }
        }
    )
    scan.signers
  }

  // OBS collection in [startIdx, endIdx) for (epoch=e, g, a)
  pure def obsAnchorInRange(
    b: List[Post],
    startIdx: int,
    endIdx: int,
    e: int,
    g: int,
    a: int
  ): { done: bool, cutIdx: int, anchorH: int } =
    if (startIdx < 0 or endIdx <= startIdx) {
      { done: false, cutIdx: -1, anchorH: 0 }
    } else {
      val scan = b.foldl(
        { idx: 0, seen: Set(), heights: List(), cutIdx: -1 },
        (st, p) =>
          if (st.cutIdx == -1 and st.idx >= startIdx and st.idx < endIdx
              and p.kind == P_OBS and p.epoch == e and p.node.in(NODES)
              and p.g == g and p.a == a and p.h >= 1
              and not(p.node.in(st.seen))) {
            val seenNext = st.seen.union(Set(p.node))
            val heightsNext = st.heights.append(p.h)
            val cutNext = if (seenNext.size() >= QUORUM) st.idx else -1
            { idx: st.idx + 1, seen: seenNext, heights: heightsNext, cutIdx: cutNext }
          } else {
            { idx: st.idx + 1, seen: st.seen, heights: st.heights, cutIdx: st.cutIdx }
          }
      )
      if (scan.cutIdx == -1) {
        { done: false, cutIdx: -1, anchorH: 0 }
      } else {
        { done: true, cutIdx: scan.cutIdx, anchorH: selectAnchorHeight(scan.heights) }
      }
    }

  // NACK failure in [cutIdx + 1, endIdx) for (epoch=e, g, a): f + 1 distinct NACKs
  pure def attemptFailedInRange(
    b: List[Post],
    cutIdx: int,
    endIdx: int,
    e: int,
    g: int,
    a: int
  ): bool =
    if (cutIdx < 0 or endIdx <= cutIdx + 1) false else {
      val scan = b.foldl(
        { idx: 0, nackers: Set() },
        (st, p) =>
          if (st.idx > cutIdx and st.idx < endIdx
              and p.kind == P_NACK and p.epoch == e and p.node.in(NODES)
              and p.g == g and p.a == a) {
            { idx: st.idx + 1, nackers: st.nackers.union(Set(p.node)) }
          } else {
            { idx: st.idx + 1, nackers: st.nackers }
          }
      )
      scan.nackers.size() >= F + 1
    }

  pure def hasEpoch1PreFreezeLock(b: List[Post], mIdx: int, g: int): bool =
    if (mIdx < 0) false else {
      val aIdx = armedIdx(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      val endIdx = if (rIdx >= 0) rIdx else b.length()
      if (aIdx < 0 or endIdx <= aIdx + 1) false else {
        safeSlicePosts(b, aIdx + 1, endIdx).foldl(false, (found, p) =>
          if (found) true
          else if (p.kind == P_PREVOTE and p.epoch == 1 and p.g == g) {
            prevoteSignersInRange(b, aIdx + 1, endIdx, 1, g, p.a, p.h, p.dg).size() >= QUORUM
          } else false
        )
      }
    }

  // Check whether sealed generation g has a pre-freeze valid partial after an anchor (§5)
  pure def hasEpoch1PreFreezeSealedRelease(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    g: int,
    prevAnchorH: int,
    prevVariant: int
  ): bool =
    if (mIdx < 0) false else {
      val aIdx = armedIdx(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      val endIdx = if (rIdx >= 0) rIdx else b.length()
      if (aIdx < 0 or endIdx <= aIdx + 1) false else {
        val o1 = obsAnchorInRange(b, aIdx + 1, endIdx, 1, g, 1)
        val f1 = o1.done and attemptFailedInRange(b, o1.cutIdx, endIdx, 1, g, 1)
        val rel1 =
          if (not(o1.done)) false else {
            val v1 = selectSealedVariant(blocks, o1.anchorH, g, prevAnchorH, prevVariant)
            v1 > 0 and safeSlicePosts(b, o1.cutIdx + 1, endIdx).foldl(false, (ok, p) =>
              ok or (p.kind == P_SEALED_PARTIAL and p.epoch == 1 and p.node.in(NODES)
                     and p.g == g and p.variant == v1)
            )
          }
        val rel2 =
          if (not(f1) or rel1) false else {
            val o2 = obsAnchorInRange(b, o1.cutIdx + 1, endIdx, 1, g, 2)
            if (not(o2.done)) false else {
              val v2 = selectSealedVariant(blocks, o2.anchorH, g, prevAnchorH, prevVariant)
              v2 > 0 and safeSlicePosts(b, o2.cutIdx + 1, endIdx).foldl(false, (ok, p) =>
                ok or (p.kind == P_SEALED_PARTIAL and p.epoch == 1 and p.node.in(NODES)
                       and p.g == g and p.variant == v2)
              )
            }
          }
        rel1 or rel2
      }
    }

  // Generation in-flight predicate at ROTATE (§5 Freeze rule)
  pure def isGenInFlightAtRotate(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    g: int
  ): bool =
    if (mIdx < 0) false else {
      val msg = msgAt(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      if (msg.rotPolicy != RotReshare or rIdx < 0) false
      else if (msg.mode == OpenMode) {
        hasEpoch1PreFreezeLock(b, mIdx, g)
      } else {
        if (g == 1) {
          hasEpoch1PreFreezeSealedRelease(b, blocks, mIdx, 1, 0, 0)
        } else {
          val aIdx = armedIdx(b, mIdx)
          val o1 = obsAnchorInRange(b, aIdx + 1, rIdx, 1, 1, 1)
          val f1 = o1.done and attemptFailedInRange(b, o1.cutIdx, rIdx, 1, 1, 1)
          val o2 =
            if (f1) obsAnchorInRange(b, o1.cutIdx + 1, rIdx, 1, 1, 2)
            else { done: false, cutIdx: -1, anchorH: 0 }
          val f2 = o2.done and attemptFailedInRange(b, o2.cutIdx, rIdx, 1, 1, 2)
          val h1 =
            if (o2.done and not(f2)) o2.anchorH
            else if (o1.done and not(f1)) o1.anchorH
            else 0
          val v1 = if (h1 > 0) selectSealedVariant(blocks, h1, 1, 0, 0) else 0
          h1 > 0 and v1 > 0 and hasEpoch1PreFreezeSealedRelease(b, blocks, mIdx, 2, h1, v1)
        }
      }
    }

  pure def gensNotInFlightAtRotate(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int
  ): Set[int] =
    GENS.filter(g => not(isGenInFlightAtRotate(b, blocks, mIdx, g)))

  // Reshare candidate set Q: first t_old = F + 1 valid dealers after ROTATE with no valid complaint
  pure def reshareCandidateDealers(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int
  ): Set[int] =
    if (mIdx < 0) Set() else {
      val msg = msgAt(b, mIdx)
      val aIdx = armedIdx(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      if (msg.rotPolicy != RotReshare or aIdx < 0 or rIdx < 0) Set() else {
        val expectedGens = gensNotInFlightAtRotate(b, blocks, mIdx)
        if (expectedGens.size() == 0) Set() else {
          val complainedDealers = b.foldl(
            { idx: 0, bad: Set() },
            (st, p) =>
              if (st.idx > rIdx and p.kind == P_RS_COMPLAINT
                  and p.epoch == 2 and p.node.in(NODES)
                  and p.targetDealer.in(NODES)) {
                val dealBad = safeSlicePosts(b, rIdx + 1, st.idx).foldl(
                  { seenDeal: false, isBad: false },
                  (dst, dp) =>
                    if (not(dst.seenDeal) and dp.kind == P_RS_DEAL
                        and dp.epoch == 1 and dp.node == p.targetDealer) {
                      { seenDeal: true, isBad: p.node.in(dp.badNodes) }
                    } else dst
                )
                if (dealBad.isBad) {
                  { idx: st.idx + 1, bad: st.bad.union(Set(p.targetDealer)) }
                } else {
                  { idx: st.idx + 1, bad: st.bad }
                }
              } else {
                { idx: st.idx + 1, bad: st.bad }
              }
          ).bad

          val scan = b.foldl(
            { idx: 0, seenDealers: Set(), q: Set() },
            (st, p) =>
              if (st.idx > rIdx and st.q.size() < F + 1
                  and p.kind == P_RS_DEAL and p.epoch == 1 and p.node.in(NODES)
                  and p.bheight <= msg.exp
                  and not(p.node.in(st.seenDealers))) {
                val seenNext = st.seenDealers.union(Set(p.node))
                val qNext =
                  if (p.gens == expectedGens and not(p.node.in(complainedDealers))) {
                    st.q.union(Set(p.node))
                  } else st.q
                { idx: st.idx + 1, seenDealers: seenNext, q: qNext }
              } else {
                { idx: st.idx + 1, seenDealers: st.seenDealers, q: st.q }
              }
          )
          if (scan.q.size() == F + 1) scan.q else Set()
        }
      }
    }

  // Board index where HANDOVER(rid, Q) completes (QUORUM READY posts for candidate Q)
  pure def handoverIdx(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int
  ): int =
    if (mIdx < 0) -1 else {
      val msg = msgAt(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      val q = reshareCandidateDealers(b, blocks, mIdx)
      if (rIdx < 0 or q.size() < F + 1) -1 else {
        val scan = b.foldl(
          { idx: 0, readyNodes: Set(), found: -1 },
          (st, p) =>
            if (st.found == -1 and st.idx > rIdx
                and p.kind == P_READY and p.epoch == 2 and p.node.in(NODES)
                and p.bheight <= msg.exp and p.dealers == q) {
              val readyNext = st.readyNodes.union(Set(p.node))
              val foundNext = if (readyNext.size() >= QUORUM) st.idx else -1
              { idx: st.idx + 1, readyNodes: readyNext, found: foundNext }
            } else {
              { idx: st.idx + 1, readyNodes: st.readyNodes, found: st.found }
            }
        )
        scan.found
      }
    }

  // Which committee epoch currently owns attempt/voting for generation g (0 if none yet)
  pure def activeEpochForGen(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    g: int
  ): int =
    if (mIdx < 0) 0 else {
      val msg = msgAt(b, mIdx)
      val aIdx = armedIdx(b, mIdx)
      if (aIdx < 0) 0 else {
        val rIdx = rotateIdx(b, mIdx)
        if (rIdx < 0 or msg.rotPolicy == RotFinish) 1
        else if (msg.rotPolicy == RotVoid) 0
        else {
          if (isGenInFlightAtRotate(b, blocks, mIdx, g)) 1
          else if (handoverIdx(b, blocks, mIdx) >= 0) 2
          else 0
        }
      }
    }

  // Range [startIdx, endIdx) of board indices valid for committee `e` on generation `g`
  pure def validRangeForGen(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    e: int,
    g: int
  ): { ok: bool, startIdx: int, endIdx: int } =
    if (mIdx < 0) { ok: false, startIdx: 0, endIdx: 0 } else {
      val msg = msgAt(b, mIdx)
      val aIdx = armedIdx(b, mIdx)
      if (aIdx < 0) { ok: false, startIdx: 0, endIdx: 0 } else {
        val rIdx = rotateIdx(b, mIdx)
        if (e == 1) {
          if (rIdx < 0 or msg.rotPolicy == RotFinish) {
            { ok: true, startIdx: aIdx + 1, endIdx: b.length() }
          } else {
            { ok: true, startIdx: aIdx + 1, endIdx: rIdx }
          }
        } else {
          val hIdx = handoverIdx(b, blocks, mIdx)
          if (msg.rotPolicy == RotReshare and hIdx >= 0
              and not(isGenInFlightAtRotate(b, blocks, mIdx, g))) {
            { ok: true, startIdx: hIdx + 1, endIdx: b.length() }
          } else {
            { ok: false, startIdx: 0, endIdx: 0 }
          }
        }
      }
    }

  // Check if a lock certificate (QUORUM PREVOTE posts) exists on board prefix b for (e, g, a, hStar, dg)
  pure def hasLockCertOnBoard(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    e: int,
    g: int,
    a: int,
    hStar: int,
    dg: int
  ): bool = {
    val rng = validRangeForGen(b, blocks, mIdx, e, g)
    rng.ok and prevoteSignersInRange(b, rng.startIdx, rng.endIdx, e, g, a, hStar, dg).size() >= QUORUM
  }

  pure def genHasAnyLock(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    g: int
  ): bool =
    EPOCHS.exists(e => {
      val rng = validRangeForGen(b, blocks, mIdx, e, g)
      rng.ok and rng.endIdx > rng.startIdx and safeSlicePosts(b, rng.startIdx, rng.endIdx).foldl(
        false,
        (found, p) =>
          if (found) true
          else if (p.kind == P_PREVOTE and p.epoch == e and p.g == g) {
            prevoteSignersInRange(b, rng.startIdx, rng.endIdx, e, g, p.a, p.h, p.dg).size() >= QUORUM
          } else false
      )
    })

  // Board cut (§3.6): eligible anchor of generation 1 as seen at board prefix `bPrefix`
  pure def gen1AnchorInPrefix(
    bPrefix: List[Post],
    blocks: List[ChainBlock],
    mIdx: int
  ): { hasAnchor: bool, anchorH: int, sealedVar: int, openFee: int } =
    if (mIdx < 0 or mIdx >= bPrefix.length()) {
      { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
    } else {
      val msg = msgAt(bPrefix, mIdx)
      val lockAnchor = EPOCHS.fold(0, (acc, e) =>
        if (acc > 0) acc else {
          val rng = validRangeForGen(bPrefix, blocks, mIdx, e, 1)
          if (not(rng.ok) or rng.endIdx <= rng.startIdx) 0 else {
            safeSlicePosts(bPrefix, rng.startIdx, rng.endIdx).foldl(0, (hFound, p) =>
              if (hFound > 0) hFound
              else if (p.kind == P_PREVOTE and p.epoch == e and p.g == 1
                       and prevoteSignersInRange(bPrefix, rng.startIdx, rng.endIdx, e, 1, p.a, p.h, p.dg).size() >= QUORUM) {
                p.h
              } else 0
            )
          }
        }
      )
      val chosenH =
        if (lockAnchor > 0) lockAnchor
        else {
          val eAct = activeEpochForGen(bPrefix, blocks, mIdx, 1)
          if (eAct == 0) 0 else {
            val rng = validRangeForGen(bPrefix, blocks, mIdx, eAct, 1)
            if (not(rng.ok)) 0 else {
              val o1 = obsAnchorInRange(bPrefix, rng.startIdx, rng.endIdx, eAct, 1, 1)
              val f1 = o1.done and attemptFailedInRange(bPrefix, o1.cutIdx, rng.endIdx, eAct, 1, 1)
              val o2 =
                if (f1) obsAnchorInRange(bPrefix, o1.cutIdx + 1, rng.endIdx, eAct, 1, 2)
                else { done: false, cutIdx: -1, anchorH: 0 }
              val f2 = o2.done and attemptFailedInRange(bPrefix, o2.cutIdx, rng.endIdx, eAct, 1, 2)
              if (o2.done and not(f2)) o2.anchorH
              else if (o1.done and not(f1)) o1.anchorH
              else 0
            }
          }
        }
      if (chosenH <= 0 or chosenH > blocks.length()) {
        { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      } else {
        val sVar = selectSealedVariant(blocks, chosenH, 1, 0, 0)
        val oFee = buildOpenTxFee(blocks, chosenH, 1, 0, 0)
        val validPrev = if (msg.mode == OpenMode) (oFee > 0) else (sVar > 0)
        if (not(validPrev)) {
          { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
        } else {
          { hasAnchor: true, anchorH: chosenH, sealedVar: sVar, openFee: oFee }
        }
      }
    }

  // Unified check: does generation g have a lock certificate (Open) or valid release (Sealed)?
  pure def genHasLockOrRelease(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    g: int
  ): bool =
    if (mIdx < 0) false else {
      val msg = msgAt(b, mIdx)
      if (msg.mode == OpenMode) {
        genHasAnyLock(b, blocks, mIdx, g)
      } else {
        EPOCHS.exists(e => {
          val rng = validRangeForGen(b, blocks, mIdx, e, g)
          if (not(rng.ok)) false else {
            val o1 = obsAnchorInRange(b, rng.startIdx, rng.endIdx, e, g, 1)
            val f1 = o1.done and attemptFailedInRange(b, o1.cutIdx, rng.endIdx, e, g, 1)
            val rel1 =
              if (not(o1.done)) false else {
                val g1Cut1 =
                  if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
                  else gen1AnchorInPrefix(safeSlicePosts(b, 0, o1.cutIdx + 1), blocks, mIdx)
                val v1 = selectSealedVariant(blocks, o1.anchorH, g, g1Cut1.anchorH, g1Cut1.sealedVar)
                v1 > 0 and safeSlicePosts(b, o1.cutIdx + 1, rng.endIdx).foldl(false, (ok, p) =>
                  ok or (p.kind == P_SEALED_PARTIAL and p.epoch == e and p.node.in(NODES)
                         and p.g == g and p.variant == v1)
                )
              }
            val rel2 =
              if (not(f1) or rel1) false else {
                val o2 = obsAnchorInRange(b, o1.cutIdx + 1, rng.endIdx, e, g, 2)
                if (not(o2.done)) false else {
                  val g1Cut2 =
                    if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
                    else gen1AnchorInPrefix(safeSlicePosts(b, 0, o2.cutIdx + 1), blocks, mIdx)
                  val v2 = selectSealedVariant(blocks, o2.anchorH, g, g1Cut2.anchorH, g1Cut2.sealedVar)
                  v2 > 0 and safeSlicePosts(b, o2.cutIdx + 1, rng.endIdx).foldl(false, (ok, p) =>
                    ok or (p.kind == P_SEALED_PARTIAL and p.epoch == e and p.node.in(NODES)
                           and p.g == g and p.variant == v2)
                  )
                }
              }
            rel1 or rel2
          }
        })
      }
    }

  // Check if any generation was locked (Open) or validly released (Sealed) at or before exp
  pure def anyGenLockedOrReleasedBeforeExp(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int
  ): bool =
    if (mIdx < 0) false else {
      val msg = msgAt(b, mIdx)
      val bAtExp = b.select(p => p.bheight <= msg.exp)
      val mIdxExp = boundMsgIdx(bAtExp)
      mIdxExp >= 0 and GENS.exists(g => genHasLockOrRelease(bAtExp, blocks, mIdxExp, g))
    }

  // Tombstone posts: f + 1 distinct FINAL(dg=txVal) or VOID posts (§3.10)
  pure def firstFinalQuorumIdx(b: List[Post], mIdx: int): int =
    if (mIdx < 0) -1 else {
      val scan = b.foldl(
        { idx: 0, found: -1 },
        (st, p) =>
          if (st.found == -1 and st.idx > mIdx and p.kind == P_FINAL
              and p.epoch.in(EPOCHS) and p.node.in(NODES) and p.dg > 0) {
            val prefix = safeSlicePosts(b, mIdx + 1, st.idx + 1)
            val signers = NODES.filter(n =>
              prefix.foldl(false, (ok, q) =>
                ok or (q.kind == P_FINAL and q.epoch == p.epoch and q.node == n and q.dg == p.dg)
              )
            )
            val foundNext = if (signers.size() >= F + 1) st.idx else -1
            { idx: st.idx + 1, found: foundNext }
          } else {
            { idx: st.idx + 1, found: st.found }
          }
      )
      scan.found
    }

  pure def firstVoidQuorumIdx(b: List[Post], mIdx: int): int =
    if (mIdx < 0) -1 else {
      val scan = b.foldl(
        { idx: 0, v1: Set(), v2: Set(), found: -1 },
        (st, p) =>
          if (st.found == -1 and st.idx > mIdx and p.kind == P_VOID
              and p.epoch.in(EPOCHS) and p.node.in(NODES)) {
            val v1Next = if (p.epoch == 1) st.v1.union(Set(p.node)) else st.v1
            val v2Next = if (p.epoch == 2) st.v2.union(Set(p.node)) else st.v2
            val foundNext = if (v1Next.size() >= F + 1 or v2Next.size() >= F + 1) st.idx else -1
            { idx: st.idx + 1, v1: v1Next, v2: v2Next, found: foundNext }
          } else {
            { idx: st.idx + 1, v1: st.v1, v2: st.v2, found: st.found }
          }
      )
      scan.found
    }

  // Compute canonical request status (§3.5)
  pure def computeReqStatus(
    b: List[Post],
    blocks: List[ChainBlock],
    curBoardHeight: int
  ): ReqStatus = {
    val mIdx = boundMsgIdx(b)
    if (mIdx < 0) StUnbound else {
      val msg = msgAt(b, mIdx)
      val cIdx = firstValidComplaintIdx(b, mIdx)
      val rIdx = rotateIdx(b, mIdx)
      val rotVoidIdx = if (rIdx >= 0 and msg.rotPolicy == RotVoid) rIdx else -1
      val fIdx = firstFinalQuorumIdx(b, mIdx)
      val vIdx = firstVoidQuorumIdx(b, mIdx)

      val voidIdx = List(cIdx, rotVoidIdx, vIdx).foldl(-1, (best, idx) =>
        if (idx >= 0 and (best == -1 or idx < best)) idx else best
      )

      val lockedOrRel = anyGenLockedOrReleasedBeforeExp(b, blocks, mIdx)

      val finalBeforeExp =
        fIdx >= 0 and (lockedOrRel or msgAt(b, fIdx).bheight <= msg.exp)
      val voidBeforeExp =
        voidIdx >= 0 and (lockedOrRel or msgAt(b, voidIdx).bheight <= msg.exp)

      if (finalBeforeExp and (not(voidBeforeExp) or fIdx < voidIdx)) {
        StFinal
      } else if (voidBeforeExp) {
        StVoid
      } else if (curBoardHeight > msg.exp and not(lockedOrRel)) {
        StExpired
      } else if (armedIdx(b, mIdx) >= 0) {
        StArmed
      } else {
        StBound
      }
    }
  }

  // Attempt start index and open status for (epoch=e, g, a) (§3.6)
  pure def attemptWindow(
    b: List[Post],
    blocks: List[ChainBlock],
    mIdx: int,
    e: int,
    g: int,
    a: int
  ): { isOpen: bool, startIdx: int, endIdx: int } = {
    val rng = validRangeForGen(b, blocks, mIdx, e, g)
    if (not(rng.ok)) {
      { isOpen: false, startIdx: 0, endIdx: 0 }
    } else {
      val g1Ok =
        if (g == 1) true
        else gen1AnchorInPrefix(b, blocks, mIdx).hasAnchor
      if (not(g1Ok)) {
        { isOpen: false, startIdx: 0, endIdx: 0 }
      } else if (a == 1) {
        { isOpen: true, startIdx: rng.startIdx, endIdx: rng.endIdx }
      } else {
        val o1 = obsAnchorInRange(b, rng.startIdx, rng.endIdx, e, g, 1)
        val f1 = o1.done and attemptFailedInRange(b, o1.cutIdx, rng.endIdx, e, g, 1)
        val noLockOrRel = not(genHasLockOrRelease(b, blocks, mIdx, g))
        if (f1 and noLockOrRel) {
          { isOpen: true, startIdx: o1.cutIdx + 1, endIdx: rng.endIdx }
        } else {
          { isOpen: false, startIdx: 0, endIdx: 0 }
        }
      }
    }
  }

  // =========================================================================
  // Signature reconstruction check for target chain execution (§3.7, §3.8, §6)
  // =========================================================================
  pure def canReconstructOpen(
    b: List[Post],
    blocks: List[ChainBlock],
    b1: Set[int],
    b2: Set[int],
    g: int,
    dg: int
  ): bool = {
    val mIdx = boundMsgIdx(b)
    if (mIdx < 0) false else {
      val msg = msgAt(b, mIdx)
      if (msg.mode != OpenMode or firstValidComplaintIdx(b, mIdx) >= 0) false else {
        val tReq = thresholdOf(msg.tProfile)
        val honest1 = NODES.exclude(b1).filter(i =>
          b.foldl(false, (ok, p) =>
            ok or (p.kind == P_PARTIAL and p.epoch == 1 and p.node == i and p.g == g and p.dg == dg)
          )
        )
        val honest2 = NODES.exclude(b2).filter(i =>
          b.foldl(false, (ok, p) =>
            ok or (p.kind == P_PARTIAL and p.epoch == 2 and p.node == i and p.g == g and p.dg == dg)
          )
        )
        val e2HasShares =
          handoverIdx(b, blocks, mIdx) >= 0 and not(isGenInFlightAtRotate(b, blocks, mIdx, g))
        (honest1.size() + b1.size() >= tReq and honest1.size() >= 1)
          or (e2HasShares and honest2.size() + b2.size() >= tReq and honest2.size() >= 1)
      }
    }
  }

  pure def canReconstructSealed(
    b: List[Post],
    blocks: List[ChainBlock],
    b1: Set[int],
    b2: Set[int],
    g: int,
    v: int
  ): bool = {
    val mIdx = boundMsgIdx(b)
    if (mIdx < 0) false else {
      val msg = msgAt(b, mIdx)
      if (msg.mode != SealedMode or firstValidComplaintIdx(b, mIdx) >= 0) false else {
        val tReq = thresholdOf(msg.tProfile)
        val honest1 = NODES.exclude(b1).filter(i =>
          b.foldl(false, (ok, p) =>
            ok or (p.kind == P_SEALED_PARTIAL and p.epoch == 1 and p.node == i
                   and p.g == g and p.variant == v)
          )
        )
        val honest2 = NODES.exclude(b2).filter(i =>
          b.foldl(false, (ok, p) =>
            ok or (p.kind == P_SEALED_PARTIAL and p.epoch == 2 and p.node == i
                   and p.g == g and p.variant == v)
          )
        )
        val e2HasShares =
          handoverIdx(b, blocks, mIdx) >= 0 and not(isGenInFlightAtRotate(b, blocks, mIdx, g))
        (honest1.size() + b1.size() >= tReq and honest1.size() >= 1)
          or (e2HasShares and honest2.size() + b2.size() >= tReq and honest2.size() >= 1)
      }
    }
  }

  // =========================================================================
  // Node and State Helpers
  // =========================================================================
  pure def initNodeState(bImpl: int): NodeState = {
    chainTip: 1,
    ledger: GENS.mapBy(_ => 0),
    abstained: Set(),
    erased: Set(),
    builderImpl: bImpl
  }

  pure def getNodes(e: int, n1: int -> NodeState, n2: int -> NodeState): int -> NodeState =
    if (e == 1) n1 else n2

  pure def nodeAt(ns: int -> NodeState, i: int): NodeState =
    if (i.in(NODES)) ns.get(i) else initNodeState(1)

  pure def isByz(e: int, i: int, b1: Set[int], b2: Set[int]): bool =
    if (e == 1) i.in(b1) else i.in(b2)

  val reqStatus: ReqStatus = computeReqStatus(board, chainBlocks, boardHeight)

  val isTombstoned: bool =
    reqStatus.in(Set(StFinal, StVoid, StExpired))

  // =========================================================================
  // Initialization
  // =========================================================================
  action keepUnchanged = all {
    byz1' = byz1,
    byz2' = byz2,
    boardHeight' = boardHeight,
    board' = board,
    chainBlocks' = chainBlocks,
    nodes1' = nodes1,
    nodes2' = nodes2,
  }

  action initWithParams(
    b1: Set[int],
    b2: Set[int],
    genesisTrigger: bool,
    genesisFee: int,
    impls1: int -> int,
    impls2: int -> int
  ): bool = all {
    b1.subseteq(NODES),
    b2.subseteq(NODES),
    b1.size() <= F,
    b2.size() <= F,
    byz1' = b1,
    byz2' = b2,
    boardHeight' = 1,
    board' = List(),
    chainBlocks' = List({
      height: 1,
      triggerOk: genesisTrigger,
      marketFee: genesisFee,
      txKind: TxNone,
      txGen: 0,
      txVal: 0
    }),
    nodes1' = NODES.mapBy(i => initNodeState(impls1.get(i))),
    nodes2' = NODES.mapBy(i => initNodeState(impls2.get(i))),
  }

  action init = {
    val validByzSets = NODES.powerset().filter(s => s.size() <= F)
    nondet b1 = validByzSets.oneOf()
    nondet b2 = validByzSets.oneOf()
    nondet trig = Set(true, false).oneOf()
    nondet fee = Set(10, 15, 30).oneOf()
    nondet divNode = Set(0).union(NODES).oneOf()
    val impls1 = NODES.mapBy(i => if (i == divNode) 2 else 1)
    val impls2 = NODES.mapBy(_ => 1)
    initWithParams(b1, b2, trig, fee, impls1, impls2)
  }

  // =========================================================================
  // Environment and Clock Actions
  // =========================================================================
  action tickBoardHeight = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val nextBh = boardHeight + 1
    val eraseNow =
      if (mIdx >= 0 and nextBh > msg.exp) {
        GENS.filter(g => not(genHasLockOrRelease(board, chainBlocks, mIdx, g)))
      } else Set()
    all {
      boardHeight < MAX_BOARD_HEIGHT,
      boardHeight' = nextBh,
      nodes1' = NODES.mapBy(i =>
        if (i.in(byz1)) nodes1.get(i)
        else { ...nodes1.get(i), erased: nodes1.get(i).erased.union(eraseNow) }
      ),
      nodes2' = NODES.mapBy(i =>
        if (i.in(byz2)) nodes2.get(i)
        else { ...nodes2.get(i), erased: nodes2.get(i).erased.union(eraseNow) }
      ),
      byz1' = byz1,
      byz2' = byz2,
      board' = board,
      chainBlocks' = chainBlocks,
    }
  }

  action advanceChainEmpty(trig: bool, fee: int): bool = {
    val nextH = chainBlocks.length() + 1
    all {
      chainBlocks.length() < MAX_CHAIN_HEIGHT,
      chainBlocks' = chainBlocks.append({
        height: nextH,
        triggerOk: trig,
        marketFee: fee,
        txKind: TxNone,
        txGen: 0,
        txVal: 0
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  action advanceChainForeignSpend(trig: bool, fee: int): bool = {
    val nextH = chainBlocks.length() + 1
    all {
      chainBlocks.length() < MAX_CHAIN_HEIGHT,
      not(pinSpentAt(chainBlocks, chainBlocks.length())),
      chainBlocks' = chainBlocks.append({
        height: nextH,
        triggerOk: trig,
        marketFee: fee,
        txKind: TxForeign,
        txGen: 0,
        txVal: 999
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  // Execute an authorized request transaction on the target chain (spends the pin!)
  action advanceChainReqSpend(g: int, valId: int, trig: bool, fee: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val reconOk =
      if (msg.mode == OpenMode) {
        canReconstructOpen(board, chainBlocks, byz1, byz2, g, valId)
      } else {
        canReconstructSealed(board, chainBlocks, byz1, byz2, g, valId)
      }
    val nextH = chainBlocks.length() + 1
    all {
      chainBlocks.length() < MAX_CHAIN_HEIGHT,
      not(pinSpentAt(chainBlocks, chainBlocks.length())),
      mIdx >= 0,
      g.in(GENS),
      reconOk,
      chainBlocks' = chainBlocks.append({
        height: nextH,
        triggerOk: trig,
        marketFee: fee,
        txKind: TxReq,
        txGen: g,
        txVal: valId
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  action syncNodeChainTip(e: int, i: int, newTip: int): bool = {
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    all {
      e.in(EPOCHS),
      i.in(NODES),
      newTip > st.chainTip,
      newTip <= chainBlocks.length(),
      nodes1' = if (e == 1) nodes1.set(i, { ...st, chainTip: newTip }) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, { ...st, chainTip: newTip }) else nodes2,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      chainBlocks' = chainBlocks,
    }
  }

  // =========================================================================
  // Step A Actions: Owner Message, Honest ACK / Complaint (§3.4)
  // =========================================================================
  action postOwnerMsg(
    mid: int,
    mode: Mode,
    tProf: ThresholdProfile,
    rotPol: RotPolicy,
    nb: int,
    exp: int,
    badNodes: Set[int]
  ): bool = all {
    board.select(p => p.kind == P_MSG).length() < 2,
    board' = board.append({
      ...emptyPost(P_MSG, boardHeight),
      mid: mid,
      mode: mode,
      tProfile: tProf,
      rotPolicy: rotPol,
      nb: nb,
      exp: exp,
      badNodes: badNodes
    }),
    byz1' = byz1,
    byz2' = byz2,
    boardHeight' = boardHeight,
    chainBlocks' = chainBlocks,
    nodes1' = nodes1,
    nodes2' = nodes2,
  }

  action honestStepA(i: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val alreadyActed = safeSlicePosts(board, mIdx + 1, board.length()).foldl(false, (seen, p) =>
      seen or (p.epoch == 1 and p.node == i and p.kind.in(Set(P_ACK, P_COMPLAINT)) and p.mid == msg.mid)
    )
    val postKind = if (i.in(msg.badNodes)) P_COMPLAINT else P_ACK
    all {
      i.in(NODES),
      not(i.in(byz1)),
      mIdx >= 0,
      reqStatus == StBound,
      not(alreadyActed),
      board' = board.append({
        ...emptyPost(postKind, boardHeight),
        epoch: 1,
        node: i,
        mid: msg.mid
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  // =========================================================================
  // Step B Actions: Honest OBS and Honest NACK (§3.6)
  // =========================================================================
  action honestObs(e: int, i: int, g: int, a: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val win = attemptWindow(board, chainBlocks, mIdx, e, g, a)
    val obs = obsAnchorInRange(board, win.startIdx, win.endIdx, e, g, a)
    val windowHeightOk =
      if (g == 1 and a == 1 and e == 1) (boardHeight >= msg.nb and boardHeight <= msg.exp)
      else (boardHeight <= msg.exp)
    val alreadyObs =
      win.isOpen and safeSlicePosts(board, win.startIdx, win.endIdx).foldl(false, (seen, p) =>
        seen or (p.kind == P_OBS and p.epoch == e and p.node == i and p.g == g and p.a == a)
      )
    val g1Info =
      if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      else gen1AnchorInPrefix(board, chainBlocks, mIdx)
    val tipEligible =
      if (msg.mode == OpenMode) {
        buildOpenTxFee(chainBlocks, st.chainTip, g, g1Info.anchorH, g1Info.openFee) > 0
      } else {
        (g == 1 or g1Info.sealedVar < MAX_VARIANTS)
          and selectSealedVariant(chainBlocks, st.chainTip, g, g1Info.anchorH, g1Info.sealedVar) > 0
      }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      g.in(GENS),
      a.in(ATTEMPTS),
      not(g.in(st.erased)),
      mIdx >= 0,
      reqStatus == StArmed,
      activeEpochForGen(board, chainBlocks, mIdx, g) == e,
      win.isOpen,
      not(obs.done),
      windowHeightOk,
      not(alreadyObs),
      tipEligible,
      board' = board.append({
        ...emptyPost(P_OBS, boardHeight),
        epoch: e,
        node: i,
        g: g,
        a: a,
        h: st.chainTip
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  action honestNack(e: int, i: int, g: int, a: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val win = attemptWindow(board, chainBlocks, mIdx, e, g, a)
    val obs = obsAnchorInRange(board, win.startIdx, win.endIdx, e, g, a)
    val alreadyNacked = safeSlicePosts(board, obs.cutIdx + 1, win.endIdx).foldl(false, (seen, p) =>
      seen or (p.kind == P_NACK and p.epoch == e and p.node == i and p.g == g and p.a == a)
    )
    val g1Cut =
      if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      else gen1AnchorInPrefix(safeSlicePosts(board, 0, obs.cutIdx + 1), chainBlocks, mIdx)
    val eligibleAtAnchor =
      if (msg.mode == OpenMode) {
        buildOpenTxFee(chainBlocks, obs.anchorH, g, g1Cut.anchorH, g1Cut.openFee) > 0
      } else {
        selectSealedVariant(chainBlocks, obs.anchorH, g, g1Cut.anchorH, g1Cut.sealedVar) > 0
      }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      g.in(GENS),
      a.in(ATTEMPTS),
      mIdx >= 0,
      reqStatus == StArmed,
      activeEpochForGen(board, chainBlocks, mIdx, g) == e,
      win.isOpen,
      obs.done,
      not(attemptFailedInRange(board, obs.cutIdx, win.endIdx, e, g, a)),
      st.chainTip >= obs.anchorH,
      not(alreadyNacked),
      not(eligibleAtAnchor),
      board' = board.append({
        ...emptyPost(P_NACK, boardHeight),
        epoch: e,
        node: i,
        g: g,
        a: a,
        h: obs.anchorH
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  // =========================================================================
  // Step C Actions: Open Mode PREVOTE and PARTIAL; Sealed Mode PARTIAL
  // =========================================================================
  action honestPrevote(e: int, i: int, g: int, a: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val win = attemptWindow(board, chainBlocks, mIdx, e, g, a)
    val obs = obsAnchorInRange(board, win.startIdx, win.endIdx, e, g, a)
    val g1Cut =
      if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      else gen1AnchorInPrefix(safeSlicePosts(board, 0, obs.cutIdx + 1), chainBlocks, mIdx)
    val fee = buildOpenTxFee(chainBlocks, obs.anchorH, g, g1Cut.anchorH, g1Cut.openFee)
    val myDg = encodeDigest(e, g, a, obs.anchorH, fee, st.builderImpl)
    val alreadyPrevotedThis = safeSlicePosts(board, obs.cutIdx + 1, win.endIdx).foldl(false, (seen, p) =>
      seen or (p.kind == P_PREVOTE and p.epoch == e and p.node == i
               and p.g == g and p.a == a and p.dg == myDg)
    )
    val stNext = { ...st, ledger: st.ledger.set(g, myDg) }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      g.in(GENS),
      a.in(ATTEMPTS),
      not(g.in(st.erased)),
      not(g.in(st.abstained)),
      // Local rule 1 (§3.9): at most one PREVOTE per (rid, g), written to durable ledger
      ENFORCE_ONE_PREVOTE implies (st.ledger.get(g) == 0),
      mIdx >= 0,
      reqStatus == StArmed,
      activeEpochForGen(board, chainBlocks, mIdx, g) == e,
      msg.mode == OpenMode,
      // Local rule 5 (§3.9): no PREVOTE after board height exp
      boardHeight <= msg.exp,
      win.isOpen,
      obs.done,
      not(attemptFailedInRange(board, obs.cutIdx, win.endIdx, e, g, a)),
      st.chainTip >= obs.anchorH,
      fee > 0,
      not(alreadyPrevotedThis),
      nodes1' = if (e == 1) nodes1.set(i, stNext) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, stNext) else nodes2,
      board' = board.append({
        ...emptyPost(P_PREVOTE, boardHeight),
        epoch: e,
        node: i,
        g: g,
        a: a,
        h: obs.anchorH,
        dg: myDg
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  // Open mode PARTIAL (§3.8, §3.9 rules 2, 3, 4, and §5 Freeze rule)
  action honestOpenPartial(e: int, i: int, g: int, a: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val rng = validRangeForGen(board, chainBlocks, mIdx, e, g)
    val win = attemptWindow(board, chainBlocks, mIdx, e, g, a)
    val obs = obsAnchorInRange(board, win.startIdx, rng.endIdx, e, g, a)
    val g1Cut =
      if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      else gen1AnchorInPrefix(safeSlicePosts(board, 0, obs.cutIdx + 1), chainBlocks, mIdx)
    val fee = buildOpenTxFee(chainBlocks, obs.anchorH, g, g1Cut.anchorH, g1Cut.openFee)
    val myDg = encodeDigest(e, g, a, obs.anchorH, fee, st.builderImpl)
    val ledgerOk = g.in(GENS) and (st.ledger.get(g) == 0 or st.ledger.get(g) == myDg)
    val lockOk = hasLockCertOnBoard(board, chainBlocks, mIdx, e, g, a, obs.anchorH, myDg)
    val alreadySent = board.foldl(false, (seen, p) =>
      seen or (p.kind == P_PARTIAL and p.epoch == e and p.node == i and p.g == g)
    )
    val stNext = {
      ...st,
      ledger: if (g.in(GENS)) st.ledger.set(g, myDg) else st.ledger,
      erased: st.erased.union(Set(g))
    }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      g.in(GENS),
      a.in(ATTEMPTS),
      not(g.in(st.erased)),
      not(g.in(st.abstained)),
      mIdx >= 0,
      reqStatus == StArmed,
      activeEpochForGen(board, chainBlocks, mIdx, g) == e,
      msg.mode == OpenMode,
      rng.ok,
      obs.done,
      st.chainTip >= obs.anchorH,
      fee > 0,
      ledgerOk,
      lockOk,
      not(alreadySent),
      nodes1' = if (e == 1) nodes1.set(i, stNext) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, stNext) else nodes2,
      board' = board.append({
        ...emptyPost(P_PARTIAL, boardHeight),
        epoch: e,
        node: i,
        g: g,
        a: a,
        h: obs.anchorH,
        dg: myDg
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  // Sealed mode PARTIAL (§3.7, §5)
  action honestSealedPartial(e: int, i: int, g: int, a: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val rng = validRangeForGen(board, chainBlocks, mIdx, e, g)
    val win = attemptWindow(board, chainBlocks, mIdx, e, g, a)
    val obs = obsAnchorInRange(board, win.startIdx, rng.endIdx, e, g, a)
    val g1Cut =
      if (g == 1) { hasAnchor: false, anchorH: 0, sealedVar: 0, openFee: 0 }
      else gen1AnchorInPrefix(safeSlicePosts(board, 0, obs.cutIdx + 1), chainBlocks, mIdx)
    val vSel = selectSealedVariant(chainBlocks, obs.anchorH, g, g1Cut.anchorH, g1Cut.sealedVar)
    val alreadySent = board.foldl(false, (seen, p) =>
      seen or (p.kind == P_SEALED_PARTIAL and p.epoch == e and p.node == i and p.g == g)
    )
    val stNext = { ...st, erased: st.erased.union(Set(g)) }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      g.in(GENS),
      a.in(ATTEMPTS),
      not(g.in(st.erased)),
      mIdx >= 0,
      reqStatus == StArmed,
      activeEpochForGen(board, chainBlocks, mIdx, g) == e,
      msg.mode == SealedMode,
      rng.ok,
      obs.done,
      not(attemptFailedInRange(board, obs.cutIdx, rng.endIdx, e, g, a)),
      st.chainTip >= obs.anchorH,
      vSel > 0,
      not(alreadySent),
      nodes1' = if (e == 1) nodes1.set(i, stNext) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, stNext) else nodes2,
      board' = board.append({
        ...emptyPost(P_SEALED_PARTIAL, boardHeight),
        epoch: e,
        node: i,
        g: g,
        a: a,
        h: obs.anchorH,
        variant: vSel
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  // =========================================================================
  // Node Crash / Disk Rollback and Clean Restart (SCHEME.md §3.9 Rules 1, 3, 4)
  // =========================================================================

  // Disk rollback: node i loses its durable slot ledger and restarts.
  // When useRule4 == true, the restarting node replays `board` for its own
  // PREVOTE or PARTIAL posts and abstains on any (rid, g) missing from its ledger.
  action rollbackNodeWithRule4(e: int, i: int, newBuilderImpl: int, useRule4: bool): bool = {
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val hasLedgerState = GENS.exists(g => st.ledger.get(g) != 0)
    val wipedLedger = GENS.mapBy(_ => 0)
    val boardPostedGens = GENS.filter(g =>
      board.foldl(false, (seen, p) =>
        seen or (p.epoch == e and p.node == i and p.g == g
                 and p.kind.in(Set(P_PREVOTE, P_PARTIAL)))
      )
    )
    val abstainedAfterReplay =
      if (useRule4) st.abstained.union(boardPostedGens)
      else Set()
    val stNext = {
      ...st,
      ledger: wipedLedger,
      abstained: abstainedAfterReplay,
      builderImpl: newBuilderImpl
    }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      newBuilderImpl.in(Set(1, 2)),
      hasLedgerState,
      nodes1' = if (e == 1) nodes1.set(i, stNext) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, stNext) else nodes2,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      chainBlocks' = chainBlocks,
    }
  }

  action rollbackNode(e: int, i: int, newBuilderImpl: int): bool =
    rollbackNodeWithRule4(e, i, newBuilderImpl, ENFORCE_RULE4)

  // Clean restart / builder upgrade: durable slot ledger is intact, so Rule 4
  // does not abstain, while Rule 1 + Rule 3 prevent voting/signing a second digest.
  action restartKeepLedger(e: int, i: int): bool = {
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val hasLedgerState = GENS.exists(g => st.ledger.get(g) != 0)
    val stNext = { ...st, builderImpl: 2 }
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      st.builderImpl == 1,
      hasLedgerState,
      nodes1' = if (e == 1) nodes1.set(i, stNext) else nodes1,
      nodes2' = if (e == 2) nodes2.set(i, stNext) else nodes2,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      board' = board,
      chainBlocks' = chainBlocks,
    }
  }

  // =========================================================================
  // Section 5 Actions: Committee Change (ROTATE, Reshare Deal, Complaint, READY)
  // =========================================================================
  action postRotate: bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val nextBoard = board.append(emptyPost(P_ROTATE, boardHeight))
    val eraseAll = if (msg.rotPolicy == RotVoid) GENS else Set()
    all {
      mIdx >= 0,
      rotateIdx(board, mIdx) == -1,
      not(isTombstoned),
      nodes1' = NODES.mapBy(i =>
        if (i.in(byz1)) nodes1.get(i)
        else { ...nodes1.get(i), erased: nodes1.get(i).erased.union(eraseAll) }
      ),
      nodes2' = nodes2,
      board' = nextBoard,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  action honestReshareDeal(i: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val rIdx = rotateIdx(board, mIdx)
    val toReshare = gensNotInFlightAtRotate(board, chainBlocks, mIdx)
    val alreadyDealt =
      rIdx >= 0 and safeSlicePosts(board, rIdx + 1, board.length()).foldl(false, (seen, p) =>
        seen or (p.kind == P_RS_DEAL and p.epoch == 1 and p.node == i)
      )
    all {
      i.in(NODES),
      not(i.in(byz1)),
      mIdx >= 0,
      reqStatus == StArmed,
      msg.rotPolicy == RotReshare,
      rIdx >= 0,
      boardHeight <= msg.exp,
      toReshare.size() > 0,
      not(alreadyDealt),
      board' = board.append({
        ...emptyPost(P_RS_DEAL, boardHeight),
        epoch: 1,
        node: i,
        gens: toReshare,
        badNodes: Set()
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  action honestReshareComplaint(j: int, dealer: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val rIdx = rotateIdx(board, mIdx)
    val dealInfo = safeSlicePosts(board, rIdx + 1, board.length()).foldl(
      { seen: false, badForJ: false },
      (st, p) =>
        if (not(st.seen) and p.kind == P_RS_DEAL and p.epoch == 1 and p.node == dealer) {
          { seen: true, badForJ: j.in(p.badNodes) }
        } else st
    )
    val alreadyComplained = safeSlicePosts(board, rIdx + 1, board.length()).foldl(false, (seen, p) =>
      seen or (p.kind == P_RS_COMPLAINT and p.epoch == 2 and p.node == j and p.targetDealer == dealer)
    )
    all {
      j.in(NODES),
      not(j.in(byz2)),
      dealer.in(NODES),
      mIdx >= 0,
      reqStatus == StArmed,
      msg.rotPolicy == RotReshare,
      rIdx >= 0,
      boardHeight <= msg.exp,
      dealInfo.seen,
      dealInfo.badForJ,
      not(alreadyComplained),
      board' = board.append({
        ...emptyPost(P_RS_COMPLAINT, boardHeight),
        epoch: 2,
        node: j,
        targetDealer: dealer
      }),
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
      nodes1' = nodes1,
      nodes2' = nodes2,
    }
  }

  action honestReady(j: int): bool = {
    val mIdx = boundMsgIdx(board)
    val msg = msgAt(board, mIdx)
    val rIdx = rotateIdx(board, mIdx)
    val q = reshareCandidateDealers(board, chainBlocks, mIdx)
    val jHasValidFromAllQ = q.forall(d =>
      safeSlicePosts(board, rIdx + 1, board.length()).foldl(
        { seen: false, ok: false },
        (st, p) =>
          if (not(st.seen) and p.kind == P_RS_DEAL and p.epoch == 1 and p.node == d) {
            { seen: true, ok: not(j.in(p.badNodes)) }
          } else st
      ).ok
    )
    val alreadyReady = safeSlicePosts(board, rIdx + 1, board.length()).foldl(false, (seen, p) =>
      seen or (p.kind == P_READY and p.epoch == 2 and p.node == j and p.dealers == q)
    )
    val nextBoard = board.append({
      ...emptyPost(P_READY, boardHeight),
      epoch: 2,
      node: j,
      dealers: q
    })
    val hoDone = mIdx >= 0 and handoverIdx(nextBoard, chainBlocks, mIdx) >= 0
    val transferredGens =
      if (hoDone) gensNotInFlightAtRotate(nextBoard, chainBlocks, mIdx) else Set()
    all {
      j.in(NODES),
      not(j.in(byz2)),
      mIdx >= 0,
      reqStatus == StArmed,
      msg.rotPolicy == RotReshare,
      rIdx >= 0,
      boardHeight <= msg.exp,
      q.size() == F + 1,
      jHasValidFromAllQ,
      not(alreadyReady),
      nodes1' = NODES.mapBy(i =>
        if (i.in(byz1)) nodes1.get(i)
        else { ...nodes1.get(i), erased: nodes1.get(i).erased.union(transferredGens) }
      ),
      nodes2' = nodes2,
      board' = nextBoard,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  // =========================================================================
  // Section 3.10 Actions: Honest FINAL and VOID Tombstone Posts
  // =========================================================================
  action honestPostFinal(e: int, i: int): bool = {
    val mIdx = boundMsgIdx(board)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val epochActive = (e == 1) or (mIdx >= 0 and handoverIdx(board, chainBlocks, mIdx) >= 0)
    val txVal = reqSpentValAt(chainBlocks, st.chainTip)
    val alreadyPosted = safeSlicePosts(board, mIdx + 1, board.length()).foldl(false, (seen, p) =>
      seen or (p.kind == P_FINAL and p.epoch == e and p.node == i and p.dg == txVal)
    )
    val nextBoard = board.append({
      ...emptyPost(P_FINAL, boardHeight),
      epoch: e,
      node: i,
      dg: txVal
    })
    val nowFinal = computeReqStatus(nextBoard, chainBlocks, boardHeight) == StFinal
    val eraseAll = if (nowFinal) GENS else Set()
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      mIdx >= 0,
      epochActive,
      not(isTombstoned),
      pinSpentByReqAt(chainBlocks, st.chainTip),
      txVal > 0,
      not(alreadyPosted),
      nodes1' = NODES.mapBy(k =>
        if (k.in(byz1)) nodes1.get(k)
        else { ...nodes1.get(k), erased: nodes1.get(k).erased.union(eraseAll) }
      ),
      nodes2' = NODES.mapBy(k =>
        if (k.in(byz2)) nodes2.get(k)
        else { ...nodes2.get(k), erased: nodes2.get(k).erased.union(eraseAll) }
      ),
      board' = nextBoard,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  action honestPostVoid(e: int, i: int): bool = {
    val mIdx = boundMsgIdx(board)
    val ns = getNodes(e, nodes1, nodes2)
    val st = nodeAt(ns, i)
    val epochActive = (e == 1) or (mIdx >= 0 and handoverIdx(board, chainBlocks, mIdx) >= 0)
    val alreadyPosted = safeSlicePosts(board, mIdx + 1, board.length()).foldl(false, (seen, p) =>
      seen or (p.kind == P_VOID and p.epoch == e and p.node == i)
    )
    val nextBoard = board.append({
      ...emptyPost(P_VOID, boardHeight),
      epoch: e,
      node: i
    })
    val nowVoid = computeReqStatus(nextBoard, chainBlocks, boardHeight) == StVoid
    val eraseAll = if (nowVoid) GENS else Set()
    all {
      e.in(EPOCHS),
      i.in(NODES),
      not(isByz(e, i, byz1, byz2)),
      mIdx >= 0,
      epochActive,
      not(isTombstoned),
      pinSpentByForeignAt(chainBlocks, st.chainTip),
      not(alreadyPosted),
      nodes1' = NODES.mapBy(k =>
        if (k.in(byz1)) nodes1.get(k)
        else { ...nodes1.get(k), erased: nodes1.get(k).erased.union(eraseAll) }
      ),
      nodes2' = NODES.mapBy(k =>
        if (k.in(byz2)) nodes2.get(k)
        else { ...nodes2.get(k), erased: nodes2.get(k).erased.union(eraseAll) }
      ),
      board' = nextBoard,
      byz1' = byz1,
      byz2' = byz2,
      boardHeight' = boardHeight,
      chainBlocks' = chainBlocks,
    }
  }

  // =========================================================================
  // Byzantine Actions: Equivocation, Arbitrary Heights/Digests, Bogus Posts
  // =========================================================================
  action byzPost(p: Post): bool = all {
    p.epoch.in(EPOCHS),
    p.node.in(NODES),
    isByz(p.epoch, p.node, byz1, byz2),
    board.select(x => isByz(x.epoch, x.node, byz1, byz2)).length() < 8,
    board' = board.append({ ...p, bheight: boardHeight }),
    byz1' = byz1,
    byz2' = byz2,
    boardHeight' = boardHeight,
    chainBlocks' = chainBlocks,
    nodes1' = nodes1,
    nodes2' = nodes2,
  }

  // Strategic Byzantine equivocation: echo any PREVOTE already on board to complete
  // competing lock certificates whenever honest nodes split or double-vote.
  action byzEchoPrevote(e: int, bNode: int, targetIdx: int): bool = {
    val p = msgAt(board, targetIdx)
    val alreadyEchoed = board.foldl(false, (seen, q) =>
      seen or (q.kind == P_PREVOTE and q.epoch == e and q.node == bNode
               and q.g == p.g and q.a == p.a and q.h == p.h and q.dg == p.dg)
    )
    all {
      targetIdx >= 0,
      targetIdx < board.length(),
      p.kind == P_PREVOTE,
      p.epoch == e,
      not(alreadyEchoed),
      byzPost({
        ...emptyPost(P_PREVOTE, boardHeight),
        epoch: e,
        node: bNode,
        g: p.g,
        a: p.a,
        h: p.h,
        dg: p.dg
      }),
    }
  }

  // =========================================================================
  // Top-level Nondeterministic Step Relation
  // =========================================================================
  action step = any {
    // 1. Owner posts MSG (valid or invalid/squat)
    {
      nondet mid = Set(1, 2).oneOf()
      nondet mode = Set(OpenMode, SealedMode).oneOf()
      nondet tProf = Set(ProfileT1, ProfileT2).oneOf()
      nondet rotPol = Set(RotFinish, RotReshare, RotVoid).oneOf()
      nondet nb = Set(1, 2).oneOf()
      nondet exp = Set(3, 4).oneOf()
      nondet badNodeOpt = Set(0, 1).oneOf()
      val badSet = if (badNodeOpt == 0) Set() else Set(1)
      postOwnerMsg(mid, mode, tProf, rotPol, nb, exp, badSet)
    },
    // 2. Honest Step A (ACK or verified COMPLAINT)
    {
      nondet i = NODES.oneOf()
      honestStepA(i)
    },
    // 3. Honest Step B (OBS or NACK)
    {
      nondet e = EPOCHS.oneOf()
      nondet i = NODES.oneOf()
      nondet g = GENS.oneOf()
      nondet a = ATTEMPTS.oneOf()
      any {
        honestObs(e, i, g, a),
        honestNack(e, i, g, a),
      }
    },
    // 4. Honest Step C (Open PREVOTE, Open PARTIAL, Sealed PARTIAL)
    {
      nondet e = EPOCHS.oneOf()
      nondet i = NODES.oneOf()
      nondet g = GENS.oneOf()
      nondet a = ATTEMPTS.oneOf()
      any {
        honestPrevote(e, i, g, a),
        honestOpenPartial(e, i, g, a),
        honestSealedPartial(e, i, g, a),
      }
    },
    // 5. Honest Node Crash / Disk Rollback (Rule 4) & Clean Builder Restart (Rule 1/3)
    {
      nondet e = EPOCHS.oneOf()
      nondet i = NODES.oneOf()
      nondet newImpl = Set(1, 2).oneOf()
      any {
        rollbackNode(e, i, newImpl),
        restartKeepLedger(e, i),
      }
    },
    // 6. Committee Rotation & Resharing (§5)
    postRotate,
    {
      nondet i = NODES.oneOf()
      honestReshareDeal(i)
    },
    {
      nondet j = NODES.oneOf()
      nondet d = NODES.oneOf()
      honestReshareComplaint(j, d)
    },
    {
      nondet j = NODES.oneOf()
      honestReady(j)
    },
    // 7. Honest FINAL and VOID Tombstones (§3.10)
    {
      nondet e = EPOCHS.oneOf()
      nondet i = NODES.oneOf()
      any {
        honestPostFinal(e, i),
        honestPostVoid(e, i),
      }
    },
    // 8. Target Chain Progression, Spend Execution & Node Tip Sync
    tickBoardHeight,
    {
      nondet trig = Set(true, false).oneOf()
      nondet fee = Set(10, 15, 30).oneOf()
      any {
        advanceChainEmpty(trig, fee),
        advanceChainForeignSpend(trig, fee),
      }
    },
    {
      nondet idx = 0.to(maxInt(0, board.length() - 1)).oneOf()
      nondet trig = Set(true, false).oneOf()
      nondet fee = Set(10, 15).oneOf()
      val p = msgAt(board, idx)
      val valId = if (p.kind == P_SEALED_PARTIAL) p.variant else p.dg
      all {
        board.length() > 0,
        p.g.in(GENS),
        advanceChainReqSpend(p.g, valId, trig, fee),
      }
    },
    {
      nondet e = EPOCHS.oneOf()
      nondet i = NODES.oneOf()
      nondet h = 1.to(MAX_CHAIN_HEIGHT).oneOf()
      syncNodeChainTip(e, i, h)
    },
    // 9. Strategic Byzantine PREVOTE Equivocation + Arbitrary Byzantine Posts
    {
      nondet e = EPOCHS.oneOf()
      nondet bNode = NODES.oneOf()
      nondet idx = 0.to(maxInt(0, board.length() - 1)).oneOf()
      all {
        isByz(e, bNode, byz1, byz2),
        byzEchoPrevote(e, bNode, idx),
      }
    },
    {
      nondet e = EPOCHS.oneOf()
      nondet bNode = NODES.oneOf()
      all {
        isByz(e, bNode, byz1, byz2),
        any {
          {
            nondet k = Set(P_ACK, P_COMPLAINT).oneOf()
            nondet mid = Set(1, 2).oneOf()
            byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, mid: mid })
          },
          {
            nondet k = Set(P_OBS, P_NACK).oneOf()
            nondet g = GENS.oneOf()
            nondet a = ATTEMPTS.oneOf()
            nondet h = Set(1, 2, 3, 4, 100).oneOf()
            byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, g: g, a: a, h: h })
          },
          {
            nondet k = Set(P_PREVOTE, P_PARTIAL).oneOf()
            nondet g = GENS.oneOf()
            nondet a = ATTEMPTS.oneOf()
            nondet h = 1.to(MAX_CHAIN_HEIGHT).oneOf()
            nondet fee = Set(10, 15).oneOf()
            nondet impl = Set(1, 2).oneOf()
            val dg = encodeDigest(e, g, a, h, fee, impl)
            byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, g: g, a: a, h: h, dg: dg })
          },
          {
            nondet g = GENS.oneOf()
            nondet v = 1.to(MAX_VARIANTS).oneOf()
            byzPost({ ...emptyPost(P_SEALED_PARTIAL, boardHeight), epoch: e, node: bNode, g: g, variant: v })
          },
          {
            nondet badTarget = Set(0, 1, 2).oneOf()
            nondet wrongGens = Set(false, true).oneOf()
            val mIdx = boundMsgIdx(board)
            val rightGens = if (mIdx >= 0) gensNotInFlightAtRotate(board, chainBlocks, mIdx) else GENS
            val dealGens = if (wrongGens) GENS else rightGens
            val badSet = if (badTarget == 0) Set() else Set(badTarget)
            byzPost({ ...emptyPost(P_RS_DEAL, boardHeight), epoch: e, node: bNode, gens: dealGens, badNodes: badSet })
          },
          {
            nondet k = Set(P_FINAL, P_VOID).oneOf()
            nondet bogusDg = Set(1, 777).oneOf()
            byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, dg: bogusDg })
          },
        }
      }
    },
  }

  // =========================================================================
  // Exploration aids (simulation only; NO protocol semantics)
  //
  // Everything in this section only composes the protocol actions defined
  // above, restricts which of their parameters are sampled, or weights how
  // often each is sampled. No guard or update of a protocol action is
  // changed. A focused step can only reach states that the full `step` can
  // also reach (each branch is a branch of `step` with narrower nondet
  // choices), and `initArmed` builds a state that `init` followed by
  // postOwnerMsg and QUORUM honestStepA reaches (see run initArmedReachableTest).
  // =========================================================================

  pure def honestOf(e: int, b1: Set[int], b2: Set[int]): Set[int] =
    NODES.filter(n => not(isByz(e, n, b1, b2)))

  pure def ackPost(n: int): Post =
    { ...emptyPost(P_ACK, 1), epoch: 1, node: n, mid: 1 }

  // Scenario init: init's nondeterministic choices, plus a valid owner MSG
  // (mid 1, nb 1, exp 4, no bad ciphertexts) and QUORUM honest ACKs already on
  // the board, so the request starts ARMED at board height 1.
  action initArmedWith(modes: Set[Mode], pols: Set[RotPolicy]): bool = {
    val validByzSets = NODES.powerset().filter(s => s.size() <= F)
    nondet b1 = validByzSets.oneOf()
    nondet b2 = validByzSets.oneOf()
    nondet trig = Set(true, false).oneOf()
    nondet fee = Set(10, 15, 30).oneOf()
    nondet divNode = Set(0).union(NODES).oneOf()
    nondet mode = modes.oneOf()
    nondet rotPol = pols.oneOf()
    nondet tAny = Set(ProfileT1, ProfileT2).oneOf()
    nondet ackers = NODES.exclude(b1).powerset().filter(s => s.size() == QUORUM).oneOf()
    val tProf = if (rotPol == RotReshare) ProfileT1 else tAny
    val impls1 = NODES.mapBy(i => if (i == divNode) 2 else 1)
    val impls2 = NODES.mapBy(_ => 1)
    val msgPost = {
      ...emptyPost(P_MSG, 1),
      mid: 1, mode: mode, tProfile: tProf, rotPolicy: rotPol, nb: 1, exp: 4, badNodes: Set()
    }
    all {
      b1.subseteq(NODES),
      b2.subseteq(NODES),
      byz1' = b1,
      byz2' = b2,
      boardHeight' = 1,
      board' = ackers.fold(List(msgPost), (l, n) => l.append(ackPost(n))),
      chainBlocks' = List({
        height: 1, triggerOk: trig, marketFee: fee, txKind: TxNone, txGen: 0, txVal: 0
      }),
      nodes1' = NODES.mapBy(i => initNodeState(impls1.get(i))),
      nodes2' = NODES.mapBy(i => initNodeState(impls2.get(i))),
    }
  }

  action initArmed = initArmedWith(Set(OpenMode, SealedMode), Set(RotFinish, RotReshare, RotVoid))
  action initArmedOpen = initArmedWith(Set(OpenMode), Set(RotFinish, RotReshare, RotVoid))
  action initArmedOpenReshare = initArmedWith(Set(OpenMode), Set(RotReshare))

  // Step B / Step C for the committee that currently owns generation g.
  action progressStepB = {
    nondet g = GENS.oneOf()
    nondet a = ATTEMPTS.oneOf()
    val e = activeEpochForGen(board, chainBlocks, boundMsgIdx(board), g)
    nondet i = honestOf(e, byz1, byz2).oneOf()
    any {
      honestObs(e, i, g, a),
      honestNack(e, i, g, a),
    }
  }

  action progressStepC = {
    nondet g = GENS.oneOf()
    nondet a = ATTEMPTS.oneOf()
    val e = activeEpochForGen(board, chainBlocks, boundMsgIdx(board), g)
    nondet i = honestOf(e, byz1, byz2).oneOf()
    any {
      honestPrevote(e, i, g, a),
      honestOpenPartial(e, i, g, a),
      honestSealedPartial(e, i, g, a),
    }
  }

  // Execute a request transaction for a (g, digest/variant) that has a partial on the board.
  action progressSpend = {
    val partialIdxs = board.indices().filter(k =>
      board.nth(k).kind.in(Set(P_PARTIAL, P_SEALED_PARTIAL)) and board.nth(k).g.in(GENS))
    nondet k = partialIdxs.oneOf()
    nondet fee = Set(10, 15).oneOf()
    val p = board.nth(k)
    val valId = if (p.kind == P_SEALED_PARTIAL) p.variant else p.dg
    advanceChainReqSpend(p.g, valId, true, fee)
  }

  // Honest progress only: owner MSG (if none), Step A, Step B, Step C, target
  // chain blocks with an eligible trigger (one chain slot is left for the spend),
  // tip sync to the chain head, spend, FINAL, ROTATE and resharing.
  action stepHonestProgress = any {
    {
      nondet mode = Set(OpenMode, SealedMode).oneOf()
      nondet rotPol = Set(RotFinish, RotReshare, RotVoid).oneOf()
      nondet tAny = Set(ProfileT1, ProfileT2).oneOf()
      val tProf = if (rotPol == RotReshare) ProfileT1 else tAny
      all {
        board.select(p => p.kind == P_MSG).length() == 0,
        postOwnerMsg(1, mode, tProf, rotPol, 1, 4, Set()),
      }
    },
    { nondet i = honestOf(1, byz1, byz2).oneOf()  honestStepA(i) },
    progressStepB, progressStepB, progressStepB,
    progressStepC, progressStepC, progressStepC,
    {
      nondet fee = Set(10, 15).oneOf()
      all { chainBlocks.length() < MAX_CHAIN_HEIGHT - 1, advanceChainEmpty(true, fee) }
    },
    {
      nondet e = EPOCHS.oneOf()
      nondet i = honestOf(e, byz1, byz2).oneOf()
      syncNodeChainTip(e, i, chainBlocks.length())
    },
    {
      nondet e = EPOCHS.oneOf()
      nondet i = honestOf(e, byz1, byz2).oneOf()
      syncNodeChainTip(e, i, chainBlocks.length())
    },
    progressSpend,
    {
      nondet e = EPOCHS.oneOf()
      nondet i = honestOf(e, byz1, byz2).oneOf()
      honestPostFinal(e, i)
    },
    postRotate,
    { nondet i = honestOf(1, byz1, byz2).oneOf()  honestReshareDeal(i) },
    { nondet j = honestOf(2, byz1, byz2).oneOf()  honestReady(j) },
  }

  // Crash faults and environment noise layered on honest progress:
  // disk rollback (with the instance's Rule 4 setting), clean builder restart,
  // board height ticks, foreign spends and ineligible / expensive blocks.
  action stepFaults = any {
    {
      nondet e = EPOCHS.oneOf()
      nondet i = honestOf(e, byz1, byz2).oneOf()
      nondet newImpl = Set(1, 2).oneOf()
      any {
        rollbackNode(e, i, newImpl),
        restartKeepLedger(e, i),
      }
    },
    tickBoardHeight,
    {
      nondet trig = Set(true, false).oneOf()
      nondet fee = Set(10, 15, 30).oneOf()
      any {
        advanceChainEmpty(trig, fee),
        advanceChainForeignSpend(trig, fee),
      }
    },
    {
      nondet e = EPOCHS.oneOf()
      nondet i = honestOf(e, byz1, byz2).oneOf()
      honestPostVoid(e, i)
    },
  }

  // Byzantine moves aimed at safety: echo an existing PREVOTE (to complete a
  // competing lock certificate), and arbitrary OBS / NACK / PREVOTE / PARTIAL /
  // sealed PARTIAL / reshare deal / FINAL / VOID posts.
  action stepByz = {
    nondet e = EPOCHS.oneOf()
    nondet bNode = NODES.filter(n => isByz(e, n, byz1, byz2)).oneOf()
    any {
      {
        nondet idx = board.indices().filter(k => board.nth(k).kind == P_PREVOTE).oneOf()
        byzEchoPrevote(e, bNode, idx)
      },
      {
        nondet idx = board.indices().filter(k => board.nth(k).kind == P_PREVOTE).oneOf()
        byzEchoPrevote(e, bNode, idx)
      },
      {
        nondet k = Set(P_OBS, P_NACK).oneOf()
        nondet g = GENS.oneOf()
        nondet a = ATTEMPTS.oneOf()
        nondet h = Set(1, 2, 3, 4, 100).oneOf()
        byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, g: g, a: a, h: h })
      },
      {
        nondet k = Set(P_PREVOTE, P_PARTIAL).oneOf()
        nondet g = GENS.oneOf()
        nondet a = ATTEMPTS.oneOf()
        nondet h = 1.to(MAX_CHAIN_HEIGHT).oneOf()
        nondet fee = Set(10, 15).oneOf()
        nondet impl = Set(1, 2).oneOf()
        val dg = encodeDigest(e, g, a, h, fee, impl)
        byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, g: g, a: a, h: h, dg: dg })
      },
      {
        nondet g = GENS.oneOf()
        nondet v = 1.to(MAX_VARIANTS).oneOf()
        byzPost({ ...emptyPost(P_SEALED_PARTIAL, boardHeight), epoch: e, node: bNode, g: g, variant: v })
      },
      {
        nondet badTarget = Set(0, 1, 2).oneOf()
        nondet wrongGens = Set(false, true).oneOf()
        val mIdx = boundMsgIdx(board)
        val rightGens = if (mIdx >= 0) gensNotInFlightAtRotate(board, chainBlocks, mIdx) else GENS
        val dealGens = if (wrongGens) GENS else rightGens
        val badSet = if (badTarget == 0) Set() else Set(badTarget)
        byzPost({ ...emptyPost(P_RS_DEAL, boardHeight), epoch: e, node: bNode, gens: dealGens, badNodes: badSet })
      },
      {
        nondet k = Set(P_FINAL, P_VOID).oneOf()
        nondet bogusDg = Set(1, 777).oneOf()
        byzPost({ ...emptyPost(k, boardHeight), epoch: e, node: bNode, dg: bogusDg })
      },
    }
  }

  // Weighted mixes. A disabled branch is resampled by the simulator, so the
  // weights below only shift how often each layer is tried.
  action stepProgressFaults = {
    nondet c = 1.to(10).oneOf()
    if (c <= 7) stepHonestProgress else stepFaults
  }

  action stepAdversarial = {
    nondet c = 1.to(10).oneOf()
    if (c <= 6) stepHonestProgress
    else if (c <= 8) stepFaults
    else stepByz
  }

  // Progress weighted over the ORIGINAL full `step` (every branch of `step`
  // stays reachable at its original relative weight inside `step`).
  action stepWeighted = {
    nondet c = 1.to(10).oneOf()
    if (c <= 6) stepHonestProgress else step
  }

  // =========================================================================
  // Reachability witnesses (each Nox is violated when state X is reached)
  // =========================================================================
  val ArmedReached: bool = {
    val mIdx = boundMsgIdx(board)
    mIdx >= 0 and armedIdx(board, mIdx) >= 0
  }
  val NoArmed: bool = not(ArmedReached)

  val LockCertReached: bool = {
    val mIdx = boundMsgIdx(board)
    mIdx >= 0 and msgAt(board, mIdx).mode == OpenMode
      and GENS.exists(g => genHasAnyLock(board, chainBlocks, mIdx, g))
  }
  val NoLockCert: bool = not(LockCertReached)

  pure def isHonestPartial(p: Post, b1: Set[int], b2: Set[int]): bool =
    p.kind.in(Set(P_PARTIAL, P_SEALED_PARTIAL)) and not(isByz(p.epoch, p.node, b1, b2))

  val HonestPartialReached: bool =
    board.foldl(false, (ok, p) => ok or isHonestPartial(p, byz1, byz2))
  val NoHonestPartial: bool = not(HonestPartialReached)

  // Fee-bump generation 2: an honest partial for g = 2.
  val Gen2PartialReached: bool =
    board.foldl(false, (ok, p) => ok or (isHonestPartial(p, byz1, byz2) and p.g == 2))
  val NoGen2: bool = not(Gen2PartialReached)

  val NoGen2Spend: bool =
    chainBlocks.select(blk => blk.txKind == TxReq and blk.txGen == 2).length() == 0

  // Rotation + reshare: HANDOVER completed on the board.
  val ReshareDoneReached: bool = {
    val mIdx = boundMsgIdx(board)
    mIdx >= 0 and handoverIdx(board, chainBlocks, mIdx) >= 0
  }
  val NoReshareDone: bool = not(ReshareDoneReached)

  // New committee released a partial (signing resumed after handover).
  val NoEpoch2Partial: bool =
    not(board.foldl(false, (ok, p) => ok or (isHonestPartial(p, byz1, byz2) and p.epoch == 2)))

  // Node rollback after its own PARTIAL: an honest node has a PARTIAL for g on
  // the board while its durable ledger entry for g is empty. Only a disk
  // rollback can produce this (PARTIAL always writes the ledger).
  val RollbackAfterPartialReached: bool =
    board.foldl(false, (ok, p) =>
      ok or (p.kind == P_PARTIAL and p.g.in(GENS) and p.epoch.in(EPOCHS)
             and not(isByz(p.epoch, p.node, byz1, byz2))
             and nodeAt(getNodes(p.epoch, nodes1, nodes2), p.node).ledger.get(p.g) == 0))
  val NoRollbackAfterPartial: bool = not(RollbackAfterPartialReached)

  // Rollback while a vote was outstanding (PREVOTE on board, ledger empty).
  val NoRollbackAfterPrevote: bool =
    not(board.foldl(false, (ok, p) =>
      ok or (p.kind == P_PREVOTE and p.g.in(GENS) and p.epoch.in(EPOCHS)
             and not(isByz(p.epoch, p.node, byz1, byz2))
             and nodeAt(getNodes(p.epoch, nodes1, nodes2), p.node).ledger.get(p.g) == 0)))

  val RollbackAfterPrevoteReached: bool = not(NoRollbackAfterPrevote)

  val Epoch2PartialReached: bool = not(NoEpoch2Partial)
  val Gen2SpendReached: bool = not(NoGen2Spend)

  // Antecedent of LockBeforeShare: an honest open-mode PARTIAL.
  val OpenPartialReached: bool =
    board.foldl(false, (ok, p) => ok or (p.kind == P_PARTIAL and isHonestPartial(p, byz1, byz2)))

  // Antecedent of FreezeSafety: HANDOVER done and an honest old-committee
  // partial on the board in the same state.
  val HandoverWithOldPartialReached: bool =
    ReshareDoneReached
      and board.foldl(false, (ok, p) => ok or (isHonestPartial(p, byz1, byz2) and p.epoch == 1))

  // Antecedents of NoTransientTombstone.
  val FinalReached: bool = reqStatus == StFinal
  val VoidReached: bool = reqStatus == StVoid
  val ExpiredReached: bool = reqStatus == StExpired
  val NoFinal: bool = not(FinalReached)
  val NoVoid: bool = not(VoidReached)
  val NoExpired: bool = not(ExpiredReached)

  // =========================================================================
  // Required Safety Invariants & Reachability Witness
  // =========================================================================

  // 1. NoNonceReuse:
  // No slot (rid, g) has honest partials released for two different digests
  // (prevents key recovery in Open mode; also verifies <= 1 variant in Sealed mode).
  val NoNonceReuse: bool =
    GENS.forall(g => {
      val honestOpenDigests = board.foldl(Set(), (acc, p) =>
        if (p.kind == P_PARTIAL and p.g == g and not(isByz(p.epoch, p.node, byz1, byz2))) {
          acc.union(Set(p.dg))
        } else acc
      )
      val honestSealedVariants = board.foldl(Set(), (acc, p) =>
        if (p.kind == P_SEALED_PARTIAL and p.g == g and not(isByz(p.epoch, p.node, byz1, byz2))) {
          acc.union(Set(p.variant))
        } else acc
      )
      honestOpenDigests.size() <= 1 and honestSealedVariants.size() <= 1
    })

  // 2. AtMostOneExecution:
  // At most one transaction of a request executes on the target chain.
  val AtMostOneExecution: bool =
    chainBlocks.select(blk => blk.txKind == TxReq).length() <= 1

  // 3. LockBeforeShare:
  // No honest partial exists for a digest without a QUORUM lock certificate
  // already present on the board prior to that partial.
  val LockBeforeShare: bool = {
    val mIdx = boundMsgIdx(board)
    board.indices().forall(idx => {
      val p = board.nth(idx)
      if (p.kind == P_PARTIAL and not(isByz(p.epoch, p.node, byz1, byz2))) {
        mIdx >= 0
          and mIdx < idx
          and hasLockCertOnBoard(safeSlicePosts(board, 0, idx), chainBlocks, mIdx, p.epoch, p.g, p.a, p.h, p.dg)
      } else true
    })
  }

  // 4. NoTransientTombstone:
  // A request is tombstoned only by FINAL, VOID or EXPIRED (grounded in actual
  // target-chain finality, valid complaint/void rotation/foreign spend, or window
  // expiry with no lock/release), never by an ineligible anchor / NACK / failed attempt.
  val NoTransientTombstone: bool = {
    val mIdx = boundMsgIdx(board)
    if (mIdx < 0) {
      not(isTombstoned)
    } else {
      val msg = msgAt(board, mIdx)
      val rIdx = rotateIdx(board, mIdx)
      val finalCause =
        pinSpentByReqAt(chainBlocks, chainBlocks.length())
          and firstFinalQuorumIdx(board, mIdx) >= 0
      val voidCause =
        firstValidComplaintIdx(board, mIdx) >= 0
          or (rIdx >= 0 and msg.rotPolicy == RotVoid)
          or (pinSpentByForeignAt(chainBlocks, chainBlocks.length())
              and firstVoidQuorumIdx(board, mIdx) >= 0)
      val expiredCause =
        boardHeight > msg.exp
          and not(anyGenLockedOrReleasedBeforeExp(board, chainBlocks, mIdx))

      ((reqStatus == StFinal) implies finalCause)
        and ((reqStatus == StVoid) implies voidCause)
        and ((reqStatus == StExpired) implies expiredCause)
        and (isTombstoned implies (reqStatus == StFinal or reqStatus == StVoid or reqStatus == StExpired))
    }
  }

  // 5. FreezeSafety:
  // No generation is both signed by the old committee after ROTATE (or holding
  // any honest old partial / reconstructible old signature) and reshared to the new committee.
  val FreezeSafety: bool = {
    val mIdx = boundMsgIdx(board)
    if (mIdx < 0) true else {
      val msg = msgAt(board, mIdx)
      val rIdx = rotateIdx(board, mIdx)
      if (msg.rotPolicy != RotReshare or rIdx < 0) true else {
        GENS.forall(g => {
          val honestDealtG = safeSlicePosts(board, rIdx + 1, board.length()).foldl(false, (ok, p) =>
            ok or (p.kind == P_RS_DEAL and p.epoch == 1 and not(p.node.in(byz1)) and g.in(p.gens))
          )
          val handoverMovedG =
            handoverIdx(board, chainBlocks, mIdx) >= 0
              and not(isGenInFlightAtRotate(board, chainBlocks, mIdx, g))
          val isReshared = honestDealtG or handoverMovedG

          val oldHonestPartialAfterRotate = safeSlicePosts(board, rIdx + 1, board.length()).foldl(false, (ok, p) =>
            ok or (p.epoch == 1 and not(p.node.in(byz1))
                   and p.g == g and p.kind.in(Set(P_PARTIAL, P_SEALED_PARTIAL)))
          )
          val oldHonestPartialAny = board.foldl(false, (ok, p) =>
            ok or (p.epoch == 1 and not(p.node.in(byz1))
                   and p.g == g and p.kind.in(Set(P_PARTIAL, P_SEALED_PARTIAL)))
          )

          not(isReshared and (oldHonestPartialAfterRotate or oldHonestPartialAny))
        })
      }
    }
  }

  // Combined safety invariant
  val AllSafetyInvariants: bool =
    NoNonceReuse
      and AtMostOneExecution
      and LockBeforeShare
      and NoTransientTombstone
      and FreezeSafety

  // Witness / Liveness-style reachability predicate:
  // SpendExecuted becomes true when an authorized transaction of the request
  // executes on the target chain. Running with --invariant=NoSpendExecuted
  // produces a concrete witness trace showing reachability of a completed spend.
  val SpendExecuted: bool =
    chainBlocks.select(blk => blk.txKind == TxReq).length() >= 1

  val NoSpendExecuted: bool = not(SpendExecuted)
}

// ===========================================================================
// Default Main Module: n = 4, f = 1 (all honest rules enabled) + Unit Tests
// ===========================================================================
module linedealing {
  import linedealing_protocol(
    N = 4,
    F = 1,
    ENFORCE_ONE_PREVOTE = true,
    ENFORCE_RULE4 = true
  ).*

  // -------------------------------------------------------------------------
  // Unit Test 1: Anchor Rule — (f, f, 1) split, Byzantine extremes, NACKs
  // -------------------------------------------------------------------------
  run anchorSplitTest =
    initWithParams(Set(4), Set(4), true, 10, NODES.mapBy(_ => 1), NODES.mapBy(_ => 1))
      .then(all {
        // f = 1: heights [100, 102, 101] -> no height has f+1=2 posts; entry 2 is 101
        assert(selectAnchorHeightForF(List(100, 102, 101), 1) == 101),
        // f = 2: heights [100, 100, 101, 101, 102] -> no height has f+1=3 posts; entry 3 is 101
        assert(selectAnchorHeightForF(List(100, 100, 101, 101, 102), 2) == 101),
        // quorum sizes: q = 2f+1 at n = 3f+1; n = 9, f = 2 gives q = 6 (LOOP item 4b)
        assert(quorumOf(4, 1) == 3 and quorumOf(7, 2) == 5 and quorumOf(16, 5) == 11),
        assert(quorumOf(9, 2) == 6 and quorumOf(8, 2) == 6 and quorumOf(10, 3) == 7),
        assert(QUORUM == 3),
        // n = 9, f = 2, q = 6: two Byzantine reports at the top (999) -> entry 3 is honest 103;
        // two Byzantine reports at the bottom (0) -> entry 3 is honest 101
        assert(selectAnchorHeightForF(List(100, 999, 101, 102, 999, 103), 2) == 103),
        assert(selectAnchorHeightForF(List(100, 0, 101, 102, 0, 103), 2) == 101),
        // f = 5: heights [100]x5 + [101]x5 + [102]x1 -> entry 6 is 101 (checks.py T11)
        assert(selectAnchorHeightForF(List(100, 100, 100, 100, 100, 101, 101, 101, 101, 101, 102), 5) == 101),
        // f Byzantine extreme reports (10^9 or 0) cannot pull anchor outside honest range [100, 105]
        assert(selectAnchorHeightForF(List(100, 100, 1000000000), 1) == 100),
        assert(selectAnchorHeightForF(List(100, 105, 0), 1) == 100),
        keepUnchanged,
      })
      // State-machine check: flickering eligibility at height 2 + (1, 1, 1) OBS split [1, 2, 3]
      // Block 1: eligible (trig=true, fee=10); Block 2: INELIGIBLE (trig=false, fee=10); Block 3: eligible (trig=true, fee=15)
      .then(advanceChainEmpty(false, 10))
      .then(advanceChainEmpty(true, 15))
      .then(syncNodeChainTip(1, 2, 3))
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotFinish, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      // Node 1 at eligible tip 1, Node 2 at eligible tip 3, Byz Node 4 injects OBS at ineligible height 2 -> (1, 1, 1) split!
      .then(honestObs(1, 1, 1, 1))
      .then(honestObs(1, 2, 1, 1))
      .then(byzPost({ ...emptyPost(P_OBS, 1), epoch: 1, node: 4, g: 1, a: 1, h: 2 }))
      // Median anchor is h* = 2 (ineligible!). Honest nodes catch up to 2 and post NACK -> f+1 = 2 NACKs fail attempt 1!
      .then(syncNodeChainTip(1, 1, 2))
      .then(syncNodeChainTip(1, 3, 3))
      .then(honestNack(1, 1, 1, 1))
      .then(honestNack(1, 2, 1, 1))
      .then(all {
        // Attempt 1 failed, NOT tombstoned (NoTransientTombstone!), attempt 2 of generation 1 is now open!
        assert(reqStatus == StArmed),
        assert(not(isTombstoned)),
        assert(NoTransientTombstone),
        assert(attemptWindow(board, chainBlocks, boundMsgIdx(board), 1, 1, 2).isOpen),
        keepUnchanged,
      })
      // Attempt 2 in generation 1 anchors at eligible height 3 and signs!
      .then(syncNodeChainTip(1, 1, 3))
      .then(honestObs(1, 1, 1, 2))
      .then(honestObs(1, 2, 1, 2))
      .then(honestObs(1, 3, 1, 2))
      .then(honestPrevote(1, 1, 1, 2))
      .then(honestPrevote(1, 2, 1, 2))
      .then(honestPrevote(1, 3, 1, 2))
      .then(honestOpenPartial(1, 1, 1, 2))
      .then(honestOpenPartial(1, 2, 1, 2))
      .then(advanceChainReqSpend(1, encodeDigest(1, 1, 2, 3, 15, 1), true, 15))
      .then(all {
        assert(SpendExecuted),
        assert(AllSafetyInvariants),
        keepUnchanged,
      })

  // -------------------------------------------------------------------------
  // Exploration aid check: the board that initArmed builds is the board that
  // init + postOwnerMsg + QUORUM honestStepA reach (same MSG, same ACK posts).
  // -------------------------------------------------------------------------
  run initArmedReachableTest =
    initWithParams(Set(4), Set(), true, 10, NODES.mapBy(_ => 1), NODES.mapBy(_ => 1))
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotReshare, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      .then(all {
        // initArmed appends the ACKs in Set.fold order; any order of honest
        // ACKs is reachable, so compare the MSG head and the ACK set.
        assert(board.length() == 4),
        assert(board.nth(0) == { ...emptyPost(P_MSG, 1), mid: 1, mode: OpenMode, tProfile: ProfileT1,
                                 rotPolicy: RotReshare, nb: 1, exp: 4, badNodes: Set() }),
        assert(Set(1, 2, 3).map(k => board.nth(k)) == Set(1, 2, 3).map(n => ackPost(n))),
        assert(reqStatus == StArmed),
        keepUnchanged,
      })

  // -------------------------------------------------------------------------
  // Unit Test 2: Vote Rules (§3.8, §3.9 rules 1, 2, 3, 5)
  // -------------------------------------------------------------------------
  run voteRulesTest =
    initWithParams(
      Set(4),
      Set(4),
      true,
      10,
      Map(1 -> 1, 2 -> 2, 3 -> 1, 4 -> 1),
      NODES.mapBy(_ => 1)
    )
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotFinish, 1, 3, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      .then(honestObs(1, 1, 1, 1))
      .then(honestObs(1, 2, 1, 1))
      .then(honestObs(1, 3, 1, 1))
      // Node 1 prevotes dgA (impl 1); Node 2 prevotes dgB (impl 2); Byz 4 echoes dgA ({1, 4} = 2 < 3, not locked yet!)
      .then(honestPrevote(1, 1, 1, 1))
      .then(honestPrevote(1, 2, 1, 1))
      .then(byzPost({ ...emptyPost(P_PREVOTE, 1), epoch: 1, node: 4, g: 1, a: 1, h: 1, dg: encodeDigest(1, 1, 1, 1, 10, 1) }))
      .then(all {
        // Only 2 PREVOTEs for dgA so far: LockBeforeShare forbids PARTIAL!
        assert(not(hasLockCertOnBoard(board, chainBlocks, boundMsgIdx(board), 1, 1, 1, 1, encodeDigest(1, 1, 1, 1, 10, 1)))),
        assert(nodes1.get(1).ledger.get(1) == encodeDigest(1, 1, 1, 1, 10, 1)),
        assert(nodes1.get(2).ledger.get(1) == encodeDigest(1, 1, 1, 1, 10, 2)),
        keepUnchanged,
      })
      // Node 3 did NOT prevote before lock, but let us also verify Node 3 can sign once locked OR prevote before exp:
      // Here Node 3 prevotes dgA before exp, completing the 2f+1=3 lock cert {1, 3, 4}; Node 2 (ledger=dgB) abstains!
      .then(honestPrevote(1, 3, 1, 1))
      .then(honestOpenPartial(1, 1, 1, 1))
      .then(honestOpenPartial(1, 3, 1, 1))
      .then(all {
        assert(hasLockCertOnBoard(board, chainBlocks, boundMsgIdx(board), 1, 1, 1, 1, encodeDigest(1, 1, 1, 1, 10, 1))),
        assert(board.select(p => p.kind == P_PARTIAL and p.node == 2).length() == 0),
        assert(AllSafetyInvariants),
        keepUnchanged,
      })

  // -------------------------------------------------------------------------
  // Unit Test 3: Rollback WITH Rule 4 (honest restart board replay prevents nonce reuse)
  // -------------------------------------------------------------------------
  run rollbackWithRule4Test =
    initWithParams(
      Set(4),
      Set(4),
      true,
      10,
      Map(1 -> 1, 2 -> 2, 3 -> 1, 4 -> 1),
      NODES.mapBy(_ => 1)
    )
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotFinish, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      .then(honestObs(1, 1, 1, 1))
      .then(honestObs(1, 2, 1, 1))
      .then(honestObs(1, 3, 1, 1))
      // Nodes 1 & 3 vote dgA; Byz 4 votes dgA -> 2f+1 = 3 lock cert for dgA! Node 1 releases PARTIAL(dgA).
      .then(honestPrevote(1, 1, 1, 1))
      .then(honestPrevote(1, 3, 1, 1))
      .then(byzPost({ ...emptyPost(P_PREVOTE, 1), epoch: 1, node: 4, g: 1, a: 1, h: 1, dg: encodeDigest(1, 1, 1, 1, 10, 1) }))
      .then(honestOpenPartial(1, 1, 1, 1))
      // Node 3 crashes, loses its durable slot ledger, and restarts with builderImpl = 2 (dgB) WITH Rule 4!
      .then(rollbackNodeWithRule4(1, 3, 2, true))
      // Node 2 votes dgB, Byz 4 equivocates dgB ({2, 4} = 2 votes < 3)
      .then(honestPrevote(1, 2, 1, 1))
      .then(byzPost({ ...emptyPost(P_PREVOTE, 1), epoch: 1, node: 4, g: 1, a: 1, h: 1, dg: encodeDigest(1, 1, 1, 1, 10, 2) }))
      .then(all {
        assert(1.in(nodes1.get(3).abstained)),
        assert(not(hasLockCertOnBoard(board, chainBlocks, boundMsgIdx(board), 1, 1, 1, 1, encodeDigest(1, 1, 1, 1, 10, 2)))),
        assert(NoNonceReuse),
        assert(AllSafetyInvariants),
        keepUnchanged,
      })

  // -------------------------------------------------------------------------
  // Unit Test 4: Rollback WITHOUT Rule 4 (broken restart violates NoNonceReuse!)
  // -------------------------------------------------------------------------
  run rollbackWithoutRule4Test =
    initWithParams(
      Set(4),
      Set(4),
      true,
      10,
      Map(1 -> 1, 2 -> 2, 3 -> 1, 4 -> 1),
      NODES.mapBy(_ => 1)
    )
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotFinish, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      .then(honestObs(1, 1, 1, 1))
      .then(honestObs(1, 2, 1, 1))
      .then(honestObs(1, 3, 1, 1))
      // Nodes 1 & 3 vote dgA; Byz 4 votes dgA -> 2f+1 = 3 lock cert for dgA! Node 1 releases PARTIAL(dgA).
      .then(honestPrevote(1, 1, 1, 1))
      .then(honestPrevote(1, 3, 1, 1))
      .then(byzPost({ ...emptyPost(P_PREVOTE, 1), epoch: 1, node: 4, g: 1, a: 1, h: 1, dg: encodeDigest(1, 1, 1, 1, 10, 1) }))
      .then(honestOpenPartial(1, 1, 1, 1))
      // Node 3 crashes, loses its durable slot ledger, and restarts with builderImpl = 2 WITHOUT Rule 4!
      .then(rollbackNodeWithRule4(1, 3, 2, false))
      // Because Rule 4 was skipped, Node 3's abstained set is empty and ledger is 0 -> Node 3 votes dgB!
      .then(honestPrevote(1, 3, 1, 1))
      .then(honestPrevote(1, 2, 1, 1))
      .then(byzPost({ ...emptyPost(P_PREVOTE, 1), epoch: 1, node: 4, g: 1, a: 1, h: 1, dg: encodeDigest(1, 1, 1, 1, 10, 2) }))
      // Now {2, 3, 4} = 3 = 2f+1 PREVOTEs for dgB! Honest Node 2 releases PARTIAL(dgB)!
      .then(honestOpenPartial(1, 2, 1, 1))
      .then(all {
        assert(not(NoNonceReuse)),
        keepUnchanged,
      })

  // -------------------------------------------------------------------------
  // Unit Test 5: Freeze & Resharing across Committee Rotation (§5)
  // -------------------------------------------------------------------------
  run freezeAndReshareTest =
    initWithParams(Set(4), Set(4), true, 10, NODES.mapBy(_ => 1), NODES.mapBy(_ => 1))
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotReshare, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      // Generation 1 anchors at height 1 and locks BEFORE ROTATE
      .then(honestObs(1, 1, 1, 1))
      .then(honestObs(1, 2, 1, 1))
      .then(honestObs(1, 3, 1, 1))
      .then(honestPrevote(1, 1, 1, 1))
      .then(honestPrevote(1, 2, 1, 1))
      .then(honestPrevote(1, 3, 1, 1))
      // ROTATE(1 -> 2) freezes the request: g=1 is in-flight, g=2 is NOT in-flight!
      .then(postRotate)
      // Old committee finishes in-flight g=1 after ROTATE, and reshares ONLY {2} to new committee
      .then(honestOpenPartial(1, 1, 1, 1))
      .then(honestOpenPartial(1, 2, 1, 1))
      .then(honestReshareDeal(1))
      .then(honestReshareDeal(2))
      .then(honestReady(1))
      .then(honestReady(2))
      .then(honestReady(3))
      // Advance target chain to height 2 (flat market fee 10; g=2 must bump to 10 + 5 = 15!)
      .then(advanceChainEmpty(true, 10))
      .then(syncNodeChainTip(2, 1, 2))
      .then(syncNodeChainTip(2, 2, 2))
      .then(syncNodeChainTip(2, 3, 2))
      // New committee (Epoch 2) anchors, locks, and signs g=2 with bumped fee 15!
      .then(honestObs(2, 1, 2, 1))
      .then(honestObs(2, 2, 2, 1))
      .then(honestObs(2, 3, 2, 1))
      .then(honestPrevote(2, 1, 2, 1))
      .then(honestPrevote(2, 2, 2, 1))
      .then(honestPrevote(2, 3, 2, 1))
      .then(honestOpenPartial(2, 1, 2, 1))
      .then(honestOpenPartial(2, 2, 2, 1))
      // Execute bumped g=2 transaction on target chain; g=1 conflicts on pin and can no longer execute!
      .then(advanceChainReqSpend(2, encodeDigest(2, 2, 1, 2, 15, 1), true, 10))
      .then(syncNodeChainTip(2, 1, 3))
      .then(syncNodeChainTip(2, 2, 3))
      .then(honestPostFinal(2, 1))
      .then(honestPostFinal(2, 2))
      .then(all {
        assert(reqStatus == StFinal),
        assert(SpendExecuted),
        assert(FreezeSafety),
        assert(AllSafetyInvariants),
        keepUnchanged,
      })
  // -------------------------------------------------------------------------
  // Regression (CONFORMANCE.md M1): an old node cannot deal after HANDOVER.
  // HANDOVER erases the transferred shares of the old committee (§5), so a
  // later RS_DEAL would deal shares the node no longer holds. Found by the
  // Rust conformance replay (n = 4 instance, seed 1022, trace
  // impl/tests/quint_regressions/deal-after-handover.itf.json).
  // -------------------------------------------------------------------------
  run dealAfterHandoverTest =
    initWithParams(Set(4), Set(4), true, 10, NODES.mapBy(_ => 1), NODES.mapBy(_ => 1))
      .then(postOwnerMsg(1, OpenMode, ProfileT1, RotReshare, 1, 4, Set()))
      .then(honestStepA(1))
      .then(honestStepA(2))
      .then(honestStepA(3))
      .then(postRotate)
      .then(honestReshareDeal(1))
      .then(honestReshareDeal(2))
      .then(honestReady(1))
      .then(honestReady(2))
      .then(honestReady(3))
      .then(all {
        assert(ReshareDoneReached),
        assert(nodes1.get(3).erased == Set(1, 2)),
        keepUnchanged,
      })
      .then(honestReshareDeal(3).fail())
}

// ===========================================================================
// Parameterized Instance: n = 7, f = 2
// Run with: quint run --main=linedealing_n7_f2 linedealing.qnt ...
// ===========================================================================
module linedealing_n7_f2 {
  import linedealing_protocol(
    N = 7,
    F = 2,
    ENFORCE_ONE_PREVOTE = true,
    ENFORCE_RULE4 = true
  ).*
}

// ===========================================================================
// Parameterized Instance: n = 9, f = 2 (n > 3f + 1; quorum q = 6, LOOP item 4b)
// Run with: quint run linedealing.qnt --main=linedealing_n9_f2 ...
// ===========================================================================
module linedealing_n9_f2 {
  import linedealing_protocol(
    N = 9,
    F = 2,
    ENFORCE_ONE_PREVOTE = true,
    ENFORCE_RULE4 = true
  ).*
}

// ===========================================================================
// Deliberately Broken Variant 1: Disables One-PREVOTE-Per-Slot Rule (Rule 1)
// Run with: quint run --main=linedealing_broken_prevote --invariant=NoNonceReuse linedealing.qnt
// ===========================================================================
module linedealing_broken_prevote {
  import linedealing_protocol(
    N = 4,
    F = 1,
    ENFORCE_ONE_PREVOTE = false,
    ENFORCE_RULE4 = true
  ).*
}

// ===========================================================================
// Deliberately Broken Variant 2: Disables Restart Board-Replay Rule (Rule 4)
// Run with: quint run --main=linedealing_broken_rule4 --invariant=NoNonceReuse linedealing.qnt
// ===========================================================================
module linedealing_broken_rule4 {
  import linedealing_protocol(
    N = 4,
    F = 1,
    ENFORCE_ONE_PREVOTE = true,
    ENFORCE_RULE4 = false
  ).*
}
