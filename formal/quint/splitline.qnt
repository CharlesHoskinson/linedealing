// -*- mode: Bluespec; -*-
// Quint model of split-line dealing: the committee state machine of
// design/enhancement/DESIGN.md (DECISIONS 21-50) and the review-3 Quint items
// Q1-Q15 of design/enhancement/review-3/QUINT-ITEMS.md.
//
// It extends formal/quint/linedealing.qnt. It keeps that model's abstractions: a
// totally ordered board whose states are pure functions of the ordered posts, the
// quorum q = (n + f + 2) / 2, a static Byzantine set, the tombstones FINAL, VOID
// and EXPIRED, and disk rollback of a node. The base model stays the model of the
// P0 profile (line dealing inside the envelope); this model covers P1 and P2.
//
// Modeled (DESIGN section in brackets):
// - the envelope state machine with merged votes [§5.1-§5.4]: POSTED, ORDERED,
//   header PRF partials after the QC, OPENED votes of a collecting request,
//   COLLECTING, ADMIT votes carrying the generation-1 anchor, ANCHORED(g),
//   RELEASED, FINAL, VOID (SLOT_TAKEN, STALLED, LAPSED, revoked), EXPIRED;
// - authorization [§5.3, §5.5]: Midnight-first (in force at finality), board-first
//   for stateless P1 charters, its prohibition for P2, revoke with SetHold, Δ_hold;
// - committee nonce slots [§4.1, §4.5]: one Schnorr slot per (generation, input)
//   shared by every variant's ticket; precedence by board order; reservation by q
//   votes; claim at ADMITTED; burn when the request with precedence ends or lapses;
//   slot_anchor [§4.1, O32];
// - ECDSA slots [§3.6 step 7, §4.4]: per (variant, input), bound to one leaf set,
//   inside the record's slot root;
// - generations g <= G_max = 2, each selecting a higher variant;
// - the peer witness [§7.7]: open (provisional until QC), release and slot
//   entries, w acks from distinct peers, rollback or clone colluders, broken
//   enclaves; readmission returning a node's own entries [§7.3];
// - checkpoints and the cold start through E [§7.11];
// - collection, STALLED as a board predicate, and reissue [§5.9];
// - the envelope id over auth_ref and the per-epoch dd rule [§4.6].
//
// Not modeled: curve arithmetic, PRF and AEAD algebra, proofs (the vectors in
// design/enhancement/vectors/ check that algebra), host-chain reorgs, rotation,
// the combiner messages of DECISIONS 50(1) (Q12), and the root-age bound (Q14 part).
//
// Every invariant carries the DESIGN §9 claim id it checks and the Q item.

module splitline_types {
  type Profile = P1 | P2
  type Suite = Schnorr | Ecdsa
  type Status = Unposted | Posted | Ordered | Final | Void | Expired | Lost
  type AuthSt = ANone | AIncluded | AFinal | ARevoked
  type SlotSt = Free | Named(int) | Reserved(int) | Claimed(int) | Burned

  // Rules of the design. A mutant flips one field.
  type Rules = {
    burnAtEnd: bool,             // §4.1, §4.5 item 4: a slot never returns to the pool
    slotPrecedence: bool,        // §4.1, DECISIONS 44 (false: item 35, first in force)
    checkDistinctSlots: bool,    // §4.5 item 2
    maxGens: int,                // §4.1: G_max = 2
    ecdsaSlotPerVariant: bool,   // §4.4
    boardFirstP2: bool,          // §5.3: forbidden (false)
    releaseAtInclusion: bool,    // §5.11: no release at Midnight inclusion (false)
    directCallBF: bool,          // §5.3 item 5: no direct call for a board-first record (false)
    partialBeforeQC: bool,       // §5.2 item 2 (false)
    admitWithoutContrib: bool,   // §5.9 item 5 (false)
    slotAnchor: bool,            // §4.1 option slot_anchor, O32 (false is the default (a) of DECISIONS 42)
    leafSetCheck: bool,          // §3.6 step 7, DECISIONS 43
    coldBurnUnclaimed: bool,     // §7.11 item 2, DECISIONS 46(3)
    ddUnique: bool,              // §4.6, DECISIONS 45
    actorChecksRA: bool,         // §4.2 actor's rules, review A-F6
    slotRootCheck: bool,         // §5.3 item 4, DECISIONS 48
    releasedStaysLocked: bool,   // §5.6 finality, DECISIONS 47
    piBindsAuthRef: bool,        // §4.6, DECISIONS 49
    stallBoardPredicate: bool,   // §5.9 item 6, DECISIONS 50(6)
    holdDelay: int,              // §5.5: Δ_hold Midnight blocks before a P2 generation-1 release
    bfPendingAfterVerify: bool,  // §5.3 board-first item 3, DECISIONS 50(5)
    witnessKeyFull: bool,        // §7.7, DECISIONS 50(4): slot keys carry suite, epoch, address
    openProvisional: bool,       // §7.7, DECISIONS 46(5): an open entry is provisional until its QC
    coldSettleLocked: bool,      // §5.6, §7.11, DECISIONS 53: a request a restart ends settles RELEASED (finding S4)
    ecdsaPrecInForce: bool,      // §4.1 ECDSA precedence, DECISIONS 54, O38: precedence on an ECDSA slot only from an
                                 // authorization in force whose source opens the slot (finding G5)
    admissionInForce: bool,      // §4.7, §5.4, DECISIONS 68: precedence and the authorization match are
                                 // admission checks, run once the authorization is in force (finding PG1)
  }

  pure val DESIGN_RULES: Rules = {
    burnAtEnd: true, slotPrecedence: true, checkDistinctSlots: true, maxGens: 2,
    ecdsaSlotPerVariant: true, boardFirstP2: false, releaseAtInclusion: false,
    directCallBF: false, partialBeforeQC: false, admitWithoutContrib: false,
    slotAnchor: false, leafSetCheck: true, coldBurnUnclaimed: true, ddUnique: true,
    actorChecksRA: true, slotRootCheck: true, releasedStaysLocked: true,
    piBindsAuthRef: true, stallBoardPredicate: true, holdDelay: 2,
    bfPendingAfterVerify: true, witnessKeyFull: true, openProvisional: true,
    coldSettleLocked: true, ecdsaPrecInForce: true, admissionInForce: true,
  }

  type Charter = { profile: Profile, bf: bool }

  type Header = {
    rec: int,            // asset record
    suite: Suite,
    collecting: bool,    // an actor slot table entry is not embedded
    ls: int,             // leaf set of the signing set (ECDSA slot binding)
    sch: int -> int,     // Schnorr: generation -> committee slot (one input)
    ec: int -> int,      // ECDSA: variant -> slot (one input)
    dd: int,             // digest of the outer dealing; honest initiators use a fresh one
    raOk: bool,          // every ticket's R_A matches the actors' own computation
  }

  type Req = {
    st: Status,
    reason: str,
    hdr: Header,
    order: int,              // board position of the envelope; 0 before ordering
    qcPos: int,              // committed position used by the open witness entry
    hdrPartials: Set[int],
    openedVotes: Set[int],
    admitVotes: Set[int],
    reserveDone: bool,
    reserved: bool,
    admitted: bool,
    contributed: bool,       // the actors posted their frames
    contribSeen: Set[int],   // honest nodes that opened the frames
    expc: bool,              // the board passed exp_c
    auth: AuthSt,
    authAt: int,             // Midnight height of authorization finality
    revokeAt: int,           // Midnight height of revoke finality; -1 none
    bfInForce: bool,
    bfTried: bool,
    nfv: int,
    everInForce: bool,
    copyOrdered: bool,
    anchors: int -> int,
  }

  type NodeLocal = {
    booted: bool,
    slotTk: int -> int,      // slot -> ticket this node signed; 0 none
    relGen: int -> int,      // rid*10+g -> variant released; 0 none
    opened: int -> int,      // rid -> committed position at which this node opened; 0 none
  }

  // kind 0 open (key rid, digest position), 1 release (key rid*10+g, digest variant),
  // 2 slot (key = witness key of the slot, digest ticket)
  type WitEntry = { owner: int, kind: int, key: int, digest: int, slot: int, prov: bool }

  type SigPartial = { node: int, slot: int, tk: int }

  type RelEv = {
    node: int, rid: int, g: int, v: int, slot: int, midH: int,
    inForce: bool, authFinal: bool, admitted: bool, slotMine: bool, held: bool, revokedSeen: bool,
    contributed: bool, profile: Profile, suite: Suite,
  }

  type Checkpoint = {
    slotsAt: int -> SlotSt,
    pendingSlots: Set[int],
    known: Set[int],
    statusAt: int -> Status,
  }

  type Midnight = {
    h: int,
    recNf: int -> int,
    recSpent: int -> bool,
    recLocked: int -> bool,
    hold: int -> bool,
    nfUsed: Set[(int, int)],
    bfPending: Set[(int, int)],
    bfPendingInvalid: Set[(int, int)],
    slotAnchors: int -> int,
  }

  type St = {
    charters: int -> Charter,
    reqs: int -> Req,
    seq: int,
    slots: int -> SlotSt,
    slotOwners: int -> Set[int],
    nodes: int -> NodeLocal,
    wit: int -> Set[WitEntry],
    sigPartials: Set[SigPartial],
    prfPartials: Set[(int, int)],     // (node, label dd*100+v*10+g)
    relEvents: Set[RelEv],
    hdrOrdered: Set[bool],            // for each header partial: was the envelope ordered
    memberAns: Set[(int, int)],       // ECDSA (slot, leaf set) answers of honest group members
    ecBurns: Set[(int, int)],         // (ECDSA slot, request whose end burned it)
    mid: Midnight,
    cp: Checkpoint,
    rollbacks: int,
    readmits: int,
    coldStarts: int,
    lastAction: str,
  }
}

module splitline_protocol {
  import splitline_types.*

  const N: int
  const F: int
  const NBYZ: int    // Byzantine nodes (non-TEE) or broken enclaves (TEE): sign, vote and ack anything
  const NCOLL: int   // honest-code nodes whose operators roll back or clone them
  const TEE: bool    // TEE mode: the witness of §7.7 gates every output
  const WACK: int    // witness acks (design: N - 1 - F)
  const RULES: Rules

  pure val Q: int = (N + F + 2) / 2
  pure val T: int = N - F
  pure val GMAX: int = 2
  pure val NODES: Set[int] = 1.to(N)
  pure val BYZ: Set[int] = NODES.filter(i => i > N - NBYZ)
  pure val COLL: Set[int] = NODES.filter(i => i <= NCOLL)
  pure val HONEST: Set[int] = NODES.exclude(BYZ)
  pure val RIDS: Set[int] = Set(1, 2, 3)  // rid 3 is the reissue of rid 1 (§5.9 item 7)
  pure val RECS: Set[int] = Set(1, 2)     // two coins of one owner
  pure val SCH_SLOTS: Set[int] = Set(1, 2, 3)
  pure val EC_SLOTS: Set[int] = Set(11, 12, 13, 14, 15, 16)
  pure val ALL_SLOTS: Set[int] = SCH_SLOTS.union(EC_SLOTS)
  pure val GENS: Set[int] = 1.to(3)
  pure val MAXH: int = 6                  // Midnight height bound
  pure def kOf(su: Suite): int = if (su == Schnorr) 3 else 2
  // ECDSA slot records: slot root of each record (DECISIONS 48) and leaf set (DECISIONS 43)
  pure def slotRoot(rec: int): Set[int] = if (rec == 1) Set(11, 12, 13, 14) else Set(15, 16)
  pure def leafOf(l: int): int = if (Set(13, 14).contains(l)) 2 else 1
  // §5.3 item 4: the source of an authorization opens the slots of one root of its record.
  // Leaf set 1 stands for the owner's root slr_own, leaf set 2 for the guardian root slr_G.
  pure val REL_KEYS: Set[int] = tuples(RIDS, GENS).map(((r, g)) => r * 10 + g)
  pure val ACK_SETS: int -> Set[Set[int]] =
    NODES.mapBy(i => NODES.exclude(Set(i)).powerset().filter(x => x.size() == WACK))

  // Corrupt nodes certify two board histories when they sit in two quorums.
  pure val forked: bool = NBYZ >= 2 * Q - N

  // ---------------------------------------------------------------- pure helpers
  pure def isSch(l: int): bool = SCH_SLOTS.contains(l)
  pure def witKey(l: int): int = if (RULES.witnessKeyFull) l else l % 10
  pure def schSlotOf(h: Header, g: int): int = h.sch.get(if (g > GMAX) GMAX else g)
  pure def slotOf(h: Header, g: int, v: int): int = if (h.suite == Schnorr) schSlotOf(h, g) else h.ec.get(v)
  pure def ticketOf(h: Header, r: int, g: int, v: int): int =
    if (h.suite == Schnorr) r * 100 + v * 10 + g else r * 100 + v * 10
  pure def labelOf(h: Header, v: int, g: int): int = h.dd * 100 + v * 10 + g
  pure def namedSlots(h: Header): Set[int] =
    if (h.suite == Schnorr) 1.to(GMAX).map(g => h.sch.get(g)) else 1.to(kOf(Ecdsa)).map(v => h.ec.get(v))
  pure def headerDistinct(h: Header): bool =
    if (h.suite == Schnorr) h.sch.get(1) != h.sch.get(2) else namedSlots(h).size() == kOf(Ecdsa)
  pure def validVariant(su: Suite, g: int, prev: int, v: int): bool = v > prev and v <= kOf(su) and g <= v

  pure def holder(x: SlotSt): int =
    match x { | Free => 0 | Named(r) => r | Reserved(r) => r | Claimed(r) => r | Burned => -1 }
  pure def slotIsMine(x: SlotSt, r: int): bool = holder(x) == r
  pure def slotUsable(x: SlotSt, r: int): bool = holder(x) == r or holder(x) == 0
  // §4.1: a request reserves only slots it has precedence on. Under DECISIONS 54 an ECDSA
  // slot has a precedence holder only once an authorization in force names it.
  pure def resvOk(x: SlotSt, r: int, l: int): bool =
    if (not(isSch(l)) and RULES.ecdsaPrecInForce and RULES.slotPrecedence) slotIsMine(x, r) else slotUsable(x, r)
  pure def isTomb(x: Status): bool = Set(Final, Void, Expired, Lost).contains(x)
  pure def srcOpens(h: Header, l: int): bool = slotRoot(h.rec).contains(l) and leafOf(l) == h.ls
  // The same test as each honest node makes it: the slot-root and leaf-set checks are
  // rules of their own (§4.7, §5.3 item 4), so their mutants drop that half.
  pure def srcOpensChk(h: Header, l: int): bool =
    (not(RULES.slotRootCheck) or slotRoot(h.rec).contains(l)) and (not(RULES.leafSetCheck) or leafOf(l) == h.ls)
  // §3.8, §5.3, §5.8: a P1 record has no escrow and no seizure source, so Midnight accepts
  // no authorization on the guardian leaf set (ls 2) of a P1 record.
  pure def srcExists(ch: int -> Charter, h: Header): bool =
    h.suite == Schnorr or h.ls == 1 or ch.get(h.rec).profile == P2

  pure def emptyNode: NodeLocal = {
    booted: true, slotTk: ALL_SLOTS.mapBy(_ => 0), relGen: REL_KEYS.mapBy(_ => 0), opened: RIDS.mapBy(_ => 0),
  }

  pure def emptyReq(h: Header): Req = {
    st: Unposted, reason: "", hdr: h, order: 0, qcPos: 0, hdrPartials: Set(), openedVotes: Set(),
    admitVotes: Set(), reserveDone: false, reserved: false, admitted: false, contributed: false,
    contribSeen: Set(), expc: false, auth: ANone, authAt: -1, revokeAt: -1, bfInForce: false,
    bfTried: false, nfv: -1, everInForce: false, copyOrdered: false, anchors: GENS.mapBy(_ => 0),
  }

  var s: St

  // ---------------------------------------------------------------- derived
  pure def inForce(rq: Req): bool = or {
    rq.auth == AFinal,
    RULES.releaseAtInclusion and rq.auth == AIncluded,
    rq.bfInForce and rq.auth != ARevoked,
  }

  pure def headerOpen(rq: Req): bool = rq.hdrPartials.size() + NBYZ >= T

  // §4.7 items 2, 3 and §5.3 item 4, as each honest node checks them.
  pure def honestHeaderOk(st: St, r: int): bool = {
    val h = st.reqs.get(r).hdr
    and {
      not(RULES.checkDistinctSlots) or headerDistinct(h),
      namedSlots(h).forall(l => resvOk(st.slots.get(l), r, l)),
      not(RULES.slotRootCheck) or h.suite == Schnorr or namedSlots(h).forall(l => slotRoot(h.rec).contains(l)),
    }
  }

  pure def setSlots(m: int -> SlotSt, ls: Set[int], v: SlotSt): int -> SlotSt = ls.fold(m, (acc, l) => acc.set(l, v))
  pure def addOwner(own: int -> Set[int], ls: Set[int], r: int): int -> Set[int] =
    ls.fold(own, (m, l) => m.set(l, m.get(l).union(Set(r))))

  pure def interpOpened(st: St, r: int): St = {
    val rq = st.reqs.get(r)
    val ls = namedSlots(rq.hdr)
    if (rq.reserveDone or rq.openedVotes.size() < Q) st
    else if (ls.forall(l => resvOk(st.slots.get(l), r, l)))
      { ...st, reqs: st.reqs.set(r, { ...rq, reserveDone: true, reserved: true }),
        slots: setSlots(st.slots, ls, Reserved(r)), slotOwners: addOwner(st.slotOwners, ls, r) }
    else { ...st, reqs: st.reqs.set(r, { ...rq, reserveDone: true }) }
  }

  pure def interpAdmit(st: St, r: int, j1: int): St = {
    val rq = st.reqs.get(r)
    val ls = namedSlots(rq.hdr)
    if (rq.admitted or rq.admitVotes.size() < Q or not(ls.forall(l => resvOk(st.slots.get(l), r, l)))) st
    else { ...st, reqs: st.reqs.set(r, { ...rq, admitted: true, anchors: rq.anchors.set(1, j1) }),
           slots: setSlots(st.slots, ls, Claimed(r)), slotOwners: addOwner(st.slotOwners, ls, r) }
  }

  pure def anyRelease(st: St, r: int): bool = st.relEvents.exists(e => e.rid == r)

  // End of a request: the slots it held are burned; settle on Midnight (§5.6 finality).
  pure def endReq(st: St, r: int, newSt: Status, why: str): St = {
    val rq = st.reqs.get(r)
    val mine = namedSlots(rq.hdr).filter(l => slotIsMine(st.slots.get(l), r))
    // §4.1 (DECISIONS 54): an ECDSA slot that the request only had precedence on holds no
    // partial; it returns to free. Committee slots and reserved ECDSA slots burn.
    val prec = mine.filter(l => not(isSch(l)) and RULES.ecdsaPrecInForce and st.slots.get(l) == Named(r))
    val ls = mine.exclude(prec)
    val rec = rq.hdr.rec
    val m = st.mid
    val nfNext = if (rq.nfv >= 0 and rq.nfv == m.recNf.get(rec)) m.recNf.set(rec, rq.nfv + 1) else m.recNf
    val m2 =
      if (newSt == Final) { ...m, recSpent: m.recSpent.set(rec, true), recLocked: m.recLocked.set(rec, false) }
      // §5.6 RELEASED: the successor is the record locked to the pinned input; a later
      // authorization spends that input under the successor's nullifier (§5.3 item 1).
      else if (anyRelease(st, r) and RULES.releasedStaysLocked) { ...m, recLocked: m.recLocked.set(rec, true), recNf: nfNext }
      else { ...m, recNf: nfNext }
    normalize({ ...st, reqs: st.reqs.set(r, { ...rq, st: newSt, reason: why }),
      slots: setSlots(setSlots(st.slots, ls, if (RULES.burnAtEnd) Burned else Free), prec, Free), mid: m2,
      ecBurns: if (RULES.burnAtEnd) st.ecBurns.union(ls.filter(l => not(isSch(l))).map(l => (l, r))) else st.ecBurns })
  }

  // §4.1 ECDSA precedence (DECISIONS 54): a free ECDSA slot goes to the earliest ordered,
  // live request that names it, whose authorization is in force and whose source opens it.
  pure def ecEligible(st: St, r: int, l: int): bool = {
    val rq = st.reqs.get(r)
    and { rq.st == Ordered, inForce(rq), namedSlots(rq.hdr).contains(l), srcOpensChk(rq.hdr, l),
          srcExists(st.charters, rq.hdr) }
  }
  // Precedence holds only while the authorization is in force: a Named slot whose holder
  // is no longer eligible returns to free before the slots are assigned again.
  pure def assignEcPrec(st: St): St =
    if (not(RULES.ecdsaPrecInForce) or not(RULES.slotPrecedence)) st
    else { ...st, slots: EC_SLOTS.fold(st.slots.keys().mapBy(l => match st.slots.get(l) {
        | Named(r) => if (not(isSch(l)) and not(ecEligible(st, r, l))) Free else Named(r)
        | _ => st.slots.get(l) }), (m, l) => {
      val cand = RIDS.filter(r => ecEligible(st, r, l))
      if (m.get(l) != Free or cand.size() == 0) m
      else {
        val first = cand.fold(0, (b, r) => if (b == 0 or st.reqs.get(r).order < st.reqs.get(b).order) r else b)
        m.set(l, Named(first)) } }) }

  pure def normalize(st: St): St = assignEcPrec(
    { ...st, reqs: st.reqs.keys().mapBy(r => {
        val rq = st.reqs.get(r)
        { ...rq, everInForce: rq.everInForce or inForce(rq) } }) })

  pure def honestPartialCount(st: St, l: int, tk: int): int =
    st.sigPartials.filter(p => p.slot == l and p.tk == tk).size()
  pure def signedTickets(st: St, l: int): Set[int] =
    st.sigPartials.filter(p => p.slot == l).map(p => p.tk).filter(tk => honestPartialCount(st, l, tk) + NBYZ >= T)
  pure def reqSigned(st: St, r: int): bool =
    namedSlots(st.reqs.get(r).hdr).exists(l => signedTickets(st, l).exists(tk => tk / 100 == r))

  // A peer acks a witness entry if it holds no other digest for the owner and key;
  // a provisional open entry is replaced (§7.7, DECISIONS 46(5)). Broken enclaves ack anything.
  pure def canAck(st: St, p: int, e: WitEntry): bool =
    BYZ.contains(p) or st.wit.get(p).forall(x =>
      not(x.owner == e.owner and x.kind == e.kind and x.key == e.key) or x.digest == e.digest
      or (x.kind == 0 and x.prov and RULES.openProvisional))
  pure def addEntries(st: St, ps: Set[int], es: Set[WitEntry]): int -> Set[WitEntry] =
    ps.exclude(BYZ).fold(st.wit, (m, p) => {
      val keep = m.get(p).filter(x => not(es.exists(e => e.owner == x.owner and e.kind == x.kind and e.key == x.key)))
      m.set(p, keep.union(es)) })

  // ---------------------------------------------------------------- init
  pure val schHeaders: Set[int -> int] = tuples(SCH_SLOTS, SCH_SLOTS).map(((a, b)) => Map(1 -> a, 2 -> b))
  pure val ecHeadersAll: Set[int -> int] = tuples(EC_SLOTS, EC_SLOTS).map(((a, b)) => Map(1 -> a, 2 -> b))
  pure val ecHeaders: Set[int -> int] =
    if (RULES.ecdsaSlotPerVariant) ecHeadersAll.filter(m => m.get(1) != m.get(2))
    else ecHeadersAll.filter(m => m.get(1) == m.get(2))

  pure def mkHeader(rec: int, su: Suite, col: bool, ls: int, sch: int -> int, ec: int -> int, dd: int, raOk: bool): Header =
    { rec: rec, suite: su, collecting: col, ls: ls, sch: sch, ec: ec, dd: dd, raOk: raOk }

  pure def initState(hdrs: int -> Header, chs: int -> Charter): St = {
    charters: chs,
    reqs: RIDS.mapBy(r => emptyReq(hdrs.get(r))),
    seq: 0,
    slots: ALL_SLOTS.mapBy(_ => Free),
    slotOwners: ALL_SLOTS.mapBy(_ => Set()),
    nodes: NODES.mapBy(_ => emptyNode),
    wit: NODES.mapBy(_ => Set()),
    sigPartials: Set(), prfPartials: Set(), relEvents: Set(), hdrOrdered: Set(), memberAns: Set(), ecBurns: Set(),
    mid: { h: 0, recNf: RECS.mapBy(_ => 0), recSpent: RECS.mapBy(_ => false), recLocked: RECS.mapBy(_ => false),
           hold: RECS.mapBy(_ => false), nfUsed: Set(), bfPending: Set(), bfPendingInvalid: Set(),
           slotAnchors: ALL_SLOTS.mapBy(_ => 0) },
    cp: { slotsAt: ALL_SLOTS.mapBy(_ => Free), pendingSlots: Set(), known: Set(), statusAt: RIDS.mapBy(_ => Unposted) },
    rollbacks: 0, readmits: 0, coldStarts: 0,
    lastAction: "init",
  }

  action initWith(hdrs: int -> Header, chs: int -> Charter): bool = all { s' = initState(hdrs, chs) }

  pure val legalCharters: Set[Charter] =
    tuples(Set(P1, P2), Set(true, false)).map(((p, b)) => { profile: p, bf: b })
      .filter(c => not(c.bf) or c.profile == P1 or RULES.boardFirstP2)

  action init: bool = {
    nondet su1 = Set(Schnorr, Ecdsa).oneOf()
    nondet su2 = Set(Schnorr, Ecdsa).oneOf()
    nondet rec2 = RECS.oneOf()
    nondet col = tuples(Set(true, false), Set(true, false), Set(true, false)).oneOf()
    nondet lss = tuples(Set(1, 2), Set(1, 2), Set(1, 2)).oneOf()
    nondet sch1 = schHeaders.oneOf()
    nondet sch2 = schHeaders.oneOf()
    nondet sch3 = schHeaders.oneOf()
    nondet ec1 = ecHeaders.oneOf()
    nondet ec2 = ecHeaders.oneOf()
    nondet ec3 = ecHeaders.oneOf()
    nondet dd2 = Set(1, 2).oneOf()
    nondet ra2 = Set(true, false).oneOf()
    nondet c1 = legalCharters.oneOf()
    nondet c2 = legalCharters.oneOf()
    initWith(
      Map(1 -> mkHeader(1, su1, col._1, lss._1, sch1, ec1, 1, true),
          2 -> mkHeader(rec2, su2, col._2, lss._2, sch2, ec2, dd2, ra2),
          3 -> mkHeader(1, su1, col._3, lss._3, sch3, ec3, 3, true)),
      Map(1 -> c1, 2 -> c2))
  }

  // ---------------------------------------------------------------- actions
  action doPost(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.st == Unposted,
      r != 3 or Set(Void, Expired).contains(s.reqs.get(1).st),
      s' = { ...s, reqs: s.reqs.set(r, { ...rq, st: Posted }), lastAction: "post" },
    }
  }

  // §4.6, §4.7: the board orders an envelope whose public checks pass. A repeated dd is
  // refused (DECISIONS 45). Precedence on every free named slot goes to it (DECISIONS 44).
  action doOrder(r: int, pos: int): bool = {
    val rq = s.reqs.get(r)
    val ddTaken = RIDS.exists(x => x != r and s.reqs.get(x).order > 0 and s.reqs.get(x).hdr.dd == rq.hdr.dd)
    // ECDSA slots take precedence from the authorization (assignEcPrec), not from the order.
    val ls = namedSlots(rq.hdr).filter(l => s.slots.get(l) == Free and (isSch(l) or not(RULES.ecdsaPrecInForce)))
    all {
      rq.st == Posted, not(rq.copyOrdered),
      not(RULES.ddUnique) or not(ddTaken),
      s' = normalize({ ...s,
        reqs: s.reqs.set(r, { ...rq, st: Ordered, order: s.seq + 1, qcPos: pos }),
        seq: s.seq + 1,
        slots: if (RULES.slotPrecedence) setSlots(s.slots, ls, Named(r)) else s.slots,
        lastAction: "order" }),
    }
  }

  // Q10: an observer rewrites auth_ref of a posted envelope and races the copy. With
  // eid = H(hd ‖ auth_ref) as the context of π, the copy fails π and is never ordered.
  action doCopyOrder(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      not(RULES.piBindsAuthRef), rq.st == Posted, not(rq.copyOrdered),
      s' = { ...s, reqs: s.reqs.set(r, { ...rq, copyOrdered: true }), lastAction: "copyOrder" },
    }
  }

  action doAuthorize(r: int): bool = {
    val rq = s.reqs.get(r)
    val rec = rq.hdr.rec
    val nf = (rec, s.mid.recNf.get(rec))
    all {
      Set(Posted, Ordered).contains(rq.st), rq.auth == ANone, not(rq.bfInForce),
      not(s.charters.get(rec).bf) or RULES.directCallBF,
      not(s.mid.recSpent.get(rec)), not(s.mid.nfUsed.contains(nf)), not(s.mid.hold.get(rec)),
      srcExists(s.charters, rq.hdr),
      s' = normalize({ ...s,
        reqs: s.reqs.set(r, { ...rq, auth: AIncluded, nfv: nf._2 }),
        mid: { ...s.mid, nfUsed: s.mid.nfUsed.union(Set(nf)) },
        lastAction: "authorize" }),
    }
  }

  action doAuthFinal(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.auth == AIncluded,
      s' = normalize({ ...s, reqs: s.reqs.set(r, { ...rq, auth: AFinal, authAt: s.mid.h }), lastAction: "authFinal" }),
    }
  }

  action doMidTick: bool = all {
    s.mid.h < MAXH,
    s' = { ...s, mid: { ...s.mid, h: s.mid.h + 1 }, lastAction: "midTick" },
  }

  // §5.3 board-first items 1-4.
  action doBoardFirstCall(r: int): bool = {
    val rq = s.reqs.get(r)
    val rec = rq.hdr.rec
    val nf = (rec, s.mid.recNf.get(rec))
    val ok = not(s.mid.bfPending.contains(nf)) and not(s.mid.bfPendingInvalid.contains(nf))
             and not(s.mid.nfUsed.contains(nf)) and not(s.mid.recSpent.get(rec)) and not(s.mid.hold.get(rec))
             and srcExists(s.charters, rq.hdr)
    all {
      s.charters.get(rec).bf, Set(Posted, Ordered).contains(rq.st), not(rq.bfTried), rq.auth == ANone,
      s' = normalize({ ...s,
        reqs: s.reqs.set(r, { ...rq, bfTried: true, bfInForce: ok, nfv: if (ok) nf._2 else rq.nfv,
                              authAt: if (ok) s.mid.h else rq.authAt }),
        mid: if (ok) { ...s.mid, bfPending: s.mid.bfPending.union(Set(nf)) } else s.mid,
        lastAction: "boardFirstCall" }),
    }
  }

  // Q14: a copy of a board-first call's nullifier under an invalid proof. It enters the
  // pending set only in the mutant that records nf before the proof verifies.
  action doBoardFirstInvalidCopy(rec: int): bool = {
    val nf = (rec, s.mid.recNf.get(rec))
    all {
      s.charters.get(rec).bf, not(RULES.bfPendingAfterVerify),
      not(s.mid.bfPending.contains(nf)), not(s.mid.bfPendingInvalid.contains(nf)),
      s' = { ...s, mid: { ...s.mid, bfPendingInvalid: s.mid.bfPendingInvalid.union(Set(nf)) },
             lastAction: "bfInvalidCopy" },
    }
  }

  action doRelay(r: int): bool = {
    val rq = s.reqs.get(r)
    val nf = (rq.hdr.rec, rq.nfv)
    all {
      rq.bfInForce, rq.auth == ANone,
      s' = normalize({ ...s,
        reqs: s.reqs.set(r, { ...rq, auth: if (s.mid.nfUsed.contains(nf)) ANone else AFinal }),
        mid: { ...s.mid, nfUsed: s.mid.nfUsed.union(Set(nf)) },
        lastAction: "relay" }),
    }
  }

  // §5.5: revoke with SetHold, final at the current Midnight height.
  action doHold(rec: int): bool = all {
    s.charters.get(rec).profile == P2, not(s.mid.hold.get(rec)),
    s' = normalize({ ...s,
      reqs: s.reqs.keys().mapBy(r => {
        val rq = s.reqs.get(r)
        if (rq.hdr.rec == rec and Set(AIncluded, AFinal).contains(rq.auth)) { ...rq, auth: ARevoked, revokeAt: s.mid.h } else rq }),
      mid: { ...s.mid, hold: s.mid.hold.set(rec, true) },
      lastAction: "hold" }),
  }

  // Q5: a node votes for a proposal that orders r at position pos; peers record a
  // provisional open entry.
  action doProposalVote(i: int, r: int, pos: int): bool = {
    val e = { owner: i, kind: 0, key: r, digest: pos, slot: 0, prov: true }
    all {
      TEE, HONEST.contains(i), s.reqs.get(r).st == Posted,
      NODES.exclude(Set(i)).exclude(BYZ).forall(p => canAck(s, p, e)),
      s' = { ...s, wit: addEntries(s, NODES.exclude(Set(i)), Set(e)), lastAction: "proposalVote" },
    }
  }

  // §5.2 item 2: header PRF partial after the QC; in TEE mode after the open witness.
  action doHeaderPartial(i: int, r: int, ackers: Set[int]): bool = {
    val rq = s.reqs.get(r)
    val nd = s.nodes.get(i)
    val e = { owner: i, kind: 0, key: r, digest: rq.qcPos, slot: 0, prov: false }
    all {
      HONEST.contains(i), nd.booted,
      rq.st == Ordered or (RULES.partialBeforeQC and rq.st == Posted),
      not(rq.hdrPartials.contains(i)),
      not(TEE) or rq.st != Ordered or all { ackers.size() == WACK, not(ackers.contains(i)), ackers.forall(p => canAck(s, p, e)) },
      s' = { ...s,
        reqs: s.reqs.set(r, { ...rq, hdrPartials: rq.hdrPartials.union(Set(i)) }),
        nodes: s.nodes.set(i, { ...nd, opened: nd.opened.set(r, rq.qcPos) }),
        wit: if (TEE and rq.st == Ordered) addEntries(s, ackers, Set(e)) else s.wit,
        hdrOrdered: s.hdrOrdered.union(Set(rq.st == Ordered)),
        lastAction: "headerPartial" },
    }
  }

  // §4.7, §5.4 item 2 (DECISIONS 68): SLOT_TAKEN when a named slot is under the precedence
  // of another request. It is an admission check, so it runs once the authorization of the
  // request is in force. The mutant admissionInForce = false runs it at opening.
  action doVoidSlotTaken(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.st == Ordered, headerOpen(rq), not(rq.admitted),
      not(RULES.admissionInForce) or inForce(rq),
      namedSlots(rq.hdr).exists(l => not(slotUsable(s.slots.get(l), r))),
      s' = { ...endReq(s, r, Void, "SLOT_TAKEN"), lastAction: "voidSlotTaken" },
    }
  }

  // §4.1: precedence lapses when the authorization is not in force by ordering + Δ_c.
  action doLapse(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      RULES.slotPrecedence, rq.st == Ordered, rq.expc, not(rq.everInForce),
      s' = { ...endReq(s, r, Void, "LAPSED"), lastAction: "lapse" },
    }
  }

  action doVoteOpened(i: int, r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      HONEST.contains(i), s.nodes.get(i).booted,
      rq.hdr.collecting, rq.st == Ordered, headerOpen(rq), inForce(rq), not(rq.expc),
      not(rq.openedVotes.contains(i)), honestHeaderOk(s, r),
      s' = normalize(interpOpened({ ...s,
        reqs: s.reqs.set(r, { ...rq, openedVotes: rq.openedVotes.union(Set(i)) }),
        lastAction: "voteOpened" }, r)),
    }
  }

  // §5.9 items 3-4 and the actor's rules of §4.2 and §3.6 step 7: actors read the
  // request and post their frames. An ECDSA group member answers only on slots bound
  // to the request's leaf set, and once per slot.
  action doContribute(r: int): bool = {
    val rq = s.reqs.get(r)
    val h = rq.hdr
    val ecSl = if (h.suite == Ecdsa) namedSlots(h) else Set()
    all {
      h.collecting, Set(Posted, Ordered).contains(rq.st), not(rq.contributed), not(rq.expc),
      not(RULES.actorChecksRA) or h.raOk,
      not(RULES.leafSetCheck) or ecSl.forall(l => leafOf(l) == h.ls),
      ecSl.forall(l => not(s.memberAns.exists(a => a._1 == l and a._2 == h.ls))),
      s' = { ...s,
        reqs: s.reqs.set(r, { ...rq, contributed: true }),
        memberAns: s.memberAns.union(ecSl.map(l => (l, h.ls))),
        lastAction: "contribute" },
    }
  }

  // A node opens the contribution frames (§4.7 item 6).
  action doSeeContrib(i: int, r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      HONEST.contains(i), rq.contributed, rq.st == Ordered, not(rq.contribSeen.contains(i)),
      s' = { ...s, reqs: s.reqs.set(r, { ...rq, contribSeen: rq.contribSeen.union(Set(i)) }), lastAction: "seeContrib" },
    }
  }

  action doVoteAdmit(i: int, r: int, j1: int): bool = {
    val rq = s.reqs.get(r)
    all {
      HONEST.contains(i), s.nodes.get(i).booted,
      rq.st == Ordered, headerOpen(rq), inForce(rq), not(rq.admitted),
      not(rq.hdr.collecting and rq.expc), not(rq.admitVotes.contains(i)),
      not(rq.hdr.collecting) or (rq.reserved and (rq.contribSeen.contains(i) or RULES.admitWithoutContrib)),
      honestHeaderOk(s, r), validVariant(rq.hdr.suite, 1, 0, j1),
      s' = normalize(interpAdmit({ ...s,
        reqs: s.reqs.set(r, { ...rq, admitVotes: rq.admitVotes.union(Set(i)) }),
        lastAction: "voteAdmit" }, r, j1)),
    }
  }

  action doByzVote(b: int, r: int, opened: bool, j1: int): bool = {
    val rq = s.reqs.get(r)
    all {
      BYZ.contains(b), rq.st == Ordered, validVariant(rq.hdr.suite, 1, 0, j1),
      if (opened) all { rq.hdr.collecting, not(rq.openedVotes.contains(b)) } else not(rq.admitVotes.contains(b)),
      s' = normalize(
        if (opened) interpOpened({ ...s, reqs: s.reqs.set(r, { ...rq, openedVotes: rq.openedVotes.union(Set(b)) }),
                                   lastAction: "byzVoteOpened" }, r)
        else interpAdmit({ ...s, reqs: s.reqs.set(r, { ...rq, admitVotes: rq.admitVotes.union(Set(b)) }),
                           lastAction: "byzVoteAdmit" }, r, j1)),
    }
  }

  // The board passes the ordering height plus Δ_c (exp_c of §5.9, the lapse height of §4.1).
  action doExpC(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.st == Ordered, not(rq.expc), not(rq.admitted),
      s' = { ...s, reqs: s.reqs.set(r, { ...rq, expc: true }), lastAction: "expc" },
    }
  }

  // STALLED: a board predicate (no q ADMIT votes committed by exp_c); the mutant needs
  // f + 1 honest nodes whose own view of the actor slot table is incomplete.
  pure def stallEnabled(st: St, r: int): bool = {
    val rq = st.reqs.get(r)
    rq.hdr.collecting and rq.expc and not(rq.admitted) and rq.st == Ordered and
      (RULES.stallBoardPredicate or HONEST.exclude(rq.contribSeen).size() >= F + 1)
  }
  action doStall(r: int): bool = all {
    stallEnabled(s, r),
    s' = { ...endReq(s, r, Void, "STALLED"), lastAction: "stall" },
  }

  action doAnchorGen(r: int, g: int, j: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.st == Ordered, rq.admitted, g >= 2, g <= RULES.maxGens,
      rq.anchors.get(g - 1) > 0, rq.anchors.get(g) == 0,
      // §5.6: generation g starts when the released variant of generation g - 1 has not
      // confirmed by its deadline, so a partial of generation g - 1 has left.
      s.relEvents.exists(e => e.rid == r and e.g == g - 1),
      validVariant(rq.hdr.suite, g, rq.anchors.get(g - 1), j),
      s' = { ...s, reqs: s.reqs.set(r, { ...rq, anchors: rq.anchors.set(g, j) }), lastAction: "anchorGen" },
    }
  }

  // O32 slot_anchor: Midnight accepts one entry slot -> ticket per slot. On a forked
  // board, any history may post first.
  action doSlotAnchor(r: int, g: int, j: int): bool = {
    val rq = s.reqs.get(r)
    val l = slotOf(rq.hdr, g, j)
    all {
      RULES.slotAnchor, rq.st == Ordered, rq.admitted, rq.anchors.get(g) > 0,
      if (forked) validVariant(rq.hdr.suite, g, 0, j) else j == rq.anchors.get(g),
      s.mid.slotAnchors.get(l) == 0,
      s' = { ...s, mid: { ...s.mid, slotAnchors: s.mid.slotAnchors.set(l, ticketOf(rq.hdr, r, g, j)) },
             lastAction: "slotAnchor" },
    }
  }

  // §5.6 items 2-5, §7.7.
  action doRelease(i: int, r: int, g: int, j: int, ackers: Set[int]): bool = {
    val rq = s.reqs.get(r)
    val h = rq.hdr
    val nd = s.nodes.get(i)
    val l = slotOf(h, g, j)
    val tk = ticketOf(h, r, g, j)
    val rk = r * 10 + g
    val p2 = s.charters.get(h.rec).profile == P2
    val eRel = { owner: i, kind: 1, key: rk, digest: j, slot: 0, prov: false }
    val eSlot = { owner: i, kind: 2, key: witKey(l), digest: tk, slot: l, prov: false }
    all {
      HONEST.contains(i), nd.booted,
      rq.st == Ordered, rq.admitted, inForce(rq),
      g <= RULES.maxGens, rq.anchors.get(g) > 0,
      if (forked) validVariant(h.suite, g, 0, j) else j == rq.anchors.get(g),
      not(h.collecting) or rq.contributed or RULES.admitWithoutContrib,
      not(p2) or g > 1 or s.mid.h >= rq.authAt + RULES.holdDelay,
      not(RULES.slotAnchor) or s.mid.slotAnchors.get(l) == tk,
      Set(0, j).contains(nd.relGen.get(rk)),
      Set(0, tk).contains(nd.slotTk.get(l)),
      not(TEE) or all {
        ackers.size() == WACK, not(ackers.contains(i)),
        ackers.forall(p => canAck(s, p, eRel) and canAck(s, p, eSlot)),
      },
      s' = { ...s,
        nodes: s.nodes.set(i, { ...nd, relGen: nd.relGen.set(rk, j), slotTk: nd.slotTk.set(l, tk) }),
        wit: if (TEE) addEntries(s, ackers, Set(eRel, eSlot)) else s.wit,
        sigPartials: s.sigPartials.union(Set({ node: i, slot: l, tk: tk })),
        prfPartials: s.prfPartials.union(Set((i, labelOf(h, j, g)))),
        relEvents: s.relEvents.union(Set({
          node: i, rid: r, g: g, v: j, slot: l, midH: s.mid.h,
          inForce: inForce(rq), authFinal: rq.auth == AFinal or (rq.bfInForce and rq.auth != ARevoked), admitted: rq.admitted, slotMine: slotIsMine(s.slots.get(l), r),
          held: s.mid.hold.get(h.rec), revokedSeen: rq.auth == ARevoked, contributed: rq.contributed,
          profile: s.charters.get(h.rec).profile, suite: h.suite })),
        lastAction: "release" },
    }
  }

  action doRollback(i: int): bool = all {
    TEE, COLL.contains(i), s.rollbacks < 2,
    s' = { ...s, nodes: s.nodes.set(i, { ...emptyNode, booted: false }), wit: s.wit.set(i, Set()),
           rollbacks: s.rollbacks + 1, lastAction: "rollback" },
  }

  action doReadmit(i: int, ackers: Set[int]): bool = {
    val nd = s.nodes.get(i)
    val es = ackers.exclude(BYZ).fold(Set(), (acc, p) => acc.union(s.wit.get(p).filter(e => e.owner == i)))
    all {
      not(nd.booted), ackers.size() == WACK, not(ackers.contains(i)),
      s' = { ...s,
        nodes: s.nodes.set(i, { ...nd, booted: true,
          relGen: es.filter(e => e.kind == 1).fold(nd.relGen, (m, e) => m.set(e.key, e.digest)),
          slotTk: es.filter(e => e.kind == 2).fold(nd.slotTk, (m, e) => m.set(e.slot, e.digest)) }),
        readmits: s.readmits + 1, lastAction: "readmit" },
    }
  }

  action doFinal(r: int): bool = all {
    s.reqs.get(r).st == Ordered, s.reqs.get(r).admitted, reqSigned(s, r),
    not(s.mid.recSpent.get(s.reqs.get(r).hdr.rec)),
    s' = { ...endReq(s, r, Final, "FINAL"), lastAction: "final" },
  }

  action doVoidRevoked(r: int): bool = {
    val rq = s.reqs.get(r)
    all {
      rq.st == Ordered, rq.auth == ARevoked, not(anyRelease(s, r)),
      s' = { ...endReq(s, r, Void, "REVOKED"), lastAction: "voidRevoked" },
    }
  }

  // exp lies after exp_c; an admitted request expires once Midnight time has passed.
  action doExpire(r: int): bool = all {
    Set(Posted, Ordered).contains(s.reqs.get(r).st),
    s.reqs.get(r).expc or s.mid.h >= 3,
    s' = { ...endReq(s, r, Expired, "EXPIRED"), lastAction: "expire" },
  }

  action doCheckpoint: bool = {
    val pend = RIDS.filter(r => s.reqs.get(r).st == Ordered and s.reqs.get(r).hdr.suite == Ecdsa)
    all {
      s.coldStarts == 0,
      s' = { ...s,
        cp: { slotsAt: s.slots,
              pendingSlots: pend.fold(Set(), (acc, r) => acc.union(namedSlots(s.reqs.get(r).hdr))),
              known: RIDS.filter(r => s.reqs.get(r).order > 0),
              statusAt: RIDS.mapBy(r => s.reqs.get(r).st) },
        lastAction: "checkpoint" },
    }
  }

  // §7.11 item 2 with no verifiable board record of the window: E burns every ECDSA slot
  // unclaimed at the checkpoint and every slot of a request pending at it (DECISIONS
  // 46(3)); the old rule excluded only slots claimed up to the checkpoint.
  pure def ecAfterColdStart(cp: Checkpoint, l: int): SlotSt =
    if (RULES.coldBurnUnclaimed) Burned
    else if (cp.slotsAt.get(l) != Free or cp.pendingSlots.contains(l)) Burned
    else Free

  action doColdStartE: bool = {
    val cp = s.cp
    all {
      s.coldStarts == 0,
      s' = { ...s,
        reqs: RIDS.mapBy(r => {
          val rq = s.reqs.get(r)
          if (rq.order == 0) rq
          else if (cp.known.contains(r) and isTomb(cp.statusAt.get(r))) { ...rq, st: cp.statusAt.get(r) }
          else { ...rq, st: Lost, reason: "COLD" } }),
        slots: ALL_SLOTS.mapBy(l => if (isSch(l)) Burned else ecAfterColdStart(cp, l)),
        nodes: NODES.mapBy(_ => emptyNode),
        wit: NODES.mapBy(_ => Set()),
        coldStarts: 1,
        lastAction: "coldStartE" },
    }
  }

  // After a cold start the committee settles every authorization whose request it lost:
  // pending at the checkpoint (§7.11 "end VOID") or ordered after it. Without a board
  // record nobody can tell whether a partial left. The old rule settled it VOID when the
  // pinned input was unspent (mutant m_cold_void); DECISIONS 53 settles it RELEASED.
  action doSettleLost(r: int): bool = {
    val rq = s.reqs.get(r)
    val rec = rq.hdr.rec
    all {
      rq.st == Lost, rq.reason == "COLD", rq.nfv >= 0,
      s' = { ...s,
        // §5.6: FINAL when the host chain shows the request's own transaction (the record is
        // spent and the request was signed), RELEASED otherwise.
        reqs: s.reqs.set(r, if (s.mid.recSpent.get(rec) and reqSigned(s, r)) { ...rq, st: Final, reason: "COLD_SETTLED_FINAL" }
                            else { ...rq, st: Void, reason: "COLD_SETTLED" }),
        mid: if (s.mid.recSpent.get(rec)) s.mid
             else if (RULES.coldSettleLocked) { ...s.mid, recLocked: s.mid.recLocked.set(rec, true),
                    recNf: if (rq.nfv == s.mid.recNf.get(rec)) s.mid.recNf.set(rec, rq.nfv + 1) else s.mid.recNf }
             else if (rq.nfv == s.mid.recNf.get(rec)) { ...s.mid, recNf: s.mid.recNf.set(rec, rq.nfv + 1) }
             else s.mid,
        lastAction: "settleLost" },
    }
  }

  // ---------------------------------------------------------------- armed starts
  // Exploration aid as initArmed of linedealing.qnt: rid 1 starts ADMITTED. armReq applies
  // the effects of doPost, doOrder, doAuthorize, doAuthFinal, doHeaderPartial by every
  // honest node and doVoteAdmit by q nodes; the scripted runs of splitline_test.qnt reach
  // ADMITTED by those actions.
  pure def armReq(st: St, r: int, j1: int): St = {
    val rq = st.reqs.get(r)
    val rec = rq.hdr.rec
    val nf = (rec, st.mid.recNf.get(rec))
    val voters = NODES.filter(i => i <= Q)
    val st1 = { ...st,
      reqs: st.reqs.set(r, { ...rq, st: Ordered, order: st.seq + 1, qcPos: 1, auth: AFinal, authAt: 0, nfv: nf._2,
                             everInForce: true, hdrPartials: HONEST, admitVotes: voters }),
      seq: st.seq + 1,
      slots: setSlots(st.slots, namedSlots(rq.hdr), Named(r)),
      mid: { ...st.mid, nfUsed: st.mid.nfUsed.union(Set(nf)) } }
    interpAdmit(st1, r, j1)
  }

  action initArmedWith(su: Suite): bool = {
    nondet sch1 = schHeaders.filter(m => m.get(1) != m.get(2)).oneOf()
    nondet ec1 = ecHeaders.filter(m => namedSlotsOk(m)).oneOf()
    nondet su2 = Set(Schnorr, Ecdsa).oneOf()
    nondet rec2 = RECS.oneOf()
    nondet col = tuples(Set(true, false), Set(true, false)).oneOf()
    nondet ls2 = Set(1, 2).oneOf()
    nondet sch2 = schHeaders.oneOf()
    nondet sch3 = schHeaders.oneOf()
    nondet ec2 = ecHeaders.oneOf()
    nondet ec3 = ecHeaders.oneOf()
    nondet c2 = legalCharters.oneOf()
    nondet j1 = Set(1, 2).oneOf()
    val hdrs = Map(1 -> mkHeader(1, su, false, 1, sch1, ec1, 1, true),
                   2 -> mkHeader(rec2, su2, col._1, ls2, sch2, ec2, 2, true),
                   3 -> mkHeader(1, su, col._2, 1, sch3, ec3, 3, true))
    all { s' = { ...armReq(initState(hdrs, Map(1 -> { profile: P1, bf: false }, 2 -> c2)), 1, j1), lastAction: "initArmed" } }
  }
  pure def namedSlotsOk(m: int -> int): bool = slotRoot(1).contains(m.get(1)) and slotRoot(1).contains(m.get(2))
    and leafOf(m.get(1)) == 1 and leafOf(m.get(2)) == 1

  action initArmedSchnorr: bool = initArmedWith(Schnorr)
  action initArmedEcdsa: bool = initArmedWith(Ecdsa)

  // ---------------------------------------------------------------- steps
  action stepProgress: bool = {
    nondet r = RIDS.oneOf()
    nondet i = HONEST.oneOf()
    nondet g = GENS.oneOf()
    nondet j = Set(1, 2, 3).oneOf()
    nondet pos = Set(1, 2).oneOf()
    nondet ackers = ACK_SETS.get(i).oneOf()
    any {
      doPost(r), doOrder(r, pos), doAuthorize(r), doAuthFinal(r), doBoardFirstCall(r), doRelay(r), doMidTick,
      doHeaderPartial(i, r, ackers), doHeaderPartial(i, r, ackers),
      doVoteOpened(i, r), doContribute(r), doSeeContrib(i, r),
      doVoteAdmit(i, r, j), doVoteAdmit(i, r, j),
      doAnchorGen(r, g, j), doSlotAnchor(r, g, j),
      doRelease(i, r, g, j, ackers), doRelease(i, r, g, j, ackers), doRelease(i, r, g, j, ackers),
      doFinal(r),
    }
  }

  action stepFaults: bool = {
    nondet r = RIDS.oneOf()
    nondet i = NODES.oneOf()
    nondet rec = RECS.oneOf()
    nondet j = Set(1, 2).oneOf()
    nondet pos = Set(1, 2).oneOf()
    nondet opened = Set(true, false).oneOf()
    nondet ackers = ACK_SETS.get(i).oneOf()
    any {
      doByzVote(i, r, opened, j), doHold(rec), doVoidSlotTaken(r), doLapse(r), doExpC(r), doStall(r),
      doVoidRevoked(r), doExpire(r), doRollback(i), doReadmit(i, ackers), doReadmit(i, ackers),
      doProposalVote(i, r, pos), doCopyOrder(r), doBoardFirstInvalidCopy(rec),
    }
  }

  action stepColdStart: bool = {
    nondet r = RIDS.oneOf()
    any { doCheckpoint, doColdStartE, doSettleLost(r) }
  }

  action stepRelease: bool = {
    nondet r = RIDS.oneOf()
    nondet i = HONEST.oneOf()
    nondet c = NODES.oneOf()
    nondet g = GENS.oneOf()
    nondet j = Set(1, 2, 3).oneOf()
    nondet ackers = ACK_SETS.get(i).oneOf()
    nondet ackersC = ACK_SETS.get(c).oneOf()
    any {
      doRelease(i, r, g, j, ackers), doRelease(i, r, g, j, ackers), doRelease(i, r, g, j, ackers),
      doAnchorGen(r, g, j), doSlotAnchor(r, g, j),
      doRollback(c), doReadmit(c, ackersC), doReadmit(c, ackersC), doFinal(r),
    }
  }
  // An action with nondets nested inside another nondet scope makes the simulator try the
  // product of both domains when the branches are disabled, so steps combine at top level only.
  action stepReleaseMix: bool = any { stepRelease, stepProgress, doIdle }

  // Stutter step: keeps a sampled trace going when no other action is enabled, so the
  // simulator does not retry a dead end until its budget runs out. Safety is unchanged.
  action doIdle: bool = all { s' = { ...s, lastAction: "idle" } }

  action step: bool = any { stepProgress, stepFaults, stepColdStart }
  action stepP4: bool = any { stepProgress, stepProgress, stepProgress, stepProgress }
  action stepMostlyProgress: bool = any { stepP4, stepP4, stepFaults, doIdle }
  action stepP16: bool = any { stepP4, stepP4, stepP4, stepP4 }
  action stepRareFaults: bool = any { stepP16, stepP16, stepFaults, doIdle }
  action stepWithColdStart: bool = any { stepP16, stepP16, stepP16, stepFaults, stepFaults, stepColdStart }
  action stepRelease4: bool = any { stepRelease, stepRelease, stepRelease, stepProgress, doIdle }
  action stepReleaseCold: bool = any { stepRelease, stepRelease, stepProgress, stepColdStart, doIdle }

  // ---------------------------------------------------------------- invariants
  // C12 (§4.1): a slot is held by one request, ever (precedence, reservation, claim).
  val C12_SlotOneRequest: bool = ALL_SLOTS.forall(l => s.slotOwners.get(l).size() <= 1)

  // C12 / Q1: no committee Schnorr slot has a t-partial signature on two tickets.
  val C12_SchnorrSlotOneTicket: bool = SCH_SLOTS.forall(l => signedTickets(s, l).size() <= 1)

  // C12, C5, R2 / Q3: no ECDSA slot signs two messages (two give an admitted set the key).
  val C12_EcdsaSlotOneMessage: bool = EC_SLOTS.forall(l => signedTickets(s, l).size() <= 1)

  // C12 with slot_anchor / Q1: honest partials on a slot exist for one ticket at most.
  val C12_OneTicketWithHonestPartials: bool =
    ALL_SLOTS.forall(l => s.sigPartials.filter(p => p.slot == l).map(p => p.tk).size() <= 1)

  // §7.7 under rollback: no honest-code node signs two tickets on one slot or releases
  // two variants for one generation.
  val W77_NodeOneTicketPerSlot: bool =
    HONEST.forall(i => ALL_SLOTS.forall(l => s.sigPartials.filter(p => p.node == i and p.slot == l).map(p => p.tk).size() <= 1))
  val W77_NodeOneVariantPerGen: bool =
    s.relEvents.forall(e1 => s.relEvents.forall(e2 =>
      (e1.node == e2.node and e1.rid == e2.rid and e1.g == e2.g) implies e1.v == e2.v))

  // C3 (§4.4): an ECDSA request gives every variant its own slot.
  val C3_EcdsaOneMessagePerSlot: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.st != Unposted and rq.hdr.suite == Ecdsa) implies namedSlots(rq.hdr).size() == kOf(Ecdsa) })

  // C17 / Q2: no ECDSA slot receives contributions from two leaf sets.
  val C17_EcdsaSlotOneLeafSet: bool =
    EC_SLOTS.forall(l => s.memberAns.filter(a => a._1 == l).size() <= 1)

  // C6: no release without an authorization in force, unrevoked, for an admitted request,
  // on a slot this request holds.
  val C6_ReleaseAuthorized: bool = s.relEvents.forall(e => e.inForce and e.authFinal and e.admitted and e.slotMine)

  // C7: no release of a P2 request after its record's hold.
  val C7_HoldStopsRelease: bool = s.relEvents.forall(e => e.profile == P2 implies not(e.held))

  // C7 / Q13: a revoke final before the authorization has been final for Δ_hold blocks
  // stops generation 1 (§5.5). A revoke final at authAt + Δ_hold races the first release.
  val C7_RevokeInDeltaHoldStopsGen1: bool =
    s.relEvents.forall(e => (e.profile == P2 and e.g == 1) implies {
      val rq = s.reqs.get(e.rid)
      not(rq.revokeAt >= 0 and rq.revokeAt < rq.authAt + DESIGN_RULES.holdDelay) })

  // C7, C6 / Q8: no release on an ECDSA slot outside the record's slot root.
  val C7_EcdsaReleaseInRecordRoot: bool =
    s.relEvents.forall(e => e.suite == Ecdsa implies slotRoot(s.reqs.get(e.rid).hdr.rec).contains(e.slot))

  // C8: no header partial before the QC.
  val C8_NoPartialBeforeOrder: bool = s.hdrOrdered.forall(o => o)

  // C9 / Q6: a variant-body label is opened only for the selected variant of every
  // ordered envelope that shares its dd.
  val C9_UnselectedSealed: bool =
    s.prfPartials.map(p => p._2).forall(lab =>
      (s.prfPartials.filter(p => p._2 == lab).size() + NBYZ >= T) implies
        RIDS.forall(r => { val rq = s.reqs.get(r)
          (rq.order > 0 and rq.hdr.dd == lab / 100) implies rq.anchors.get(lab % 10) == (lab / 10) % 10 }))

  // C9 / Q6: no two ordered envelopes share dd.
  val C9_DdUnique: bool =
    RIDS.forall(a => RIDS.forall(b => (a != b and s.reqs.get(a).order > 0 and s.reqs.get(b).order > 0)
      implies s.reqs.get(a).hdr.dd != s.reqs.get(b).hdr.dd))

  // C11: one authorization in force per nullifier.
  val C11_OneAuthPerNullifier: bool =
    RIDS.forall(r1 => RIDS.forall(r2 => { val a = s.reqs.get(r1)  val b = s.reqs.get(r2)
      (r1 != r2 and a.everInForce and b.everInForce and a.hdr.rec == b.hdr.rec) implies a.nfv != b.nfv }))

  // C11, C7 / Q9: a record with a released, unconfirmed request is never unspent.
  val C11_ReleasedNeverUnspent: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (Set(Void, Expired).contains(rq.st) and anyRelease(s, r) and not(s.mid.recSpent.get(rq.hdr.rec))
        and rq.nfv >= 0)
        implies s.mid.recLocked.get(rq.hdr.rec) })

  // C13 / Q4: SLOT_TAKEN only when an earlier-ordered request named the slot. With the
  // ECDSA rule of DECISIONS 54, an ECDSA request is also voided by a request whose
  // authorization was in force, which may be ordered later than an unauthorized namer.
  val C13_SlotTakenOnlyByEarlier: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.reason == "SLOT_TAKEN") implies RIDS.exists(x => x != r and s.reqs.get(x).order > 0
        and (s.reqs.get(x).order < rq.order
             or (RULES.ecdsaPrecInForce and rq.hdr.suite == Ecdsa and s.reqs.get(x).everInForce))
        and namedSlots(s.reqs.get(x).hdr).intersect(namedSlots(rq.hdr)).size() > 0) })

  // C20 / Q4: a later-ordered request never holds a slot that an earlier live request names.
  // ECDSA slots under DECISIONS 54: the earlier request must also be in force and its
  // source must open the slot. Midnight's one authorize per nf makes that impossible.
  val C20_NoLaterTakesEarlierSlot: bool =
    ALL_SLOTS.forall(l => { val x = holder(s.slots.get(l))
      x > 0 implies RIDS.forall(r => { val rq = s.reqs.get(r)
        not(r != x and rq.st == Ordered and rq.order > 0 and rq.order < s.reqs.get(x).order
            and namedSlots(rq.hdr).contains(l)
            and (isSch(l) or not(RULES.ecdsaPrecInForce) or (inForce(rq) and srcOpens(rq.hdr, l)))) }) })

  // C13, O38 / G5: an ECDSA slot is held only by a request whose authorization was in
  // force and whose source opens the slot's root (§4.1 ECDSA precedence, §5.3 item 4).
  val C13_EcdsaPrecOnlyInForce: bool =
    EC_SLOTS.forall(l => { val x = holder(s.slots.get(l))
      x > 0 implies (s.reqs.get(x).everInForce and srcOpens(s.reqs.get(x).hdr, l)) })

  // C13, O38 / G5: no request whose authorization never came into force burns an ECDSA slot.
  val C13_EcdsaNoBurnByUnauthorized: bool = s.ecBurns.forall(e => s.reqs.get(e._2).everInForce)

  // C13, O38 / G5: an authorized ECDSA request ends SLOT_TAKEN only because of another
  // request whose authorization was in force.
  val C13_EcdsaSlotTakenOnlyByInForce: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.reason == "SLOT_TAKEN" and rq.hdr.suite == Ecdsa and rq.everInForce) implies
        RIDS.exists(x => x != r and s.reqs.get(x).everInForce
          and namedSlots(s.reqs.get(x).hdr).intersect(namedSlots(rq.hdr)).size() > 0) })

  // C13, C6 (§4.7, §5.4, DECISIONS 68): a request ends SLOT_TAKEN only after its own
  // authorization was in force. Opening checks only the structure of the header.
  val C13_SlotTakenOnlyInForce: bool =
    RIDS.forall(r => s.reqs.get(r).reason == "SLOT_TAKEN" implies s.reqs.get(r).everInForce)

  // C16 (§7.11 item 2): after a cold start through E no slot of the old pools is usable;
  // the model has no refill, so no release follows a cold start.
  val C16_ColdStartBurnsAll: bool = s.coldStarts > 0 implies ALL_SLOTS.forall(l => s.slots.get(l) == Burned)

  // C13, O38 (§4.1, DECISIONS 54): an ECDSA slot burns only at the end of a request that
  // reserved or claimed it; a slot without a reservation holds no partial.
  val C13_EcdsaBurnOnlyIfReserved: bool = s.ecBurns.forall(e => s.slotOwners.get(e._1).contains(e._2))

  // C13, O38: precedence on an ECDSA slot holds only while the authorization is in force
  // and its source opens the slot.
  val C13_EcdsaNamedOnlyWhileInForce: bool =
    not(RULES.ecdsaPrecInForce) or EC_SLOTS.forall(l => match s.slots.get(l) {
      | Named(r) => inForce(s.reqs.get(r)) and srcOpens(s.reqs.get(r).hdr, l)
      | _ => true })

  // C11 (§5.6): a spent record is never locked again; a cold-start settlement of a
  // request whose transaction confirmed settles FINAL.
  val C11_SpentNeverRelocked: bool = RECS.forall(rec => not(s.mid.recSpent.get(rec) and s.mid.recLocked.get(rec)))

  // C6 (§3.8, §5.3, §5.8): no authorization on the guardian leaf set of a P1 record comes into force.
  val C6_P1NoGuardianSource: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.everInForce and rq.hdr.suite == Ecdsa and s.charters.get(rq.hdr.rec).profile == P1) implies rq.hdr.ls == 1 })

  // C7, C6 / Q8: no ECDSA release on a slot outside the root that the request's source opens.
  val C7_EcdsaReleaseInSourceRoot: bool =
    s.relEvents.forall(e => e.suite == Ecdsa implies srcOpens(s.reqs.get(e.rid).hdr, e.slot))

  // C20: a collecting request releases nothing before its contributions.
  val C20_NoReleaseWithoutCollection: bool =
    s.relEvents.forall(e => s.reqs.get(e.rid).hdr.collecting implies e.contributed)

  // C18 / Q7: an honest actor contributes only to tickets whose R_A it recomputed.
  val C18_ContribOnlyMatchingRA: bool = RIDS.forall(r => s.reqs.get(r).contributed implies s.reqs.get(r).hdr.raOk)

  // C13 / Q10: no copy with a rewritten auth_ref is ordered.
  val C13_NoRewrittenCopyOrdered: bool = RIDS.forall(r => not(s.reqs.get(r).copyOrdered))

  // C13 / Q11: past exp_c, a collecting request that is not admitted can be voided STALLED.
  val C13_StallResolves: bool =
    RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.hdr.collecting and rq.expc and rq.st == Ordered and not(rq.admitted)) implies stallEnabled(s, r) })

  // C6, C11 / Q14: an invalid proof never enters a nullifier into the pending set.
  val C11_PendingOnlyVerified: bool = s.mid.bfPendingInvalid.size() == 0

  // C13 / Q15: a witness key names one slot (suite, epoch, address).
  val C13_WitnessKeyUnambiguous: bool =
    NODES.forall(p => s.wit.get(p).forall(a => s.wit.get(p).forall(b =>
      (a.kind == 2 and b.kind == 2 and a.owner == b.owner and a.key == b.key) implies a.slot == b.slot)))

  // C13 / Q5: an honest node that has not opened an ordered envelope can collect w acks
  // for the open entry of its committed position.
  val C13_OpenNotBlocked: bool =
    not(TEE) or RIDS.forall(r => { val rq = s.reqs.get(r)
      (rq.st == Ordered) implies HONEST.forall(i => rq.hdrPartials.contains(i) or {
        val e = { owner: i, kind: 0, key: r, digest: rq.qcPos, slot: 0, prov: false }
        NODES.exclude(Set(i)).filter(p => canAck(s, p, e)).size() >= WACK }) })

  // §4.1: generations stay within G_max and select higher variants.
  val GMAX_OneFeeBump: bool =
    s.relEvents.forall(e => e.g <= GMAX and e.v >= e.g) and
    RIDS.forall(r => { val a = s.reqs.get(r).anchors  a.get(2) > 0 implies a.get(2) > a.get(1) })

  val AllInvariants: bool = and {
    C12_SlotOneRequest, C12_SchnorrSlotOneTicket, C12_EcdsaSlotOneMessage, C12_OneTicketWithHonestPartials,
    W77_NodeOneTicketPerSlot, W77_NodeOneVariantPerGen, C3_EcdsaOneMessagePerSlot, C17_EcdsaSlotOneLeafSet,
    C6_ReleaseAuthorized, C7_HoldStopsRelease, C7_RevokeInDeltaHoldStopsGen1, C7_EcdsaReleaseInRecordRoot,
    C8_NoPartialBeforeOrder, C9_UnselectedSealed, C9_DdUnique, C11_OneAuthPerNullifier, C11_ReleasedNeverUnspent,
    C13_SlotTakenOnlyByEarlier, C20_NoLaterTakesEarlierSlot, C20_NoReleaseWithoutCollection, C18_ContribOnlyMatchingRA,
    C13_NoRewrittenCopyOrdered, C13_StallResolves, C11_PendingOnlyVerified, C13_WitnessKeyUnambiguous,
    C13_OpenNotBlocked, GMAX_OneFeeBump, C13_EcdsaPrecOnlyInForce, C13_EcdsaNoBurnByUnauthorized,
    C13_EcdsaSlotTakenOnlyByInForce, C16_ColdStartBurnsAll,
    C13_EcdsaBurnOnlyIfReserved, C13_EcdsaNamedOnlyWhileInForce, C11_SpentNeverRelocked,
    C6_P1NoGuardianSource, C7_EcdsaReleaseInSourceRoot, C13_SlotTakenOnlyInForce,
  }

  // ---------------------------------------------------------------- reachability
  val AdmittedReached: bool = RIDS.exists(r => s.reqs.get(r).admitted)
  val CollectingAdmittedReached: bool = RIDS.exists(r => s.reqs.get(r).admitted and s.reqs.get(r).hdr.collecting)
  val ReleaseReached: bool = s.relEvents.size() > 0
  val SignedReached: bool = ALL_SLOTS.exists(l => signedTickets(s, l).size() > 0)
  val EcdsaSignedReached: bool = EC_SLOTS.exists(l => signedTickets(s, l).size() > 0)
  val Gen2ReleaseReached: bool = s.relEvents.exists(e => e.g == 2)
  val StalledReached: bool = RIDS.exists(r => s.reqs.get(r).reason == "STALLED")
  val SlotTakenReached: bool = RIDS.exists(r => s.reqs.get(r).reason == "SLOT_TAKEN")
  val LapsedReached: bool = RIDS.exists(r => s.reqs.get(r).reason == "LAPSED")
  val FinalReached: bool = RIDS.exists(r => s.reqs.get(r).st == Final)
  val ExpiredReached: bool = RIDS.exists(r => s.reqs.get(r).st == Expired)
  val ReleasedThenEndedReached: bool = RIDS.exists(r => Set(Void, Expired).contains(s.reqs.get(r).st) and anyRelease(s, r))
  val BoardFirstReleaseReached: bool = s.relEvents.exists(e => s.reqs.get(e.rid).bfInForce)
  val P2Gen1ReleaseReached: bool = s.relEvents.exists(e => e.profile == P2 and e.g == 1)
  val HoldAfterReleaseReached: bool = RIDS.exists(r => s.mid.hold.get(s.reqs.get(r).hdr.rec) and anyRelease(s, r))
  val ReissueReleaseReached: bool = s.relEvents.exists(e => e.rid == 3)
  val TwoReqsShareSlotReached: bool =
    ALL_SLOTS.exists(l => RIDS.filter(r => s.reqs.get(r).order > 0 and namedSlots(s.reqs.get(r).hdr).contains(l)).size() >= 2)
  val EcdsaContribReached: bool = s.memberAns.size() > 0
  val RollbackAfterReleaseReached: bool = s.rollbacks > 0 and s.relEvents.exists(e => COLL.contains(e.node))
  val ReadmitReached: bool = s.readmits > 0
  val ProvisionalOpenReached: bool = NODES.exists(p => s.wit.get(p).exists(e => e.kind == 0 and e.prov))
  val ColdStartReached: bool = s.coldStarts > 0
  // G5: an ECDSA request whose authorization never came into force ended, and a slot it
  // named is not burned.
  val EcdsaUnauthEndNoBurnReached: bool = RIDS.exists(r => { val rq = s.reqs.get(r)
    rq.hdr.suite == Ecdsa and isTomb(rq.st) and rq.order > 0 and not(rq.everInForce)
      and namedSlots(rq.hdr).exists(l => s.slots.get(l) != Burned) })
  // G5: an in-force ECDSA request holds a slot that an earlier-ordered unauthorized request named.
  val EcdsaAuthAfterUnauthReached: bool = EC_SLOTS.exists(l => { val x = holder(s.slots.get(l))
    x > 0 and RIDS.exists(r => r != x and s.reqs.get(r).order > 0 and s.reqs.get(r).order < s.reqs.get(x).order
      and not(s.reqs.get(r).everInForce) and namedSlots(s.reqs.get(r).hdr).contains(l)) })
  val SlotAnchorReached: bool = ALL_SLOTS.exists(l => s.mid.slotAnchors.get(l) > 0)
}
