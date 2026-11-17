// -*- mode: Bluespec; -*-
// Scripted regression runs for splitline.qnt. Each scenario runs once on the mutant (the
// rule removed), where it reaches a state that breaks the target invariant, and once on the
// design instance, where the step that harms the victim is refused and every invariant holds.
// Run: quint test splitline_test.qnt --main <module> --match <run>
// Export traces: add --out-itf '../../tests/quint-regressions/splitline/{test}.itf.json'
//
// G5 (DECISIONS 54, O38): record 1 is a P2 address. Request 2 is the user's envelope that
// names the guardian slots 13 and 14 and never gets an authorization. Request 1 is the
// guardians' seizure request on the same slots, with an authorization in force. Both use
// embedded contributions, so no group member answers either request (§5.8: guardians answer
// only a settled order).

module g5_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = RX).* from "./splitline"
  const RX: Rules

  pure val g5Headers: int -> Header = Map(
    1 -> mkHeader(1, Ecdsa, false, 2, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 1, true),
    2 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 2, true),
    3 -> mkHeader(1, Ecdsa, false, 2, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))
  pure val g5Charters: int -> Charter = Map(1 -> { profile: P2, bf: false }, 2 -> { profile: P1, bf: false })

  // The user's envelope is ordered first; the seizure request is ordered and its
  // authorization becomes final.
  action g5Start: bool = initWith(g5Headers, g5Charters)
    .then(doPost(2)).then(doOrder(2, 1))
    .then(doPost(1)).then(doOrder(1, 1)).then(doAuthorize(1)).then(doAuthFinal(1))

  action openHeader(r: int): bool = doHeaderPartial(1, r, Set()).then(doHeaderPartial(2, r, Set()))

  // Old rule: the unauthorized namer has precedence, so the seizure request ends SLOT_TAKEN.
  run g5VoidBroken = g5Start.then(openHeader(1)).then(doVoidSlotTaken(1))
    .expect(s.reqs.get(1).reason == "SLOT_TAKEN" and not(C13_EcdsaSlotTakenOnlyByInForce)
            and not(C13_EcdsaPrecOnlyInForce))
  // Design: the seizure request takes the slots when its authorization comes into force
  // and is admitted. The user's envelope opens but never comes into force, so no node runs
  // its admission checks (DECISIONS 68): it posts no SLOT_TAKEN, and the envelope lapses
  // at exp_c without a burn.
  run g5VoidHolds = g5Start.then(openHeader(1))
    .expect(AllInvariants and s.slots.get(13) == Named(1) and s.slots.get(14) == Named(1))
    .then(doVoteAdmit(1, 1, 1)).then(doVoteAdmit(2, 1, 1)).then(doVoteAdmit(3, 1, 1))
    .then(openHeader(2)).then(doExpC(2)).then(doLapse(2))
    .expect(AllInvariants and s.reqs.get(1).admitted and s.reqs.get(2).reason == "LAPSED"
            and s.slots.get(13) == Claimed(1) and s.slots.get(14) == Claimed(1))
  run g5VoidUnauthRefusedHolds = g5Start.then(openHeader(1))
    .then(doVoteAdmit(1, 1, 1)).then(doVoteAdmit(2, 1, 1)).then(doVoteAdmit(3, 1, 1))
    .then(openHeader(2)).then(doVoidSlotTaken(2).fail())

  run g5VoidRefusedHolds = g5Start.then(openHeader(1)).then(doVoidSlotTaken(1).fail())

  // Old rule: the user's envelope lapses and its end burns the guardian slots.
  run g5BurnBroken = initWith(g5Headers, g5Charters)
    .then(doPost(2)).then(doOrder(2, 1)).then(doExpC(2)).then(doLapse(2))
    .expect(s.slots.get(13) == Burned and s.slots.get(14) == Burned and not(C13_EcdsaNoBurnByUnauthorized))
  // Design: the lapse burns nothing, and the seizure request is admitted on the slots.
  run g5BurnHolds = initWith(g5Headers, g5Charters)
    .then(doPost(2)).then(doOrder(2, 1)).then(doExpC(2)).then(doLapse(2))
    .expect(AllInvariants and s.slots.get(13) == Free and s.slots.get(14) == Free)
    .then(doPost(1)).then(doOrder(1, 1)).then(doAuthorize(1)).then(doAuthFinal(1)).then(openHeader(1))
    .then(doVoteAdmit(1, 1, 1)).then(doVoteAdmit(2, 1, 1)).then(doVoteAdmit(3, 1, 1))
    .expect(AllInvariants and s.reqs.get(1).admitted and s.slots.get(13) == Claimed(1))
}

module gt_design { import splitline_types.* from "./splitline"
  import g5_scenarios(RX = DESIGN_RULES).* }
module gt_m_g5 { import splitline_types.* from "./splitline"
  import g5_scenarios(RX = { ...DESIGN_RULES, ecdsaPrecInForce: false }).* }

// PG1 (REVIEW-17a finding 5, DECISIONS 68): opening checks against admission checks.
// Requests 1 and 2 name Schnorr slot 1; request 1 is ordered first and holds its
// precedence. The header of request 2 opens while its authorization is not yet final.
module pg1_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = RX).* from "./splitline"
  const RX: Rules

  pure val pg1Headers: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 1, 2 -> 3), Map(1 -> 11, 2 -> 12), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  pure val pg1Charters: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })

  action pg1Open: bool = initWith(pg1Headers, pg1Charters)
    .then(doPost(1)).then(doOrder(1, 1)).then(doPost(2)).then(doOrder(2, 2))
    .then(doHeaderPartial(1, 2, Set())).then(doHeaderPartial(2, 2, Set()))

  // Old reading of §4.7 item 3: the precedence check runs at opening, before the
  // authorization of request 2 is in force, and request 2 ends SLOT_TAKEN unauthorized.
  run pg1OpenVoidBroken = pg1Open.then(doVoidSlotTaken(2))
    .expect(s.reqs.get(2).reason == "SLOT_TAKEN" and not(C13_SlotTakenOnlyInForce))
  // Design: the opened header waits for its authorization. SLOT_TAKEN follows once the
  // authorization is in force.
  run pg1OpenVoidRefusedHolds = pg1Open.then(doVoidSlotTaken(2).fail())
  run pg1OpenVoidHolds = pg1Open.expect(AllInvariants and s.reqs.get(2).st == Ordered)
    .then(doAuthorize(2)).then(doAuthFinal(2)).then(doVoidSlotTaken(2))
    .expect(AllInvariants and s.reqs.get(2).reason == "SLOT_TAKEN" and s.reqs.get(2).everInForce)
}

module pg1_design { import splitline_types.* from "./splitline"
  import pg1_scenarios(RX = DESIGN_RULES).* }
module pg1_m_open { import splitline_types.* from "./splitline"
  import pg1_scenarios(RX = { ...DESIGN_RULES, admissionInForce: false }).* }

// Regression runs for the QA findings of the Carbon lane (COUNTEREXAMPLES.md, QA-1 to QA-10).
// Each run is the lane's counterexample on the design instance: before the fix the run
// reached a state that broke the named property, after it every invariant holds.
module fix_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = DESIGN_RULES).* from "./splitline"

  pure val chP2: int -> Charter = Map(1 -> { profile: P2, bf: false }, 2 -> { profile: P1, bf: false })
  pure val chP1: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })
  pure val hSch: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  pure val hEc: int -> Header = Map(
    1 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(1, Ecdsa, false, 2, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 2, true),
    3 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))
  pure val hGuard: int -> Header = Map(
    1 -> mkHeader(1, Ecdsa, false, 2, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 1, true),
    2 -> mkHeader(2, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))

  action open2(r: int): bool = doHeaderPartial(1, r, Set()).then(doHeaderPartial(2, r, Set()))
  action admit3(r: int): bool = doVoteAdmit(1, r, 1).then(doVoteAdmit(2, r, 1)).then(doVoteAdmit(3, r, 1))
  action authed(r: int): bool = doPost(r).then(doOrder(r, 1)).then(doAuthorize(r)).then(doAuthFinal(r))

  // QA-1: a hold final at authAt + Δ_hold, after the first release at that height.
  run c7BoundaryHolds = initWith(hSch, chP2).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doMidTick).then(doMidTick).then(doRelease(1, 1, 1, 1, Set())).then(doHold(1))
    .expect(AllInvariants)
  // QA-1: a hold final one block earlier stops generation 1.
  run c7EarlyHoldStopsHolds = initWith(hSch, chP2).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doMidTick).then(doHold(1)).then(doMidTick).then(doRelease(1, 1, 1, 1, Set()).fail())

  // QA-2, QA-3: a hold revokes request 1 before any reservation. Its precedence ends and
  // the void burns nothing.
  run ecRevokeFreesHolds = initWith(hEc, chP2).then(authed(1))
    .expect(s.slots.get(11) == Named(1))
    .then(doHold(1))
    .expect(AllInvariants and s.slots.get(11) == Free and s.slots.get(12) == Free)
    .then(doVoidRevoked(1))
    .expect(AllInvariants and s.slots.get(11) == Free and s.ecBurns == Set())

  // QA-2: request 1 expires unreserved; reissue request 3 takes slots 11 and 12.
  run ecExpireReissueHolds = initWith(hEc, chP1).then(authed(1)).then(doExpC(1)).then(doExpire(1))
    .expect(AllInvariants and s.slots.get(11) == Free)
    .then(authed(3)).then(open2(3)).then(admit3(3))
    .expect(AllInvariants and s.reqs.get(3).admitted and s.slots.get(11) == Claimed(3))

  // QA-8a: request 1 is FINAL after the checkpoint; the cold start loses it and the
  // settlement reads the host chain: FINAL, and the spent record is not locked.
  run coldFinalSettlesFinalHolds = initWith(hEc, chP1).then(doCheckpoint).then(authed(1))
    .then(open2(1)).then(admit3(1)).then(doRelease(1, 1, 1, 1, Set())).then(doRelease(2, 1, 1, 1, Set()))
    .then(doFinal(1)).then(doColdStartE).then(doSettleLost(1))
    .expect(AllInvariants and s.reqs.get(1).st == Final and not(s.mid.recLocked.get(1)))

  // QA-8b: request 1 released a partial and expired (RELEASED); the owner's re-post
  // authorizes on the successor record (§5.3 item 1).
  run releasedRepostHolds = initWith(hSch, chP1).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doRelease(1, 1, 1, 1, Set())).then(doMidTick).then(doMidTick).then(doMidTick).then(doExpire(1))
    .expect(AllInvariants and s.mid.recLocked.get(1))
    .then(authed(3))
    .expect(AllInvariants and s.reqs.get(3).auth == AFinal and s.reqs.get(3).nfv == 1)

  // S1b (item 11 replay): generation 2 anchors only after a partial of generation 1 left.
  run gen2AfterReleaseHolds = initWith(hSch, chP1).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doAnchorGen(1, 2, 2).fail())
  run gen2AnchorsHolds = initWith(hSch, chP1).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doRelease(1, 1, 1, 1, Set())).then(doAnchorGen(1, 2, 2))
    .expect(AllInvariants and s.reqs.get(1).anchors.get(2) == 2)

  // QA-9: a P1 record has no seizure source; Midnight refuses an authorization on ls 2.
  run p1GuardianRefusedHolds = initWith(hGuard, chP1).then(doPost(1)).then(doOrder(1, 1))
    .then(doAuthorize(1).fail())
}

// QA-10: the WACK = 5 mutant of sl_n9_tee_b3_c1_w5 (w = n - 2 - f). A rolled-back node
// readmits with five acks that miss its release entry and signs a second variant.
module w5_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 9, F = 2, NBYZ = 3, NCOLL = 1, TEE = true, WACK = 5, RULES = DESIGN_RULES).* from "./splitline"
  pure val ch: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })
  pure val hs: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  run w5Broken = initWith(hs, ch)
    .then(doPost(1)).then(doOrder(1, 1)).then(doAuthorize(1)).then(doAuthFinal(1))
    .then(doHeaderPartial(1, 1, Set(2, 3, 4, 5, 6))).then(doHeaderPartial(2, 1, Set(1, 3, 4, 5, 6)))
    .then(doHeaderPartial(3, 1, Set(1, 2, 4, 5, 6))).then(doHeaderPartial(4, 1, Set(1, 2, 3, 5, 6)))
    .then(doVoteAdmit(1, 1, 1)).then(doVoteAdmit(2, 1, 1)).then(doVoteAdmit(3, 1, 1))
    .then(doVoteAdmit(4, 1, 1)).then(doVoteAdmit(5, 1, 1)).then(doVoteAdmit(6, 1, 1))
    .then(doRelease(1, 1, 1, 1, Set(2, 3, 7, 8, 9))).then(doRollback(1))
    .then(doReadmit(1, Set(4, 5, 7, 8, 9))).then(doRelease(1, 1, 1, 2, Set(4, 5, 7, 8, 9)))
    .expect(not(W77_NodeOneTicketPerSlot) and not(W77_NodeOneVariantPerGen))
}

// QA-6, QA-7: scripted kills of the mutants m_slot_root and m_leafset, which sampled
// runs from initArmedEcdsa do not reach (the armed request names its own root and leaf set).
module rule_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = RX).* from "./splitline"
  const RX: Rules
  pure val ch: int -> Charter = Map(1 -> { profile: P2, bf: false }, 2 -> { profile: P1, bf: false })
  // r1 and r2 collect on the guardian slots 13 and 14, r1 with the owner's leaf set.
  pure val hs: int -> Header = Map(
    1 -> mkHeader(1, Ecdsa, true, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 1, true),
    2 -> mkHeader(1, Ecdsa, true, 2, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 2, true),
    3 -> mkHeader(2, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))
  run leafSetBroken = initWith(hs, ch).then(doPost(1)).then(doContribute(1)).then(doPost(2)).then(doContribute(2))
    .expect(not(C17_EcdsaSlotOneLeafSet))
  run leafSetHolds = initWith(hs, ch).then(doPost(1)).then(doContribute(1).fail())
  action toRelease(r: int): bool = doPost(r).then(doOrder(r, 1)).then(doAuthorize(r)).then(doAuthFinal(r))
    .then(doHeaderPartial(1, r, Set())).then(doHeaderPartial(2, r, Set()))
    .then(doVoteAdmit(1, r, 1)).then(doVoteAdmit(2, r, 1)).then(doVoteAdmit(3, r, 1))
  // r1 of record 2 names slots 11 and 12 of record 1.
  pure val hx: int -> Header = Map(
    1 -> mkHeader(2, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 13, 2 -> 14), 2, true),
    3 -> mkHeader(2, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 15, 2 -> 16), 3, true))
  run slotRootBroken = initWith(hx, ch).then(toRelease(1)).then(doRelease(1, 1, 1, 1, Set()))
    .expect(not(C7_EcdsaReleaseInRecordRoot))
  run slotRootHolds = initWith(hx, ch).then(doPost(1)).then(doOrder(1, 1)).then(doAuthorize(1)).then(doAuthFinal(1))
    .then(doHeaderPartial(1, 1, Set())).then(doHeaderPartial(2, 1, Set()))
    .expect(AllInvariants and s.slots.get(11) == Free)
    .then(doVoteAdmit(1, 1, 1).fail())
}
module rt_design { import splitline_types.* from "./splitline"
  import rule_scenarios(RX = DESIGN_RULES).* }
module rt_m_leafset { import splitline_types.* from "./splitline"
  import rule_scenarios(RX = { ...DESIGN_RULES, leafSetCheck: false }).* }
module rt_m_slot_root { import splitline_types.* from "./splitline"
  import rule_scenarios(RX = { ...DESIGN_RULES, slotRootCheck: false }).* }

// Deterministic kills of the mutants that the sampled jobs from `init` do not reach in 25
// steps (runner 26d). Each run passes on its mutant and fails on the design instance
// (jobs neg_mt_design_*).
module mutant_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 1, NCOLL = 0, TEE = false, WACK = 2, RULES = RX).* from "./splitline"
  const RX: Rules
  pure val chP1: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })
  pure val chP2: int -> Charter = Map(1 -> { profile: P2, bf: false }, 2 -> { profile: P1, bf: false })
  pure val chBf: int -> Charter = Map(1 -> { profile: P2, bf: true }, 2 -> { profile: P1, bf: false })
  // r1 Schnorr slots 1, 2; r2 (record 2) slots 2, 3; r3 reissue of record 1 on slots 2, 3
  pure val hSch: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  pure val hEc: int -> Header = Map(
    1 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))
  // r1 names Schnorr slot 1 for both generations; r1 collecting
  pure val hSame: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 1), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  pure val hCol: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, true, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))

  action ordered(r: int): bool = doPost(r).then(doOrder(r, 1))
  action authed(r: int): bool = ordered(r).then(doAuthorize(r)).then(doAuthFinal(r))
  action open2(r: int): bool = doHeaderPartial(1, r, Set()).then(doHeaderPartial(2, r, Set()))
  action admit3(r: int): bool = doVoteAdmit(1, r, 1).then(doVoteAdmit(2, r, 1)).then(doVoteAdmit(3, r, 1))
  action rel2(r: int, g: int, j: int): bool = doRelease(1, r, g, j, Set()).then(doRelease(2, r, g, j, Set()))

  // m_burn: r1 expires after its claim, its slots return free, and reissue r3 claims slot 2.
  run burnBroken = initWith(hSch, chP1).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doMidTick).then(doMidTick).then(doMidTick).then(doExpire(1))
    .then(authed(3)).then(open2(3)).then(admit3(3))
    .expect(not(C12_SlotOneRequest))
  // m_precedence: r2, ordered after r1, claims slot 2 that live r1 names.
  run precedenceBroken = initWith(hSch, chP1).then(ordered(1)).then(authed(2)).then(open2(2)).then(admit3(2))
    .expect(not(C20_NoLaterTakesEarlierSlot))
  // m_distinct: r1 names slot 1 for both generations; nodes 1 and 2 sign generation 1 on it
  // and node 3 signs generation 2 on it.
  run distinctBroken = initWith(hSame, chP1).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(rel2(1, 1, 1)).then(doAnchorGen(1, 2, 2)).then(doRelease(3, 1, 2, 2, Set()))
    .expect(not(C12_OneTicketWithHonestPartials))
  // m_bf_p2: a P2 board-first charter; the hold does not reach the board-first call.
  run bfP2Broken = initWith(hSch, chBf)
    .expect(legalCharters.contains({ profile: P2, bf: true }))
    .then(ordered(1)).then(doBoardFirstCall(1)).then(open2(1)).then(admit3(1))
    .then(doMidTick).then(doMidTick).then(doHold(1)).then(doRelease(1, 1, 1, 1, Set()))
    .expect(not(C7_HoldStopsRelease))
  // m_inclusion: release while the authorization is only included.
  run inclusionBroken = initWith(hSch, chP1).then(ordered(1)).then(doAuthorize(1)).then(open2(1)).then(admit3(1))
    .then(doRelease(1, 1, 1, 1, Set()))
    .expect(not(C6_ReleaseAuthorized))
  // m_no_collect: a collecting request is admitted and released without contributions.
  run noCollectBroken = initWith(hCol, chP1).then(authed(1)).then(open2(1))
    .then(doVoteOpened(1, 1)).then(doVoteOpened(2, 1)).then(doVoteOpened(3, 1)).then(admit3(1))
    .then(doRelease(1, 1, 1, 1, Set()))
    .expect(not(C20_NoReleaseWithoutCollection))
  // m_cold_old: r1 signs on slot 11 after the checkpoint; the cold start leaves slot 11
  // free, and reissue r3 signs a second message on it.
  run coldOldBroken = initWith(hEc, chP1).then(doCheckpoint).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(rel2(1, 1, 1)).then(doColdStartE).then(doSettleLost(1))
    .then(authed(3)).then(open2(3)).then(admit3(3)).then(rel2(3, 1, 1))
    .expect(not(C12_EcdsaSlotOneMessage))
  // m_hold0: generation 1 releases at the authorization height, and a hold final in the
  // same block comes too late.
  run hold0Broken = initWith(hSch, chP2).then(authed(1)).then(open2(1)).then(admit3(1))
    .then(doRelease(1, 1, 1, 1, Set())).then(doHold(1))
    .expect(not(C7_RevokeInDeltaHoldStopsGen1))
}
module mt_design { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = DESIGN_RULES).* }
module mt_m_burn { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, burnAtEnd: false }).* }
module mt_m_precedence { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, slotPrecedence: false }).* }
module mt_m_distinct { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, checkDistinctSlots: false }).* }
module mt_m_bf_p2 { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, boardFirstP2: true }).* }
module mt_m_inclusion { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, releaseAtInclusion: true }).* }
module mt_m_no_collect { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, admitWithoutContrib: true }).* }
module mt_m_cold_old { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, coldBurnUnclaimed: false }).* }
module mt_m_hold0 { import splitline_types.* from "./splitline"
  import mutant_scenarios(RX = { ...DESIGN_RULES, holdDelay: 0 }).* }

// m_witkey (TEE): node 1 releases on Schnorr slot 1 for r1 (record 2) and on ECDSA slot 11
// for r2 (record 1). With keys l % 10 the two slot entries share key 1, and the witnesses
// refuse the second release, because they hold another digest under that key. The witness
// keeps one entry per key, so C13_WitnessKeyUnambiguous cannot fail in this model; the
// mutant shows as a refused honest release. The run passes on the design and fails on
// the mutant.
module witkey_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = 4, F = 1, NBYZ = 0, NCOLL = 1, TEE = true, WACK = 2, RULES = RX).* from "./splitline"
  const RX: Rules
  pure val ch: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })
  pure val hs: int -> Header = Map(
    1 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 15, 2 -> 16), 1, true),
    2 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 2, true),
    3 -> mkHeader(1, Ecdsa, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 3, true))
  action prep(r: int): bool = doPost(r).then(doOrder(r, 1)).then(doAuthorize(r)).then(doAuthFinal(r))
    .then(doHeaderPartial(1, r, Set(2, 3))).then(doHeaderPartial(2, r, Set(1, 3))).then(doHeaderPartial(3, r, Set(1, 2)))
    .then(doVoteAdmit(1, r, 1)).then(doVoteAdmit(2, r, 1)).then(doVoteAdmit(3, r, 1))
  run witkeyReleaseHolds = initWith(hs, ch).then(prep(1)).then(prep(2))
    .then(doRelease(1, 1, 1, 1, Set(2, 3))).then(doRelease(1, 2, 1, 1, Set(2, 3)))
    .expect(AllInvariants and s.relEvents.size() == 2)
}
module wk_design { import splitline_types.* from "./splitline"
  import witkey_scenarios(RX = DESIGN_RULES).* }
module wk_m_witkey { import splitline_types.* from "./splitline"
  import witkey_scenarios(RX = { ...DESIGN_RULES, witnessKeyFull: false }).* }

// S1 at n = 7 (|C| = 3) and n = 9 (|C| = 5): a forked board lets two honest halves release
// different variants on one Schnorr slot, and the corrupt nodes complete both.
module q1_scenarios {
  import splitline_types.* from "./splitline"
  import splitline_protocol(N = NX, F = 2, NBYZ = BX, NCOLL = 0, TEE = false, WACK = 2, RULES = DESIGN_RULES).* from "./splitline"
  const NX: int
  const BX: int
  pure val ch: int -> Charter = Map(1 -> { profile: P1, bf: false }, 2 -> { profile: P1, bf: false })
  pure val hs: int -> Header = Map(
    1 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 1, 2 -> 2), Map(1 -> 11, 2 -> 12), 1, true),
    2 -> mkHeader(2, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 15, 2 -> 16), 2, true),
    3 -> mkHeader(1, Schnorr, false, 1, Map(1 -> 2, 2 -> 3), Map(1 -> 11, 2 -> 12), 3, true))
  run q1ForkBroken = initWith(hs, ch)
    .then(doPost(1)).then(doOrder(1, 1)).then(doAuthorize(1)).then(doAuthFinal(1))
    .then(doHeaderPartial(1, 1, Set())).then(doHeaderPartial(2, 1, Set()))
    .then(doHeaderPartial(3, 1, Set())).then(doHeaderPartial(4, 1, Set()))
    .then(doVoteAdmit(1, 1, 1)).then(doVoteAdmit(2, 1, 1)).then(doVoteAdmit(3, 1, 1)).then(doVoteAdmit(4, 1, 1))
    .then(doByzVote(NX, 1, false, 1)).then(doByzVote(NX - 1, 1, false, 1))
    .then(doRelease(1, 1, 1, 1, Set())).then(doRelease(2, 1, 1, 1, Set()))
    .then(doRelease(3, 1, 1, 2, Set())).then(doRelease(4, 1, 1, 2, Set()))
    .expect(forked and not(C12_SchnorrSlotOneTicket))
}
module q1_n7_b3 { import splitline_types.* from "./splitline"
  import q1_scenarios(NX = 7, BX = 3).* }
module q1_n9_b5 { import splitline_types.* from "./splitline"
  import q1_scenarios(NX = 9, BX = 5).* }
