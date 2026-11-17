// -*- mode: Bluespec; -*-
// Scripted schedules for splitspec.qnt. Each schedule reaches a precondition that random
// runs reach rarely; the design instance must hold every invariant along it, and the named
// planted rule change must break its named invariant on the same schedule.
//
// The fragment `releasedOne` (one Schnorr owner spend through release of generation 1) is
// repeated in each module that uses it, because an imported fragment would bind a second
// instance of the state variables.
// ------------------------------------------------------------------ design, TEE P2
module test_tee_p2 {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "none").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1))

  // RQ-001 launch values and the instance values.
  run rq001ParamsTest = all {
    assert(qOf(9, 2) == 6 and tOf(9, 2) == 7 and wOf(9, 2) == 6),
    assert(qOf(17, 5) == 12 and tOf(17, 5) == 12 and wOf(17, 5) == 11),
    assert(N >= 3 * F + 1 and F >= 1 and Q == 3 and T == 3 and W == 2),
    init,
  }

  // JNY-001: a single-user spend reaches FINAL (RQ-003..RQ-044, RQ-049, RQ-053).
  run jny001FinalTest =
    releasedOne
      .then(hostConfirm(1))
      .then(postFinal(1, 1, 2)).then(postFinal(1, 1, 3)).then(postFinal(1, 1, 4))
      .expect(and { req(1).phase == "FINAL", req(1).outcome == "FINAL", st.signed_leaf.get(1) == "FINAL",
                    st.cslots.get(1).bstat == "BURNED", inv })
      .then(landCheckpoint)
      .expect(and { st.auths.get(1).settled == "FINAL", st.record.coin == 2, st.record.rstate == "UNSPENT",
                    st.committee_txs == 1, inv })

  // RQ-008: no partial before order; RQ-057: no release before ADMITTED.
  run rq057NoReleaseBeforeAdmitTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      
      .then(order(1)).then(openHeader(1))
      
      .then(admitWith(1, 1)).then(sendRelease(1, 1))
      .expect(inv)
  run rq057NoReleaseBeforeAdmitBlocked1Test =    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(sendRelease(1, 1).fail())
  run rq057NoReleaseBeforeAdmitBlocked2Test =    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      
      .then(order(1)).then(openHeader(1))
      .then(sendRelease(1, 1).fail())

  // RQ-024 / AU-010: no ADMIT before finality.
  run rq024NotInForceTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(order(1)).then(openHeader(1))
      
      .then(finalizeAuth(1)).then(admitWith(1, 1)).expect(req(1).phase == "ADMITTED")
  run rq024NotInForceBlocked1Test =    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(order(1)).then(openHeader(1))
      .then(admitWith(1, 1).fail())

  // RQ-033: P2 hold wait of DELTA_HOLD Midnight blocks.
  run rq033HoldWaitTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1))
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(tickMidnight).then(sendRelease(1, 1))
  run rq033HoldWaitBlocked1Test =    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1))
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1).fail())

  // RQ-034 / RQ-059 / C7: revocation before release voids, and no partial follows it.
  run rq034RevokeTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(revoke(1))
      .then(postVoid(1, 1, 2, "REVOKED")).then(postVoid(1, 1, 3, "REVOKED"))
      .expect(and { req(1).phase == "VOID", req(1).reason == "REVOKED", req(1).outcome == "VOID", inv })
  run rq034RevokeBlocked1Test =    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(revoke(1)).then(sendRelease(1, 1).fail())

  // RQ-042 / RQ-045: one corrupt post per epoch forms no tombstone.
  run rq042CrossEpochTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(rotate)
      .then(postVoid(1, 1, 1, "STALLED")).then(postVoid(1, 2, 1, "STALLED"))
      .expect(and { req(1).phase == "POSTED", inv })

  // SL-005 / SL-010: a never-authorized envelope lapses and its committee slots burn.
  run sl010LapseBurnsTest =
    init.then(postWith(1, "SCHNORR", "NONE", 2, false, 1, 2, 1, 2, "none", 10))
      .then(order(1)).then(openHeader(1)).then(DELTA_C.reps(_ => tick))
      .expect(and { req(1).lapsed, st.cslots.get(1).bstat == "BURNED", st.cslots.get(2).bstat == "BURNED", inv })

  // SL-010, the end half: the design twin of killCommitteeBurnReservedOnlyTest. The precedence
  // holder ends unreserved and its committee slots burn. Item 14 used a never-authorized holder,
  // whose slot SL-005 had already burned at the lapse (height 5) before its late expire; the holder
  // is now in force, so only the RQ-046 expiry at height 8 (urgent, lead ruling A) burns the slot.
  run sl010EndBurnsTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1))
      .then(order(1)).then(openHeader(1)).then(6.reps(_ => tick))
      .expect(and { req(1).phase == "OPENED", not(req(1).lapsed), st.cslots.get(1).bstat == "NAMED" })
      .then(tick)
      .expect(and { req(1).phase == "EXPIRED", req(1).end_height == 8, inv_SL010_committeeBurnAtPrecEnd,
                    st.cslots.get(1).bstat == "BURNED", inv })

  // SL-006 / SL-007: an unauthorized ECDSA namer first; the later owner request takes the slot.
  run sl006EcdsaPrecTest =
    init.then(postWith(1, "ECDSA", "NONE", 1, false, 1, 2, 1, 2, "none", 13))
      .then(postWith(2, "ECDSA", "OWNER", 1, false, 1, 2, 1, 2, "none", 16))   // exp 16: live after request 1 expires
      .then(order(1)).then(order(2)).then(openHeader(1)).then(openHeader(2))
      .then(authorize(2)).then(finalizeAuth(2)).then(ecdsaPrec(2))
      .expect(and { st.eslots.get(1).prec == 2, inv })
      .then(admitWith(2, 1))
      .expect(and { st.eslots.get(1).reserver == 2, st.eslots.get(1).bstat == "CLAIMED", inv })
      .then(12.reps(_ => tick)).expect(and { req(1).phase == "EXPIRED", req(2).phase == "ADMITTED" })
      .expect(and { st.eslots.get(1).bstat == "CLAIMED", inv })     // SL-007: the spam end burns nothing

  // SL-011: the reserver's end burns every ECDSA slot it reserved, the unselected variant included.
  run sl011EcdsaBurnTest =
    init.then(postWith(1, "ECDSA", "OWNER", 2, false, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight).then(order(1)).then(openHeader(1))
      .then(ecdsaPrec(1)).then(admitWith(1, 1)).then(sendRelease(1, 1)).then(hostConfirm(1))
      .then(postFinal(1, 1, 2)).then(postFinal(1, 1, 3)).then(postFinal(1, 1, 4))
      .expect(and { st.eslots.get(1).bstat == "BURNED", st.eslots.get(2).bstat == "BURNED", inv })

  // JNY-002 and RQ-047: a collecting request with a silent actor stalls; with a frame it admits.
  run jny002StallTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      
      .then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED")).then(postVoid(1, 1, 3, "STALLED"))
      .expect(and { req(1).reason == "STALLED", req(1).outcome == "VOID", g.sent == Set(), inv })
  run jny002StallBlocked1Test =    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(admitWith(1, 1).fail())
  run jny002AdmitTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(frame(1))                                                // RQ-021: held before open
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .expect(req(1).filled)
      .then(admitWith(1, 1)).expect(and { req(1).phase == "ADMITTED", inv })

  // AU-021 / RQ-060: the reissue carries the VOID leaf; the record is UNSPENT under a new nf.
  run au021ReissueTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED")).then(postVoid(1, 1, 3, "STALLED"))
      .then(schnorrOwner(2, 3, 4, 13)).then(reissue(1, 2))
      .expect(and { st.held.get(1) == "VOID", st.auths.get(1).settled == "VOID", st.record.pending_auth == 2,
                    st.committee_txs == 0, inv })

  // RQ-048 / RQ-052 / JNY-003 (S1): a restart ends a released live request; the lost release
  // evidence does not make it VOID, so the record stays locked to the pin and the re-post
  // cannot spend the coin twice.
  run rq052RestartReleasedTest =
    releasedOne
      .then(restartWith(true))
      .expect(and { req(1).any_release, req(1).released.get(1) == 1, inv_RQ076_C11_releaseMonotone })   // RQ-076
      .then(postVoid(1, 1, 2, "RESTART")).then(postVoid(1, 1, 3, "RESTART"))
      .expect(and { req(1).restart_end, req(1).outcome == "RELEASED", inv })
      .then(landCheckpoint)
      .expect(and { st.record.rstate == "LOCKED", st.cp.restart_seq == 1, inv })
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .expect(st.auths.get(2).pin == st.auths.get(1).pin)
      .then(finalizeAuth(2)).then(tickMidnight).then(order(2)).then(openHeader(2)).then(admitWith(2, 1))
      .then(sendRelease(2, 1)).then(hostConfirm(2))
      
      .expect(inv)
  run rq052RestartReleasedBlocked1Test =    releasedOne
      .then(restartWith(true))
      .then(postVoid(1, 1, 2, "RESTART")).then(postVoid(1, 1, 3, "RESTART"))
      .expect(and { req(1).restart_end, req(1).outcome == "RELEASED", inv })
      .then(landCheckpoint)
      .expect(and { st.record.rstate == "LOCKED", st.cp.restart_seq == 1, inv })
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .expect(st.auths.get(2).pin == st.auths.get(1).pin)
      .then(finalizeAuth(2)).then(tickMidnight).then(order(2)).then(openHeader(2)).then(admitWith(2, 1))
      .then(sendRelease(2, 1)).then(hostConfirm(2))
      .then(hostConfirm(1).fail())

  // RQ-068 / D-058 (S3): a carried VOID leaf is held by Midnight, so the request is settled and
  // the restart does not end it again (DECISIONS 58, lead ruling E); its leaf stays VOID (RQ-054).
  run rq054CarveOutTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED")).then(postVoid(1, 1, 3, "STALLED"))
      .then(schnorrOwner(2, 3, 4, 13)).then(reissue(1, 2))
      .then(restartWith(false))
      .expect(and { not(req(1).restart_end), req(1).outcome == "VOID", st.signed_leaf.get(1) == "VOID",
                    st.held.get(1) == "VOID", inv })

  // RQ-068 (S2 on TEE): a request that expired after a release, then a restart: re-ended.
  run rq068ReEndTest =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(req(1).outcome == "RELEASED")
      .then(restartWith(false))
      .expect(and { req(1).restart_end, st.signed_leaf.get(1) == "RELEASED", inv })

  // CP-005 / CP-013: one checkpoint carries every end of its interval and no settle write.
  run cp013BatchTest =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "none", 7))
      .then(schnorrOwner(2, 2, 3, 7)).then(authorize(2))
      .then(10.reps(_ => tick)).expect(and { req(1).phase == "EXPIRED", req(2).phase == "EXPIRED" })
      .then(landCheckpoint)
      .expect(and { st.cp.settle_root == Set((2, "VOID")), st.committee_txs == 1, st.record.rstate == "UNSPENT",
                    st.record.nf == 2, inv })

  // CP-009: after a restart the checkpoint jumps h by B.
  run cp009JumpTest =
    init.then(restartWith(false)).then(landCheckpoint)
      .expect(and { st.cp.h == B, st.cp.pending_min == B + 1, st.cp.restart_seq == 1, inv })

  // FINDING F3 regression (EN-023, DECISIONS 62): an envelope with exp = 10 orders at board height 5
  // (exp_c = 9 < 10) and is refused at height 6 (exp_c would be 10).
  run en023ExpCTest =
    init.then(schnorrOwner(1, 1, 2, 10)).then(4.reps(_ => tick)).then(order(1))
      .expect(and { req(1).exp_c == 9, req(1).exp == 10, inv_EN023_expCBelowExp, inv })
  run en023ExpCRefusedTest =
    init.then(schnorrOwner(1, 1, 2, 10)).then(5.reps(_ => tick))
      .then(order(1).fail())

  // FINDING F4 regression (SL-005, DECISIONS 63): request 1 has a dealer fault and never opens;
  // request 2, never authorized, waits for it (Q-003), lapses at 2 + DELTA_C, and opens after
  // request 1 ends VOID. The precedence it takes is lapsed and its committee slot burns at once.
  run sl005LateOpenLapsedTest =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "dealer_fault", 16))
      .then(postWith(2, "SCHNORR", "NONE", 1, false, 3, 4, 1, 2, "none", 16))
      .then(order(1)).then(order(2)).then(DELTA_C.reps(_ => tick))
      .expect(and { req(2).lapsed, not(req(2).hdr_open) })
      .then(postVoid(1, 1, 2, "DEALER_FAULT")).then(postVoid(1, 1, 3, "DEALER_FAULT"))
      .then(openHeader(2))
      .expect(and { req(2).hdr_open, st.cslots.get(3).prec == 2, st.cslots.get(3).bstat == "BURNED",
                    inv_SL005_SL010_lapsedPrecBurned, inv })

  // RQ-046 (lead ruling A): the tick that takes the board height past exp expires the request; no
  // request event lands in between. exp = 7, order at height 1: live at 7, EXPIRED at 8.
  run rq046UrgentExpiryTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(6.reps(_ => tick))
      .expect(and { st.board_height == 7, req(1).phase == "OPENED", inv })
      .then(tick)
      .expect(and { req(1).phase == "EXPIRED", req(1).end_height == 8, req(1).outcome == "VOID",
                    inv_RQ046_urgentExpiry, inv })
  run rq046UrgentExpiryBlocked1Test =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(7.reps(_ => tick))
      .then(admitWith(1, 1).fail())
  // The checkpoint raises the board height too: the request expires in it and its leaf goes to
  // the next root (end_height above the landed board height).
  run rq046ExpiryAtCheckpointTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1))
      .then(7.reps(_ => tick)).then(landCheckpoint)
      .expect(and { req(1).phase == "EXPIRED", req(1).end_height == 8, st.cp.board_height == 7,
                    st.cp.settle_root == Set(), inv })
      .then(landCheckpoint)
      .expect(and { st.cp.settle_root == Set((1, "VOID")), inv })

  // RQ-021 hold while ORDERED at a height at most exp_c; RQ-020 (lead ruling B) refuses the hold
  // above exp_c; RQ-075 (DECISIONS 70, lead ruling C) refuses an OPENED or ADMITTED target.
  action collectingOwner(e: int): bool = postWith(e, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13)
  run rq021FrameOrderedHeldTest =
    init.then(collectingOwner(1)).then(order(1)).then(DELTA_C.reps(_ => tick))
      .expect(and { st.board_height == req(1).exp_c, req(1).phase == "ORDERED" })
      .then(frame(1))
      .expect(and { req(1).frame_held, inv })
  run rq020FrameOrderedLateBlocked1Test =
    init.then(collectingOwner(1)).then(order(1)).then((DELTA_C + 1).reps(_ => tick))
      .expect(and { st.board_height == req(1).exp_c + 1, req(1).phase == "ORDERED" })
      .then(frame(1).fail())
  run rq075FrameOpenedBlocked1Test =
    init.then(collectingOwner(1)).then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1))
      .expect(and { req(1).phase == "OPENED", st.board_height <= req(1).exp_c })
      .then(frame(1).fail())
  run rq075FrameAdmittedBlocked1Test =
    init.then(collectingOwner(1)).then(frame(1)).then(authorize(1)).then(finalizeAuth(1)).then(order(1))
      .then(openHeader(1)).then(openedVote(1)).then(admitWith(1, 1))
      .expect(and { req(1).phase == "ADMITTED", st.board_height <= req(1).exp_c })
      .then(frame(1).fail())

  // RQ-076 (DECISIONS 70, lead ruling D): a restart that loses the board tail keeps the release
  // record of a request that released after the latest landed checkpoint.
  run rq076RestartKeepsReleaseTest =
    releasedOne
      .expect(and { req(1).release_height > st.cp.board_height, req(1).any_release })
      .then(restartWith(true))
      .expect(and { req(1).any_release, req(1).released.get(1) == 1, req(1).restart_end,
                    inv_RQ076_C11_releaseMonotone, inv })

  // RQ-025 (DECISIONS 68): AUTH_REFUSED is an admission check; no honest node posts it before the
  // authorization is in force, and every honest node posts it after.
  action refusedOwner(e: int): bool = postWith(e, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "auth_refused", 13)
  run rq025AuthRefusedTest =
    init.then(refusedOwner(1)).then(authorize(1)).then(order(1)).then(openHeader(1))
      .then(finalizeAuth(1))
      .then(postVoid(1, 1, 2, "AUTH_REFUSED")).then(postVoid(1, 1, 3, "AUTH_REFUSED"))
      .expect(and { req(1).phase == "VOID", req(1).reason == "AUTH_REFUSED", w_auth_refused,
                    inv_RQ025_SL016_admissionChecksInForce, inv })
  run rq025NotInForceBlocked1Test =
    init.then(refusedOwner(1)).then(authorize(1)).then(order(1)).then(openHeader(1))
      .expect(and { req(1).phase == "OPENED", not(inForce(st, 1)) })
      .then(postVoid(1, 1, 2, "AUTH_REFUSED").fail())

  // SL-016 (DECISIONS 68): request 1 (never authorized) holds prec on committee slot 1; request 2
  // names slot 1 too. Honest SLOT_TAKEN posts for request 2 only once its authorization is in force.
  run precHolderAndNamer =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "none", 13))
      .then(postWith(2, "SCHNORR", "OWNER", 1, false, 1, 3, 1, 2, "none", 13))
      .then(order(1)).then(order(2)).then(openHeader(1)).then(openHeader(2)).then(authorize(2))
  run sl016InForceTest =
    precHolderAndNamer.then(finalizeAuth(2))
      .then(postVoid(2, 1, 2, "SLOT_TAKEN")).then(postVoid(2, 1, 3, "SLOT_TAKEN"))
      .expect(and { req(2).phase == "VOID", req(2).reason == "SLOT_TAKEN", st.cslots.get(1).prec == 1,
                    inv_RQ025_SL016_admissionChecksInForce, inv })
  run sl016NotInForceBlocked1Test =
    precHolderAndNamer
      .expect(and { st.cslots.get(1).prec == 1, req(2).phase == "OPENED", not(inForce(st, 2)) })
      .then(postVoid(2, 1, 2, "SLOT_TAKEN").fail())

  // Finding F7 (CP-014, CP-040, SL-004, SL-013), regression test of DECISIONS 71: checkpoint 1
  // lands with pending_min 2 (request 1 reserved slot 2). Request 2, never authorized, then takes
  // precedence on slot 1 (SL-004). Revision 6 listed slot 1, so the honest checkpoint had
  // pending_min 1 and CP-040 refused it (cp040PendingMinLoweredBlocked1Test of revision 6). CP-014
  // now lists only slots at or above the landed pending_min, so the checkpoint lands with
  // pending_min 2, and SL-013 still ends request 2 VOID with SLOT_TAKEN.
  run pendingFloorSetUp =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 2, 3, 1, 2, "none", 16))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(landCheckpoint)
      .expect(and { st.cp.pending_min == 2, st.cp.h == 2, inv })
      .then(postWith(2, "SCHNORR", "NONE", 1, false, 1, 4, 1, 2, "none", 16))
      .then(order(2)).then(openHeader(2))
      .expect(and { st.cslots.get(1).prec == 2, w_prec_below_floor, not(w_cp_pending_min_lowered),
                    inv_CP014_CP040_honestFloorKept })
  run f7SpamPrecedenceLandsTest =
    pendingFloorSetUp.then(landCheckpoint)
      .expect(and { st.cp.seq == 2, st.cp.pending_min == 2, not(st.cp.pending.contains((1, 2))),
                    st.cp.pending.contains((2, 1)), st.cp.pending_count == st.cp.pending.size(),
                    st.cslots.get(1).prec == 2, inv_CP040_pendingMinForward, inv })
      .then(postVoid(2, 1, 2, "SLOT_TAKEN")).then(postVoid(2, 1, 3, "SLOT_TAKEN"))
      .expect(and { req(2).phase == "VOID", req(2).reason == "SLOT_TAKEN", st.cslots.get(1).bstat == "BURNED", inv })
  // CP-040 scenario "Old index pending again": a checkpoint with pending_min 1 after a landed
  // pending_min 3 is refused. No honest checkpoint lowers the floor any more (DECISIONS 71), so
  // the contract rule is checked on a hand-built checkpoint.
  run cp040OldIndexRefusedTest = all {
    assert(cpCode({ ...cpZero, seq: 1, h: 3, pending_min: 3 }, { ...cpZero, seq: 2, h: 3, pending_min: 1 }, false)
           == "pending_min_lowered"),
    assert(cpCode({ ...cpZero, seq: 1, h: 3, pending_min: 3 }, { ...cpZero, seq: 2, h: 3, pending_min: 3 }, false) == ""),
    init,
  }
  run cp040LapseUnblocksTest =
    pendingFloorSetUp.then(DELTA_C.reps(_ => tick))
      .expect(and { req(2).lapsed, st.cslots.get(1).bstat == "BURNED", not(w_cp_pending_min_lowered) })
      .then(landCheckpoint)
      .expect(and { st.cp.pending_min == 2, inv_CP040_pendingMinForward, inv })

  // SH-030 to SH-037 (DECISIONS 67): the holder acknowledges with pop_u, q members sign ACK_OK,
  // acknowledge sets acked, and only then a payer pays.
  run shAckPayTest =
    init.then(registerAddr(true)).expect(and { st.addr.registered, not(st.addr.acked) })
      .then(holderAck).then(ackOk(2)).then(ackOk(3)).then(ackOk(4)).then(acknowledge)
      .expect(st.addr.acked)
      .then(payAddr)
      .expect(and { st.addr.paid, w_paid_acked, inv_SH033_SH037_ackedNeedsCertificate,
                    inv_SH031_SH036_C1_ackedOnlyRightEc, inv_SH035_payOnlyAcked, inv })
  run shWrongEcBlocked1Test = init.then(registerAddr(false)).then(holderAck.fail())
  run shCreatorAckBlocked1Test =
    init.then(registerAddr(false)).then(creatorAck).then(ackOk(1)).expect(and { w_creator_ack, inv })
      .then(ackOk(2).fail())
  run shShortCertificateBlocked1Test =
    init.then(registerAddr(true)).then(holderAck).then(ackOk(1)).then(ackOk(2)).then(acknowledge.fail())
  run shPayBeforeAckBlocked1Test = init.then(registerAddr(true)).then(payAddr.fail())
}

// --------------------------------------------------------------- design, NON_TEE P2
module test_nontee_p2 {
  import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "none").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  // RQ-069: the RELEASE commits before the partials leave.
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(recordRelease(1, 1)).then(sendRelease(1, 1))

  // S2 on NON_TEE: the request released and expired (RELEASED), and a restart that loses the board
  // tail with the RELEASE burns its slot before the next checkpoint: RQ-068 re-ends it RELEASED.
  run rq068NonTeeRestartTest =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(and { req(1).outcome == "RELEASED", inv })
      .then(restartWith(true))
      .expect(and { req(1).restart_end, req(1).any_release, req(1).released.get(1) == 1,
                    st.signed_leaf.get(1) == "RELEASED", inv })
      .then(landCheckpoint)
      .expect(and { st.record.rstate == "LOCKED", inv })

  // FINDING F1 regression (RQ-069, DECISIONS 59). The revision-2 schedule sent the partials with
  // no committed RELEASE; that send now fails.
  run f1NonTeeExpiryDoubleSpendBlocked1Test =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1).fail())
  // With the record first, the expiry settles RELEASED, the record stays LOCKED to pin 1, the
  // re-post authorizes pin 1, and the second confirmation fails (Blocked2).
  run f1NonTeeExpiryDoubleSpendTest =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(and { req(1).outcome == "RELEASED", inv_RQ069_C11_sentNeverVoid })
      .then(landCheckpoint)
      .expect(and { st.auths.get(1).settled == "RELEASED", st.record.rstate == "LOCKED", st.record.pin == 1, inv })
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .expect(st.auths.get(2).pin == 1)
      .then(finalizeAuth(2)).then(tickMidnight)
      .then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(recordRelease(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2))
      .expect(and { inv_AU024_C11_oneSpendPerRecordState, inv })
  run f1NonTeeExpiryDoubleSpendBlocked2Test =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .then(landCheckpoint)
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .then(finalizeAuth(2)).then(tickMidnight)
      .then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(recordRelease(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2))
      .then(hostConfirm(1).fail())
}

// ------------------------------------------------------------------------ mutants
module test_m_restart_void_unspent {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "restart_void_unspent").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1))
  // Item 14 killed this mutant on releasedOne: the restart with a lost tail cleared any_release.
  // RQ-076 (DECISIONS 70) keeps any_release, so that schedule settles RELEASED under the mutant as
  // well (killRestartVoidUnspentReleasedSurvivesTest). The kill now uses an admitted request with
  // no release: the mutant settles its restart end VOID, against RQ-052.
  run killRestartVoidUnspentTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(restartWith(true))
      .then(postVoid(1, 1, 2, "RESTART")).then(postVoid(1, 1, 3, "RESTART"))
      .expect(and { req(1).outcome == "VOID", not(inv_RQ052_RQ068_C11_restartEndNeverVoid) })
  run killRestartVoidUnspentReleasedSurvivesTest =
    releasedOne
      .then(restartWith(true))
      .then(postVoid(1, 1, 2, "RESTART")).then(postVoid(1, 1, 3, "RESTART"))
      .expect(and { req(1).outcome == "RELEASED", inv_RQ052_RQ068_C11_restartEndNeverVoid })
}
module test_m_d058_b_nontee {
  import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "d058_b").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(recordRelease(1, 1)).then(sendRelease(1, 1))
  // Revision 3: with RQ-069 the expired request already settles RELEASED, so option (b) no longer
  // reaches a second spend here; it still leaves the request without its restart re-end.
  run killD058bTest =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .then(restartWith(false))
      .expect(not(inv_RQ068_C11_reEnded))
}
module test_m_d058_b {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "d058_b").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1))
  run killD058bTeeTest =
    releasedOne.then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED").then(restartWith(false))
      .expect(not(inv_RQ068_C11_reEnded))
}
module test_m_replace_held {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "replace_held").* from "./splitspec"
  run killReplaceHeldTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED")).then(postVoid(1, 1, 3, "STALLED"))
      .then(postWith(2, "SCHNORR", "OWNER", 1, false, 3, 4, 1, 2, "none", 13)).then(reissue(1, 2))
      .then(restartWith(false))
      .expect(not(inv_RQ054_C11_heldLeafNeverReplaced))
}
module test_m_ecdsa_prec_at_open {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ecdsa_prec_at_open").* from "./splitspec"
  run killEcdsaPrecAtOpenTest =
    init.then(postWith(1, "ECDSA", "NONE", 1, false, 1, 2, 1, 2, "none", 13))
      .then(postWith(2, "ECDSA", "OWNER", 1, false, 1, 2, 1, 2, "none", 13))
      .then(order(1)).then(order(2)).then(openHeader(1))
      .expect(not(inv_SL007_C13_ecdsaPrecOnlyInForce))
      .then(openHeader(2)).then(authorize(2)).then(finalizeAuth(2))
      .then(postVoid(2, 1, 2, "SLOT_TAKEN"))
      .expect(not(inv_RQ063_C13_ecdsaTakenOnlyByInForce))
}
module test_m_committee_burn_reserved_only {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "committee_burn_reserved_only").* from "./splitspec"
  run killCommitteeBurnReservedOnlyTest =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "none", 7))
      .then(order(1)).then(openHeader(1)).then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(not(inv_SL010_committeeBurnAtPrecEnd))
}
module test_m_ecdsa_burn_by_namer {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ecdsa_burn_by_namer").* from "./splitspec"
  run killEcdsaBurnByNamerTest =
    init.then(postWith(1, "ECDSA", "NONE", 1, false, 1, 2, 1, 2, "none", 7))
      .then(order(1)).then(openHeader(1)).then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(not(inv_SL011_SL028_ecdsaBurnOnlyByReserver))
}
module test_m_settle_per_request {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "settle_per_request").* from "./splitspec"
  run killSettlePerRequestTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 7)).then(authorize(1))
      .then(8.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(not(inv_CP005_batchedWrites))
}
module test_m_root_omit {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "root_omit").* from "./splitspec"
  run killRootOmitTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 7)).then(authorize(1))
      .then(8.reps(_ => tick)).expect(req(1).phase == "EXPIRED").then(landCheckpoint)
      .expect(not(inv_CP013_AU020_settledByRoot))
}
module test_m_no_jump {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "no_jump").* from "./splitspec"
  run killNoJumpTest =
    init.then(restartWith(false)).then(landCheckpoint)
      .expect(not(inv_CP007_CP008_CP009_landedChain))
}
module test_m_cross_epoch {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "cross_epoch").* from "./splitspec"
  run killCrossEpochTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 7)).then(rotate)
      .then(postVoid(1, 1, 1, "STALLED")).then(postVoid(1, 2, 1, "STALLED"))
      .expect(not(inv_RQ042_C13_voidNeedsHonestPost))
}
module test_m_ignore_revoke {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ignore_revoke").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1))
  run killIgnoreRevokeTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(revoke(1)).then(sendRelease(1, 1))
      .expect(not(inv_RQ059_C7_noReleaseAfterRevoke))
}
module test_m_any_variant {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "any_variant").* from "./splitspec"
  run killAnyVariantTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 2, false, 1, 2, 1, 2, "none", 13)).then(authorize(1))
      .then(finalizeAuth(1)).then(tickMidnight).then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendReleaseWith(1, 1, 1)).then(sendReleaseWith(1, 1, 2))
      .expect(and { not(inv_RQ058_C9_oneVariantPerGeneration), not(inv_SL027_C12_oneTicketPerSlot) })
}

// --------------------------------------------------------------- design, TEE P1
module test_tee_p1 {
  import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "none").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  run releasedOne =
    init
      .then(schnorrOwner(1, 1, 2, 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1))
      .then(sendRelease(1, 1))

  // FINDING F2 regression (RQ-045, RQ-072, DECISIONS 61): in a P1 charter one honest MALFORMED
  // post and one corrupt REVOKED post complete the tombstone; its reason is MIXED, not REVOKED.
  run f2CorruptReasonTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "malformed", 13))
      .then(order(1)).then(openHeader(1))
      .then(postVoid(1, 1, 2, "MALFORMED")).then(postVoid(1, 1, 1, "REVOKED"))
      .expect(and { req(1).phase == "VOID", req(1).reason == "MIXED", inv_RQ045_RQ072_C13_C20_reasonHasHonestPost, inv })

  // FINDING F5 regression (AU-029, DECISIONS 60): the re-post of a RELEASED request authorizes on
  // pin 1 and settles VOID; the record stays LOCKED to pin 1, the next authorization takes pin 1,
  // and the confirmation of pin 1 after pin 2's request spent it fails (Blocked2).
  run f5LockedVoidUnlocksTest =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .then(landCheckpoint)
      .expect(and { st.record.rstate == "LOCKED", st.record.pin == 1, inv })
      .then(schnorrOwner(3, 3, 4, 7)).then(authorize(3))
      .expect(st.auths.get(3).pin == 1)
      .then(8.reps(_ => tick)).expect(req(3).phase == "EXPIRED")
      .then(landCheckpoint)
      .expect(and { st.auths.get(3).settled == "VOID", st.record.rstate == "LOCKED", st.record.pin == 1, inv })
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .expect(and { st.auths.get(2).pin == 1, inv_AU025_C11_releasedNeverUnspent, inv })
      .then(finalizeAuth(2)).then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2))
      .expect(and { inv_AU024_C11_oneSpendPerRecordState, inv })
  run f5LockedVoidUnlocksBlocked2Test =
    releasedOne
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED").then(landCheckpoint)
      .then(schnorrOwner(3, 3, 4, 7)).then(authorize(3))
      .then(8.reps(_ => tick)).expect(req(3).phase == "EXPIRED").then(landCheckpoint)
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .then(finalizeAuth(2)).then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2))
      .then(hostConfirm(1).fail())

  // F6 (C20, DECISIONS 64, owner ruling): honest member 2 posts STALLED at exp_c on a filled
  // collecting request; the q ADMIT votes commit after it (late admission stays allowed),
  // generation 1 releases, and corrupt member 1 completes the tombstone with STALLED. Revision 3
  // gave reason STALLED; with any_release = true the STALLED posts are no reason posts (RQ-074),
  // so the reason is MIXED and the outcome RELEASED.
  run f6StalledAfterAdmitTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(frame(1)).then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED"))
      .then(admitWith(1, 1)).then(sendRelease(1, 1))
      .then(postVoid(1, 1, 1, "STALLED"))
      .expect(and { req(1).phase == "VOID", req(1).reason == "MIXED", req(1).outcome == "RELEASED",
                    req(1).any_release, inv_C20_stalledReleasedNothing, inv_RQ073_C20_noStalledAfterRelease, inv })
  // Without a RELEASE the same two posts still give STALLED (RQ-047, RQ-045).
  run f6StalledNoReleaseTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED")).then(postVoid(1, 1, 1, "STALLED"))
      .expect(and { req(1).phase == "VOID", req(1).reason == "STALLED", req(1).outcome == "VOID", inv })
}

// ------------------------------------------------- mutants of revision 3 (DECISIONS 59 to 63)
module test_m_send_before_record {
  import splitspec(MODE = "NON_TEE", PROFILE = "P2", MUT = "send_before_record").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  // The revision-2 F1 schedule: send with no committed RELEASE, expire VOID, two confirmations.
  run killSendBeforeRecordTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(sendRelease(1, 1))
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED")
      .expect(and { req(1).outcome == "VOID", not(inv_RQ069_C11_sentNeverVoid) })
      .then(landCheckpoint)
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2)).then(finalizeAuth(2)).then(tickMidnight)
      .then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2)).then(hostConfirm(1))
      .expect(not(inv_AU024_C11_oneSpendPerRecordState))
}
module test_m_locked_void_unlocks {
  import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "locked_void_unlocks").* from "./splitspec"
  action schnorrOwner(e: int, c1: int, c2: int, expOff: int): bool =
    postWith(e, "SCHNORR", "OWNER", 1, false, c1, c2, 1, 2, "none", expOff)
  // The revision-2 F5 schedule.
  run killLockedVoidUnlocksTest =
    init.then(schnorrOwner(1, 1, 2, 7)).then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(sendRelease(1, 1))
      .then(7.reps(_ => tick)).expect(req(1).phase == "EXPIRED").then(landCheckpoint)
      .then(schnorrOwner(3, 3, 4, 7)).then(authorize(3))
      .then(8.reps(_ => tick)).expect(req(3).phase == "EXPIRED").then(landCheckpoint)
      .expect(and { st.record.rstate == "UNSPENT", st.record.pin == -1 })
      .then(schnorrOwner(2, 3, 4, 13)).then(authorize(2))
      .expect(and { st.auths.get(2).pin == 2, not(inv_AU025_C11_releasedNeverUnspent) })
      .then(finalizeAuth(2)).then(order(2)).then(openHeader(2)).then(admitWith(2, 1)).then(sendRelease(2, 1))
      .then(hostConfirm(2)).then(hostConfirm(1))
      .expect(not(inv_AU024_C11_oneSpendPerRecordState))
}
module test_m_completing_reason {
  import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "completing_reason").* from "./splitspec"
  // The revision-2 F2 schedule: the corrupt completing post names REVOKED in P1.
  run killCompletingReasonTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "malformed", 13))
      .then(order(1)).then(openHeader(1))
      .then(postVoid(1, 1, 2, "MALFORMED")).then(postVoid(1, 1, 1, "REVOKED"))
      .expect(and { req(1).reason == "REVOKED", not(inv_RQ045_RQ072_C13_C20_reasonHasHonestPost) })
}
module test_m_stalled_after_release {
  import splitspec(MODE = "TEE", PROFILE = "P1", MUT = "stalled_after_release").* from "./splitspec"
  // The revision-3 F6 schedule: STALLED posts count for the reason after the release.
  run killStalledAfterReleaseTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, true, 1, 2, 1, 2, "none", 13))
      .then(authorize(1)).then(finalizeAuth(1)).then(order(1)).then(openHeader(1)).then(openedVote(1))
      .then(frame(1)).then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "STALLED"))
      .then(admitWith(1, 1)).then(sendRelease(1, 1))
      .then(postVoid(1, 1, 1, "STALLED"))
      .expect(and { req(1).reason == "STALLED", req(1).any_release,
                    not(inv_C20_stalledReleasedNothing), not(inv_RQ073_C20_noStalledAfterRelease) })
}
module test_m_stalled_after_release_nontee {
  import splitspec(MODE = "NON_TEE", PROFILE = "P1", MUT = "stalled_after_release").* from "./splitspec"
  // The F6 schedule on the NON_TEE path: state 40 of the revision 3 seed 0x14 trace and steps 41,
  // 48 and 50 at height 16 (replay_f6.qnt, replayF6Seed14MutantTest). On MUT = "none" the same
  // schedule ends with reason MIXED (replayF6Seed14UrgentTest).
  pure val s40_st = { auths: Map(1 -> { auth: 1, coin: 1, final_height: 0, nf: 1, pin: 1, settled: "NONE", status: "FINAL" }), board_height: 16, checkpoints: 6, committee_txs: 7, cp: { board_height: 14, h: 0, pending: Set((1, 1), (2, 1)), pending_count: 2, pending_min: 1, restart_seq: 0, seq: 6, settle_root: Set() }, cslots: Map(1 -> { bstat: "RESERVED", namers: Set(1), prec: 1, rsv: true }, 2 -> { bstat: "RESERVED", namers: Set(1), prec: 1, rsv: true }, 3 -> { bstat: "UNNAMED", namers: Set(), prec: 0, rsv: false }, 4 -> { bstat: "UNNAMED", namers: Set(), prec: 0, rsv: false }), eks_writes: 1, epochs: Set(1, 2), eslots: Map(1 -> { bstat: "UNNAMED", namers: Set(3), prec: 0, reserver: 0, root: "OWN" }, 2 -> { bstat: "UNNAMED", namers: Set(3), prec: 0, reserver: 0, root: "OWN" }, 3 -> { bstat: "UNNAMED", namers: Set(), prec: 0, reserver: 0, root: "G" }), held: Map(), host_spent: Set(), midnight_height: 8, posts: Set({ eid: 1, epoch: 1, kind: "VOID", member: 4, reason: "STALLED" }, { eid: 1, epoch: 2, kind: "FINAL", member: 1, reason: "NONE" }, { eid: 1, epoch: 2, kind: "VOID", member: 1, reason: "SLOT_TAKEN" }, { eid: 2, epoch: 1, kind: "FINAL", member: 1, reason: "NONE" }, { eid: 2, epoch: 1, kind: "VOID", member: 1, reason: "REVOKED" }, { eid: 2, epoch: 2, kind: "FINAL", member: 1, reason: "NONE" }, { eid: 2, epoch: 2, kind: "VOID", member: 1, reason: "MALFORMED" }, { eid: 3, epoch: 1, kind: "VOID", member: 1, reason: "DEALER_FAULT" }, { eid: 3, epoch: 2, kind: "FINAL", member: 1, reason: "NONE" }, { eid: 3, epoch: 2, kind: "VOID", member: 1, reason: "SLOT_TAKEN" }), record: { coin: 1, hold_set: false, next_nf: 2, next_pin: 2, nf: 1, nf_used: true, pending_auth: 1, pin: -1, rstate: "PENDING" }, requests: Map(1 -> { G: 2, K: 2, L: 1, anchor: Map(1 -> 0, 2 -> 0), any_release: false, collecting: true, complaint: "none", cslot: Map(1 -> 1, 2 -> 2), dealer_fault_recorded: false, eid: 1, end_height: -1, epoch: 1, eslot: Map(1 -> 1, 2 -> 2), exp: 16, exp_c: 9, fault: "none", filled: true, frame_held: true, hdr_open: true, lapsed: false, order_pos: 5, outcome: "NONE", phase: "COLLECTING", profile: "P1", reason: "NONE", release_height: -1, released: Map(1 -> 0, 2 -> 0), req_type: "SPEND", restart_end: false, source: "OWNER", suite: "SCHNORR" }, 2 -> { G: 1, K: 1, L: 1, anchor: Map(1 -> 0, 2 -> 0), any_release: false, collecting: false, complaint: "none", cslot: Map(1 -> 2, 2 -> 1), dealer_fault_recorded: false, eid: 2, end_height: -1, epoch: 1, eslot: Map(1 -> 3, 2 -> 2), exp: 16, exp_c: -1, fault: "none", filled: false, frame_held: false, hdr_open: false, lapsed: false, order_pos: -1, outcome: "NONE", phase: "POSTED", profile: "P1", reason: "NONE", release_height: -1, released: Map(1 -> 0, 2 -> 0), req_type: "SPEND", restart_end: false, source: "OWNER", suite: "SCHNORR" }, 3 -> { G: 2, K: 2, L: 1, anchor: Map(1 -> 0, 2 -> 0), any_release: false, collecting: false, complaint: "none", cslot: Map(1 -> 3, 2 -> 2), dealer_fault_recorded: false, eid: 3, end_height: -1, epoch: 1, eslot: Map(1 -> 1, 2 -> 2), exp: 18, exp_c: 10, fault: "none", filled: false, frame_held: false, hdr_open: true, lapsed: true, order_pos: 6, outcome: "NONE", phase: "OPENED", profile: "P1", reason: "NONE", release_height: -1, released: Map(1 -> 0, 2 -> 0), req_type: "SPEND", restart_end: false, source: "OWNER", suite: "ECDSA" }), restart_open: false, restarts: 0, signed_leaf: Map(), addr: { registered: false, ec_ok: false, ack_env: "NONE", ack_ok: Set(), acked: false, paid: false } }
  pure val s40_g = { admitted: Set(), burn_hi: -1, burn_lo: 0, burned_pending: 0, burned_usable: 0, cp_prev: { board_height: 10, h: 0, pending: Set((1, 1), (2, 1)), pending_count: 2, pending_min: 1, restart_seq: 0, seq: 5, settle_root: Set() }, eburn_restart: Set(), first_after_restart: false, hdr_sent: Set(1, 3), held_changed: false, honest_void: Set((1, "STALLED")), restart_hit: Set(), sent: Set(), sent_revoked: Set(), slot_tickets: Set(), taken_by: Set(), rel_seen: Set(), adm_posts: Set() }
  pure val s40_lastOp = { arg: 11, code: "", eid: 2, kind: "post_void" }

  action load(s: State, gg: Ghost, op: Op): bool = all { st' = s, g' = gg, lastOp' = op }
  run killStalledAfterReleaseNonteeTest =
    load(s40_st, s40_g, s40_lastOp)
      .then(admitWith(1, 2)).then(recordRelease(1, 1))
      .then(postVoid(1, 1, 1, "STALLED"))
      .expect(and { req(1).reason == "STALLED", req(1).any_release, not(inv_RQ073_C20_noStalledAfterRelease) })
}
module test_m_exp_c_unchecked {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "exp_c_unchecked").* from "./splitspec"
  run killExpCUncheckedTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 10)).then(5.reps(_ => tick))
      .then(order(1))
      .expect(and { req(1).exp_c == 10, not(inv_EN023_expCBelowExp) })
}
module test_m_lapse_once {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "lapse_once").* from "./splitspec"
  // The F4 schedule: the late header takes a lapsed precedence that nothing burns.
  run killLapseOnceTest =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "dealer_fault", 16))
      .then(postWith(2, "SCHNORR", "NONE", 1, false, 3, 4, 1, 2, "none", 16))
      .then(order(1)).then(order(2)).then(DELTA_C.reps(_ => tick))
      .then(postVoid(1, 1, 2, "DEALER_FAULT")).then(postVoid(1, 1, 3, "DEALER_FAULT"))
      .then(openHeader(2))
      .expect(and { req(2).lapsed, st.cslots.get(3).bstat == "NAMED", not(inv_SL005_SL010_lapsedPrecBurned) })
}

// ------------------------------------------- mutants of the item 14 replay rulings (DECISIONS 70)
module test_m_late_expiry {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "late_expiry").* from "./splitspec"
  // Ruling A planted back: the board passes exp and the request stays live until `expire`.
  run killLateExpiryTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 7)).then(authorize(1))
      .then(finalizeAuth(1)).then(tickMidnight).then(order(1)).then(openHeader(1)).then(7.reps(_ => tick))
      .expect(and { req(1).phase == "OPENED", st.board_height == 8, not(inv_RQ046_urgentExpiry) })
      .then(admitWith(1, 1))
      .expect(req(1).phase == "ADMITTED")
}
module test_m_restart_clears_release {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "restart_clears_release").* from "./splitspec"
  // Ruling D planted back: the restart with a lost tail clears the release record.
  run killRestartClearsReleaseTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "none", 7))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(sendRelease(1, 1))
      .then(restartWith(true))
      .expect(and { not(req(1).any_release), not(inv_RQ076_C11_releaseMonotone) })
}

// ------------------------------------- mutants of the design corrections (DECISIONS 67 to 69)
module test_m_auth_refused_before_force {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "auth_refused_before_force").* from "./splitspec"
  run killAuthRefusedBeforeForceTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 1, 2, 1, 2, "auth_refused", 13))
      .then(authorize(1)).then(order(1)).then(openHeader(1))
      .then(postVoid(1, 1, 2, "AUTH_REFUSED"))
      .expect(not(inv_RQ025_SL016_admissionChecksInForce))
}
module test_m_taken_before_force {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "taken_before_force").* from "./splitspec"
  run killTakenBeforeForceTest =
    init.then(postWith(1, "SCHNORR", "NONE", 1, false, 1, 2, 1, 2, "none", 13))
      .then(postWith(2, "SCHNORR", "OWNER", 1, false, 1, 3, 1, 2, "none", 13))
      .then(order(1)).then(order(2)).then(openHeader(1)).then(openHeader(2)).then(authorize(2))
      .then(postVoid(2, 1, 2, "SLOT_TAKEN"))
      .expect(not(inv_RQ025_SL016_admissionChecksInForce))
}
module test_m_pending_min_unchecked {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pending_min_unchecked").* from "./splitspec"
  // Since DECISIONS 71 no honest checkpoint lowers pending_min, so no schedule of the model reaches
  // the rule (random runs survive). The kill is the CP-040 scenario on a hand-built checkpoint:
  // the mutant accepts pending_min 1 after a landed 3 (design twin: cp040OldIndexRefusedTest).
  run killPendingMinUncheckedTest = all {
    assert(cpCode({ ...cpZero, seq: 1, h: 3, pending_min: 3 }, { ...cpZero, seq: 2, h: 3, pending_min: 1 }, false) == ""),
    init,
  }
}
module test_m_pending_unwindowed {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pending_unwindowed").* from "./splitspec"
  // The F7 schedule with the CP-014 listing of revision 6: slot 1 below the landed floor is listed,
  // the honest checkpoint has pending_min 1, and CP-040 refuses it.
  run killPendingUnwindowedTest =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 2, 3, 1, 2, "none", 16))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(landCheckpoint)
      .then(postWith(2, "SCHNORR", "NONE", 1, false, 1, 4, 1, 2, "none", 16))
      .then(order(2)).then(openHeader(2))
      .expect(and { nextCp(st, g).pending_min == 1, w_cp_pending_min_lowered, not(inv_CP014_CP040_honestFloorKept) })
  run killPendingUnwindowedBlocked1Test =
    init.then(postWith(1, "SCHNORR", "OWNER", 1, false, 2, 3, 1, 2, "none", 16))
      .then(authorize(1)).then(finalizeAuth(1)).then(tickMidnight)
      .then(order(1)).then(openHeader(1)).then(admitWith(1, 1)).then(landCheckpoint)
      .then(postWith(2, "SCHNORR", "NONE", 1, false, 1, 4, 1, 2, "none", 16))
      .then(order(2)).then(openHeader(2)).then(landCheckpoint.fail())
}
module test_m_ack_without_pop {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ack_without_pop").* from "./splitspec"
  run killAckWithoutPopTest =
    init.then(registerAddr(false)).then(creatorAck).then(ackOk(2)).then(ackOk(3)).then(ackOk(4))
      .then(acknowledge)
      .expect(not(inv_SH031_SH036_C1_ackedOnlyRightEc))
}
module test_m_ack_cert_short {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "ack_cert_short").* from "./splitspec"
  run killAckCertShortTest =
    init.then(registerAddr(false)).then(creatorAck).then(ackOk(1)).then(acknowledge)
      .expect(and { not(inv_SH033_SH037_ackedNeedsCertificate), not(inv_SH031_SH036_C1_ackedOnlyRightEc) })
}
module test_m_pay_before_ack {
  import splitspec(MODE = "TEE", PROFILE = "P2", MUT = "pay_before_ack").* from "./splitspec"
  run killPayBeforeAckTest =
    init.then(registerAddr(true)).then(payAddr)
      .expect(not(inv_SH035_payOnlyAcked))
}
