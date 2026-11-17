// -*- mode: Bluespec; -*-
// Tests of passportShard: one refusal test per guard of SHARD-SPEC §5, with
// multi-code refusals, and acceptance tests for the effects that the
// invariants rely on. Run: quint test passportShard_test.qnt --main passportShardTest --match '^(t|od[0-9]+)_'
module passportShardTest {
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(3), synced: Set(0, 1, 2), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 0
  ).* from "./passportShard"

  action A(name: str, by: int, d: int, ic: int, nf: int, succ: int, g: int, u: bool): bool =
    attempt(mk(name, by, d, ic, nf, succ, g, u))
  action op0(name: str): bool = A(name, 0, 0, 0, 0, 0, 0, false)
  action enroll(by: int, d: int): bool = A("ENROLL", by, d, 0, 0, 0, 0, false)
  action unlock(d: int, ic: int): bool = A("UNLOCK", 0, d, ic, 0, 0, 0, false)
  action approve(d: int, ic: int, nf: int): bool = A("APPROVE", 0, d, ic, nf, 0, 0, false)
  action authorize(d: int, ic: int, nf: int): bool = A("AUTHORIZE", 0, d, ic, nf, 0, 0, false)
  action release(ic: int, nf: int): bool = A("RELEASE", 0, 0, ic, nf, 0, 0, false)
  action corruptG(g: int): bool = A("CORRUPT_GUARDIAN", 0, 0, 0, 0, 0, g, false)

  def accepted: bool = lastRefused == Set()

  // ---- ENROLL (PS-007)
  run t_enroll_refusals =
    init.then(enroll(1, 0)).expect(lastRefused == Set("not-enrolled", "no-wrap", "already-enrolled"))
  run t_enroll_alreadyEnrolled =
    init.then(enroll(0, 0)).expect(lastRefused == Set("already-enrolled"))
  run t_enroll_bySuccessor = // creds is a subset of readers, so no-wrap never fails alone
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 1, 0, false))
      .then(op0("RECOVER_FINALISE"))
      .then(enroll(1, 2)).expect(accepted)
  run t_enroll_notEnrolled_only = // removed device 1 keeps its wrap (PS-008)
    init.then(enroll(0, 1)).then(A("REMOVE_DEVICE", 0, 1, 0, 0, 0, 0, false))
      .then(enroll(1, 2)).expect(lastRefused == Set("not-enrolled"))
  run t_enroll_pendingSuccessor = // PS-067, honest pending recovery
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 1, 0, false))
      .then(enroll(0, 1)).expect(lastRefused == Set("pending-successor"))
  run t_enroll_pendingSuccessor_combined = // PS-007 and PS-067 codes together
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 1, 0, false))
      .then(enroll(3, 1)).expect(lastRefused == Set("not-enrolled", "no-wrap", "pending-successor"))
  run t_enroll_afterCancel = // the guard ends with the pending recovery
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 1, 0, false))
      .then(A("RECOVER_CANCEL", 0, 0, 0, 0, 0, 0, false))
      .then(enroll(0, 1)).expect(and { accepted, s.creds == Set(0, 1) })
  run t_enroll_effect =
    init.then(enroll(0, 1)).expect(and {
      accepted, s.creds == Set(0, 1), s.readers == Set(0, 1), s.prf_log == Set(0) })

  // ---- REMOVE_DEVICE (PS-009)
  run t_remove_refusals =
    init.then(A("REMOVE_DEVICE", 1, 1, 0, 0, 0, 0, false))
      .expect(lastRefused == Set("not-enrolled", "unknown-device", "self-removal"))
  run t_remove_self =
    init.then(A("REMOVE_DEVICE", 0, 0, 0, 0, 0, 0, false)).expect(lastRefused == Set("self-removal"))
  run t_remove_effect =
    init.then(enroll(0, 1)).then(A("REMOVE_DEVICE", 1, 0, 0, 0, 0, 0, false))
      .expect(and { accepted, s.creds == Set(1), s.readers == Set(0, 1) })

  // ---- UNLOCK (PS-013)
  run t_unlock_refusals =
    init.then(unlock(2, 0)).expect(lastRefused == Set("not-enrolled", "no-wrap"))
  run t_unlock_removed =
    init.then(enroll(0, 1)).then(A("REMOVE_DEVICE", 0, 1, 0, 0, 0, 0, false))
      .then(unlock(1, 0)).expect(lastRefused == Set("not-enrolled"))
  run t_unlock_originLeak = // PS-012 on a web reader
    init.then(op0("CORRUPT_ORIGIN")).then(unlock(0, 1))
      .expect(and { accepted, s.adv_root, s.via_origin_leak == Set(0), s.unlock_log == Set((0, 1)) })
  run t_unlock_nativeNoLeak = // PS-012 does not apply to a native reader
    init.then(enroll(0, 3)).then(op0("CORRUPT_ORIGIN")).then(unlock(3, 1))
      .expect(and { accepted, not(s.adv_root), s.via_origin_leak == Set() })

  // ---- APPROVE (PS-017)
  run t_approve_notEnrolled =
    init.then(approve(1, 0, 0)).expect(lastRefused == Set("not-enrolled"))

  // ---- AUTHORIZE (PS-019, PS-020, PS-021)
  run t_authorize_refusals =
    init.then(authorize(1, 0, 0)).expect(lastRefused == Set("no-assertion", "not-enrolled"))
  run t_authorize_nfUsed =
    init.then(approve(0, 0, 0)).then(approve(0, 1, 0)).then(authorize(0, 0, 0))
      .then(authorize(0, 1, 0)).expect(lastRefused == Set("nf-used"))
  run t_authorize_removedCred = // PS-020: the honest path refuses a removed credential
    init.then(enroll(0, 1)).then(approve(1, 0, 0)).then(A("REMOVE_DEVICE", 0, 1, 0, 0, 0, 0, false))
      .then(authorize(1, 0, 0)).expect(lastRefused == Set("not-enrolled"))

  // ---- RELEASE (PS-023, PS-024, PS-025)
  run t_release_refusals =
    init.then(op0("CORRUPT_COMMITTEE")).then(release(0, 0))
      .expect(lastRefused == Set("committee-corrupt", "not-authorized", "no-contribution"))
  run t_release_noContribution =
    init.then(approve(0, 0, 0)).then(authorize(0, 0, 0)).then(release(0, 0))
      .expect(lastRefused == Set("no-contribution"))
  run t_release_ok =
    init.then(unlock(0, 0)).then(approve(0, 0, 0)).then(authorize(0, 0, 0)).then(release(0, 0))
      .expect(and { accepted, s.sigs == Set(0) })
  run t_release_afterReprovision = // PS-042: the successor committee is honest
    init.then(op0("CORRUPT_COMMITTEE")).then(op0("E_REPROVISION"))
      .then(unlock(0, 0)).then(approve(0, 0, 0)).then(authorize(0, 0, 0)).then(release(0, 0))
      .expect(and { accepted, s.adv_xf, s.epoch == 1 })

  // ---- PUBLISH_RWRAP (PS-031)
  run t_rwrap_refusals =
    init.then(A("PUBLISH_RWRAP", 2, 0, 0, 0, 0, 0, false)).expect(lastRefused == Set("not-enrolled", "no-wrap"))

  // ---- RECOVER_SUBMIT (PS-033)
  run t_submit_refusals =
    init.then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 0, 0, false))
      .expect(lastRefused == Set("no-recovery-wrap", "already-enrolled"))
  run t_submit_pending =
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 1, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 2, 0, false))
      .expect(lastRefused == Set("recovery-pending"))

  // ---- RECOVER_CANCEL (PS-035)
  run t_cancel_refusals =
    init.then(A("RECOVER_CANCEL", 1, 0, 0, 0, 0, 0, false)).expect(lastRefused == Set("not-enrolled", "no-pending"))

  // ---- RECOVER_FINALISE (PS-039, PS-036, PS-037)
  run t_finalise_noPending =
    init.then(op0("RECOVER_FINALISE")).expect(lastRefused == Set("no-pending"))
  run t_finalise_effect =
    init.then(op0("CORRUPT_ORIGIN"))
      .then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("RECOVER_SUBMIT", 0, 0, 0, 0, 2, 0, false))
      .then(op0("RECOVER_FINALISE"))
      .expect(and { accepted, s.creds == Set(2), s.readers == Set(0, 2), not(s.r_wrap), s.r_wrap_ever,
                    s.pending == PNone, s.via_recovery_leak == Set(2), s.adv_cred == Set() })

  // ---- ADV_RECOVER_SUBMIT (PS-041, PS-038, PS-046)
  run t_advSubmit_refusals =
    init.then(A("ADV_RECOVER_SUBMIT", 0, 0, 0, 0, 0, 0, false))
      .expect(lastRefused == Set("no-quorum", "no-recovery-wrap", "already-enrolled"))
  run t_advRecovery =
    init.then(corruptG(0)).then(corruptG(1)).expect(not(s.adv_root))
      .then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false)).expect(and { s.adv_root, s.via_quorum })
      .then(A("ADV_RECOVER_SUBMIT", 0, 0, 0, 0, 2, 0, false))
      .then(A("ADV_RECOVER_SUBMIT", 0, 0, 0, 0, 3, 0, false)).expect(lastRefused == Set("recovery-pending"))
      .then(op0("RECOVER_FINALISE")).expect(and { accepted, s.adv_cred == Set(2), s.creds == Set(2) })
  run t_advRecovery_cancelled = // PS-034: a live device cancels
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false)).then(corruptG(0)).then(corruptG(2))
      .expect(s.via_quorum)
      .then(A("ADV_RECOVER_SUBMIT", 0, 0, 0, 0, 2, 0, false))
      .then(A("RECOVER_CANCEL", 0, 0, 0, 0, 0, 0, false)).expect(and { accepted, s.pending == PNone })

  // ---- CORRUPT_GUARDIAN (PS-047)
  run t_guardian_unknown = init.then(corruptG(3)).expect(lastRefused == Set("unknown-guardian"))
  run t_guardian_already = init.then(corruptG(1)).then(corruptG(1)).expect(lastRefused == Set("already-corrupt"))
  run t_guardian_belowQuorum =
    init.then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false)).then(corruptG(1)).expect(not(s.adv_root))

  // ---- STEAL_DEVICE (PS-050, PS-048, PS-049, PS-062)
  run t_steal_unknown =
    init.then(A("STEAL_DEVICE", 0, 2, 0, 0, 0, 0, true)).expect(lastRefused == Set("unknown-device"))
  run t_steal_locked = init.then(A("STEAL_DEVICE", 0, 0, 0, 0, 0, 0, false))
      .expect(and { accepted, s == initState(CFG, D0) })
  run t_steal_unlocked = init.then(A("STEAL_DEVICE", 0, 0, 0, 0, 0, 0, true))
      .expect(and { accepted, s.adv_cred == Set(0), s.adv_root, s.via_theft == Set(0) })

  // ---- PROVIDER_TAKEOVER (PS-052, PS-051, PS-063)
  run t_provider_refusals =
    init.then(A("PROVIDER_TAKEOVER", 0, 3, 0, 0, 0, 0, false)).expect(lastRefused == Set("not-synced", "unknown-device"))
  run t_provider_unknown =
    init.then(A("PROVIDER_TAKEOVER", 0, 2, 0, 0, 0, 0, false)).expect(lastRefused == Set("unknown-device"))
  run t_provider_web =
    init.then(A("PROVIDER_TAKEOVER", 0, 0, 0, 0, 0, 0, false))
      .expect(and { accepted, s.adv_cred == Set(0), s.via_provider == Set(0), s.adv_root })

  // ---- ADV_ASSERT (PS-054)
  run t_advAssert_noCred =
    init.then(A("ADV_ASSERT", 0, 0, 0, 0, 0, 0, false)).expect(lastRefused == Set("no-credential"))

  // ---- ORIGIN_ASSERT (PS-066)
  run t_originAssert_refusals =
    init.then(A("ORIGIN_ASSERT", 0, 3, 0, 0, 0, 0, false))
      .expect(lastRefused == Set("origin-honest", "not-enrolled", "native-credential"))
  run t_originAssert_native =
    init.then(enroll(0, 3)).then(op0("CORRUPT_ORIGIN")).then(A("ORIGIN_ASSERT", 0, 3, 0, 0, 0, 0, false))
      .expect(lastRefused == Set("native-credential"))
  run t_originAssert_ok =
    init.then(op0("CORRUPT_ORIGIN")).then(A("ORIGIN_ASSERT", 0, 0, 1, 2, 0, 0, false))
      .expect(and { accepted, s.hijacked == Set((0, 1, 2)), s.asserts == Set((0, 1, 2)) })

  // ---- ADV_SIGN (PS-056)
  run t_advSign_refusals =
    init.then(A("ADV_SIGN", 0, 0, 0, 0, 0, 0, false)).expect(lastRefused == Set("no-committee-half", "no-contribution"))
  run t_advSign_noContribution = // a fully corrupt committee alone signs nothing (PS-058)
    init.then(op0("CORRUPT_COMMITTEE")).then(A("ADV_SIGN", 0, 0, 1, 0, 0, 0, false))
      .expect(lastRefused == Set("no-contribution"))
  run t_advSign_dealtIntent = // it signs an intent that the user dealt, without authorization
    init.then(op0("CORRUPT_E")).then(unlock(0, 1)).then(A("ADV_SIGN", 0, 0, 1, 0, 0, 0, false))
      .expect(and { accepted, s.sigs == Set(1), s.authorized == Set() })

  // ---- the no-guard operations (PS-042 to PS-045)
  run t_noGuardOps =
    init.then(op0("CORRUPT_COMMITTEE")).expect(and { accepted, s.committee_corrupt, s.adv_xf })
      .then(op0("E_REPROVISION")).expect(and { accepted, not(s.committee_corrupt), s.adv_xf, s.epoch == 1 })
      .then(op0("CORRUPT_E")).expect(and { accepted, s.e_corrupt, not(s.adv_root) })
      .then(op0("CORRUPT_ORIGIN")).expect(and { accepted, s.origin_corrupt })

  // ---- OPEN DESIGN OD-1 (COUNTEREXAMPLES.md): the pending successor id can be
  // enrolled while the adversary's recovery is pending; RECOVER_FINALISE does
  // not recheck freshness, so the adversary gains the credential of a device
  // that the user enrolled (PS-007, PS-036, PS-038, PS-041).
  // OD-1, fixed by PS-067 (decision D-1): ENROLL refuses the id of the pending
  // successor, so the honest device never shares an id with the successor of
  // the adversary. Before the fix, ENROLL(0, 2) passed and RECOVER_FINALISE put
  // the enrolled id 2 in adv_cred.
  run od1_pendingSuccessorEnrolled =
    init.then(corruptG(0)).then(corruptG(1))
      .then(A("PUBLISH_RWRAP", 0, 0, 0, 0, 0, 0, false))
      .then(A("ADV_RECOVER_SUBMIT", 0, 0, 0, 0, 2, 0, false))
      .then(enroll(0, 2))
      .expect(and { lastRefused == Set("pending-successor"), s.creds == Set(0), s.readers == Set(0),
                    ghost.enrolled == Set() })
      .then(op0("RECOVER_FINALISE"))
      .expect(and { accepted, s.creds == Set(2), s.adv_cred == Set(2), ghost.adv_finalised == Set(2),
                    inv_PS067_enrolledNeverAdvSuccessor, inv })

  // ---- directed runs for the thin antecedents of PS-059 and the coalition
  // invariant (adv_xf false and a signature present), ending in .expect(inv)
  run t_inv_honestReleaseWithTheft =
    init.then(enroll(0, 1)).then(unlock(1, 0)).then(approve(1, 0, 0)).then(authorize(1, 0, 0))
      .then(release(0, 0))
      .then(A("STEAL_DEVICE", 0, 1, 0, 0, 0, 0, true))
      .then(A("ADV_ASSERT", 0, 1, 1, 1, 0, 0, false)).then(authorize(1, 1, 1))
      .then(release(1, 1))
      .expect(and { accepted, s.sigs == Set(0, 1), not(s.adv_xf), w_ant059, w_antCoalition, inv })
  run t_inv_hijackedRelease =
    init.then(op0("CORRUPT_ORIGIN")).then(unlock(0, 0))
      .then(A("ORIGIN_ASSERT", 0, 0, 1, 2, 0, 0, false)).then(authorize(0, 1, 2))
      .then(release(1, 2))
      .expect(and { accepted, s.sigs == Set(1), not(s.adv_xf), w_ant059, w_hijackAuth, inv })
  run t_inv_corruptCommitteeDealtOnly =
    init.then(op0("CORRUPT_COMMITTEE")).then(unlock(0, 1)).then(A("ADV_SIGN", 0, 0, 1, 0, 0, 0, false))
      .then(A("ADV_SIGN", 0, 0, 0, 0, 0, 0, false))
      .expect(and { lastRefused == Set("no-contribution"), s.sigs == Set(1), w_ant058corrupt, inv })
}
