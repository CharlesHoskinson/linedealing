// -*- mode: Bluespec; -*-
//
// Passport first-shard placement: an independent Quint model.
//
// Source: research/passport-fit/SHARD-SPEC.md, sections 3 to 7 only
// (state, operations, requirements PS-001 to PS-067, hypotheses, adversaries).
// The model was written without reading the Lean oracle.
//
// Shape
// - `s` is the state of SHARD-SPEC §3, with the same key names. The replayer
//   sends it to the oracle as is (pending: PNone -> null, PSome(r) -> r).
// - Every operation of §4 is one step. A step whose guards fail is a refused
//   step: `s` stays unchanged (PS-057) and `lastRefused` holds the codes.
//   This lets the replay compare refusal codes as well as accepted effects.
// - `lastOp` is the operation of the step (the replay contract).
// - `ghost` holds model-only history for transition invariants. The replayer
//   drops it.
// - `MUTANT` selects a broken guard or effect. 0 is the specified model.
module passportShard {

  // ---------------------------------------------------------------- types
  type Cfg = {
    quorum: int,
    n_guard: int,
    native: Set[int],
    synced: Set[int],
    overlap: Set[int],
  }

  type Pending = PNone | PSome({ succ: int, adv: bool })

  type State = {
    cfg: Cfg,
    readers: Set[int],
    creds: Set[int],
    r_wrap: bool,
    r_wrap_ever: bool,
    pending: Pending,
    unlock_log: Set[(int, int)],
    prf_log: Set[int],
    approved: Set[(int, int, int)],
    asserts: Set[(int, int, int)],
    hijacked: Set[(int, int, int)],
    authorized: Set[(int, int)],
    used_nf: Set[int],
    sigs: Set[int],
    adv_root: bool,
    adv_xf: bool,
    via_origin_leak: Set[int],
    via_recovery_leak: Set[int],
    via_theft: Set[int],
    via_provider: Set[int],
    via_quorum: bool,
    adv_cred: Set[int],
    adv_guard: Set[int],
    origin_corrupt: bool,
    committee_corrupt: bool,
    e_corrupt: bool,
    epoch: int,
  }

  // One operation of §4. Parameters an operation does not take are ignored.
  type Op = {
    op: str,
    by: int,
    d: int,
    ic: int,
    nf: int,
    succ: int,
    g: int,
    unlocked: bool,
  }

  type Ghost = {
    // CORRUPT_COMMITTEE or CORRUPT_E happened at some time
    cx_corrupted: bool,
    // intents that the honest committee released
    released: Set[int],
    // intents that ADV_SIGN completed
    adv_signed: Set[int],
    // adv_xf before the last step
    prev_adv_xf: bool,
    // device ids that a passing ENROLL added
    enrolled: Set[int],
    // successors that a passing RECOVER_FINALISE with pending.adv added to adv_cred
    adv_finalised: Set[int],
  }

  // ---------------------------------------------------------------- constants
  const CFG: Cfg
  const DEV: Set[int]     // device ids the adversary and the user pick from
  const IC: Set[int]      // intents
  const NF: Set[int]      // nullifiers
  const D0: int           // the device that creates the account (PS-004)
  const MUTANT: int       // 0: the specified model

  pure val OPS: Set[str] = Set(
    "ENROLL", "REMOVE_DEVICE", "UNLOCK", "APPROVE", "AUTHORIZE", "RELEASE",
    "PUBLISH_RWRAP", "RECOVER_SUBMIT", "RECOVER_CANCEL", "RECOVER_FINALISE",
    "E_REPROVISION", "ADV_RECOVER_SUBMIT", "CORRUPT_COMMITTEE", "CORRUPT_E",
    "CORRUPT_ORIGIN", "CORRUPT_GUARDIAN", "STEAL_DEVICE", "PROVIDER_TAKEOVER",
    "ADV_ASSERT", "ORIGIN_ASSERT", "ADV_SIGN",
  )

  // ---------------------------------------------------------------- state
  var s: State
  var lastOp: Op
  var lastRefused: Set[str]
  var ghost: Ghost

  // ---------------------------------------------------------------- helpers
  pure def codeIf(c: bool, code: str): Set[str] = if (c) Set(code) else Set()

  // §4 fixed phrases
  pure def fresh(st: State, d: int): bool =
    not(st.creds.contains(d)) and not(st.readers.contains(d))
  pure def known(st: State, d: int): bool =
    st.creds.contains(d) or st.readers.contains(d)

  pure def isPending(p: Pending): bool = match p { | PNone => false | PSome(_) => true }
  pure def pendSucc(p: Pending): int = match p { | PNone => -1 | PSome(r) => r.succ }
  pure def pendAdv(p: Pending): bool = match p { | PNone => false | PSome(r) => r.adv }

  pure def hasContribution(st: State, ic: int): bool =
    st.unlock_log.exists(p => p._2 == ic)

  pure def recordPrf(st: State, d: int): State =
    { ...st, prf_log: st.prf_log.union(Set(d)) }

  // PS-012: a passing UNLOCK, ENROLL or PUBLISH_RWRAP on a web reader leaks the
  // root to a corrupt origin (H-PAGE).
  pure def originLeak(st: State, dev: int): State =
    if (st.origin_corrupt and not(st.cfg.native.contains(dev)))
      { ...st, adv_root: true, via_origin_leak: st.via_origin_leak.union(Set(dev)) }
    else st

  // PS-046: evaluated after the other effects of CORRUPT_GUARDIAN or PUBLISH_RWRAP.
  pure def quorumLeak(st: State): State =
    if (st.r_wrap_ever and st.adv_guard.size() >= st.cfg.quorum)
      { ...st, adv_root: true, via_quorum: true }
    else st

  // ---------------------------------------------------------------- guards
  // The refusal codes of §5 for op `o` in state `st`. Empty: the op passes.
  pure def guards(m: int, st: State, o: Op): Set[str] =
    if (o.op == "ENROLL")                                        // PS-007, PS-067
      codeIf(not(st.creds.contains(o.by)), "not-enrolled")
        .union(codeIf(not(st.readers.contains(o.by)), "no-wrap"))
        .union(codeIf(not(fresh(st, o.d)), "already-enrolled"))
        .union(codeIf(m != 13 and isPending(st.pending) and pendSucc(st.pending) == o.d,
                      "pending-successor"))
    else if (o.op == "REMOVE_DEVICE")                            // PS-009
      codeIf(not(st.creds.contains(o.by)), "not-enrolled")
        .union(codeIf(not(st.creds.contains(o.d)), "unknown-device"))
        .union(codeIf(o.by == o.d, "self-removal"))
    else if (o.op == "UNLOCK")                                   // PS-013
      codeIf(not(st.creds.contains(o.d)), "not-enrolled")
        .union(codeIf(not(st.readers.contains(o.d)), "no-wrap"))
    else if (o.op == "APPROVE")                                  // PS-017
      codeIf(not(st.creds.contains(o.d)), "not-enrolled")
    else if (o.op == "AUTHORIZE")                                // PS-019, PS-020, PS-021
      codeIf(m != 1 and not(st.asserts.contains((o.d, o.ic, o.nf))), "no-assertion")
        .union(codeIf(not(st.creds.contains(o.d)), "not-enrolled"))
        .union(codeIf(m != 2 and st.used_nf.contains(o.nf), "nf-used"))
    else if (o.op == "RELEASE")                                  // PS-023, PS-024, PS-025
      codeIf(m != 11 and st.committee_corrupt, "committee-corrupt")
        .union(codeIf(m != 3 and not(st.authorized.contains((o.ic, o.nf))), "not-authorized"))
        .union(codeIf(m != 4 and not(hasContribution(st, o.ic)) and not(st.adv_root), "no-contribution"))
    else if (o.op == "PUBLISH_RWRAP")                            // PS-031
      codeIf(not(st.creds.contains(o.by)), "not-enrolled")
        .union(codeIf(not(st.readers.contains(o.by)), "no-wrap"))
    else if (o.op == "RECOVER_SUBMIT")                           // PS-033
      codeIf(not(st.r_wrap), "no-recovery-wrap")
        .union(codeIf(isPending(st.pending), "recovery-pending"))
        .union(codeIf(not(fresh(st, o.succ)), "already-enrolled"))
    else if (o.op == "RECOVER_CANCEL")                           // PS-035
      codeIf(not(st.creds.contains(o.by)), "not-enrolled")
        .union(codeIf(not(isPending(st.pending)), "no-pending"))
    else if (o.op == "RECOVER_FINALISE")                         // PS-039
      codeIf(not(isPending(st.pending)), "no-pending")
    else if (o.op == "ADV_RECOVER_SUBMIT")                       // PS-041
      codeIf(st.adv_guard.size() < st.cfg.quorum, "no-quorum")
        .union(codeIf(not(st.r_wrap), "no-recovery-wrap"))
        .union(codeIf(isPending(st.pending), "recovery-pending"))
        .union(codeIf(not(fresh(st, o.succ)), "already-enrolled"))
    else if (o.op == "CORRUPT_GUARDIAN")                         // PS-047
      codeIf(not(o.g < st.cfg.n_guard), "unknown-guardian")
        .union(codeIf(st.adv_guard.contains(o.g), "already-corrupt"))
    else if (o.op == "STEAL_DEVICE")                             // PS-050
      codeIf(not(known(st, o.d)), "unknown-device")
    else if (o.op == "PROVIDER_TAKEOVER")                        // PS-052
      codeIf(not(st.cfg.synced.contains(o.d)), "not-synced")
        .union(codeIf(not(known(st, o.d)), "unknown-device"))
    else if (o.op == "ADV_ASSERT")                               // PS-054
      codeIf(m != 9 and not(st.adv_cred.contains(o.d)), "no-credential")
    else if (o.op == "ORIGIN_ASSERT")                            // PS-066
      codeIf(not(st.origin_corrupt), "origin-honest")
        .union(codeIf(not(st.creds.contains(o.d)), "not-enrolled"))
        .union(codeIf(m != 10 and st.cfg.native.contains(o.d), "native-credential"))
    else if (o.op == "ADV_SIGN")                                 // PS-056
      codeIf(m != 5 and not(st.adv_xf), "no-committee-half")
        .union(codeIf(not(hasContribution(st, o.ic)) and not(st.adv_root), "no-contribution"))
    // E_REPROVISION, CORRUPT_COMMITTEE, CORRUPT_E, CORRUPT_ORIGIN: no guard
    // (PS-042 to PS-045)
    else Set()

  // ---------------------------------------------------------------- effects
  // The effect of a passing op. Called only when guards() is empty.
  pure def effect(m: int, st: State, o: Op): State =
    if (o.op == "ENROLL")                                        // PS-006, PS-012
      originLeak({ ...recordPrf(st, o.by),
                   creds: st.creds.union(Set(o.d)),
                   readers: st.readers.union(Set(o.d)) }, o.by)
    else if (o.op == "REMOVE_DEVICE")                            // PS-008
      { ...st, creds: st.creds.exclude(Set(o.d)) }
    else if (o.op == "UNLOCK")                                   // PS-010, PS-011, PS-012
      originLeak({ ...(if (m == 8) st else recordPrf(st, o.d)),
                   unlock_log: st.unlock_log.union(Set((o.d, o.ic))) }, o.d)
    else if (o.op == "APPROVE")                                  // PS-016
      { ...st, approved: st.approved.union(Set((o.d, o.ic, o.nf))),
               asserts: st.asserts.union(Set((o.d, o.ic, o.nf))) }
    else if (o.op == "AUTHORIZE")                                // PS-018
      { ...st, authorized: st.authorized.union(Set((o.ic, o.nf))),
               used_nf: st.used_nf.union(Set(o.nf)) }
    else if (o.op == "RELEASE")                                  // PS-022
      { ...st, sigs: st.sigs.union(Set(o.ic)) }
    else if (o.op == "PUBLISH_RWRAP")                            // PS-030, PS-012, PS-046
      quorumLeak(originLeak({ ...recordPrf(st, o.by), r_wrap: true, r_wrap_ever: true }, o.by))
    else if (o.op == "RECOVER_SUBMIT")                           // PS-032
      { ...st, pending: PSome({ succ: o.succ, adv: false }) }
    else if (o.op == "RECOVER_CANCEL")                           // PS-034
      { ...st, pending: PNone }
    else if (o.op == "RECOVER_FINALISE") {                       // PS-036, PS-037, PS-038
      val succ = pendSucc(st.pending)
      val adv = pendAdv(st.pending)
      val base = { ...st, creds: Set(succ), readers: st.readers.union(Set(succ)),
                   r_wrap: false, pending: PNone }
      val leaked =
        if (st.origin_corrupt and not(adv) and not(st.cfg.native.contains(succ)))
          { ...base, adv_root: true, via_recovery_leak: base.via_recovery_leak.union(Set(succ)) }
        else base
      if (adv) { ...leaked, adv_cred: leaked.adv_cred.union(Set(succ)) } else leaked
    }
    else if (o.op == "E_REPROVISION")                            // PS-042
      { ...st, committee_corrupt: false, epoch: st.epoch + 1,
               adv_xf: if (m == 7) false else st.adv_xf }
    else if (o.op == "ADV_RECOVER_SUBMIT")                       // PS-040
      { ...st, pending: PSome({ succ: o.succ, adv: true }) }
    else if (o.op == "CORRUPT_COMMITTEE")                        // PS-043
      { ...st, committee_corrupt: true, adv_xf: true }
    else if (o.op == "CORRUPT_E")                                // PS-044
      { ...st, e_corrupt: true, adv_xf: true,
               adv_root: if (m == 6) true else st.adv_root }
    else if (o.op == "CORRUPT_ORIGIN")                           // PS-045
      { ...st, origin_corrupt: true }
    else if (o.op == "CORRUPT_GUARDIAN")                         // PS-061, PS-046
      quorumLeak({ ...st, adv_guard: st.adv_guard.union(Set(o.g)) })
    else if (o.op == "STEAL_DEVICE")                             // PS-048, PS-049, PS-062
      if (not(o.unlocked)) st
      else if (st.readers.contains(o.d))
        { ...(if (m == 12) st else recordPrf(st, o.d)), adv_cred: st.adv_cred.union(Set(o.d)),
          adv_root: true, via_theft: st.via_theft.union(Set(o.d)) }
      else { ...st, adv_cred: st.adv_cred.union(Set(o.d)) }
    else if (o.op == "PROVIDER_TAKEOVER") {                      // PS-051, PS-063
      val withCred = { ...st, adv_cred: st.adv_cred.union(Set(o.d)) }
      if (st.readers.contains(o.d) and not(st.cfg.native.contains(o.d)))
        { ...withCred, adv_root: true, via_provider: st.via_provider.union(Set(o.d)) }
      else withCred
    }
    else if (o.op == "ADV_ASSERT")                               // PS-053
      { ...st, asserts: st.asserts.union(Set((o.d, o.ic, o.nf))) }
    else if (o.op == "ORIGIN_ASSERT")                            // PS-065
      { ...st, hijacked: st.hijacked.union(Set((o.d, o.ic, o.nf))),
               asserts: st.asserts.union(Set((o.d, o.ic, o.nf))) }
    else if (o.op == "ADV_SIGN")                                 // PS-055
      { ...st, sigs: st.sigs.union(Set(o.ic)) }
    else st

  pure def nextGhost(gh: Ghost, st: State, o: Op, passed: bool): Ghost = {
    val cx = gh.cx_corrupted or (passed and (o.op == "CORRUPT_COMMITTEE" or o.op == "CORRUPT_E"))
    {
      cx_corrupted: cx,
      released: if (passed and o.op == "RELEASE") gh.released.union(Set(o.ic)) else gh.released,
      adv_signed: if (passed and o.op == "ADV_SIGN") gh.adv_signed.union(Set(o.ic)) else gh.adv_signed,
      prev_adv_xf: st.adv_xf,
      enrolled: if (passed and o.op == "ENROLL") gh.enrolled.union(Set(o.d)) else gh.enrolled,
      adv_finalised:
        if (passed and o.op == "RECOVER_FINALISE" and pendAdv(st.pending))
          gh.adv_finalised.union(Set(pendSucc(st.pending)))
        else gh.adv_finalised,
    }
  }

  // ---------------------------------------------------------------- init (PS-004)
  pure def initState(cfg: Cfg, d0: int): State = {
    cfg: cfg,
    readers: Set(d0), creds: Set(d0), prf_log: Set(d0),
    r_wrap: false, r_wrap_ever: false, pending: PNone,
    unlock_log: Set(), approved: Set(), asserts: Set(), hijacked: Set(),
    authorized: Set(), used_nf: Set(), sigs: Set(),
    adv_root: false, adv_xf: false,
    via_origin_leak: Set(), via_recovery_leak: Set(), via_theft: Set(), via_provider: Set(),
    via_quorum: false, adv_cred: Set(), adv_guard: Set(),
    origin_corrupt: false, committee_corrupt: false, e_corrupt: false,
    epoch: 0,
  }

  pure val noOp: Op = { op: "INIT", by: 0, d: 0, ic: 0, nf: 0, succ: 0, g: 0, unlocked: false }

  action init = all {
    s' = initState(CFG, D0),
    lastOp' = noOp,
    lastRefused' = Set(),
    ghost' = { cx_corrupted: false, released: Set(), adv_signed: Set(), prev_adv_xf: false,
               enrolled: Set(), adv_finalised: Set() },
  }

  // ---------------------------------------------------------------- actions
  // One attempt of op `o`: accepted (effect) or refused (PS-057: unchanged).
  action attempt(o: Op): bool = {
    val codes = guards(MUTANT, s, o)
    val passed = codes.size() == 0
    all {
      s' = if (passed) effect(MUTANT, s, o) else s,
      lastOp' = o,
      lastRefused' = codes,
      ghost' = nextGhost(ghost, s, o, passed),
    }
  }

  // Only a passing attempt.
  action pass(o: Op): bool = all {
    guards(MUTANT, s, o).size() == 0,
    attempt(o),
  }

  pure def mk(name: str, by: int, d: int, ic: int, nf: int, succ: int, g: int, u: bool): Op =
    { op: name, by: by, d: d, ic: ic, nf: nf, succ: succ, g: g, unlocked: u }

  // Mixed step: any op with any parameters, accepted or refused. Replay traces.
  action step = {
    nondet name = OPS.oneOf()
    nondet by = DEV.oneOf()
    nondet d = DEV.oneOf()
    nondet ic = IC.oneOf()
    nondet nf = NF.oneOf()
    nondet succ = DEV.oneOf()
    nondet g = 0.to(CFG.n_guard).oneOf()
    nondet u = Bool.oneOf()
    attempt(mk(name, by, d, ic, nf, succ, g, u))
  }

  // A passing operation of the user, the honest committee or E.
  action honestPass = {
    nondet by = DEV.oneOf()
    nondet d = DEV.oneOf()
    nondet ic = IC.oneOf()
    nondet nf = NF.oneOf()
    nondet succ = DEV.oneOf()
    nondet g = 0.to(CFG.n_guard).oneOf()
    nondet u = Bool.oneOf()
    any {
      pass(mk("ENROLL", by, d, ic, nf, succ, g, u)),
      pass(mk("REMOVE_DEVICE", by, d, ic, nf, succ, g, u)),
      pass(mk("UNLOCK", by, d, ic, nf, succ, g, u)),
      pass(mk("APPROVE", by, d, ic, nf, succ, g, u)),
      pass(mk("AUTHORIZE", by, d, ic, nf, succ, g, u)),
      pass(mk("RELEASE", by, d, ic, nf, succ, g, u)),
      pass(mk("PUBLISH_RWRAP", by, d, ic, nf, succ, g, u)),
      pass(mk("RECOVER_SUBMIT", by, d, ic, nf, succ, g, u)),
      pass(mk("RECOVER_CANCEL", by, d, ic, nf, succ, g, u)),
      pass(mk("RECOVER_FINALISE", by, d, ic, nf, succ, g, u)),
      pass(mk("E_REPROVISION", by, d, ic, nf, succ, g, u)),
    }
  }

  // A passing operation of the adversary.
  action advPass = {
    nondet by = DEV.oneOf()
    nondet d = DEV.oneOf()
    nondet ic = IC.oneOf()
    nondet nf = NF.oneOf()
    nondet succ = DEV.oneOf()
    nondet g = 0.to(CFG.n_guard).oneOf()
    nondet u = Bool.oneOf()
    any {
      pass(mk("ADV_RECOVER_SUBMIT", by, d, ic, nf, succ, g, u)),
      pass(mk("CORRUPT_COMMITTEE", by, d, ic, nf, succ, g, u)),
      pass(mk("CORRUPT_E", by, d, ic, nf, succ, g, u)),
      pass(mk("CORRUPT_ORIGIN", by, d, ic, nf, succ, g, u)),
      pass(mk("CORRUPT_GUARDIAN", by, d, ic, nf, succ, g, u)),
      pass(mk("STEAL_DEVICE", by, d, ic, nf, succ, g, u)),
      pass(mk("PROVIDER_TAKEOVER", by, d, ic, nf, succ, g, u)),
      pass(mk("ADV_ASSERT", by, d, ic, nf, succ, g, u)),
      pass(mk("ORIGIN_ASSERT", by, d, ic, nf, succ, g, u)),
      pass(mk("ADV_SIGN", by, d, ic, nf, succ, g, u)),
    }
  }

  // Accepted-only steps for the invariant runs (they reach deep recovery and
  // corruption states faster than the mixed step).
  action stepPass = any { honestPass, advPass }
  // Mostly honest: the adversary moves on about one step in five.
  action stepMostlyHonest = any { honestPass, honestPass, honestPass, honestPass, advPass }

  // ---------------------------------------------------------------- invariants
  val viaEmpty: bool = and {
    s.via_origin_leak == Set(), s.via_recovery_leak == Set(),
    s.via_theft == Set(), s.via_provider == Set(), not(s.via_quorum),
  }

  // PS-001: cfg never changes.
  val inv_PS001_cfgFixed: bool = s.cfg == CFG

  // PS-058 (with PS-022, PS-025, PS-055, PS-056, H-SIG, H-CONTRIB): no signature
  // outside the access structure Fenrir AND (d_1 OR ... OR d_m OR R), even with a
  // fully corrupt committee or E. While the root has not leaked, every signed
  // intent has a user-verified unlock.
  val inv_PS058_accessStructure: bool =
    viaEmpty implies s.sigs.forall(ic =>
      s.unlock_log.exists(p => p._2 == ic and s.prf_log.contains(p._1)))

  // PS-059 (with PS-019, PS-022, PS-024): while x_f is not known to the
  // adversary, every signature has an authorization in force backed by an
  // assertion over the same (ic, nf).
  val inv_PS059_committeeNeedsAuthorization: bool =
    not(s.adv_xf) implies s.sigs.forall(ic =>
      s.authorized.exists(a => a._1 == ic and
        s.asserts.exists(t => t._2 == ic and t._3 == a._2)))

  // PS-060 (with PS-011, PS-012, PS-062): a signature needs a user-verified
  // unlock of its intent, except through the named exceptions: a provider
  // takeover, a recovery leak or a corrupt guardian quorum (no user
  // verification), and a root that leaked at a user-verified origin unlock or
  // from an unlocked stolen device.
  val inv_PS060_userVerifiedUnlock: bool =
    (s.via_provider == Set() and s.via_recovery_leak == Set() and not(s.via_quorum))
      implies s.sigs.forall(ic =>
        s.readers.exists(d => s.prf_log.contains(d) and or {
          s.unlock_log.contains((d, ic)),
          s.via_origin_leak.contains(d),
          s.via_theft.contains(d),
        }))

  // No user-side coalition signs without the committee (PS-043, PS-044,
  // PS-055, PS-056, H-SIG). Devices, the origin, the provider and the
  // guardians never yield x_f; without a corruption of the committee or of E,
  // every signature is an honest release.
  val inv_noUserCoalitionWithoutCommittee: bool = and {
    s.adv_xf iff ghost.cx_corrupted,
    not(ghost.cx_corrupted) implies s.sigs.subseteq(ghost.released),
  }

  // Recovery keeps the committee half and puts no whole key in one place
  // (PS-036, PS-038, PS-042, PS-044, PS-046, H-SHAMIR, H-WRAP).
  // - A reprovision or any recovery operation leaves adv_xf as it was.
  // - The root reaches the adversary only through a named leak; E holds no
  //   part of it; a recovery wrap reaches the adversary only with a quorum.
  // - The whole key (root and x_f) needs a committee-or-E corruption AND a
  //   root leak: no single party of the recovery path holds both.
  val inv_recoveryNoWholeKey: bool = and {
    Set("E_REPROVISION", "RECOVER_SUBMIT", "RECOVER_CANCEL", "RECOVER_FINALISE",
        "ADV_RECOVER_SUBMIT", "PUBLISH_RWRAP").contains(lastOp.op)
      implies s.adv_xf == ghost.prev_adv_xf,
    (lastOp.op == "E_REPROVISION") implies not(s.committee_corrupt),
    s.adv_root iff not(viaEmpty),
    s.via_quorum implies (s.adv_guard.size() >= s.cfg.quorum and s.r_wrap_ever),
    (s.adv_root and s.adv_xf) implies (ghost.cx_corrupted and not(viaEmpty)),
  }

  // An assertion authorizes only the intent it binds (PS-018, PS-019, H-BIND).
  val inv_PS019_assertionBindsIntent: bool =
    s.authorized.forall(a =>
      s.used_nf.contains(a._2) and
      s.asserts.exists(t => t._2 == a._1 and t._3 == a._2))

  // One nf authorizes one intent (PS-021, PS-064, H-MIDNIGHT).
  val inv_PS064_oneIntentPerNf: bool =
    s.authorized.forall(a => s.authorized.forall(b => a._2 == b._2 implies a._1 == b._1))

  // Every authorization traces to a user approval of that exact (ic, nf), to an
  // approval gesture the corrupt origin redirected, or to a credential the
  // adversary holds (PS-016, PS-053, PS-054, PS-065, H-ES256, H-BLIND).
  val inv_authorizationSource: bool =
    s.authorized.forall(a =>
      s.asserts.exists(t => t._2 == a._1 and t._3 == a._2 and or {
        s.approved.contains(t),
        s.hijacked.contains(t),
        s.adv_cred.contains(t._1),
      }))

  // A corrupt origin redirects only approvals on web credentials (PS-066, H-BLIND).
  val inv_PS066_hijackWebOnly: bool = and {
    s.hijacked.forall(t => not(s.cfg.native.contains(t._1))),
    s.hijacked != Set() implies s.origin_corrupt,
  }

  // PS-002, PS-003 hold for the instance (the model never leaves the domain).
  val inv_cfgDomain: bool = and {
    s.cfg.quorum >= 1, s.cfg.quorum <= s.cfg.n_guard, s.cfg.overlap == Set(),
  }

  // PS-067 (decision D-1, OD-1): no device id that the user enrolled with a
  // passing ENROLL is ever added to adv_cred by RECOVER_FINALISE. STEAL_DEVICE and
  // PROVIDER_TAKEOVER put enrolled ids in adv_cred legitimately, so the invariant
  // reads the ghost history, not s.adv_cred.
  val inv_PS067_enrolledNeverAdvSuccessor: bool =
    ghost.enrolled.intersect(ghost.adv_finalised) == Set()

  val inv: bool = and {
    inv_PS001_cfgFixed,
    inv_PS058_accessStructure,
    inv_PS059_committeeNeedsAuthorization,
    inv_PS060_userVerifiedUnlock,
    inv_noUserCoalitionWithoutCommittee,
    inv_recoveryNoWholeKey,
    inv_PS019_assertionBindsIntent,
    inv_PS064_oneIntentPerNf,
    inv_authorizationSource,
    inv_PS066_hijackWebOnly,
    inv_cfgDomain,
    inv_PS067_enrolledNeverAdvSuccessor,
  }

  // ---------------------------------------------------------------- witnesses
  // Reached states (pass to --witnesses; each must be reached in > 0 traces).
  val w_honestFinalise: bool = lastOp.op == "RECOVER_FINALISE" and lastRefused == Set() and s.adv_cred == Set()
  val w_advFinalise: bool = lastOp.op == "RECOVER_FINALISE" and lastRefused == Set() and s.adv_cred != Set() and s.via_quorum
  val w_viaOrigin: bool = s.via_origin_leak != Set()
  val w_viaRecovery: bool = s.via_recovery_leak != Set()
  val w_viaTheft: bool = s.via_theft != Set()
  val w_viaProvider: bool = s.via_provider != Set()
  val w_viaQuorum: bool = s.via_quorum
  val w_wholeKey: bool = s.adv_root and s.adv_xf
  val w_releaseSig: bool = ghost.released != Set()
  val w_advSig: bool = ghost.adv_signed != Set()
  val w_hijackAuth: bool = s.authorized.exists(a => s.hijacked.exists(t => t._2 == a._1 and t._3 == a._2))
  val w_sigAfterReprovision: bool = s.epoch > 0 and s.sigs != Set()
  val w_refused: bool = lastRefused.size() >= 2
  // Antecedents of the conditional invariants, with a signature present, so
  // that each invariant is checked on states where it is not vacuous.
  val w_ant058: bool = viaEmpty and s.sigs != Set()
  val w_ant059: bool = not(s.adv_xf) and s.sigs != Set()
  val w_ant060: bool = s.via_provider == Set() and s.via_recovery_leak == Set() and
    not(s.via_quorum) and s.sigs != Set()
  // PS-060 through a named user-verified exception: a signed intent never unlocked
  val w_ant060exception: bool = s.via_provider == Set() and s.via_recovery_leak == Set() and
    not(s.via_quorum) and s.sigs.exists(ic => not(s.unlock_log.exists(p => p._2 == ic)))
  val w_antCoalition: bool = not(ghost.cx_corrupted) and s.sigs != Set()
  // a corrupt committee or E signs only dealt intents (PS-058 with adv_xf)
  val w_ant058corrupt: bool = viaEmpty and s.adv_xf and ghost.adv_signed != Set()
  val w_wholeKeyViaQuorum: bool = s.adv_root and s.adv_xf and s.via_quorum
  val w_twoAuthorizations: bool = s.authorized.size() >= 2
  // PS-067: both ghost sets are non-empty (the invariant is not vacuous), and
  // the pending-successor refusal occurs (mixed step only)
  val w_ant067: bool = ghost.enrolled != Set() and ghost.adv_finalised != Set()
  val w_pendingSuccessorRefused: bool = lastRefused.contains("pending-successor")
}

// ---------------------------------------------------------------- instances
// Web readers only, every credential synced, quorum 2 of 3.
module webSynced {
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 0
  ).*
}

// Mixed readers: 1 and 3 native, 0 and 1 synced, quorum 1 of 2.
module mixed {
  import passportShard(
    CFG = { quorum: 1, n_guard: 2, native: Set(1, 3), synced: Set(0, 1), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 0
  ).*
}

// Native readers only, nothing synced, quorum 3 of 3; account device is native.
module allNative {
  import passportShard(
    CFG = { quorum: 3, n_guard: 3, native: Set(0, 1, 2, 3), synced: Set(), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 0
  ).*
}

// Account created on device 2, larger ids, quorum 1 of 1.
module d0Two {
  import passportShard(
    CFG = { quorum: 1, n_guard: 1, native: Set(5), synced: Set(2, 5), overlap: Set() },
    DEV = Set(2, 5, 7), IC = Set(3, 4), NF = Set(0, 9), D0 = 2, MUTANT = 0
  ).*
}

// ---------------------------------------------------------------- mutants
// Each mutant breaks one guard or effect. The named invariant must fail.
module mut1_noAssertion {       // PS-019 -> inv_PS059 / inv_PS019
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 1).*
}
module mut2_nfReuse {           // PS-021 -> inv_PS064
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 2).*
}
module mut3_noAuthorization {   // PS-024 -> inv_PS059
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 3).*
}
module mut4_noContribution {    // PS-025 -> inv_PS058
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 4).*
}
module mut5_noCommitteeHalf {   // PS-056 -> inv_noUserCoalitionWithoutCommittee
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 5).*
}
module mut6_eHoldsRoot {        // PS-044 -> inv_recoveryNoWholeKey
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 6).*
}
module mut7_reprovisionDropsXf { // PS-042 -> inv_recoveryNoWholeKey
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 7).*
}
module mut8_unlockNoPrf {       // PS-011 -> inv_PS058
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 8).*
}
module mut9_advAssertNoCred {   // PS-054 -> inv_authorizationSource
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 9).*
}
module mut10_originNative {     // PS-066 -> inv_PS066_hijackWebOnly
  import passportShard(
    CFG = { quorum: 1, n_guard: 2, native: Set(1, 3), synced: Set(0, 1), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 10).*
}
module mut11_corruptRelease {   // PS-023 -> no state invariant expected to fail
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 11).*
}
module mut12_theftNoPrf {       // PS-062 -> inv_PS060_userVerifiedUnlock
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 12).*
}
module mut13_enrollPendingSucc { // PS-067 -> inv_PS067_enrolledNeverAdvSuccessor
  import passportShard(
    CFG = { quorum: 2, n_guard: 3, native: Set(), synced: Set(0, 1, 2, 3), overlap: Set() },
    DEV = Set(0, 1, 2, 3), IC = Set(0, 1), NF = Set(0, 1, 2), D0 = 0, MUTANT = 13).*
}
