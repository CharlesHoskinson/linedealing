import SplitHandoff.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` checks it against the definitions
the theorems describe, and `#guard` checks it with the compiled evaluator.
Expected values come from the spec text (the scenario numbers), not from `#eval`.

Path inventory (bounded): ROTATE to ROTATING; ROTATE to QUEUED and the release at a
grace end; CARRY, complaint and `Q`; READY counting; ARM; activation; late activation;
abort from ROTATING; abort from ARMED; grace end and sweep; refused operations.
-/

namespace SplitHandoff

def seats9 : List Nat := [1, 2, 3, 4, 5, 6, 7, 8, 9]

/-- `n = 9`, `f = 2`, `q = 6`, `t = 7`; one secp address of user 1 with two ECDSA slots. -/
def gen9 : Genesis :=
  { roster := seats9, n := 9, f := 2, q := 6, t := 7, xf := { secp := 1001, ed := 2002 },
    users := [{ id := 1, shard := 77, tweak := 3, pool := 4, sealed := 5, slotRoot := 6, asset := 7 }],
    addrs := [{ id := 10, curve := .secp, user := 1, shard := 77, ecdsa := true, slots := [0, 1] }] }

def prm : Params := { deltaRot := 100, deltaGrace := 50, deltaSweep := 5, deltaCw := 3 }

def s0 : St := init prm gen9

/-- A scheduled ROTATE to epoch 1 that replaces seat 9 by seat 10. -/
def rot1 : Rotate :=
  { target := 1, source := 0, roster := [1, 2, 3, 4, 5, 6, 7, 8, 10], n := 9, f := 2, q := 6, t := 7,
    emergency := false, sigs := 6 }

def codes (s : St) (a : Act) : List String := (refusals s a.op).map Refusal.code

-- HO-004: `n' = 9`, `f' = 2` gives `q' = 6`, `t' = 7`; `t' = 6` is refused
theorem pin_params : paramsOk 9 2 6 7 := by decide +kernel
#guard decide (paramsOk 9 2 6 7)
theorem pin_bad_t : codes s0 (.rotate { rot1 with t := 6 }) = ["bad_params"] := by decide +kernel
#guard codes s0 (.rotate { rot1 with t := 6 }) == ["bad_params"]

-- HO-003: five signatures at `q = 6`
theorem pin_five_sigs : codes s0 (.rotate { rot1 with sigs := 5 }) = ["rotate_unauthorized"] := by decide +kernel
#guard codes s0 (.rotate { rot1 with sigs := 5 }) == ["rotate_unauthorized"]

-- HO-005: a scheduled ROTATE that replaces two seats at `f = 2`; HO-006: an emergency one may
def rot2seats : Rotate := { rot1 with roster := [1, 2, 3, 4, 5, 6, 7, 10, 11] }
theorem pin_two_seats : codes s0 (.rotate rot2seats) = ["too_many_seats"] := by decide +kernel
#guard codes s0 (.rotate rot2seats) == ["too_many_seats"]
theorem pin_emergency : codes s0 (.rotate { rot2seats with emergency := true }) = [] := by decide +kernel
#guard codes s0 (.rotate { rot2seats with emergency := true }) == []

-- HO-007: epoch 0 is current and the ROTATE names epoch 2
theorem pin_skip : codes s0 (.rotate { rot1 with target := 2 }) = ["bad_epoch"] := by decide +kernel
#guard codes s0 (.rotate { rot1 with target := 2 }) == ["bad_epoch"]

-- HO-008: an unknown source
theorem pin_source : codes s0 (.rotate { rot1 with source := 7 }) = ["bad_source"] := by decide +kernel
#guard codes s0 (.rotate { rot1 with source := 7 }) == ["bad_source"]

-- several refusals at once: every code, sorted (ledger 1)
theorem pin_many : codes s0 (.rotate { rot1 with target := 2, sigs := 1 }) = ["bad_epoch", "rotate_unauthorized"] := by
  decide +kernel
#guard codes s0 (.rotate { rot1 with target := 2, sigs := 1 }) == ["bad_epoch", "rotate_unauthorized"]

-- an operation with a wrong actor tag is refused (HO-058)
theorem pin_actor : refusals s0 { actor := .user, act := .rotate rot1 } = [.noRule] := by decide +kernel
#guard refusals s0 { actor := .user, act := .rotate rot1 } == [.noRule]
theorem pin_user_ack : codes s0 (.userAck 1) = ["no-rule"] := by decide +kernel

-- HO-001, HO-012: before any ROTATE epoch 1 is IDLE; a valid ROTATE with its preconditions met
-- is ROTATING with `m_R` the Midnight height and `m_D = m_R + Δ_rot`
def s1 : St := run s0 [(Act.midnightTick 20).op, (Act.rotate rot1).op]
theorem pin_idle : s0.ho.phase = .IDLE := by decide +kernel
theorem pin_rotating : (s1.ho.phase, s1.ho.mR, s1.ho.mD) = (.ROTATING, 20, 120) := by decide +kernel
#guard (s1.ho.phase, s1.ho.mR, s1.ho.mD) == (.ROTATING, 20, 120)

-- HO-009: a second ROTATE while one is ROTATING
theorem pin_open : codes s1 (.rotate rot1) = ["rotation_open"] := by decide +kernel
#guard codes s1 (.rotate rot1) == ["rotation_open"]

-- HO-013, HO-014: the joining seat 10 is pending; seat 12 is unknown
theorem pin_boot : (next s1 (Act.admitBoot 10 true).op).pending = [10] := by decide +kernel
#guard (next s1 (Act.admitBoot 10 true).op).pending == [10]
theorem pin_unknown : codes s1 (.admitBoot 12 true) = ["seat_unknown"] := by decide +kernel
#guard codes s1 (.admitBoot 12 true) == ["seat_unknown"]

-- HO-018: no carry before `EKS_{e+1}` is complete; HO-019: a wrong constant term
theorem pin_no_eks : codes s1 (.carry 1 true) = ["no-rule"] := by decide +kernel
def s2 : St := next s1 Act.eks.op
theorem pin_mismatch : codes s2 (.carry 3 false) = ["carry_mismatch"] := by decide +kernel
#guard codes s2 (.carry 3 false) == ["carry_mismatch"]
-- a carry mismatch leaves the state unchanged (HO-022)
theorem pin_mismatch_same : next s2 (Act.carry 3 false).op = s2 := by decide +kernel

-- HO-020, HO-021: seat 3 is disqualified inside `Δ_cw`; seats 1, 2 and 4 to 9 deal;
-- `Q` is seats 1, 2 and 4 to 8
def carries (l : List Nat) : List Op := l.map (fun d => (Act.carry d true).op)
def s3 : St := run s2 (carries seats9 ++ [(Act.complaint 3).op])
theorem pin_q : qualified s3 = [1, 2, 4, 5, 6, 7, 8] := by decide +kernel
#guard qualified s3 == [1, 2, 4, 5, 6, 7, 8]
-- a complaint after the window is refused
theorem pin_late_complaint : codes (next s3 (Act.midnightTick 24).op) (.complaint 4) = ["no-rule"] := by decide +kernel

-- HO-030: four READY for one `Q` and three for another; no pair counts above four
def q1 : List Nat := [1, 2, 4, 5, 6, 7, 8]
def sSplit : St := run s3 ([1, 2, 3, 4].map (fun x => (Act.ready x q1 50).op)
  ++ [5, 6, 7].map (fun x => (Act.ready x [1, 2, 3] 50).op))
theorem pin_split : (readyCount sSplit q1 50, readyCount sSplit [1, 2, 3] 50) = (4, 3) := by decide +kernel
#guard (readyCount sSplit q1 50, readyCount sSplit [1, 2, 3] 50) == (4, 3)
theorem pin_split_no_arm : codes (next sSplit (Act.midnightTick 30).op) (.arm 7) = ["no-rule"] := by decide +kernel

-- HO-031, HO-064: the seventh READY for one pair; after the last complaint window closes the
-- block at position 12 commits the heartbeat: ARMED with `H = 12`
def readies (l : List Nat) : List Op := l.map (fun x => (Act.ready x q1 50).op)
def blocks : Nat → List Op
  | 0 => []
  | k + 1 => Act.block.op :: blocks k
def s4 : St := run s3 ([(Act.midnightTick 30).op] ++ readies [1, 2, 3, 4, 5, 6, 10] ++ blocks 12)
theorem pin_window_open : codes (next s3 (Act.midnightTick 23).op |> fun s => run s (readies [1, 2, 3, 4, 5, 6, 10])) (.arm 7)
    = ["no-rule"] := by decide +kernel
def s5 : St := next s4 (Act.arm 7).op
theorem pin_armed : (s5.ho.phase, s5.ho.H) = (.ARMED, 12) := by decide +kernel
#guard (s5.ho.phase, s5.ho.H) == (.ARMED, 12)
-- six partials do not make the heartbeat
theorem pin_arm_six : codes s4 (.arm 6) = ["no-rule"] := by decide +kernel
-- HO-032: the board makes no block between `H` and the activation
theorem pin_halt : codes s5 .block = ["no-rule"] := by decide +kernel
#guard codes s5 .block == ["no-rule"]
-- HO-046: a source checkpoint above `H` is refused
theorem pin_superseded : codes s5 (.signCheckpoint 0 13) = ["epoch_superseded"] := by decide +kernel
#guard codes s5 (.signCheckpoint 0 13) == ["epoch_superseded"]
theorem pin_at_H : codes s5 (.signCheckpoint 0 12) = [] := by decide +kernel

-- HO-048: six target signatures; HO-049: an operator key of a guardian
theorem pin_bad_activation : codes s5 (.activate true 6 true true true) = ["bad_activation"] := by decide +kernel
#guard codes s5 (.activate true 6 true true true) == ["bad_activation"]
theorem pin_not_disjoint : codes s5 (.activate true 7 true true false) = ["operator_not_disjoint"] := by decide +kernel
#guard codes s5 (.activate true 7 true true false) == ["operator_not_disjoint"]

-- HO-032, HO-047, HO-050: the activation record lands; block 13 needs epoch 1, block 12 epoch 0
def s6 : St := next s5 (Act.activate true 7 true true true).op
theorem pin_activated : (s6.ho.phase, s6.cur, s6.landed, validatorAt s6 12, validatorAt s6 13)
    = (.HANDED_OVER, 1, 1, 0, 1) := by decide +kernel
#guard (s6.ho.phase, s6.cur, s6.landed, validatorAt s6 12, validatorAt s6 13) == (.HANDED_OVER, 1, 1, 0, 1)
-- HO-056, HO-057, HO-063: `X_f`, the user and every standing sharing in epoch 1
theorem pin_carried : (s6.xf, s6.users, (s6.sharings.filter (·.epoch == 1)).map (·.secret)) =
    (s0.xf, s0.users, [.xf .secp, .xf .ed, .slot 10 0, .slot 10 1]) := by decide +kernel
-- HO-051: an epoch 0 checkpoint after the activation; HO-068, HO-050: `t' = 7` signatures
theorem pin_old_cp : codes s6 (.submitCheckpoint 0 9) = ["epoch_superseded"] := by decide +kernel
#guard codes s6 (.submitCheckpoint 0 9) == ["epoch_superseded"]
theorem pin_few : codes s6 (.submitCheckpoint 1 6) = ["too_few_signers"] := by decide +kernel
#guard codes s6 (.submitCheckpoint 1 6) == ["too_few_signers"]
theorem pin_seven : codes s6 (.submitCheckpoint 1 7) = [] := by decide +kernel
-- HO-068 scenario at genesis: six signers at `t = 7`
theorem pin_six_genesis : codes s0 (.submitCheckpoint 0 6) = ["too_few_signers"] := by decide +kernel

-- HO-010, HO-011: epoch 0 is in grace; a valid ROTATE for epoch 2 is QUEUED
def rot2 : Rotate := { rot1 with target := 2, source := 1, roster := [1, 2, 3, 4, 5, 6, 7, 8, 11] }
def s7 : St := next s6 (Act.rotate rot2).op
theorem pin_queued : s7.ho.phase = .QUEUED := by decide +kernel
#guard s7.ho.phase == .QUEUED
-- HO-012: epoch 0 closes at Midnight 80 (30 + Δ_grace); the queue is released with `m_R = 80`
def s8 : St := next s7 (Act.midnightTick 80).op
theorem pin_released : (s8.ho.phase, s8.ho.mR, statusOf s8 0) = (.ROTATING, 80, some .closed) := by decide +kernel
#guard (s8.ho.phase, s8.ho.mR, statusOf s8 0) == (.ROTATING, 80, some .closed)
-- HO-045: the sharings of epoch 0 are erased at its grace end
theorem pin_erased : (s8.sharings.filter (·.epoch == 0)) = [] := by decide +kernel
-- HO-008, HO-053: a closed source, a certificate of a closed epoch
theorem pin_closed_source : codes (next s8 (Act.midnightTick 300).op) (.rotate { rot2 with source := 0 })
    = ["bad_source"] := by decide +kernel
theorem pin_cert_closed : codes s8 (.cert 0) = ["epoch_closed"] := by decide +kernel
#guard codes s8 (.cert 0) == ["epoch_closed"]

-- HO-033, HO-035: Midnight passes `m_D = 120` with the handoff ROTATING
def sAb : St := next s3 (Act.midnightTick 121).op
theorem pin_abort : (sAb.ho.phase, sAb.cur, sAb.sharings, sAb.epochs) = (.ABORTED, 0, s3.sharings, s3.epochs) := by
  decide +kernel
#guard (sAb.ho.phase, sAb.cur, sAb.sharings == s3.sharings) == (.ABORTED, 0, true)
theorem pin_at_deadline : (next s3 (Act.midnightTick 120).op).ho.phase = .ROTATING := by decide +kernel

-- HO-065, HO-066: the activation record never landed; block 13 needs epoch 0
def sAb2 : St := next s5 (Act.midnightTick 121).op
theorem pin_armed_abort : (sAb2.ho.phase, validatorAt sAb2 13, codes sAb2 .block) = (.ABORTED, 0, []) := by
  decide +kernel
#guard (sAb2.ho.phase, validatorAt sAb2 13, codes sAb2 .block) == (.ABORTED, 0, [])
theorem pin_late : codes sAb2 (.activate true 7 true true true) = ["activation_late"] := by decide +kernel
#guard codes sAb2 (.activate true 7 true true true) == ["activation_late"]

-- HO-036, HO-059: the sweep of request 41 at position 20,000
def r41 : Req := { id := 41, bind := 4, sweep := some 20000, live := true, slots := [] }
theorem pin_owner : (owner r41 19999, owner r41 20000) = (4, 5) := by decide +kernel
#guard (owner r41 19999, owner r41 20000) == (4, 5)

-- HO-038, HO-039, HO-040, HO-041, HO-043, HO-044: a request of epoch 0 across the activation and
-- its sweep; slot 1 is bound to ticket 99 before the sweep and is installed bound in epoch 1
def sR : St := run s5 []
def sReq : St := run s3 [(Act.order 41 0 [(10, 1)]).op, (Act.useSlot 41 10 1 99).op]
theorem pin_header : codes sReq (.header 41 1) = ["pool_epoch_mismatch"] := by decide +kernel
#guard codes sReq (.header 41 1) == ["pool_epoch_mismatch"]
def sReq2 : St := run sReq ([(Act.midnightTick 30).op] ++ readies [1, 2, 3, 4, 5, 6, 10] ++ blocks 12
  ++ [(Act.arm 7).op, (Act.activate true 7 true true true).op])
theorem pin_old_owner : (codes sReq2 (.entry 41 0), codes sReq2 (.entry 41 1), codes sReq2 (.envelope 0))
    = ([], ["not_owner"], []) := by decide +kernel
-- the activation carried only the free slot 0 (HO-018); the sweep at Midnight 75 = 80 − Δ_sweep
def sSw : St := run sReq2 [(Act.midnightTick 75).op, Act.block.op, (Act.sweepReady 0).op]
theorem pin_sweep : ((sSw.requests.map (·.sweep)), codes sSw (.entry 41 1), codes sSw (.envelope 0),
    (sSw.sharings.filter (fun sh => sh.epoch == 1 && sh.secret == .slot 10 1)).map (·.st))
    = ([some 13], [], ["epoch_closed"], [.bound 99]) := by decide +kernel
#guard ((sSw.requests.map (·.sweep)), codes sSw (.entry 41 1), codes sSw (.envelope 0)) ==
  ([some 13], [], ["epoch_closed"])
theorem pin_sweep_early : codes (next sReq2 (Act.midnightTick 74).op) (.sweepReady 0) = ["no-rule"] := by
  decide +kernel

end SplitHandoff
