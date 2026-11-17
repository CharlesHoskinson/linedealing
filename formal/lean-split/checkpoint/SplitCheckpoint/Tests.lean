import SplitCheckpoint.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` checks it against the definitions
the theorems describe, and `#guard` checks it with the compiled evaluator.
Expected values come from the spec text (the scenario numbers), not from `#eval`.
-/

namespace SplitCheckpoint

/-- The launch committee: `n = 9`, `f = 2`, so `w = 6`, `t = 7`, `q = 6`; `B = 200`. -/
def p9 : Params := { n := 9, f := 2, mode := .TEE, B := 200, slotAnchor := false, dRec := 30 }

theorem pin_params : p9.w = 6 ∧ p9.t = 7 ∧ p9.q = 6 ∧ paramsOk p9 = true := by decide +kernel
#guard p9.w == 6 && p9.t == 7 && p9.q == 6 && paramsOk p9

/-- Pool `(BIP340, 3)` with `h = 130` and live indices 95, 96, 120, 121. -/
def pool0 : Pool := { pool := 1, h := 130, pendingMin := 95, pending := [95, 96, 120, 121], pendingCount := 4 }

def cp500 : Cp :=
  { seq := 500, epoch := 3, boardHeight := 1000, boardRoot := 0, witnessRoot := 0, pools := [pool0],
    settle := [], bf := [(1, 77)], bootCounters := [], restartSeq := 200, seatRoots := [], restores := [] }

def zeros : List (Nat × Nat) := (List.range 9).map (fun s => (s, 0))
def ones : List (Nat × Nat) := (List.range 9).map (fun s => (s, 1))

/-- A ready node of the launch committee with checkpoint 500 landed. -/
def st9 : St := { init p9 with chain := [cp500], lastLandMh := 1000, ready := true, tickets := zeros }

/-- An account pool of 20 unused ECDSA slots with restart mark 200. -/
def acct20 : Acct := { id := 7, slots := List.replicate 20 .free, mark := 200, refill := false }

def codes (s : St) (op : Op) : List String := match (apply s op).2 with
  | .refused rs => rs.map Refusal.code
  | _ => []

-- CP-002: no live request and `h = 400`: `pending_min = 401`, `pending_count = 0`
theorem pin_no_live : pendingFields 0 400 [] = (401, [], 0) := by decide +kernel
#guard pendingFields 0 400 [] == (401, [], 0)

-- CP-014: live indices 95, 96, 120, 121 and `h = 130`: `pending_min = 95`, `pending_count = 4`
-- (no landed checkpoint, so no floor)
theorem pin_pending : pendingFields 0 130 [121, 95, 120, 96] = (95, [95, 96, 120, 121], 4) := by decide +kernel
#guard pendingFields 0 130 [121, 95, 120, 96] == (95, [95, 96, 120, 121], 4)
theorem pin_sign_pending : signPending [] pool0 [96, 95, 121, 120] = true ∧ signPending [] pool0 [95, 96] = false := by
  decide +kernel
#guard signPending [] pool0 [96, 95, 121, 120] && !signPending [] pool0 [95, 96]

-- CP-014 scenario "Precedence below the landed floor" (finding F7, DECISIONS 71): the previous
-- landed checkpoint has `pending_min = 2`, live requests hold indices 1 and 2, and `h = 2`:
-- `pending_min = 2` and `pending_count = 1`. The fields of the listing before DECISIONS 71
-- (`pending_min = 1`, `pending_count = 2`) are not signed.
def poolF7 (pm : Nat) (l : List Nat) : Pool := { pool0 with h := 2, pendingMin := pm, pending := l, pendingCount := l.length }
def stF7 : St := { st9 with chain := [{ cp500 with pools := [poolF7 2 [2]] }] }
theorem pin_pending_floor : pendingFields 2 2 [1, 2] = (2, [2], 1)
    ∧ (apply stF7 (.signPending (poolF7 2 [2]) [1, 2])).2 = .bool true
    ∧ (apply stF7 (.signPending (poolF7 1 [1, 2]) [1, 2])).2 = .bool false := by decide +kernel
#guard pendingFields 2 2 [1, 2] == (2, [2], 1)
  && (apply stF7 (.signPending (poolF7 2 [2]) [1, 2])).2 == .bool true
  && (apply stF7 (.signPending (poolF7 1 [1, 2]) [1, 2])).2 == .bool false

-- CP-014: "A pool that the previous landed checkpoint does not list has no floor": the landed
-- checkpoint lists only pool 2, so pool 1 lists both live indices 1 and 2.
def stF7other : St := { st9 with chain := [{ cp500 with pools := [{ poolF7 2 [2] with pool := 2 }] }] }
theorem pin_pending_no_floor : (apply stF7other (.signPending (poolF7 1 [1, 2]) [1, 2])).2 = .bool true
    ∧ (apply stF7other (.signPending (poolF7 2 [2]) [1, 2])).2 = .bool false := by decide +kernel
#guard (apply stF7other (.signPending (poolF7 1 [1, 2]) [1, 2])).2 == .bool true
  && (apply stF7other (.signPending (poolF7 2 [2]) [1, 2])).2 == .bool false

-- CP-014 with CP-040 (DECISIONS 71): after the F7 checkpoint the signed fields land; the fields
-- of the old listing are refused with `pending_min_lowered`.
theorem pin_f7_lands : codes stF7 (.land { cp500 with seq := 501, pools := [poolF7 2 [2]] } 1100) = []
    ∧ codes stF7 (.land { cp500 with seq := 501, pools := [poolF7 1 [1, 2]] } 1100) = ["pending_min_lowered"] := by
  decide +kernel
#guard codes stF7 (.land { cp500 with seq := 501, pools := [poolF7 2 [2]] } 1100) == []
  && codes stF7 (.land { cp500 with seq := 501, pools := [poolF7 1 [1, 2]] } 1100) == ["pending_min_lowered"]

def cand (h pm : Nat) : Cp := { cp500 with seq := 501, pools := [{ pool0 with h, pendingMin := pm, pending := [], pendingCount := 0 }] }

-- CP-007: `h = 90` after a landed `h = 100`
def st100 : St := { st9 with chain := [{ cp500 with pools := [{ pool0 with h := 100, pendingMin := 91, pending := [91], pendingCount := 1 }] }] }
theorem pin_lowered : codes st100 (.land (cand 90 91) 1100) = ["h_lowered"] := by decide +kernel
#guard codes st100 (.land (cand 90 91) 1100) == ["h_lowered"]

-- CP-008: `h = 100` and `pending_min = 105`
theorem pin_gap : codes st100 (.land (cand 100 105) 1100) = ["pending_gap"] := by decide +kernel
#guard codes st100 (.land (cand 100 105) 1100) == ["pending_gap"]
theorem pin_no_gap : codes st100 (.land (cand 100 101) 1100) = [] := by decide +kernel
#guard codes st100 (.land (cand 100 101) 1100) == []

/-- The checkpoint after a whole-committee restart: every seat records boot
counter 1 from its `RestoreDone` naming checkpoint 500. -/
def restores1 : List Restore := (List.range 9).map (fun s => { seat := s, bootCtr := 1, cpSeq := 500, whole := true })
def cand501 (h pm : Nat) : Cp := { cand h pm with bootCounters := ones, restores := restores1 }

-- CP-009: after a whole-committee restart `h` stays at `cp1.h + 10` with `B = 200`
theorem pin_jump : codes st9 (.land (cand501 140 141) 1100) = ["restart_jump"] := by decide +kernel
#guard codes st9 (.land (cand501 140 141) 1100) == ["restart_jump"]
-- the jump to `cp1.h + B` with `pending_min = h + 1` lands
theorem pin_jump_ok : codes st9 (.land (cand501 330 331) 1100) = [] := by decide +kernel
#guard codes st9 (.land (cand501 330 331) 1100) == []
-- `pending_min ≤ cp1.h + B` is a jump failure too
theorem pin_jump_pmin : codes st9 (.land (cand501 330 330) 1100) = ["restart_jump"] := by decide +kernel
#guard codes st9 (.land (cand501 330 330) 1100) == ["restart_jump"]
-- a partial restart (one seat) needs no jump
theorem pin_no_jump_partial :
    codes st9 (.land { cand 140 141 with bootCounters := [(3, 1)], restores := [{ seat := 3, bootCtr := 1, cpSeq := 500, whole := false }] } 1100) = [] := by
  decide +kernel
#guard codes st9 (.land { cand 140 141 with bootCounters := [(3, 1)], restores := [{ seat := 3, bootCtr := 1, cpSeq := 500, whole := false }] } 1100) == []

-- CP-010: seat 3 at boot counter 12 with no `RestoreDone` for 12
theorem pin_counter_only : codes st9 (.land { cand 140 141 with bootCounters := [(3, 12)] } 1100) = ["no_restore_statement"] := by
  decide +kernel
#guard codes st9 (.land { cand 140 141 with bootCounters := [(3, 12)] } 1100) == ["no_restore_statement"]

-- CP-011: checkpoint 501 carries a whole-restart `RestoreDone` naming 500 at `restart_seq = 200`
theorem pin_marker : latestRestartSeq (apply st9 (.land (cand501 330 331) 1100)).1 = 501 := by decide +kernel
#guard latestRestartSeq (apply st9 (.land (cand501 330 331) 1100)).1 == 501
theorem pin_marker_kept : latestRestartSeq (apply st9 (.land (cand 140 141) 1100)).1 = 200 := by decide +kernel
#guard latestRestartSeq (apply st9 (.land (cand 140 141) 1100)).1 == 200
-- a partial-restart `RestoreDone` (`whole_restart = false`) naming 500 leaves `restart_seq` at 200
def candPartial : Cp :=
  { cand 140 141 with bootCounters := [(3, 1)], restores := [{ seat := 3, bootCtr := 1, cpSeq := 500, whole := false }] }
theorem pin_marker_partial : latestRestartSeq (apply st9 (.land candPartial 1100)).1 = 200 := by decide +kernel
#guard latestRestartSeq (apply st9 (.land candPartial 1100)).1 == 200

-- CP-012: two calls of an interval with one `nf`; an `nf` of a landed `bf_root`
theorem pin_bf : signBf [cp500] [(1, 5), (2, 5)] = false ∧ signBf [cp500] [(3, 77)] = false
    ∧ signBf [cp500] [(1, 5), (2, 6)] = true := by decide +kernel
#guard !signBf [cp500] [(1, 5), (2, 5)] && !signBf [cp500] [(3, 77)] && signBf [cp500] [(1, 5), (2, 6)]

-- CP-013: Midnight records `auth` 9 as settled VOID; a replay offers `(9, RELEASED)`
theorem pin_settle : signSettle [(9, .RELEASED)] [(9, .RELEASED)] [9] = false
    ∧ signSettle [(9, .VOID)] [(9, .VOID)] [9] = true ∧ signSettle [(4, .FINAL)] [(4, .FINAL), (5, .VOID)] [] = false := by
  decide +kernel
#guard !signSettle [(9, .RELEASED)] [(9, .RELEASED)] [9] && signSettle [(9, .VOID)] [(9, .VOID)] [9]
  && !signSettle [(4, .FINAL)] [(4, .FINAL), (5, .VOID)] []

-- CP-015: seat 2's log holds two puts with one digest
theorem pin_seat_root : signSeatRoot [.put 5, .bind 1 9, .put 5] = false ∧ signSeatRoot [.put 5, .bind 1 9, .bind 2 9] = true
    ∧ signSeatRoot [.bind 1 9, .bind 1 8] = false := by decide +kernel
#guard !signSeatRoot [.put 5, .bind 1 9, .put 5] && signSeatRoot [.put 5, .bind 1 9, .bind 2 9] && !signSeatRoot [.bind 1 9, .bind 1 8]

-- CP-016: a put entry above the board height of the latest landed checkpoint does not count
theorem pin_tail : covered st9 1001 = false ∧ covered st9 1000 = true := by decide +kernel
#guard !covered st9 1001 && covered st9 1000

-- CP-017: seat 6 holds boot ticket 9 and the latest checkpoint records 8
theorem pin_not_continuous : continuous 9 [(6, 9)] { cp500 with bootCounters := [(6, 8)] } = 8 := by decide +kernel
#guard continuous 9 [(6, 9)] { cp500 with bootCounters := [(6, 8)] } == 8

-- CP-018: all nine nodes reboot and no seat is continuous
theorem pin_region_outage : continuous 9 ones cp500 = 0 ∧ wholeRestart p9 ones cp500 = true := by decide +kernel
#guard continuous 9 ones cp500 == 0 && wholeRestart p9 ones cp500

-- CP-019: a booting node that cannot verify the snapshot opens no session
def booted : St := (apply st9 .boot).1
theorem pin_unverified : codes booted (.readLedger false ones []) = ["ledger_unverified"]
    ∧ codes booted (.openSession 1) = ["ledger_unverified"] := by decide +kernel
#guard codes booted (.readLedger false ones []) == ["ledger_unverified"] && codes booted (.openSession 1) == ["ledger_unverified"]

-- CP-020: `pending_min = 95`, `h = 130`, `B = 200`: indices 95 to 330 are burned
def restarted : St := (apply { booted with accts := [acct20] } (.readLedger true ones [])).1
theorem pin_burn_range : burned restarted 1 95 = true ∧ burned restarted 1 330 = true
    ∧ burned restarted 1 94 = false ∧ burned restarted 1 331 = false := by decide +kernel
#guard burned restarted 1 95 && burned restarted 1 330 && !burned restarted 1 94 && !burned restarted 1 331

-- CP-021: an address with 20 unused ECDSA slots: all 20 are burned
theorem pin_acct_burn : restarted.accts.map (·.slots) = [List.replicate 20 .burned] := by decide +kernel
#guard restarted.accts.map (·.slots) == [List.replicate 20 .burned]

-- CP-022: node 1 kept running and reads the same ledger: it burns the same sets
theorem pin_survivor : (apply { st9 with accts := [acct20] } (.readLedger true ones [])).1.burnC = restarted.burnC := by
  decide +kernel
#guard (apply { st9 with accts := [acct20] } (.readLedger true ones [])).1.burnC == restarted.burnC

-- CP-023: checkpoints 500 and 501 read during one restart: both ranges burn
def cp501 : Cp := { cp500 with seq := 501, pools := [{ pool0 with pool := 2, h := 400, pendingMin := 401, pending := [], pendingCount := 0 }] }
def twice : St := (apply { restarted with chain := cp501 :: restarted.chain } (.readLedger true ones [])).1
theorem pin_union : burned twice 1 95 = true ∧ burned twice 2 600 = true := by decide +kernel
#guard burned twice 1 95 && burned twice 2 600

-- CP-024: pool session `slots-BIP340-3` created after the restart opens with 95 to 330 burned
theorem pin_session : (apply restarted (.openSession 1)).1.sessions = [(1, [(1, 95, 330)])] := by decide +kernel
#guard (apply restarted (.openSession 1)).1.sessions == [(1, [(1, 95, 330)])]

-- CP-025: an ECDSA bind before the marker checkpoint lands binds nothing
def acctFresh : St := (apply restarted (.openAcct { acct20 with id := 8, mark := 200 })).1
theorem pin_bind_before_marker : codes acctFresh (.bindAcct 8 0 5) = ["no-rule"] := by decide +kernel
#guard codes acctFresh (.bindAcct 8 0 5) == ["no-rule"]

-- CP-011, CP-025, CP-027: the marker checkpoint with seven continuous seats
-- writes the marker, allows binds and ends the restart
def marked : St := (apply acctFresh (.land (cand501 330 331) 1100)).1
theorem pin_marker_end : marked.markerLanded = true ∧ marked.restartOpen = false
    ∧ marked.accts.map (·.mark) = [501, 501] ∧ codes marked (.bindAcct 7 0 5) = ["no-rule"] := by decide +kernel
#guard marked.markerLanded && !marked.restartOpen && marked.accts.map (·.mark) == [501, 501]

-- CP-027: continuity below `w + 1` at the marker checkpoint keeps the restart open
def lost : St := (apply { acctFresh with tickets := (List.range 9).map (fun s => (s, 2)) } (.land (cand501 330 331) 1100)).1
theorem pin_second_loss : lost.markerLanded = true ∧ lost.restartOpen = true := by decide +kernel
#guard lost.markerLanded && lost.restartOpen

-- CP-027: six continuous seats (`w`, not `w + 1`) at the marker checkpoint keep the restart open
def six : St := (apply { acctFresh with tickets := (List.range 9).map (fun s => (s, if s < 6 then 1 else 2)) }
  (.land (cand501 330 331) 1100)).1
theorem pin_six_continuous : six.markerLanded = true ∧ six.restartOpen = true := by decide +kernel
#guard six.markerLanded && six.restartOpen

-- CP-026: a node boots after checkpoint 501 set `restart_seq = 501` and opens a pool with mark 200
def late : St := (apply { st9 with chain := [{ cp500 with seq := 501, restartSeq := 501 }] } (.openAcct acct20)).1
theorem pin_late_boot : late.accts = [{ acct20 with slots := List.replicate 20 .burned, mark := 501 }] := by decide +kernel
#guard late.accts == [{ acct20 with slots := List.replicate 20 .burned, mark := 501 }]

-- CP-028: one node reboots and eight seats are continuous: nothing is burned
def oneReboot : St := (apply { booted with accts := [acct20] } (.readLedger true ((List.range 9).map (fun s => (s, if s = 3 then 1 else 0))) [])).1
theorem pin_one_reboot : oneReboot.burnC = [] ∧ oneReboot.accts = [acct20] ∧ oneReboot.restartOpen = false := by
  decide +kernel
#guard oneReboot.burnC == [] && oneReboot.accts == [acct20] && !oneReboot.restartOpen

-- CP-029: a slot restores `free` from an old disk and a covered entry binds it to `d`
def anchored : St := (apply { booted with params := { p9 with slotAnchor := true }, accts := [acct20] } (.readLedger true ones [(7, 0, 42)])).1
theorem pin_anchor : anchored.burnC = [] ∧ (anchored.accts.map (·.slots.take 2)) = [[.bound 42, .free]] := by
  decide +kernel
#guard anchored.burnC == [] && anchored.accts.map (·.slots.take 2) == [[.bound 42, .free]]

-- CP-030: only four nodes have tier 0 intact; six operators sign `coldStart`
theorem pin_cold_start : (apply st9 (.coldStart 4 6)).1.coldStarted = true ∧ codes st9 (.coldStart 7 6) = ["no-rule"]
    ∧ codes st9 (.coldStart 4 5) = ["no-rule"] := by decide +kernel
#guard (apply st9 (.coldStart 4 6)).1.coldStarted && codes st9 (.coldStart 7 6) == ["no-rule"]

-- CP-031: `E` cannot fetch seat 7's log: it reshares no ECDSA slot of seat 7; CP-032: none without anchors
theorem pin_reshare : reshare true [(7, 1, false, false), (2, 3, false, true), (2, 4, true, true)] = [(2, 3)]
    ∧ reshare false [(2, 3, false, true)] = [] := by decide +kernel
#guard reshare true [(7, 1, false, false), (2, 3, false, true), (2, 4, true, true)] == [(2, 3)]

-- CP-033: a non-TEE committee restarts at once: a new pool is dealt, every address refills
def nonTee : St := (apply { st9 with params := { p9 with mode := .NON_TEE }, accts := [acct20] } .nonTeeRestart).1
theorem pin_non_tee : nonTee.newPool = true ∧ nonTee.accts = [{ acct20 with slots := List.replicate 20 .burned, refill := true }] := by
  decide +kernel
#guard nonTee.newPool && nonTee.accts == [{ acct20 with slots := List.replicate 20 .burned, refill := true }]

-- CP-034, CP-035: with `Δ_rec = 30` blocks after the landing at 1000: early at 1029, accepted at 1030
theorem pin_recover : codes st9 (.recover 1029) = ["recovery_early"] ∧ (apply st9 (.recover 1030)).1.recovered = true := by
  decide +kernel
#guard codes st9 (.recover 1029) == ["recovery_early"] && (apply st9 (.recover 1030)).1.recovered

-- CP-036: a request ordered below the replay floor with no proof of non-service
theorem pin_floor : codes st9 (.orderReq 900 [950] false) = ["below_floor"] ∧ codes st9 (.orderReq 900 [950] true) = []
    ∧ codes st9 (.orderReq 1000 [950] false) = [] := by decide +kernel
#guard codes st9 (.orderReq 900 [950] false) == ["below_floor"] && codes st9 (.orderReq 900 [950] true) == []

-- CP-037: a release of an `anchor_before_release` charter waits for the next checkpoint root
theorem pin_release_anchor : releaseOk st9 true 1001 = false ∧ releaseOk st9 false 1001 = true ∧ releaseOk st9 true 990 = true := by
  decide +kernel
#guard !releaseOk st9 true 1001 && releaseOk st9 false 1001 && releaseOk st9 true 990

-- CP-003: one checkpoint per 60 s of board time
theorem pin_due : due 0 60 = true ∧ due 0 59 = false := by decide +kernel
#guard due 0 60 && !due 0 59

-- CP-004: node 4 appends `RestoreDone`; a checkpoint carries it before node 5 reboots
def r4 : Restore := { seat := 4, bootCtr := 1, cpSeq := 500, whole := false }
def appended : St := (apply st9 (.restoreDone r4)).1
theorem pin_rolling : (apply appended .mayReboot).2 = .bool false
    ∧ (apply (apply appended (.land { cand 140 141 with bootCounters := [(4, 1)], restores := [r4] } 1100)).1 .mayReboot).2 = .bool true := by
  decide +kernel
#guard (apply appended .mayReboot).2 == .bool false

-- CP-005: a landing is one committee write; no request adds one
theorem pin_one_write : (apply st9 (.land (cand 140 141) 1100)).1.writes = [.checkpoint] := by decide +kernel
#guard (apply st9 (.land (cand 140 141) 1100)).1.writes == [.checkpoint]

-- CP-006: the nine nodes of epoch 4 each hold six acks; six signatures
theorem pin_eks : (apply st9 (.eks 4 (List.replicate 9 6) 6)).1.writes = [.eks 4]
    ∧ codes st9 (.eks 4 (5 :: List.replicate 8 6) 6) = ["no-rule"] := by decide +kernel
#guard (apply st9 (.eks 4 (List.replicate 9 6) 6)).1.writes == [.eks 4]

-- CP-039: one checkpoint read with `B = 200` and three pending indices: at most 203 usable indices burn
def pool3 : Pool := { pool := 1, h := 130, pendingMin := 95, pending := [95, 96, 120], pendingCount := 3 }
theorem pin_loss : cnt (usable pool3) 95 (130 + 200 + 1 - 95) = 203 := by decide +kernel
#guard cnt (usable pool3) 95 (130 + 200 + 1 - 95) == 203
theorem pin_loss_bound : cnt (usable pool3) 95 (130 + 200 + 1 - 95) ≤ 200 + pool3.pending.length :=
  C16_bounded_loss 200 pool3 (by decide)

-- CP-002: 52 bytes per pool
theorem pin_pool_bytes : poolBytes = 52 := by decide +kernel
#guard poolBytes == 52

-- refusal codes as the wire carries them, in code order
theorem pin_codes : [Refusal.belowFloor, .hLowered, .ledgerUnverified, .noRule, .noRestoreStatement,
    .outsideCapability, .outsideStateDomain, .pendingGap, .pendingMinLowered, .recoveryEarly, .restartJump].map Refusal.code =
    ["below_floor", "h_lowered", "ledger_unverified", "no-rule", "no_restore_statement",
     "outside-capability", "outside-state-domain", "pending_gap", "pending_min_lowered", "recovery_early",
     "restart_jump"] := by decide +kernel
#guard ["below_floor", "h_lowered", "ledger_unverified", "no-rule", "no_restore_statement",
     "outside-capability", "outside-state-domain", "pending_gap", "pending_min_lowered", "recovery_early",
     "restart_jump"].mergeSort ==
    ["below_floor", "h_lowered", "ledger_unverified", "no-rule", "no_restore_statement",
     "outside-capability", "outside-state-domain", "pending_gap", "pending_min_lowered", "recovery_early",
     "restart_jump"]

-- several landing refusals together, sorted (ledger 1)
theorem pin_two_codes : codes st100 (.land { cand 90 105 with seq := 7 } 1100) = ["h_lowered", "no-rule", "pending_gap"] := by
  decide +kernel
#guard codes st100 (.land { cand 90 105 with seq := 7 } 1100) == ["h_lowered", "no-rule", "pending_gap"]

-- a refused landing leaves the state unchanged
theorem pin_refused_unchanged : (apply st100 (.land (cand 90 91) 1100)).1 = st100 := by decide +kernel
#guard (apply st100 (.land (cand 90 91) 1100)).1 == st100

/-! ## DECISIONS 69: CP-011, CP-016, CP-021, CP-022 and CP-039 to CP-043 -/

/-- A landed checkpoint 500 that carries a whole-restart `RestoreDone` naming 400
while `restart_seq` is still 200 (a `--step` state). -/
def cpCarried : Cp := { cp500 with restores := [{ seat := 3, bootCtr := 0, cpSeq := 400, whole := true }] }
def stFollow : St := { st9 with chain := [cpCarried] }
def follow1 : St := (apply stFollow (.land (cand 330 331) 1100)).1

-- CP-011: checkpoint 501 follows a checkpoint that carries a qualifying `RestoreDone`:
-- it sets `restart_seq = 501`, a checkpoint with no restores must jump (CP-041),
-- and checkpoint 502 keeps `restart_seq = 501`
-- CP-011, CP-041
theorem pin_marker_follows : latestRestartSeq follow1 = 501
    ∧ codes stFollow (.land (cand 140 141) 1100) = ["restart_jump"]
    ∧ latestRestartSeq (apply follow1 (.land { cand 340 341 with seq := 502 } 1200)).1 = 501 := by decide +kernel
#guard latestRestartSeq follow1 == 501 && codes stFollow (.land (cand 140 141) 1100) == ["restart_jump"]
  && latestRestartSeq (apply follow1 (.land { cand 340 341 with seq := 502 } 1200)).1 == 501

-- CP-016: binding entries `(nf, e)`: two slot nullifiers with one hidden digest sign,
-- a second binding for one `nf` does not
theorem pin_binding_entries : signSeatRoot [.bind 1 9, .bind 2 9] = true ∧ signSeatRoot [.bind 1 9, .bind 1 8] = false := by
  decide +kernel
#guard signSeatRoot [.bind 1 9, .bind 2 9] && !signSeatRoot [.bind 1 9, .bind 1 8]

-- CP-040: a checkpoint shows `pending_min = 1` after a landed `pending_min = 3`;
-- an equal `pending_min` lands
def st3 : St := { st9 with chain := [{ cp500 with pools := [{ pool0 with h := 10, pendingMin := 3, pending := [3], pendingCount := 1 }] }] }
-- CP-040
theorem pin_pmin_lowered : codes st3 (.land (cand 10 1) 1100) = ["pending_min_lowered"]
    ∧ codes st3 (.land (cand 10 3) 1100) = [] := by decide +kernel
#guard codes st3 (.land (cand 10 1) 1100) == ["pending_min_lowered"] && codes st3 (.land (cand 10 3) 1100) == []

/-- Checkpoint 501 after the whole-committee restart, `restart_seq = 501`, `h = 330`. -/
def cp501m : Cp :=
  { cp500 with seq := 501, restartSeq := 501, bootCounters := ones, restores := restores1,
               pools := [{ pool0 with h := 330, pendingMin := 331, pending := [], pendingCount := 0 }] }
def st501 : St := { st9 with chain := [cp501m, cp500] }
/-- Seat 8 syncs one checkpoint later: boot counter 2, `RestoreDone` naming 501. -/
def r8 : Restore := { seat := 8, bootCtr := 2, cpSeq := 501, whole := true }
def cand502 (h pm : Nat) (r : Restore) : Cp :=
  { cp501m with seq := 502, bootCounters := (List.range 9).map (fun s => (s, if s = 8 then 2 else 1)), restores := [r],
                pools := [{ pool0 with h, pendingMin := pm, pending := [], pendingCount := 0 }] }

-- CP-041: checkpoint 502 moves `restart_seq` from 501 to 502 and keeps `h` at
-- `cp1.h + 10` with `B = 200`, while eight seats keep their boot counters (CP-009 holds)
theorem pin_marker_jump : codes st501 (.land (cand502 340 341 r8) 1200) = ["restart_jump"]
    ∧ latestRestartSeq (apply st501 (.land (cand502 530 531 r8) 1200)).1 = 502
    ∧ codes st501 (.land (cand502 340 341 { r8 with whole := false }) 1200) = [] := by decide +kernel
#guard codes st501 (.land (cand502 340 341 r8) 1200) == ["restart_jump"]
  && latestRestartSeq (apply st501 (.land (cand502 530 531 r8) 1200)).1 == 502
  && codes st501 (.land (cand502 340 341 { r8 with whole := false }) 1200) == []

-- CP-039: the seat that syncs late retires one window `B`: `h = cp1.h + B` lands,
-- `h = cp1.h + B - 1` is refused
theorem pin_seat_window : codes st501 (.land (cand502 530 531 r8) 1200) = []
    ∧ codes st501 (.land (cand502 529 530 r8) 1200) = ["restart_jump"]
    ∧ codes st501 (.land (cand502 529 535 r8) 1200) = ["pending_gap", "restart_jump"] := by decide +kernel
#guard codes st501 (.land (cand502 530 531 r8) 1200) == [] && codes st501 (.land (cand502 529 530 r8) 1200) == ["restart_jump"]
  && codes st501 (.land (cand502 529 535 r8) 1200) == ["pending_gap", "restart_jump"]

-- CP-021: an account pool opened after the classification and before the marker
-- burns; after the marker, a second read of the same restart generation burns no
-- account slot again
theorem pin_open_burn : (apply restarted (.openAcct { acct20 with id := 8 })).1.accts.head?.map (·.slots)
    = some (List.replicate 20 .burned) := by decide +kernel
#guard (apply restarted (.openAcct { acct20 with id := 8 })).1.accts.head?.map (·.slots) == some (List.replicate 20 .burned)
def gen2 : St := (runOps lost [.openAcct { id := 9, slots := [.free, .free], mark := 501, refill := false },
  .bindAcct 9 0 5, .readLedger true ((List.range 9).map (fun s => (s, 2))) []]).1
-- CP-021, CP-027
theorem pin_once_per_generation : (gen2.accts.find? (·.id == 9)).map (·.slots) = some [.bound 5, .free]
    ∧ gen2.restartOpen = true := by decide +kernel
#guard (gen2.accts.find? (·.id == 9)).map (·.slots) == some [.bound 5, .free] && gen2.restartOpen

-- CP-022: node 1 kept running with an open session of pool 1: the session burns 95 to 330 at once
def survivor : St := (apply { st9 with sessions := [(1, [])], accts := [acct20] } (.readLedger true ones [])).1
-- CP-022
theorem pin_survivor_session : survivor.sessions = [(1, [(1, 95, 330)])] := by decide +kernel
#guard survivor.sessions == [(1, [(1, 95, 330)])]

-- CP-042: the board loses the tail that held the `RestoreDone` of node 4 before
-- checkpoint 502 covered it: node 4 appends it again; a checkpoint before the new
-- append records no boot counter for the seat
def lostTail : St := (runOps st9 [.restoreDone r4, .loseTail]).1
-- CP-042, CP-010
theorem pin_reappend : lostTail.board = [] ∧ lostTail.pendingRestores = [r4]
    ∧ (apply lostTail (.readLedger true zeros [])).1.board = [r4]
    ∧ codes lostTail (.land { cand 140 141 with bootCounters := [(4, 1)] } 1100) = ["no_restore_statement"] := by
  decide +kernel
#guard lostTail.board == [] && (apply lostTail (.readLedger true zeros [])).1.board == [r4]
  && codes lostTail (.land { cand 140 141 with bootCounters := [(4, 1)] } 1100) == ["no_restore_statement"]

-- CP-043: a later ledger view claims coverage and does not verify: the node keeps
-- the last verified view, answers `ledger_unverified` to binds and anchored
-- releases, and is ready again when a new view verifies
def unver : St := (apply { st9 with accts := [acct20] } (.readLedger false zeros [(7, 0, 42)])).1
-- CP-043, CP-037
theorem pin_later_unverified : unver = { st9 with accts := [acct20], ready := false }
    ∧ codes unver (.bindAcct 7 0 42) = ["ledger_unverified"]
    ∧ codes unver (.releaseAnchor true 990) = ["ledger_unverified"] ∧ codes unver (.releaseAnchor false 990) = []
    ∧ (apply unver (.readLedger true zeros [])).1.ready = true := by decide +kernel
#guard unver == { st9 with accts := [acct20], ready := false } && codes unver (.bindAcct 7 0 42) == ["ledger_unverified"]
  && codes unver (.releaseAnchor true 990) == ["ledger_unverified"] && (apply unver (.readLedger true zeros [])).1.ready

/-- C16 witness: a whole-committee restart is reachable from `init` (land, boot,
read), and the conditional of `C16_run_window_burned` fires. -/
theorem witness_restart : ∃ ops, (run (init p9) ops).restartOpen = true := by
  refine ⟨[.land { cp500 with seq := 0, restartSeq := 0 } 1000, .boot, .readLedger true ones []], ?_⟩
  decide +kernel

end SplitCheckpoint
