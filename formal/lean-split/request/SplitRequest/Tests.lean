import SplitRequest.Theorems

/-!
# Pins from the split-request scenarios

Each expected value is written from the requirement sentence or its scenario,
not copied from an evaluation. Every pin is checked twice: by the kernel
(`decide +kernel`) and by the compiled code (`#guard`).

The base run: committee `n = 9`, `f = 2` (`q = 6`, `t = 7`, `w = 6`), epoch 0
registered, `Δ_c = 600`. Request 1 (SPEND) is posted with `exp = 5000`, the
board reaches height 100, and the block at height 100 orders it with a QC.
-/

namespace SplitRequest


def p9 : Params := { n := 9, f := 2, deltaC := 600, deltaHold := 10, mode := .TEE }
def es0 : List (Nat × Nat × Nat) := [(0, 9, 2)]
def s0 : St := init p9 es0
def rates8 : List Nat := [1, 2, 3, 4, 5, 6, 7, 8]

def opsOrder (pr : Profile) : List Op := [.post 1 0 5000 .SPEND pr, .tick 100, .order 1 true 0]
def opsOpen (pr : Profile) : List Op := opsOrder pr ++ [.openHdr 1 8 2 false 0 rates8]
def admits (k : Nat) : List Op := (List.range k).map (fun i => .voteAdmit 1 i 7 50)
/-- six ADMIT votes; the anchor height is 50 and the host fee median there is 3 -/
def opsAdmit (pr : Profile) : List Op := opsOpen pr ++ [.hostFee 50 3] ++ admits 6
def opsRel : List Op := opsAdmit .P1 ++ [.release 1 1 3]
def finals (k : Nat) : List Op := (List.range k).map (fun i => .postFinal 1 0 i 42)
def vposts (k : Nat) (rs : Reason) : List Op := (List.range k).map (fun i => .postVoid 1 0 i rs)

def req (ops : List Op) : Option Req := find (run s0 ops) 1
def phaseOf (ops : List Op) : Option Phase := (req ops).map (·.phase)
def lastObs (ops : List Op) : Option Obs := (runOps s0 ops).2.getLast?

-- RQ-001: n = 9, f = 2 gives q = 6, t = 7, w = 6; n = 17, f = 5 gives q = 12, t = 12, w = 11
theorem pin_rq001 : p9.q = 6 ∧ p9.t = 7 ∧ p9.w = 6 ∧ qOf 17 5 = 12 ∧ 17 - 5 = 12 ∧ 17 - 1 - 5 = 11 := by
  decide +kernel
#guard p9.q == 6 && p9.t == 7 && p9.w == 6 && qOf 17 5 == 12

-- RQ-001: the domain n ≥ 3f + 1, f ≥ 1 (bound, bound − 1, f = 0)
theorem pin_rq001_domain : committeeOk 7 2 = true ∧ committeeOk 6 2 = false ∧ committeeOk 4 0 = false := by
  decide +kernel
#guard committeeOk 7 2 && !committeeOk 6 2 && !committeeOk 4 0

-- RQ-002, RQ-003: a new request is POSTED, reason NONE, no release, no restart end, outcome NONE
theorem pin_rq002 : (req [.post 1 0 5000 .SPEND .P1]).map
    (fun r => (r.phase, r.reason, r.anyRelease, r.restartEnd, r.outcome)) =
    some (.POSTED, .NONE, false, false, .NONE) := by decide +kernel
#guard (req [.post 1 0 5000 .SPEND .P1]).map (fun r => (r.phase, r.reason, r.anyRelease, r.restartEnd, r.outcome))
  == some (.POSTED, .NONE, false, false, .NONE)

-- RQ-004: an ADMIT vote for an eid with no request
theorem pin_rq004 : lastObs (opsOrder .P1 ++ [.voteAdmit 9 0 7 50]) = some (.refused [.unknownRequest]) := by
  decide +kernel
#guard lastObs (opsOrder .P1 ++ [.voteAdmit 9 0 7 50]) == some (.refused [.unknownRequest])

-- RQ-006: the block at height 100 with a QC orders the request; exp_c = 100 + 600
theorem pin_rq006 : (req (opsOrder .P1)).map (fun r => (r.phase, r.expC)) = some (.ORDERED, some 700) := by
  decide +kernel
#guard (req (opsOrder .P1)).map (fun r => (r.phase, r.expC)) == some (.ORDERED, some 700)

-- RQ-007: a proposal without a QC leaves the request POSTED
theorem pin_rq007 : lastObs [.post 1 0 5000 .SPEND .P1, .order 1 false 0] = some (.refused [.noQc]) ∧
    phaseOf [.post 1 0 5000 .SPEND .P1, .order 1 false 0] = some .POSTED := by decide +kernel
#guard lastObs [.post 1 0 5000 .SPEND .P1, .order 1 false 0] == some (.refused [.noQc])

-- RQ-013: K = 8, L = 2 opens with G = 2 and collecting = false
theorem pin_rq013 : (req (opsOpen .P1)).map (fun r => (r.phase, r.G, r.collecting)) =
    some (.OPENED, 2, false) := by decide +kernel
#guard (req (opsOpen .P1)).map (fun r => (r.phase, r.G, r.collecting)) == some (.OPENED, 2, false)

-- RQ-067: K = 1, L = 1 gives G = 1
theorem pin_rq067 : (req (opsOrder .P1 ++ [.openHdr 1 1 1 false 0 [5]])).map (·.G) = some 1 := by decide +kernel
#guard (req (opsOrder .P1 ++ [.openHdr 1 1 1 false 0 [5]])).map (·.G) == some 1

-- RQ-067: K = 9 is above K_max
theorem pin_rq067_kmax : lastObs (opsOrder .P1 ++ [.openHdr 1 9 2 false 0 [1, 2, 3, 4, 5, 6, 7, 8, 9]]) =
    some (.refused [.outsideCapability]) := by decide +kernel
#guard lastObs (opsOrder .P1 ++ [.openHdr 1 9 2 false 0 [1, 2, 3, 4, 5, 6, 7, 8, 9]]) ==
  some (.refused [.outsideCapability])

-- RQ-026: five ADMIT votes leave the request OPENED; the sixth admits it
theorem pin_rq026 : phaseOf (opsOpen .P1 ++ [.hostFee 50 3] ++ admits 5) = some .OPENED ∧
    phaseOf (opsAdmit .P1) = some .ADMITTED := by decide +kernel
#guard phaseOf (opsOpen .P1 ++ [.hostFee 50 3] ++ admits 5) == some .OPENED
#guard phaseOf (opsAdmit .P1) == some .ADMITTED

-- RQ-027: the anchor is the first variant whose rate meets the median 3: variant 3
theorem pin_rq027 : (req (opsAdmit .P1)).map (·.anchor1) = some (some 3) := by decide +kernel
#guard (req (opsAdmit .P1)).map (·.anchor1) == some (some 3)

-- RQ-027: the anchor height is entry f + 1 of the heights sorted highest first
theorem pin_rq027_height : anchorHeight 2 [10, 40, 30, 20, 50] = 30 := by decide +kernel
#guard anchorHeight 2 [10, 40, 30, 20, 50] == 30

-- RQ-027: no rate meets the median: the highest variant K
theorem pin_rq027_highest : select 8 rates8 100 = 8 := by decide +kernel
#guard select 8 rates8 100 == 8

-- RQ-028: generation 1 missed its deadline and the generation 2 median 5 selects variant 5
theorem pin_rq028 : (req (opsAdmit .P1 ++ [.hostFee 60 5, .obs2 1 true [60, 60, 60]])).map (·.anchor2) =
    some (some 5) := by decide +kernel
#guard (req (opsAdmit .P1 ++ [.hostFee 60 5, .obs2 1 true [60, 60, 60]])).map (·.anchor2) == some (some 5)

-- RQ-029: an OBS set for generation 2 that would select variant 1 leaves anchor[2] none
theorem pin_rq029 : (req (opsAdmit .P1 ++ [.hostFee 61 1, .obs2 1 true [61, 61, 61]])).map (·.anchor2) =
    some none := by decide +kernel
#guard (req (opsAdmit .P1 ++ [.hostFee 61 1, .obs2 1 true [61, 61, 61]])).map (·.anchor2) == some none

-- RQ-029: a generation 2 selection equal to anchor[1] = 3 also leaves anchor[2] none
theorem pin_rq029_equal : (req (opsAdmit .P1 ++ [.hostFee 62 3, .obs2 1 true [62, 62, 62]])).map (·.anchor2) =
    some none := by decide +kernel
#guard (req (opsAdmit .P1 ++ [.hostFee 62 3, .obs2 1 true [62, 62, 62]])).map (·.anchor2) == some none

-- RQ-037: a witnessed release of generation 1 with variant 3
theorem pin_rq037 : (req opsRel).map (fun r => (r.released1, r.anyRelease)) = some (some 3, true) := by
  decide +kernel
#guard (req opsRel).map (fun r => (r.released1, r.anyRelease)) == some (some 3, true)

-- RQ-044: five FINAL votes leave the request ADMITTED; the sixth makes it FINAL (RQ-049: outcome FINAL)
theorem pin_rq044 : phaseOf (opsRel ++ finals 5) = some .ADMITTED ∧
    (req (opsRel ++ finals 6)).map (fun r => (r.phase, r.outcome)) = some (.FINAL, .FINAL) := by decide +kernel
#guard phaseOf (opsRel ++ finals 5) == some .ADMITTED
#guard (req (opsRel ++ finals 6)).map (fun r => (r.phase, r.outcome)) == some (.FINAL, .FINAL)

-- RQ-005: an ADMIT vote after FINAL
theorem pin_rq005 : lastObs (opsRel ++ finals 6 ++ [.voteAdmit 1 7 7 50]) = some (.refused [.terminal]) := by
  decide +kernel
#guard lastObs (opsRel ++ finals 6 ++ [.voteAdmit 1 7 7 50]) == some (.refused [.terminal])

-- RQ-045, RQ-050: three SLOT_TAKEN posts at f = 2 end the request VOID SLOT_TAKEN; it released nothing: VOID
theorem pin_rq045 : (req (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN)).map (fun r => (r.phase, r.reason, r.outcome)) =
    some (.VOID, .SLOT_TAKEN, .VOID) := by decide +kernel
#guard (req (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN)).map (fun r => (r.phase, r.reason, r.outcome)) ==
  some (.VOID, .SLOT_TAKEN, .VOID)

-- RQ-042: two old-committee and one new-committee VOID posts at f = f' = 2 form no tombstone
theorem pin_rq042 : phaseOf (opsOpen .P1 ++ [.rotate 1 9 2, .postVoid 1 0 0 .STALLED, .postVoid 1 0 1 .STALLED,
    .postVoid 1 1 0 .STALLED]) = some .OPENED := by decide +kernel
#guard phaseOf (opsOpen .P1 ++ [.rotate 1 9 2, .postVoid 1 0 0 .STALLED, .postVoid 1 0 1 .STALLED,
    .postVoid 1 1 0 .STALLED]) == some .OPENED

-- RQ-043: a FINAL post of epoch 5 before the ROTATE that registers it
theorem pin_rq043 : lastObs (opsRel ++ [.postFinal 1 5 0 42]) = some (.refused [.unknownEpoch]) := by
  decide +kernel
#guard lastObs (opsRel ++ [.postFinal 1 5 0 42]) == some (.refused [.unknownEpoch])

-- RQ-046, RQ-050: the board passes exp with no tombstone: EXPIRED; nothing released: VOID
theorem pin_rq046 : (req (opsOpen .P1 ++ [.tick 5001])).map (fun r => (r.phase, r.outcome)) =
    some (.EXPIRED, .VOID) := by decide +kernel
#guard (req (opsOpen .P1 ++ [.tick 5001])).map (fun r => (r.phase, r.outcome)) == some (.EXPIRED, .VOID)

-- RQ-046 at the bound: the board at exp itself does not expire the request
theorem pin_rq046_bound : phaseOf (opsOpen .P1 ++ [.tick 5000]) = some .OPENED := by decide +kernel
#guard phaseOf (opsOpen .P1 ++ [.tick 5000]) == some .OPENED

-- RQ-051: a request that released generation 1 expires: RELEASED
theorem pin_rq051 : (req (opsRel ++ [.tick 5001])).map (·.outcome) = some .RELEASED := by decide +kernel
#guard (req (opsRel ++ [.tick 5001])).map (·.outcome) == some .RELEASED

-- RQ-068: a request ended VOID STALLED after the latest landed checkpoint, then a restart burn:
-- restart_end, phase VOID, outcome RELEASED
theorem pin_rq068 : (req (opsOpen .P1 ++ vposts 3 .STALLED ++ [.restartBurn 1])).map
    (fun r => (r.restartEnd, r.phase, r.outcome)) = some (true, .VOID, .RELEASED) := by decide +kernel
#guard (req (opsOpen .P1 ++ vposts 3 .STALLED ++ [.restartBurn 1])).map
    (fun r => (r.restartEnd, r.phase, r.outcome)) == some (true, .VOID, .RELEASED)

-- RQ-068: the host chain shows a variant at confirmation depth: outcome FINAL
theorem pin_rq068_confirmed : (req (opsOpen .P1 ++ vposts 3 .STALLED ++ [.confirm 1, .restartBurn 1])).map
    (·.outcome) = some .FINAL := by decide +kernel
#guard (req (opsOpen .P1 ++ vposts 3 .STALLED ++ [.confirm 1, .restartBurn 1])).map (·.outcome) == some .FINAL

-- RQ-048, RQ-052: a restart burns a slot of a live request; it ends VOID RESTART with outcome FINAL
-- when the host chain shows its variant at confirmation depth, RELEASED otherwise
theorem pin_rq052 : (req (opsOpen .P1 ++ [.confirm 1, .restartBurn 1] ++ vposts 3 .RESTART)).map
    (fun r => (r.phase, r.outcome)) = some (.VOID, .FINAL) ∧
    (req (opsOpen .P1 ++ [.restartBurn 1] ++ vposts 3 .RESTART)).map (·.outcome) = some .RELEASED := by
  decide +kernel
#guard (req (opsOpen .P1 ++ [.confirm 1, .restartBurn 1] ++ vposts 3 .RESTART)).map (·.outcome) == some .FINAL

-- RQ-054, C11: once a landed checkpoint covers the end, the restart burn does not move the leaf
theorem pin_rq054_held : lastObs (opsOpen .P1 ++ vposts 3 .STALLED ++ [.landCp 100, .restartBurn 1]) =
    some (.refused [.terminal]) := by decide +kernel
#guard lastObs (opsOpen .P1 ++ vposts 3 .STALLED ++ [.landCp 100, .restartBurn 1]) == some (.refused [.terminal])

-- RQ-017: the sixth OPENED vote with one header hash makes a collecting request COLLECTING
def opsColl : List Op := opsOrder .P1 ++ [.openHdr 1 8 2 true 3 rates8]
def opened (k : Nat) : List Op := (List.range k).map (fun i => .voteOpened 1 i 7)
theorem pin_rq017 : phaseOf (opsColl ++ opened 5) = some .OPENED ∧ phaseOf (opsColl ++ opened 6) = some .COLLECTING := by
  decide +kernel
#guard phaseOf (opsColl ++ opened 6) == some .COLLECTING

-- RQ-018, RQ-019: the first well-formed frame for position 2 attaches; a second one is position_filled
def fr (cid : Nat) : Frame := { position := 2, tokenOk := true, lengthsOk := true, height := 0, cid }
theorem pin_rq018 : (req (opsColl ++ opened 6 ++ [.frame 1 (fr 11)])).map (·.positions) =
    some [none, none, some 11] ∧
    lastObs (opsColl ++ opened 6 ++ [.frame 1 (fr 11), .frame 1 (fr 12)]) = some (.refused [.positionFilled]) := by
  decide +kernel
#guard lastObs (opsColl ++ opened 6 ++ [.frame 1 (fr 11), .frame 1 (fr 12)]) == some (.refused [.positionFilled])

-- RQ-020: a frame ordered at height exp_c + 1 = 701
theorem pin_rq020 : lastObs (opsColl ++ opened 6 ++ [.tick 701, .frame 1 (fr 11)]) =
    some (.refused [.lateContribution]) := by decide +kernel
#guard lastObs (opsColl ++ opened 6 ++ [.tick 701, .frame 1 (fr 11)]) == some (.refused [.lateContribution])

-- RQ-020 before COLLECTING (item 13 replay): ordered at 100, exp_c = 700; a frame ordered at
-- 701 while the target is ORDERED is refused, not held; at 700 it is held
theorem pin_rq020_ordered : lastObs (opsOrder .P1 ++ [.tick 701, .frame 1 (fr 11)]) =
    some (.refused [.lateContribution]) := by decide +kernel
#guard lastObs (opsOrder .P1 ++ [.tick 701, .frame 1 (fr 11)]) == some (.refused [.lateContribution])
theorem pin_rq020_ordered_bound : (req (opsOrder .P1 ++ [.tick 700, .frame 1 (fr 11)])).map (·.held.length) =
    some 1 := by decide +kernel
#guard (req (opsOrder .P1 ++ [.tick 700, .frame 1 (fr 11)])).map (·.held.length) == some 1

-- RQ-021, RQ-075 (ledger 8, lead ruling): a frame for a request in OPENED, inside the window, and one
-- for an ADMITTED request are refused with late_contribution
theorem pin_rq021_opened : lastObs (opsColl ++ [.frame 1 (fr 11)]) = some (.refused [.lateContribution]) := by
  decide +kernel
#guard lastObs (opsColl ++ [.frame 1 (fr 11)]) == some (.refused [.lateContribution])
-- RQ-021, RQ-075 (ledger 8, lead ruling): the same refusal for an ADMITTED request
theorem pin_rq021_admitted : lastObs (opsAdmit .P1 ++ [.frame 1 (fr 11)]) = some (.refused [.lateContribution]) := by
  decide +kernel
#guard lastObs (opsAdmit .P1 ++ [.frame 1 (fr 11)]) == some (.refused [.lateContribution])

-- RQ-076 (ledger 28, lead ruling): a whole-committee restart keeps the release record
theorem pin_rq076 : (req (opsRel ++ [.restartBurn 1])).map (fun r => (r.anyRelease, r.released1, r.restartEnd)) =
    some (true, some 3, true) := by decide +kernel
#guard (req (opsRel ++ [.restartBurn 1])).map (fun r => (r.anyRelease, r.released1, r.restartEnd)) ==
    some (true, some 3, true)

-- RQ-018 at the bound: a frame ordered at height exp_c = 700 attaches
theorem pin_rq018_bound : (req (opsColl ++ opened 6 ++ [.tick 700, .frame 1 (fr 11)])).map (·.positions) =
    some [none, none, some 11] := by decide +kernel
#guard (req (opsColl ++ opened 6 ++ [.tick 700, .frame 1 (fr 11)])).map (·.positions) == some [none, none, some 11]

-- RQ-021: a frame ordered before the target opens is held and attaches at COLLECTING
theorem pin_rq021 : (req (opsOrder .P1 ++ [.frame 1 (fr 11), .openHdr 1 8 2 true 3 rates8] ++ opened 6)).map
    (·.positions) = some [none, none, some 11] := by decide +kernel
#guard (req (opsOrder .P1 ++ [.frame 1 (fr 11), .openHdr 1 8 2 true 3 rates8] ++ opened 6)).map (·.positions) ==
  some [none, none, some 11]

-- RQ-036: a non-TEE release goes to f + 1 = 3 combiners at n = 9; TEE to all n
theorem pin_rq036 : combinerCount { p9 with mode := .NON_TEE } = 3 ∧ combinerCount p9 = 9 := by decide +kernel
#guard combinerCount { p9 with mode := .NON_TEE } == 3

/-! ## The honest node -/

def v0 : View :=
  { shareOk := true, sentHeader := false, hdr := .ok, auth := .inForce, revokedAt := none, midFinal := 100,
    obsMid1 := 90, obsMid2 := 90, holdAge := 100, slots := .ok, admissionOk := true, votedOpened := false,
    votedAdmit := false, relCheck := true, acks1 := 6, acks2 := 6, bound := true, sentGens := [],
    contribFail := false, seesConfirm := false, postedFinal := false, pinSpent := false, settled := false,
    signedLeaf := none }

def acts (ops : List Op) (v : View) : List Act :=
  match req ops with
  | some r => nodeAct (run s0 ops).ctx r v
  | none => []

-- RQ-008: no partial for a posted, unordered request
theorem pin_rq008 : acts [.post 1 0 5000 .SPEND .P1] v0 = [] := by decide +kernel
#guard acts [.post 1 0 5000 .SPEND .P1] v0 == []

-- RQ-009: a good share: header partial and ACK
theorem pin_rq009 : acts (opsOrder .P1) v0 = [.headerPartial, .ack] := by decide +kernel
#guard acts (opsOrder .P1) v0 == [.headerPartial, .ack]

-- RQ-010: a bad share: a complaint, no header partial
theorem pin_rq010 : acts (opsOrder .P1) { v0 with shareOk := false } = [.complain] := by decide +kernel
#guard acts (opsOrder .P1) { v0 with shareOk := false } == [.complain]

-- RQ-023: an open single-user header with the authorization in force: one ADMIT vote
theorem pin_rq023 : acts (opsOpen .P1) v0 = [.voteAdmit] ∧ acts (opsOpen .P1) { v0 with votedAdmit := true } = [] := by
  decide +kernel
#guard acts (opsOpen .P1) v0 == [.voteAdmit]

-- RQ-024: the authorization is included but not final: no ADMIT vote
theorem pin_rq024 : acts (opsOpen .P1) { v0 with auth := .notInForce } = [.refuse .notInForce] := by decide +kernel
#guard acts (opsOpen .P1) { v0 with auth := .notInForce } == [.refuse .notInForce]

-- RQ-025: Midnight refused the `authorize` call: VOID AUTH_REFUSED
theorem pin_rq025 : Act.postVoid .AUTH_REFUSED ∈ acts (opsOpen .P1) { v0 with auth := .refused } := by decide +kernel
#guard (acts (opsOpen .P1) { v0 with auth := .refused }).contains (.postVoid .AUTH_REFUSED)
-- RQ-025 (DECISIONS 68): the authorization is in force and commits to another `tkc`: VOID
-- AUTH_REFUSED and no vote; before it is in force the node refuses `not_in_force` and posts no VOID
theorem pin_rq025_mismatch : acts (opsOpen .P1) { v0 with auth := .inForceMismatch } = [.postVoid .AUTH_REFUSED] ∧
    acts (opsOpen .P1) { v0 with auth := .notInForce } = [.refuse .notInForce] := by decide +kernel
#guard acts (opsOpen .P1) { v0 with auth := .inForceMismatch } == [.postVoid .AUTH_REFUSED]

-- RQ-030: anchor[1] = 3 and every check of generation 1 passes: the release of (3, 1)
theorem pin_rq030 : acts (opsAdmit .P1) v0 = [.release 1 3] := by decide +kernel
#guard acts (opsAdmit .P1) v0 == [.release 1 3]

-- RQ-032: a revocation at a Midnight height below the newest OBS report: no release; VOID REVOKED (RQ-034)
theorem pin_rq032 : acts (opsAdmit .P1) { v0 with revokedAt := some 80 } = [.postVoid .REVOKED] := by decide +kernel
#guard acts (opsAdmit .P1) { v0 with revokedAt := some 80 } == [.postVoid .REVOKED]

-- RQ-033: a P2 authorization final one Midnight block ago: nothing for generation 1
theorem pin_rq033 : acts (opsAdmit .P2) { v0 with holdAge := 1 } = [] ∧ acts (opsAdmit .P2) v0 = [.release 1 3] := by
  decide +kernel
#guard acts (opsAdmit .P2) { v0 with holdAge := 1 } == []

-- RQ-035: five acks at n = 9 (w = 6): no partial
theorem pin_rq035 : acts (opsAdmit .P1) { v0 with acks1 := 5 } = [] := by decide +kernel
#guard acts (opsAdmit .P1) { v0 with acks1 := 5 } == []

-- RQ-040: a node sees the variant at confirmation depth: it posts FINAL
theorem pin_rq040 : Act.postFinal ∈ acts opsRel { v0 with seesConfirm := true, sentGens := [1] } := by decide +kernel
#guard (acts opsRel { v0 with seesConfirm := true, sentGens := [1] }).contains .postFinal

-- RQ-053: a request gets outcome VOID: the node signs (auth, VOID), then erases (RQ-055)
theorem pin_rq053 : acts (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN) v0 = [.signLeaf .VOID, .erase] := by decide +kernel
#guard acts (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN) v0 == [.signLeaf .VOID, .erase]

-- RQ-054: a node that signed (auth, VOID) signs no other outcome once Midnight holds the leaf
theorem pin_rq054 : acts (opsOpen .P1 ++ vposts 3 .STALLED ++ [.landCp 100]) { v0 with signedLeaf := some .VOID } =
    [.erase] := by decide +kernel
#guard acts (opsOpen .P1 ++ vposts 3 .STALLED ++ [.landCp 100]) { v0 with signedLeaf := some .VOID } == [.erase]

-- RQ-061: a replay of a request whose auth Midnight records as settled: no vote
theorem pin_rq061 : acts (opsOpen .P1) { v0 with settled := true } = [.refuse .settled] := by decide +kernel
#guard acts (opsOpen .P1) { v0 with settled := true } == [.refuse .settled]

-- RQ-062: a BIRTH request goes to the birth check and keeps no signing state
theorem pin_rq062 : acts [.post 1 0 5000 .BIRTH .P1, .tick 100, .order 1 true 0, .openHdr 1 8 2 false 0 rates8] v0 =
    [.handoff] := by decide +kernel
#guard acts [.post 1 0 5000 .BIRTH .P1, .tick 100, .order 1 true 0, .openHdr 1 8 2 false 0 rates8] v0 == [.handoff]

-- RQ-011: a verified complaint before any ADMIT vote: every honest node posts VOID SHARE_COMPLAINT
theorem pin_rq011 : Act.postVoid .SHARE_COMPLAINT ∈ acts (opsOpen .P1 ++ [.complaint 1]) v0 := by decide +kernel
#guard (acts (opsOpen .P1 ++ [.complaint 1]) v0).contains (.postVoid .SHARE_COMPLAINT)

-- RQ-012: a verified complaint after the first ADMIT vote: the dealer's fault, phase and reason kept
theorem pin_rq012 : (req (opsOpen .P1 ++ [.hostFee 50 3] ++ admits 1 ++ [.complaint 1])).map
    (fun r => (r.dealerFault, r.earlyComplaint, r.phase, r.reason)) = some (true, false, .OPENED, .NONE) := by
  decide +kernel
#guard (req (opsOpen .P1 ++ [.hostFee 50 3] ++ admits 1 ++ [.complaint 1])).map (·.dealerFault) == some true

-- RQ-014, RQ-015: an opened header that is malformed, or a dealer fault on a key: VOID with that reason
theorem pin_rq014 : Act.postVoid .MALFORMED ∈ acts (opsOrder .P1) { v0 with hdr := .malformed } ∧
    Act.postVoid .DEALER_FAULT ∈ acts (opsOrder .P1) { v0 with hdr := .dealerFault } := by decide +kernel
#guard (acts (opsOrder .P1) { v0 with hdr := .malformed }).contains (.postVoid .MALFORMED)
#guard (acts (opsOrder .P1) { v0 with hdr := .dealerFault }).contains (.postVoid .DEALER_FAULT)

-- RQ-016: a collecting request whose authorization is in force and slots in the window: one OPENED vote
theorem pin_rq016 : acts opsColl v0 = [.voteOpened] := by decide +kernel
#guard acts opsColl v0 == [.voteOpened]

-- RQ-022: a verified complaint against the frame of position 2: position 2 holds no contribution
theorem pin_rq022 : (req (opsColl ++ opened 6 ++ [.frame 1 (fr 11), .detach 1 2])).map (·.positions) =
    some [none, none, none] := by decide +kernel
#guard (req (opsColl ++ opened 6 ++ [.frame 1 (fr 11), .detach 1 2])).map (·.positions) == some [none, none, none]

-- RQ-031: a release check fails: VOID RELEASE_CHECK and no release
theorem pin_rq031 : acts (opsAdmit .P1) { v0 with relCheck := false } = [.postVoid .RELEASE_CHECK] := by
  decide +kernel
#guard acts (opsAdmit .P1) { v0 with relCheck := false } == [.postVoid .RELEASE_CHECK]

-- RQ-038, RQ-039: a failing actor scalar: VOID CONTRIBUTION; in NON_TEE mode also the failure evidence
def actsN (ops : List Op) (v : View) : List Act :=
  match req ops with
  | some r => nodeAct { (run s0 ops).ctx with params := { p9 with mode := .NON_TEE } } r v
  | none => []
theorem pin_rq038 : Act.postVoid .CONTRIBUTION ∈ acts (opsAdmit .P1) { v0 with contribFail := true } ∧
    Act.evidence ∉ acts (opsAdmit .P1) { v0 with contribFail := true } ∧
    Act.evidence ∈ actsN (opsAdmit .P1) { v0 with contribFail := true } := by decide +kernel
#guard (actsN (opsAdmit .P1) { v0 with contribFail := true }).contains .evidence

-- RQ-041: a TEE node sees the pinned input spent elsewhere: VOID PIN_SPENT
theorem pin_rq041 : Act.postVoid .PIN_SPENT ∈ acts (opsAdmit .P1) { v0 with pinSpent := true } := by decide +kernel
#guard (acts (opsAdmit .P1) { v0 with pinSpent := true }).contains (.postVoid .PIN_SPENT)

-- RQ-032, RQ-059 at the bounds: a revocation at the read height blocks the release; one above it does not;
-- an OBS report newer than the read height blocks it
theorem pin_rq059_bounds : Act.release 1 3 ∉ acts (opsAdmit .P1) { v0 with revokedAt := some 100 } ∧
    Act.release 1 3 ∈ acts (opsAdmit .P1) { v0 with revokedAt := some 101 } ∧
    acts (opsAdmit .P1) { v0 with obsMid1 := 101 } = [] := by decide +kernel
#guard !(acts (opsAdmit .P1) { v0 with revokedAt := some 100 }).contains (.release 1 3)
#guard (acts (opsAdmit .P1) { v0 with revokedAt := some 101 }).contains (.release 1 3)
#guard acts (opsAdmit .P1) { v0 with obsMid1 := 101 } == []

-- RQ-030, C6: an authorization not in force: no release
theorem pin_rq030_not_in_force : acts (opsAdmit .P1) { v0 with auth := .notInForce } = [] := by decide +kernel
#guard acts (opsAdmit .P1) { v0 with auth := .notInForce } == []

/-! ## Reachable states are in the `--step` domain -/

-- the end states of runs pass `validState`, so `--step` accepts them
theorem pin_run_validState : validState (run s0 (opsRel ++ finals 6)) = true ∧
    validState (run s0 (opsOpen .P1 ++ [.rotate 1 9 2] ++ vposts 3 .STALLED ++ [.landCp 100])) = true ∧
    validState (run s0 (opsOpen .P1 ++ vposts 3 .STALLED ++ [.restartBurn 1, .tick 6000])) = true := by
  decide +kernel
#guard validState (run s0 (opsRel ++ finals 6))

/-! ## Witnesses -/

/-- C13, RQ-063: an authorized single-user request reaches FINAL along an
honest run. A witness that the FINAL branch fires, not the liveness claim. -/
theorem witness_C13_final : phaseOf (opsRel ++ finals 6) = some .FINAL := by decide +kernel
#guard phaseOf (opsRel ++ finals 6) == some .FINAL

/-- RQ-047: the board reaches exp_c with position 2 empty: the honest node posts VOID STALLED. -/
theorem witness_rq047_stalled : Act.postVoid .STALLED ∈ acts (opsColl ++ opened 6 ++ [.tick 700]) v0 := by
  decide +kernel
#guard (acts (opsColl ++ opened 6 ++ [.tick 700]) v0).contains (.postVoid .STALLED)

/-! ## Revision 4 (DECISIONS 59 to 64): EN-023 at order, RQ-069, RQ-071 to RQ-074 -/

-- EN-023 at the ordering block (RQ-006 scenario): exp = 650, b = 100, Δ_c = 600 is refused and
-- the request stays POSTED; bound: exp = 701 orders (700 < 701), exp = 700 does not
def opsOrderExp (x : Nat) : List Op := [.post 1 0 x .SPEND .P1, .tick 100, .order 1 true 0]
theorem pin_en023_order : lastObs (opsOrderExp 650) = some (.refused [.expCNotBelowExp]) ∧
    phaseOf (opsOrderExp 650) = some .POSTED ∧ lastObs (opsOrderExp 700) = some (.refused [.expCNotBelowExp]) ∧
    phaseOf (opsOrderExp 701) = some .ORDERED := by decide +kernel
#guard lastObs (opsOrderExp 650) == some (.refused [.expCNotBelowExp]) && phaseOf (opsOrderExp 650) == some .POSTED
  && lastObs (opsOrderExp 700) == some (.refused [.expCNotBelowExp]) && phaseOf (opsOrderExp 701) == some .ORDERED

-- The committee of the F2 and F6 scenarios: n = 4, f = 1 (q = 3), epoch 0
def p4 : Params := { n := 4, f := 1, deltaC := 600, deltaHold := 10, mode := .TEE }
def s4 : St := init p4 [(0, 4, 1)]
def req4 (ops : List Op) : Option Req := find (run s4 ops) 1
def lastObs4 (ops : List Op) : Option Obs := (runOps s4 ops).2.getLast?
def end4 (ops : List Op) : Option (Phase × Reason × Outcome) := (req4 ops).map (fun r => (r.phase, r.reason, r.outcome))
def open4 : List Op := opsOpen .P1

-- RQ-072 scenario: at f = 1 one post MALFORMED and the completing post REVOKED: VOID with reason MIXED
theorem pin_rq072 : end4 (open4 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .REVOKED]) =
    some (.VOID, .MIXED, .VOID) := by decide +kernel
#guard end4 (open4 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .REVOKED]) == some (.VOID, .MIXED, .VOID)

-- RQ-045: f + 1 posts with one reason give that reason; at f = 2 two MALFORMED and one REVOKED give MIXED
theorem pin_rq045_common : phaseOf (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN) = some .VOID ∧
    (req (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN)).map (·.reason) = some .SLOT_TAKEN ∧
    (req (opsOpen .P1 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .MALFORMED, .postVoid 1 0 2 .REVOKED])).map
      (·.reason) = some .MIXED := by decide +kernel
#guard (req (opsOpen .P1 ++ vposts 3 .SLOT_TAKEN)).map (·.reason) == some .SLOT_TAKEN
#guard (req (opsOpen .P1 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .MALFORMED, .postVoid 1 0 2 .REVOKED])).map
  (·.reason) == some .MIXED

-- RQ-065, RQ-072: MIXED is a tombstone reason, never a post reason
theorem pin_rq065_mixed_post : lastObs4 (open4 ++ [.postVoid 1 0 0 .MIXED]) = some (.refused [.outsideCapability]) := by
  decide +kernel
#guard lastObs4 (open4 ++ [.postVoid 1 0 0 .MIXED]) == some (.refused [.outsideCapability])

-- RQ-073, RQ-074 scenario (F6): at f = 1 an honest STALLED post, then the q = 3 ADMIT votes, a
-- RELEASE of generation 1, and a corrupt STALLED post: VOID, reason MIXED, outcome RELEASED
def f6ops (rel : Bool) : List Op :=
  open4 ++ [.postVoid 1 0 0 .STALLED, .hostFee 50 3, .voteAdmit 1 0 7 50, .voteAdmit 1 1 7 50, .voteAdmit 1 2 7 50]
    ++ (if rel then [.release 1 1 3] else []) ++ [.postVoid 1 0 1 .STALLED]
theorem pin_rq073_f6 : end4 (f6ops true) = some (.VOID, .MIXED, .RELEASED) := by decide +kernel
#guard end4 (f6ops true) == some (.VOID, .MIXED, .RELEASED)

-- RQ-073: the same posts with no RELEASE keep reason STALLED and outcome VOID
theorem pin_rq073_no_release : end4 (f6ops false) = some (.VOID, .STALLED, .VOID) := by decide +kernel
#guard end4 (f6ops false) == some (.VOID, .STALLED, .VOID)

-- RQ-074 scenario: the STALLED post before the RELEASE also stops being a reason post: two
-- STALLED posts after a RELEASE give MIXED
theorem pin_rq074 : reasonPosts true [.STALLED, .STALLED] = [] ∧ tombReason 1 true [.STALLED, .STALLED] = .MIXED ∧
    tombReason 1 false [.STALLED, .STALLED] = .STALLED ∧ tombReason 1 true [.STALLED, .SLOT_TAKEN] = .MIXED := by
  decide +kernel
#guard reasonPosts true [.STALLED, .STALLED] == [] && tombReason 1 true [.STALLED, .STALLED] == .MIXED
  && tombReason 1 false [.STALLED, .STALLED] == .STALLED && tombReason 1 true [.STALLED, .SLOT_TAKEN] == .MIXED

-- RQ-071 scenario: no reissue carries the VOID leaf of a MIXED request; a STALLED one is carried
theorem pin_rq071 : lastObs4 (open4 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .REVOKED, .carry 1]) =
    some (.refused [.noRule]) ∧
    (req4 (f6ops false ++ [.carry 1])).map (·.carried) = some true ∧
    readsAs .MIXED .STALLED = false ∧ readsAs .MIXED .SLOT_TAKEN = false ∧ readsAs .MIXED .REVOKED = false := by
  decide +kernel
#guard lastObs4 (open4 ++ [.postVoid 1 0 0 .MALFORMED, .postVoid 1 0 1 .REVOKED, .carry 1]) == some (.refused [.noRule])
#guard (req4 (f6ops false ++ [.carry 1])).map (·.carried) == some true

-- RQ-069 scenario: a NON_TEE node passes every release check of generation 1 and its RELEASE has
-- not committed: it posts RELEASE and sends no partial; once the RELEASE committed it sends
theorem pin_rq069 : actsN (opsAdmit .P1) v0 = [.recordRelease 1 3] ∧ actsN opsRel v0 = [.release 1 3] ∧
    acts (opsAdmit .P1) v0 = [.release 1 3] := by decide +kernel
#guard actsN (opsAdmit .P1) v0 == [.recordRelease 1 3] && actsN opsRel v0 == [.release 1 3]

-- RQ-069 scenario: the RELEASE reaches the board after the request expired: `terminal`, no partial
theorem pin_rq069_expired : lastObs (opsAdmit .P1 ++ [.tick 5001, .release 1 1 3]) = some (.refused [.terminal]) ∧
    Act.release 1 3 ∉ actsN (opsAdmit .P1 ++ [.tick 5001]) v0 := by decide +kernel
#guard lastObs (opsAdmit .P1 ++ [.tick 5001, .release 1 1 3]) == some (.refused [.terminal])
#guard !(actsN (opsAdmit .P1 ++ [.tick 5001]) v0).contains (.release 1 3)

end SplitRequest
