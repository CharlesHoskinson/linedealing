import SplitAuthorization.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` checks it against the definitions
the theorems describe, and `#guard` checks it with the compiled evaluator.
Expected values come from the spec text and its scenarios, not from `#eval`.

Fixture: charter 1 is P1, charter 2 is P2, charter 3 is a board-first P0
charter. Record 10 (P1, tag 7), record 20 (P2, tag 8, with `slr_G`) and record
30 (board-first P0, tag 9) land with fresh nullifiers. The epoch quorum is 3.
-/

namespace SplitAuthorization

def refsOp (s : St) (op : Op) : List String := (opRefusals s op).map Refusal.code

def obsOf (s : St) (op : Op) : Obs := (apply s op).2

def sB : St := run (init { mode := .TEE, q := 3 })
  [.charter 1 .P1 false false, .charter 2 .P2 false false, .charter 3 .P0 true false,
   .record 10 1 100 (.fresh 10) 7 (some 1) none,
   .record 20 2 200 (.fresh 20) 8 (some 2) (some 3),
   .record 30 3 300 (.fresh 30) 9 none none]

/-- An owner spend of record 10 whose intent pins input 5. -/
def c1 : Call :=
  { rid := 10, nf := .fresh 10, auth := 501, rh := 601, source := .OWNER, slot := none, inputsOk := true,
    predOk := true, inGamma := true, blacklisted := false, ticketOk := true, pin := 5, toExit := false,
    carry := none }

/-- An owner spend of the P2 record 20. -/
def c2 : Call := { c1 with rid := 20, nf := .fresh 20, auth := 502, rh := 602, pin := 0 }

/-- A seizure of the P2 record 20 under its `slr_G` slot. -/
def c3 : Call := { c2 with auth := 505, source := .SEIZURE, slot := some (20, .G) }

def s1 : St := run sB [.authorize c1]
def s2 : St := run sB [.authorize c2]
def sF : St := run s1 [.finalize 501 50]
def sFin : St := run s1 [.settleRoot [(501, .FINAL)]]
def sVoid : St := run s1 [.settleRoot [(501, .VOID)]]
def sL : St := run s1 [.settleRoot [(501, .RELEASED)]]
def sV : St := run s2 [.revoke 502 8]
def sRec : St := run sB [.recover]
def sS : St := run sB [.authorize c3]

/-- Re-posts on the locked record: nonce `n + 1` and the pinned nonce `n = 5`. -/
def cL6 : Call := { c1 with nf := .ofSettle 501 .RELEASED, auth := 503, pin := 6 }
def cL5 : Call := { cL6 with pin := 5 }

/-- The reissue of the stalled request 501 with its signed VOID leaf. -/
def cRe : Call :=
  { c1 with auth := 504, nf := .ofSettle 501 .VOID, carry := some { auth0 := 501, outcome := .VOID, sigs := 3 } }

/-- A board-first call on record 30 with a root of age 40 under bound 100, interval 30 and `F_M` 30. -/
def bf1 : BfCall :=
  { auth := 701, nf := .fresh 30, proofOk := true, rootFinal := true, rootAge := 40, bound := 100,
    interval := 30, fM := 30, carrySigs := none }

def sP : St := run sB [.bfCall bf1]
def sR : St := run sB [.bfRoot [{ auth := 701, nf := .fresh 30, rh := 801, root := 901 }]]

/-- Ledger 11 (AU-029): the pinned re-post of the locked record settles VOID. -/
def sLV : St := run sL [.authorize cL5, .settleRoot [(503, .VOID)]]
def cLV9 : Call := { c1 with auth := 506, nf := .ofSettle 503 .VOID, pin := 9 }

-- A refused operation leaves the state unchanged
theorem pin_refused_unchanged : (apply s1 (.authorize { c1 with auth := 502 })).1 = s1 := by decide +kernel

-- AU-001: a new P1 record is UNSPENT with a fresh nf
theorem pin_birth : ((recOf sB 10).map (fun r => (r.rstate, r.nf.isFresh))) = [(.UNSPENT, true)] := by decide +kernel
#guard ((recOf sB 10).map (fun r => (r.rstate, r.nf.isFresh))) == [(.UNSPENT, true)]

-- AU-004: a valid authorize on the current nf of an unspent record makes it PENDING
theorem pin_valid_pending : ((recOf s1 10).map (·.rstate)) = [.PENDING] := by decide +kernel
#guard ((recOf s1 10).map (·.rstate)) == [.PENDING]

-- AU-002, AU-010: the new authorization is SUBMITTED with final_height none
theorem pin_submitted : ((allAuths s1).map (fun b => (b.auth, b.status, b.finalHeight, b.settled))) = [(501, .SUBMITTED, none, .NONE)] := by decide +kernel
#guard ((allAuths s1).map (fun b => (b.auth, b.status, b.finalHeight, b.settled))) == [(501, .SUBMITTED, none, .NONE)]

-- AU-005: an ECDSA slot under slr_own of another record does not verify
theorem pin_slot_other_record : refsOp sB (.authorize { c1 with slot := some (20, .OWN) }) = ["no-rule"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with slot := some (20, .OWN) }) == ["no-rule"]

-- AU-005: the slot under the record's own slr_own verifies
theorem pin_slot_own_record : refsOp sB (.authorize { c1 with slot := some (10, .OWN) }) = [] := by decide +kernel
#guard refsOp sB (.authorize { c1 with slot := some (10, .OWN) }) == []

-- AU-005: in NON_TEE mode a failed ticket proof does not verify; in TEE mode it is not read
theorem pin_ticket : (refsOp { sB with params := { sB.params with mode := .NON_TEE } } (.authorize { c1 with ticketOk := false }), refsOp sB (.authorize { c1 with ticketOk := false })) = (["no-rule"], []) := by decide +kernel
#guard (refsOp { sB with params := { sB.params with mode := .NON_TEE } } (.authorize { c1 with ticketOk := false }), refsOp sB (.authorize { c1 with ticketOk := false })) == (["no-rule"], [])

-- AU-006: no source admits a seizure order on a P1 record
theorem pin_seizure_p1 : refsOp sB (.authorize { c1 with source := .SEIZURE, slot := some (10, .G) }) = ["no-rule"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with source := .SEIZURE, slot := some (10, .G) }) == ["no-rule"]

-- AU-006: the seizure source on a P2 record opens a slot under slr_G
theorem pin_seizure_p2 : refsOp sB (.authorize c3) = [] := by decide +kernel
#guard refsOp sB (.authorize c3) == []

-- AU-007: the owner of a held P2 record cannot prove a spend
theorem pin_held_p2 : refsOp { sB with holds := [8] } (.authorize c2) = ["no-rule"] := by decide +kernel
#guard refsOp { sB with holds := [8] } (.authorize c2) == ["no-rule"]

-- AU-007: a registry-blacklisted P2 owner spend does not verify; an unheld one does
theorem pin_blacklisted_p2 : (refsOp sB (.authorize { c2 with blacklisted := true }), refsOp sB (.authorize c2)) = (["no-rule"], []) := by decide +kernel
#guard (refsOp sB (.authorize { c2 with blacklisted := true }), refsOp sB (.authorize c2)) == (["no-rule"], [])

-- AU-008: a second authorize on the same nf is refused and the state is unchanged
theorem pin_second_authorize : (refsOp s1 (.authorize { c1 with auth := 502 }), (apply s1 (.authorize { c1 with auth := 502 })).1 == s1) = (["nf_used"], true) := by decide +kernel
#guard (refsOp s1 (.authorize { c1 with auth := 502 }), (apply s1 (.authorize { c1 with auth := 502 })).1 == s1) == (["nf_used"], true)

-- AU-023, AU-025: a RELEASED settlement locks the record to the pin of its intent
theorem pin_released_locks : ((recOf sL 10).map (fun r => (r.rstate, r.nf, r.pin))) = [(.LOCKED, .ofSettle 501 .RELEASED, some 5)] := by decide +kernel
#guard ((recOf sL 10).map (fun r => (r.rstate, r.nf, r.pin))) == [(.LOCKED, .ofSettle 501 .RELEASED, some 5)]

-- AU-009: a locked record refuses an intent with nonce n + 1 for pin = n
theorem pin_nonce_next : refsOp sL (.authorize cL6) = ["pin_mismatch"] := by decide +kernel
#guard refsOp sL (.authorize cL6) == ["pin_mismatch"]

-- AU-009: the re-post that spends the pin is accepted
theorem pin_nonce_pin : refsOp sL (.authorize cL5) = [] := by decide +kernel
#guard refsOp sL (.authorize cL5) == []

-- AU-010: included, not final: not in force
theorem pin_included_not_final : obsOf s1 (.query 501 100) = .inForce false := by decide +kernel
#guard obsOf s1 (.query 501 100) == .inForce false

-- AU-010: in force from the Midnight block at which it is final
theorem pin_final_height : (obsOf sF (.query 501 49), obsOf sF (.query 501 50)) = (.inForce false, .inForce true) := by decide +kernel
#guard (obsOf sF (.query 501 49), obsOf sF (.query 501 50)) == (.inForce false, .inForce true)

-- AU-011: a P1 charter with a daily limit (stateful) cannot set board_first; P2 cannot either
theorem pin_charter_bf : (refsOp sB (.charter 7 .P1 true true), refsOp sB (.charter 8 .P2 true false), refsOp sB (.charter 9 .P1 true false)) = (["board_first_forbidden"], ["board_first_forbidden"], []) := by decide +kernel
#guard (refsOp sB (.charter 7 .P1 true true), refsOp sB (.charter 8 .P2 true false), refsOp sB (.charter 9 .P1 true false)) == (["board_first_forbidden"], ["board_first_forbidden"], [])

-- AU-012: a direct authorize for a board-first record is refused
theorem pin_direct_bf : refsOp sB (.authorize { c1 with rid := 30, nf := .fresh 30 }) = ["board_first_record"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with rid := 30, nf := .fresh 30 }) == ["board_first_record"]

-- AU-013: a board-first call whose root is older than the bound minus the interval and F_M is not accepted
theorem pin_stale_root : (refsOp sB (.bfCall { bf1 with rootAge := 41 }), refsOp sB (.bfCall { bf1 with rootAge := 40 })) = (["no-rule"], []) := by decide +kernel
#guard (refsOp sB (.bfCall { bf1 with rootAge := 41 }), refsOp sB (.bfCall { bf1 with rootAge := 40 })) == (["no-rule"], [])

-- AU-013: a call whose nf a landed bf_root already holds is not accepted
theorem pin_landed_nf : refsOp sR (.bfCall { bf1 with auth := 702 }) = ["no-rule"] := by decide +kernel
#guard refsOp sR (.bfCall { bf1 with auth := 702 }) == ["no-rule"]

-- AU-014: the first verified call for nf puts nf in the pending set
theorem pin_first_verified : sP.node.pending = [.fresh 30] := by decide +kernel
#guard sP.node.pending == [.fresh 30]

-- AU-015: a second verified call with the same nf is refused and the first stays in force
theorem pin_duplicate_call : (refsOp sP (.bfCall { bf1 with auth := 702 }), obsOf sP (.query 701 0)) = (["nf_pending"], .inForce true) := by decide +kernel
#guard (refsOp sP (.bfCall { bf1 with auth := 702 }), obsOf sP (.query 701 0)) == (["nf_pending"], .inForce true)

-- AU-016: a board-first P0 call is in force for the node once ordered; another auth is not
theorem pin_bf_in_force : (obsOf sP (.query 701 0), obsOf sP (.query 702 0)) = (.inForce true, .inForce false) := by decide +kernel
#guard (obsOf sP (.query 701 0), obsOf sP (.query 702 0)) == (.inForce true, .inForce false)

-- AU-018: revoking a pending P2 authorization makes it REVOKED and holds the record's tag
theorem pin_freeze : ((allAuths sV).map (·.status), sV.holds) = ([.REVOKED], [8]) := by decide +kernel
#guard ((allAuths sV).map (·.status), sV.holds) == ([.REVOKED], [8])

-- AU-007, AU-018: after the hold, the owner of the P2 record cannot prove a spend
theorem pin_freeze_holds : refsOp sV (.authorize { c2 with auth := 503 }) = ["nf_used", "no-rule"] := by decide +kernel
#guard refsOp sV (.authorize { c2 with auth := 503 }) == ["nf_used", "no-rule"]

-- AU-019: revoke on a P1 authorization is refused
theorem pin_revoke_p1 : refsOp s1 (.revoke 501 7) = ["not_revocable"] := by decide +kernel
#guard refsOp s1 (.revoke 501 7) == ["not_revocable"]

-- AU-019: revoke on a settled P2 authorization is refused
theorem pin_revoke_settled : refsOp (apply s2 (.settleRoot [(502, .FINAL)])).1 (.revoke 502 8) = ["not_revocable"] := by decide +kernel
#guard refsOp (apply s2 (.settleRoot [(502, .FINAL)])).1 (.revoke 502 8) == ["not_revocable"]

-- AU-020: a settle_root over (auth, FINAL) sets settled = FINAL
theorem pin_final_by_root : ((allAuths sFin).map (·.settled)) = [.FINAL] := by decide +kernel
#guard ((allAuths sFin).map (·.settled)) == [.FINAL]

-- AU-021: a reissue that carries the signed VOID leaf of its stalled request is accepted and the stalled authorization is VOID
theorem pin_reissue : (refsOp s1 (.authorize cRe), ((allAuths (apply s1 (.authorize cRe)).1).map (fun b => (b.auth, b.settled)))) = ([], [(504, .NONE), (501, .VOID)]) := by decide +kernel
#guard (refsOp s1 (.authorize cRe), ((allAuths (apply s1 (.authorize cRe)).1).map (fun b => (b.auth, b.settled)))) == ([], [(504, .NONE), (501, .VOID)])

-- AU-021: a carried VOID leaf with fewer than q signatures is not valid
theorem pin_carry_short : refsOp s1 (.authorize { cRe with carry := some { auth0 := 501, outcome := .VOID, sigs := 2 } }) = ["bad_carry", "no-rule"] := by decide +kernel
#guard refsOp s1 (.authorize { cRe with carry := some { auth0 := 501, outcome := .VOID, sigs := 2 } }) == ["bad_carry", "no-rule"]

-- AU-022: an authorize that carries a leaf with outcome FINAL is refused
theorem pin_carried_final : refsOp sB (.authorize { c1 with carry := some { auth0 := 999, outcome := .FINAL, sigs := 3 } }) = ["bad_carry"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with carry := some { auth0 := 999, outcome := .FINAL, sigs := 3 } }) == ["bad_carry"]

-- AU-023: an authorization that settles VOID leaves the record UNSPENT under N(nsk, auth, VOID)
theorem pin_void_successor : ((recOf sVoid 10).map (fun r => (r.rstate, r.nf))) = [(.UNSPENT, .ofSettle 501 .VOID)] := by decide +kernel
#guard ((recOf sVoid 10).map (fun r => (r.rstate, r.nf))) == [(.UNSPENT, .ofSettle 501 .VOID)]

-- AU-024: a second settlement from one record state needs a second authorize on the same nf and is refused
theorem pin_two_settlements : refsOp sFin (.authorize { c1 with auth := 502 }) = ["nf_used", "no-rule"] := by decide +kernel
#guard refsOp sFin (.authorize { c1 with auth := 502 }) == ["nf_used", "no-rule"]

-- AU-026: a bf_root moves each named board-first record to PENDING in one operation
theorem pin_bf_root : ((recOf sR 30).map (fun r => (r.rstate, r.auths.map (fun b => (b.auth, b.status, b.direct))))) = [(.PENDING, [(701, .SUBMITTED, false)])] := by decide +kernel
#guard ((recOf sR 30).map (fun r => (r.rstate, r.auths.map (fun b => (b.auth, b.status, b.direct))))) == [(.PENDING, [(701, .SUBMITTED, false)])]

-- AU-027: the recovery source before a recovery transition is refused
theorem pin_exit_early : refsOp sB (.authorize { c1 with source := .RECOVERY, toExit := true }) = ["no_recovery"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with source := .RECOVERY, toExit := true }) == ["no_recovery"]

-- AU-027: after the transition, a recovery exit to the exit address is accepted; another output is not
theorem pin_exit_after : (refsOp sRec (.authorize { c1 with source := .RECOVERY, toExit := true }), refsOp sRec (.authorize { c1 with source := .RECOVERY, toExit := false })) = ([], ["no_recovery"]) := by decide +kernel
#guard (refsOp sRec (.authorize { c1 with source := .RECOVERY, toExit := true }), refsOp sRec (.authorize { c1 with source := .RECOVERY, toExit := false })) == ([], ["no_recovery"])

-- AU-028: a seizure output to an address other than D_reg is VOID AUTH_REFUSED
theorem pin_seizure_dreg : (obsOf sS (.seizure 505 false), obsOf sS (.seizure 505 true)) = (.void "AUTH_REFUSED", .ok) := by decide +kernel
#guard (obsOf sS (.seizure 505 false), obsOf sS (.seizure 505 true)) == (.void "AUTH_REFUSED", .ok)

-- AU-028: a seizure admission for an authorization that is not a seizure has no rule
theorem pin_seizure_not : refsOp s1 (.seizure 501 true) = ["no-rule"] := by decide +kernel
#guard refsOp s1 (.seizure 501 true) == ["no-rule"]

-- Ledger 1: every code that applies, in code order
theorem pin_codes_sorted : refsOp sL (.authorize { cL6 with auth := 501, source := .SEIZURE }) = ["no-rule", "outside-capability", "pin_mismatch"] := by decide +kernel
#guard refsOp sL (.authorize { cL6 with auth := 501, source := .SEIZURE }) == ["no-rule", "outside-capability", "pin_mismatch"]

-- Ledger 5: a record birth with a nullifier that is not fresh is outside the capability
theorem pin_birth_not_fresh : refsOp sB (.record 40 1 400 (.ofSettle 1 .VOID) 7 none none) = ["outside-capability"] := by decide +kernel
#guard refsOp sB (.record 40 1 400 (.ofSettle 1 .VOID) 7 none none) == ["outside-capability"]

-- Ledger 5: slr_G on a record that is not P2 is outside the capability
theorem pin_slr_g_p1 : refsOp sB (.record 40 1 400 (.fresh 40) 7 none (some 4)) = ["outside-capability"] := by decide +kernel
#guard refsOp sB (.record 40 1 400 (.fresh 40) 7 none (some 4)) == ["outside-capability"]

-- Ledger 6: a valid carry of an auth_0 without an unsettled authorization has no rule
theorem pin_carry_unknown : refsOp sB (.authorize { c1 with carry := some { auth0 := 999, outcome := .VOID, sigs := 3 } }) = ["no-rule"] := by decide +kernel
#guard refsOp sB (.authorize { c1 with carry := some { auth0 := 999, outcome := .VOID, sigs := 3 } }) == ["no-rule"]

-- AU-029, AU-025 scenario "Re-post that ends VOID" (ledger 11, ruled by DECISIONS 60): the re-post of a
-- RELEASED request authorizes on pin 5 and settles VOID: the record stays LOCKED to pin 5 under
-- N(nsk, auth, VOID); an authorization on another pin is refused, one on pin 5 is accepted
def cLV5 : Call := { cLV9 with pin := 5 }
theorem pin_au029_locked_void : ((recOf sLV 10).map (fun r => (r.rstate, r.nf, r.pin)), refsOp sLV (.authorize cLV9),
    refsOp sLV (.authorize cLV5)) = ([(.LOCKED, .ofSettle 503 .VOID, some 5)], ["pin_mismatch"], []) := by decide +kernel
#guard ((recOf sLV 10).map (fun r => (r.rstate, r.nf, r.pin)), refsOp sLV (.authorize cLV9), refsOp sLV (.authorize cLV5))
  == ([(.LOCKED, .ofSettle 503 .VOID, some 5)], ["pin_mismatch"], [])

end SplitAuthorization
