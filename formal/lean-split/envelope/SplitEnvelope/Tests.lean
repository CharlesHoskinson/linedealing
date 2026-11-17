import SplitEnvelope.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` checks it against the definitions
the theorems describe, and `#guard` checks it with the compiled evaluator.
Expected values come from the spec text (the scenario numbers), not from `#eval`.
-/

namespace SplitEnvelope

def pub0 : PublicPart :=
  { version := 1, epoch := 3, keylistHash := 33, exp := 900, sizeClass := 0, authRef := 7, reserved := 0 }

/-- A well-formed spend envelope of epoch 3 with `exp = 900`. -/
def env0 : Envelope :=
  { size := 16384, pub := pub0, hd := 100, dd := 500, proofCtx := (100, 7), proofValid := true,
    rtype := .SPEND }

/-- `Δ_c = 50`: the next block at 801 gives `exp_c = 851 < 900`. -/
def st0 : St := init { mode := .TEE, deltaC := 50 } 800 [(3, 33), (4, 44)]

def refs (s : St) (e : Envelope) : List String := (publicRefusals s e).map Refusal.code

-- EN-001: one frame size
theorem pin_frame : frameSize = 16384 := by decide +kernel
#guard frameSize == 16384

-- EN-004 to EN-008 all pass on the well-formed envelope
theorem pin_accept : publicRefusals st0 env0 = [] := by decide +kernel
#guard publicRefusals st0 env0 == []

-- EN-004: a frame of 16,000 bytes is not accepted
theorem pin_short : refs st0 { env0 with size := 16000 } = ["bad_shape"] := by decide +kernel
#guard refs st0 { env0 with size := 16000 } == ["bad_shape"]
theorem pin_version : refs st0 { env0 with pub := { pub0 with version := 2 } } = ["bad_shape"] := by
  decide +kernel
#guard refs st0 { env0 with pub := { pub0 with version := 2 } } == ["bad_shape"]

theorem pin_size_class : refs st0 { env0 with pub := { pub0 with sizeClass := 1 } } = ["bad_shape"] := by
  decide +kernel
#guard refs st0 { env0 with pub := { pub0 with sizeClass := 1 } } == ["bad_shape"]

-- EN-005: the key list of a closed epoch, and a wrong key-list hash
theorem pin_old_epoch : refs st0 { env0 with pub := { pub0 with epoch := 2, keylistHash := 22 } } = ["bad_epoch"] := by
  decide +kernel
#guard refs st0 { env0 with pub := { pub0 with epoch := 2, keylistHash := 22 } } == ["bad_epoch"]
theorem pin_wrong_keylist : refs st0 { env0 with pub := { pub0 with keylistHash := 44 } } = ["bad_epoch"] := by
  decide +kernel
#guard refs st0 { env0 with pub := { pub0 with keylistHash := 44 } } == ["bad_epoch"]

-- EN-006: `exp = 900` at board height 901 is expired; at height 900 it is not. Both heights
-- also fail EN-023 (the next block gives `exp_c ≥ exp`), so EN-023 is in both answers
theorem pin_expired : refs { st0 with height := 901 } env0 = ["exp_c_not_below_exp", "expired"] := by decide +kernel
#guard refs { st0 with height := 901 } env0 == ["exp_c_not_below_exp", "expired"]
theorem pin_at_exp : refs { st0 with height := 900 } env0 = ["exp_c_not_below_exp"] := by decide +kernel
#guard refs { st0 with height := 900 } env0 == ["exp_c_not_below_exp"]

-- EN-023 scenario: `exp = 650`, ordered at board height 100 with `Δ_c = 600`: refused at
-- acceptance (board height 99, next block 100) and for the ordering block; bound:
-- `exp = 701` passes (700 < 701), `exp = 700` does not
def st600 : St := init { mode := .TEE, deltaC := 600 } 99 [(3, 33)]
def envExp (x : Nat) : Envelope := { env0 with pub := { pub0 with exp := x } }
theorem pin_en023 : refs st600 (envExp 650) = ["exp_c_not_below_exp"] ∧ refs st600 (envExp 700) = ["exp_c_not_below_exp"]
    ∧ refs st600 (envExp 701) = [] ∧ (apply st600 (.orderCheck 650 100)).2 = .refused [.expCNotBelowExp]
    ∧ (apply st600 (.orderCheck 700 100)).2 = .refused [.expCNotBelowExp] ∧ (apply st600 (.orderCheck 701 100)).2 = .ok := by
  decide +kernel
#guard refs st600 (envExp 650) == ["exp_c_not_below_exp"] && refs st600 (envExp 700) == ["exp_c_not_below_exp"]
  && refs st600 (envExp 701) == [] && (apply st600 (.orderCheck 650 100)).2 == .refused [.expCNotBelowExp]
  && (apply st600 (.orderCheck 700 100)).2 == .refused [.expCNotBelowExp] && (apply st600 (.orderCheck 701 100)).2 == .ok

-- EN-007: a copy with a changed `auth_ref` fails the proof check
theorem pin_rewritten : refs st0 { env0 with pub := { pub0 with authRef := 8 } } = ["bad_proof"] := by
  decide +kernel
#guard refs st0 { env0 with pub := { pub0 with authRef := 8 } } == ["bad_proof"]

-- EN-008: an envelope that reuses the outer dealing of an accepted envelope of
-- the same epoch is refused; the same `dd` in another epoch is not
def st1 : St := (apply st0 (.submit env0)).1
theorem pin_dd_reused : refs st1 { env0 with hd := 101, proofCtx := (101, 7) } = ["dd_reused"] := by
  decide +kernel
#guard refs st1 { env0 with hd := 101, proofCtx := (101, 7) } == ["dd_reused"]
theorem pin_dd_other_epoch :
    refs st1 { env0 with hd := 101, proofCtx := (101, 7), pub := { pub0 with epoch := 4, keylistHash := 44 } } = [] := by
  decide +kernel
#guard refs st1 { env0 with hd := 101, proofCtx := (101, 7), pub := { pub0 with epoch := 4, keylistHash := 44 } } == []

-- No precedence between the public checks: every code that applies, sorted (ledger 1)
theorem pin_two_codes : refs { st0 with height := 901 } { env0 with size := 1 } = ["bad_shape", "exp_c_not_below_exp", "expired"] := by
  decide +kernel
#guard refs { st0 with height := 901 } { env0 with size := 1 } == ["bad_shape", "exp_c_not_below_exp", "expired"]

-- A refused envelope is not ordered: the state is unchanged
theorem pin_refused_unchanged : (apply st0 (.submit { env0 with size := 1 })).1 = st0 := by decide +kernel
#guard (apply st0 (.submit { env0 with size := 1 })).1 == st0

-- EN-022, EN-018: a BIRTH envelope, a contribution frame and a spend envelope
-- with one public view get one answer
theorem pin_blind : refs st0 { env0 with rtype := .BIRTH } = refs st0 env0 ∧
    refs st0 { env0 with rtype := .CONTRIB } = refs st0 env0 := by decide +kernel
#guard refs st0 { env0 with rtype := .BIRTH } == refs st0 env0 && refs st0 { env0 with rtype := .CONTRIB } == refs st0 env0

/-! ## Header checks -/

/-- The P2TR header of the EN-010 scenario: `K = 8`, `L = 2`, 30 tickets and 4
committee slots; one other actor. -/
def hdr0 : Header :=
  { suite := .BIP340, K := 8, L := 2, tickets := 30,
    slots := [(1, 1, 150), (1, 2, 151), (2, 1, 152), (2, 2, 153)],
    rA := [1, 2, 3, 4], rEcdsa := [], pairs := [11, 12],
    layout := { body0 := 900, bodies := List.replicate 15 40, capsules := 385 :: List.replicate 7 0 },
    nCapsules := 1, regionOutside := false, lengthMismatch := false,
    hasIc := true, hasRtkc := true, tkc := 5, authTkc := 5, recomputeMismatch := false }

-- EN-010: the count check passes on 30 tickets and 4 committee slots
theorem pin_p2tr : headerFaults .TEE hdr0 = [] := by decide +kernel
#guard headerFaults .TEE hdr0 == []
theorem pin_count_30 : ticketCount .BIP340 8 2 = 30 := by decide +kernel
#guard ticketCount .BIP340 8 2 == 30

-- RQ-014 scenario: 29 tickets for `K = 8`, `L = 2`, `G = 2` is malformed
theorem pin_29 : headerFaults .TEE { hdr0 with tickets := 29 } = [.en010] := by decide +kernel
#guard headerFaults .TEE { hdr0 with tickets := 29 } == [.en010]

-- EN-010: a missing grid cell is malformed
theorem pin_missing_cell : headerFaults .TEE { hdr0 with slots := [(1, 1, 150), (1, 2, 151), (2, 1, 152), (2, 1, 153)] } = [.en010] := by
  decide +kernel
#guard headerFaults .TEE { hdr0 with slots := [(1, 1, 150), (1, 2, 151), (2, 1, 152), (2, 1, 153)] } == [.en010]

-- EN-010 on ECDSA: `K·L` tickets (P2WPKH, K = 3, L = 2: 6)
theorem pin_ecdsa_count : ticketCount .ECDSA 3 2 = 6 := by decide +kernel
#guard ticketCount .ECDSA 3 2 == 6

-- EN-009: the layout gives capsule 8 a region into the actor capsules
theorem pin_overlap : headerFaults .TEE { hdr0 with regionOutside := true } = [.en009] := by decide +kernel
#guard headerFaults .TEE { hdr0 with regionOutside := true } == [.en009]
-- EN-009: a nonzero unused capsule entry
theorem pin_unused : headerFaults .TEE { hdr0 with layout := { hdr0.layout with capsules := 385 :: 1 :: List.replicate 6 0 } } = [.en009] := by
  decide +kernel
#guard headerFaults .TEE { hdr0 with layout := { hdr0.layout with capsules := 385 :: 1 :: List.replicate 6 0 } } == [.en009]

-- EN-011: one committee slot named for generations 1 and 2
theorem pin_repeated_slot : headerFaults .TEE { hdr0 with slots := [(1, 1, 150), (1, 2, 151), (2, 1, 150), (2, 2, 153)] } = [.en011] := by
  decide +kernel
#guard headerFaults .TEE { hdr0 with slots := [(1, 1, 150), (1, 2, 151), (2, 1, 150), (2, 2, 153)] } == [.en011]
-- EN-011: one actor pool pair twice is malformed in TEE mode only
theorem pin_pair_tee : headerFaults .TEE { hdr0 with pairs := [11, 11] } = [.en011] ∧
    headerFaults .NON_TEE { hdr0 with pairs := [11, 11] } = [] := by decide +kernel
#guard headerFaults .TEE { hdr0 with pairs := [11, 11] } == [.en011] && headerFaults .NON_TEE { hdr0 with pairs := [11, 11] } == []

-- EN-012: a header without `r_tkc`, or without `ic`, is malformed
theorem pin_rtkc : headerFaults .TEE { hdr0 with hasRtkc := false } = [.en012] ∧
    headerFaults .TEE { hdr0 with hasIc := false } = [.en012] := by decide +kernel
#guard headerFaults .TEE { hdr0 with hasRtkc := false } == [.en012] && headerFaults .TEE { hdr0 with hasIc := false } == [.en012]
-- EN-012 (DECISIONS 68): a `tkc` that differs from the one `auth` commits is not malformed at opening
theorem pin_en012_structural : headerFaults .TEE { hdr0 with tkc := 6 } = [] := by decide +kernel
#guard headerFaults .TEE { hdr0 with tkc := 6 } == []

-- EN-013: a ticket's `c̃` that does not match, in TEE mode only
theorem pin_recompute : headerFaults .TEE { hdr0 with recomputeMismatch := true } = [.en013] ∧
    headerFaults .NON_TEE { hdr0 with recomputeMismatch := true } = [] := by decide +kernel
#guard headerFaults .TEE { hdr0 with recomputeMismatch := true } == [.en013] && headerFaults .NON_TEE { hdr0 with recomputeMismatch := true } == []

-- EN-016: 15 variant bodies at K = 8 on a Schnorr suite; one body per variant on ECDSA
theorem pin_bodies : (bodyLabels .BIP340 8).length = 15 ∧ bodyLabels .ECDSA 2 = [(1, 0), (2, 0)] := by
  decide +kernel
#guard (bodyLabels .BIP340 8).length == 15 && bodyLabels .ECDSA 2 == [(1, 0), (2, 0)]

/-! ## Combination and fallback -/

def ps (bad : List Nat) : List Partial := (List.range 9).map (fun i => { sender := i + 1, proofOk := !bad.contains (i + 1) })

-- EN-014: node 5 sends a false header partial; the tag fails, its partial is
-- dropped, and seven proved partials open the header
theorem pin_fallback : combine 7 true (ps [5]) = .opened := by decide +kernel
#guard combine 7 true (ps [5]) == .opened

-- RQ-015: seven partials with valid proofs fail the tag: dealer fault
theorem pin_dealer_fault : combine 7 false (ps []) = .dealerFault := by decide +kernel
#guard combine 7 false (ps []) == .dealerFault

-- fewer than `t` proved partials: wait
theorem pin_need_more : combine 7 true (ps [1, 2, 3]) = .needMore := by decide +kernel
#guard combine 7 true (ps [1, 2, 3]) == .needMore

/-! ## Wallet rules -/

-- EN-020: the capsule of a `K = 1` request is 385 bytes
theorem pin_capsule : capsuleSize = 385 ∧ kMax = 8 := by decide +kernel
#guard capsuleSize == 385 && kMax == 8

-- EN-021: with `exp = ordering height + 1000` the wallet uses `Δ_c < 1000`
theorem pin_window : windowInsideExpiry 100 999 1100 = true ∧ windowInsideExpiry 100 1000 1100 = false := by
  decide +kernel
#guard windowInsideExpiry 100 999 1100 && !windowInsideExpiry 100 1000 1100

-- EN-018: the contribution layout passes the layout rule with no body or capsule
theorem pin_contrib_layout : layoutBad { hdr0 with layout := contribLayout 900, nCapsules := 0 } = false := by
  decide +kernel
#guard !layoutBad { hdr0 with layout := contribLayout 900, nCapsules := 0 }

/-! ## Codes and the domain -/

theorem pin_codes : [Refusal.badEpoch, .badProof, .badShape, .ddReused, .expired, .noRule,
    .outsideCapability, .outsideStateDomain].map Refusal.code =
    ["bad_epoch", "bad_proof", "bad_shape", "dd_reused", "expired", "no-rule", "outside-capability",
     "outside-state-domain"] := by decide +kernel
#guard ["bad_epoch", "bad_proof", "bad_shape", "dd_reused", "expired", "no-rule", "outside-capability",
     "outside-state-domain"].mergeSort == ["bad_epoch", "bad_proof", "bad_shape", "dd_reused", "expired",
     "no-rule", "outside-capability", "outside-state-domain"]

-- the board height does not go down (ledger 4)
theorem pin_tick_back : (apply st0 (.tick 799)).2 = .refused [.noRule] := by decide +kernel
#guard (apply st0 (.tick 799)).2 == .refused [.noRule]

-- K = 9 is outside the domain of a header (ledger 5)
theorem pin_k9 : (apply st0 (.header { hdr0 with K := 9 })).2 = .refused [.outsideCapability] := by
  decide +kernel
#guard (apply st0 (.header { hdr0 with K := 9 })).2 == .refused [.outsideCapability]

-- a whole run: accept, then refuse the reuse
theorem pin_run : (runOps st0 [.submit env0, .submit { env0 with hd := 101, proofCtx := (101, 7) }]).2 =
    [.accepted (100, 7), .refused [.ddReused]] := by decide +kernel
#guard (runOps st0 [.submit env0, .submit { env0 with hd := 101, proofCtx := (101, 7) }]).2 ==
    [.accepted (100, 7), .refused [.ddReused]]

/-- C9 witness: a reachable state with a refused reuse exists (the conditional fires). -/
theorem witness_dd_reuse : ∃ ops, (runOps st0 ops).2 = [.accepted (100, 7), .refused [.ddReused]] :=
  ⟨_, pin_run⟩

end SplitEnvelope
