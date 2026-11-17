import SplitSlots.Spec

/-!
# Known answers, written from the requirement sentences and their scenarios

Each answer is pinned twice: `decide +kernel` against the definitions the
theorems describe, `#guard` with the compiled evaluator. Expected values come
from the spec text (the scenario numbers), not from `#eval`.
-/

namespace SplitSlots

def p0 : Params := { mode := .TEE, w := 6 }
def s0 : St := init p0

def cs (ops : List Op) : List (Nat × BStat × Option Nat) :=
  (run s0 ops).cslots.map (fun x => (x.idx, x.bstat, x.prec))
def es (ops : List Op) : List (Nat × BStat × Option Nat × Option Nat) :=
  (run s0 ops).eslots.map (fun x => (x.idx, x.bstat, x.prec, x.reserver))
def obs (ops : List Op) : List Obs := (runOps s0 ops).2

-- SL-001: epoch 3 deals BIP340 and Ed25519 slots; each pool starts at index 1
theorem pin_two_suites : ((run s0 [.dealC .BIP340 3 2, .dealC .ED25519 3 2]).cslots.map CSlot.key) =
    [(.BIP340, 3, 1), (.BIP340, 3, 2), (.ED25519, 3, 1), (.ED25519, 3, 2)] := by decide +kernel
#guard ((run s0 [.dealC .BIP340 3 2, .dealC .ED25519 3 2]).cslots.map CSlot.key) ==
    [(.BIP340, 3, 1), (.BIP340, 3, 2), (.ED25519, 3, 1), (.ED25519, 3, 2)]

-- SL-002: a dealt slot that no header names
theorem pin_dealt : cs [.dealC .BIP340 3 1] = [(1, .UNNAMED, none)] ∧
    (run s0 [.dealC .BIP340 3 1]).cslots.map (·.namers) = [[]] := by decide +kernel
#guard cs [.dealC .BIP340 3 1] == [(1, .UNNAMED, none)]

-- SL-003: a guardian slot lies under `slr_G`
theorem pin_guardian : (run s0 [.dealE 9 77 .G 1]).eslots.map (fun x => (x.idx, x.root, x.leafSet)) = [(1, .G, 77)] := by
  decide +kernel
#guard (run s0 [.dealE 9 77 .G 1]).eslots.map (fun x => (x.idx, x.root, x.leafSet)) == [(1, .G, 77)]

-- SL-004, SL-016: request B (eid 2, position 20) names a slot of A (eid 1, position 10);
-- B's authorization comes into force first. A keeps precedence, and B is VOID SLOT_TAKEN
-- when its authorization comes into force, not at its open (DECISIONS 68).
def copied : List Op :=
  [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .openC 2 20 [(.BIP340, 3, 1)], .inForce 2 .OWN]
theorem pin_copied : cs copied = [(1, .NAMED, some 1)] ∧ (obs copied).drop 1 = [.ok, .ok, .voidSlotTaken] := by
  decide +kernel
#guard cs copied == [(1, .NAMED, some 1)] && (obs copied).drop 1 == [.ok, .ok, .voidSlotTaken]

-- SL-016 (DECISIONS 68): B's authorization is in force before its header opens: VOID
-- SLOT_TAKEN at the open; a B that never comes into force gets no SLOT_TAKEN
theorem pin_sl016_in_force_first : (obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .inForce 2 .OWN,
      .openC 2 20 [(.BIP340, 3, 1)]]).getLast? = some .voidSlotTaken ∧
    obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .openC 2 20 [(.BIP340, 3, 1)], .lapse 2] =
      [.ok, .ok, .ok, .ok] := by decide +kernel
#guard (obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .inForce 2 .OWN,
      .openC 2 20 [(.BIP340, 3, 1)]]).getLast? == some .voidSlotTaken
#guard obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .openC 2 20 [(.BIP340, 3, 1)], .lapse 2] ==
      [.ok, .ok, .ok, .ok]

-- SL-005, SL-010: an envelope that names four committee slots lapses: all four burn
def lapsing : List Op :=
  [.dealC .BIP340 3 4, .openC 1 10 [(.BIP340, 3, 1), (.BIP340, 3, 2), (.BIP340, 3, 3), (.BIP340, 3, 4)], .lapse 1]
theorem pin_lapse : (cs lapsing).map (·.2.1) = [.BURNED, .BURNED, .BURNED, .BURNED] := by decide +kernel
#guard (cs lapsing).map (·.2.1) == [.BURNED, .BURNED, .BURNED, .BURNED]

-- SL-005: a request whose authorization is in force does not lapse
theorem pin_no_lapse_in_force : obs [.inForce 1 .OWN, .lapse 1] = [.ok, .refused [.noRule]] := by decide +kernel
#guard obs [.inForce 1 .OWN, .lapse 1] == [.ok, .refused [.noRule]]

-- SL-005 scenario "Header that opens after the lapse height" (DECISIONS 63): request 2, ordered
-- at height 100 with no authorization in force, lapses at 700 while it waits for the earlier
-- header of request 1; it opens at 750 and takes precedence on slot 2: the precedence is lapsed
-- and the slot burns (SL-010). Request 1's slot 1 keeps NAMED.
def lateOpen : List Op :=
  [.dealC .BIP340 3 2, .lapse 2, .openC 1 10 [(.BIP340, 3, 1)], .openC 2 20 [(.BIP340, 3, 2)]]
theorem pin_sl005_late_open : cs lateOpen = [(1, .NAMED, some 1), (2, .BURNED, some 2)] := by decide +kernel
#guard cs lateOpen == [(1, .NAMED, some 1), (2, .BURNED, some 2)]

-- SL-005: the same header with no lapse takes a live precedence
theorem pin_sl005_no_lapse : cs (lateOpen.erase (.lapse 2)) = [(1, .NAMED, some 1), (2, .NAMED, some 2)] := by
  decide +kernel
#guard cs (lateOpen.erase (.lapse 2)) == [(1, .NAMED, some 1), (2, .NAMED, some 2)]

-- SL-005: a lapsed request that names a slot under another precedence takes none; the slot keeps
-- its holder and is not burned by the lapse
theorem pin_sl005_not_holder : cs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .lapse 2,
    .openC 2 20 [(.BIP340, 3, 1)]] = [(1, .NAMED, some 1)] := by decide +kernel
#guard cs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .lapse 2, .openC 2 20 [(.BIP340, 3, 1)]]
  == [(1, .NAMED, some 1)]

-- SL-006: envelope E (eid 5) names slot 7 with no authorization; a later owner
-- request (eid 6) names slot 7 and comes into force: it gets precedence
def ecdsaRace : List Op := [.dealE 1 50 .OWN 7, .openE 5 10 [(1, 7)], .openE 6 20 [(1, 7)], .inForce 6 .OWN]
theorem pin_owner_first : (es ecdsaRace).getLast? = some (7, .NAMED, some 6, none) := by decide +kernel
#guard (es ecdsaRace).getLast? == some (7, .NAMED, some 6, none)

-- SL-016: ECDSA slot 7 has precedence for request 6 in force; request 8 names it and comes
-- into force later: VOID SLOT_TAKEN at its `in_force`
def ecdsaTaken : List Op := ecdsaRace ++ [.openE 8 30 [(1, 7)], .inForce 8 .OWN]
theorem pin_sl016_ecdsa : (obs ecdsaTaken).drop 4 = [.ok, .voidSlotTaken] := by decide +kernel
#guard (obs ecdsaTaken).drop 4 == [.ok, .voidSlotTaken]

-- SL-006: a source that opens `slr_own` takes no precedence on a slot under `slr_G`
theorem pin_root : es [.dealE 1 50 .G 1, .openE 6 20 [(1, 1)], .inForce 6 .OWN] = [(1, .UNNAMED, none, none)] := by
  decide +kernel
#guard es [.dealE 1 50 .G 1, .openE 6 20 [(1, 1)], .inForce 6 .OWN] == [(1, .UNNAMED, none, none)]

-- SL-007, SL-028: a spam envelope with no authorization names guardian slot 30 and
-- expires: slot 30 keeps its state
def spam : List Op := [.dealE 1 50 .G 30, .openE 9 10 [(1, 30)], .endReq 9]
theorem pin_spam : (es spam).getLast? = some (30, .UNNAMED, none, none) := by decide +kernel
#guard (es spam).getLast? == some (30, .UNNAMED, none, none)

-- SL-008: six ADMIT votes commit for the request with precedence on slot 12
def admitted : List Op :=
  [.dealC .BIP340 3 12, .openC 1 10 [(.BIP340, 3, 12)], .inForce 1 .OWN, .reserve 1]
theorem pin_reserve : (cs admitted).getLast? = some (12, .RESERVED, some 1) := by decide +kernel
#guard (cs admitted).getLast? == some (12, .RESERVED, some 1)

-- SL-008: no reservation without an authorization in force
theorem pin_reserve_needs_force : (obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .reserve 1]).getLast? =
    some (.refused [.noRule]) := by decide +kernel
#guard (obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1)], .reserve 1]).getLast? == some (.refused [.noRule])

-- SL-009: admission claims the reserved slots
theorem pin_claim : (cs (admitted ++ [.claim 1])).getLast? = some (12, .CLAIMED, some 1) := by decide +kernel
#guard (cs (admitted ++ [.claim 1])).getLast? == some (12, .CLAIMED, some 1)

-- SL-010: the end of the request with precedence burns the slot, used or not
theorem pin_end_burns : (cs (admitted ++ [.endReq 1])).getLast? = some (12, .BURNED, some 1) := by decide +kernel
#guard (cs (admitted ++ [.endReq 1])).getLast? == some (12, .BURNED, some 1)

-- SL-011: an ECDSA request with K = 3 reaches FINAL with variant 1: every ECDSA
-- slot it reserved, the slots of variants 2 and 3 included, burns
def ecdsaFinal : List Op :=
  [.dealE 1 50 .OWN 3, .openE 4 10 [(1, 1), (1, 2), (1, 3)], .inForce 4 .OWN, .reserve 4, .claim 4, .endReq 4]
theorem pin_ecdsa_final : es ecdsaFinal = [(1, .BURNED, some 4, some 4), (2, .BURNED, some 4, some 4), (3, .BURNED, some 4, some 4)] := by
  decide +kernel
#guard es ecdsaFinal == [(1, .BURNED, some 4, some 4), (2, .BURNED, some 4, some 4), (3, .BURNED, some 4, some 4)]

-- SL-012: `cp.h = 100`, `B = 200`, a header names index 150: in the window
theorem pin_window : verdict true 100 101 [] 200 1 150 = .inWindow := by decide +kernel
#guard verdict true 100 101 [] 200 1 150 == .inWindow

-- SL-013: `cp.h = 100`, `cp.pending_min = 90`, index 95 that no pending request holds
theorem pin_skipped : verdict true 100 90 [] 200 1 95 = .slotTaken := by decide +kernel
#guard verdict true 100 90 [] 200 1 95 == .slotTaken
-- SL-012: index 95 pending for the same request is in the window; for another request it is taken
theorem pin_pending : verdict true 100 90 [(95, 1)] 200 1 95 = .inWindow ∧
    verdict true 100 90 [(95, 2)] 200 1 95 = .slotTaken ∧ verdict true 100 90 [(89, 1)] 200 1 89 = .slotTaken := by
  decide +kernel
#guard verdict true 100 90 [(95, 1)] 200 1 95 == .inWindow && verdict true 100 90 [(95, 2)] 200 1 95 == .slotTaken

-- SL-014: `cp.h = 100`, `B = 200`, index 301 is above the window; 300 is in it
theorem pin_above : verdict true 100 101 [] 200 1 301 = .aboveWindow ∧ verdict true 100 101 [] 200 1 300 = .inWindow := by
  decide +kernel
#guard verdict true 100 101 [] 200 1 301 == .aboveWindow && verdict true 100 101 [] 200 1 300 == .inWindow

-- SL-015: a pool of epoch 4 that no landed checkpoint lists
theorem pin_unlisted : verdict false 100 101 [] 200 1 150 = .poolUnlisted := by decide +kernel
#guard verdict false 100 101 [] 200 1 150 == .poolUnlisted

-- SL-017: a header names a burned slot: it stays BURNED and gets no `prec`
theorem pin_burned_named : cs [.dealC .BIP340 3 1, .burnRange .BIP340 3 1 1, .openC 1 10 [(.BIP340, 3, 1)]] =
    [(1, .BURNED, none)] := by decide +kernel
#guard cs [.dealC .BIP340 3 1, .burnRange .BIP340 3 1 1, .openC 1 10 [(.BIP340, 3, 1)]] == [(1, .BURNED, none)]

-- SL-018: a `bound(d)` slot never becomes `free`; a second bind to another digest is refused
def bound7 : List Op := [.seatPut 1, .seatBind 1 7 6 6]
theorem pin_bound : (run s0 bound7).seat.map (·.st) = [.bound 7] ∧
    (obs (bound7 ++ [.seatBind 1 8 6 6])).getLast? = some (.refused [.noRule]) := by decide +kernel
#guard (run s0 bound7).seat.map (·.st) == [.bound 7]

-- SL-019: the `slot` entries have `w` acks and the sealed version five at `w = 6`: no partial
theorem pin_bind_round : (obs [.seatPut 1, .seatBind 1 7 6 5, .seatRelease 1 7]).getLast? = some (.refused [.noRule]) := by
  decide +kernel
#guard (obs [.seatPut 1, .seatBind 1 7 6 5, .seatRelease 1 7]).getLast? == some (.refused [.noRule])

-- SL-020: a slot bound to `d` and a release that asks for `d'`: `slot_bound`
theorem pin_slot_bound : (obs (bound7 ++ [.seatRelease 1 8])).getLast? = some (.refused [.slotBound]) := by decide +kernel
#guard (obs (bound7 ++ [.seatRelease 1 8])).getLast? == some (.refused [.slotBound])

-- SL-021: eight tickets name one slot; the node signs only the selected one
def eight : List Op := bound7 ++ (List.range 8).map (fun i => .seatRelease 1 (i + 3))
theorem pin_one_ticket : (run s0 eight).seat.map (·.signed) = [[7]] := by decide +kernel
#guard (run s0 eight).seat.map (·.signed) == [[7]]

-- SL-022: after index 500 burned, the next dealing starts above the highest dealt index
theorem pin_refill : (cs [.dealC .BIP340 3 500, .burnRange .BIP340 3 500 500, .dealC .BIP340 3 1]).getLast? =
    some (501, .UNNAMED, none) := by decide +kernel
#guard (cs [.dealC .BIP340 3 500, .burnRange .BIP340 3 500 500, .dealC .BIP340 3 1]).getLast? == some (501, .UNNAMED, none)

-- SL-023: a batch of 16 slot dealings with good shares: one equation accepts all 32 shares
theorem pin_batch_ok : batchCheck (List.replicate 32 true) = [] := by decide +kernel
#guard batchCheck (List.replicate 32 true) == []

-- SL-024: polynomial 5 of a batch is bad: the complaint names polynomial 5
theorem pin_batch_bad : batchCheck ((List.range 16).map (fun i => i + 1 != 5)) = [5] := by decide +kernel
#guard batchCheck ((List.range 16).map (fun i => i + 1 != 5)) == [5]

-- SL-025: dealer 2 of slot 9 has a valid complaint: the slot sums the first seven others
theorem pin_qualified : qualified 7 ((List.range 9).map (fun i => (i + 1, i + 1 == 2))) = some [1, 3, 4, 5, 6, 7, 8] := by
  decide +kernel
#guard qualified 7 ((List.range 9).map (fun i => (i + 1, i + 1 == 2))) == some [1, 3, 4, 5, 6, 7, 8]

-- SL-026: two board histories show two tickets for one slot; a covered entry binds the first
theorem pin_anchor : anchorOk true [(40, 7)] 40 7 = true ∧ anchorOk true [(40, 7)] 40 8 = false ∧
    anchorOk false [] 40 8 = true := by decide +kernel
#guard anchorOk true [(40, 7)] 40 7 && !anchorOk true [(40, 7)] 40 8 && anchorOk false [] 40 8

-- SL-030: a request with a `bound` slot reaches FINAL: `slot_burn`, and the slot is `burned`
theorem pin_burn : (run s0 (bound7 ++ [.seatBurn 1])).seat.map (·.st) = [.burned] ∧
    (obs (bound7 ++ [.seatBurn 1, .seatRelease 1 7])).getLast? = some (.refused [.noRule]) := by decide +kernel
#guard (run s0 (bound7 ++ [.seatBurn 1])).seat.map (·.st) == [.burned]

-- SL-018: no seat slot in NON_TEE mode
theorem pin_non_tee : (runOps (init { mode := .NON_TEE, w := 6 }) [.seatPut 1]).2 = [.refused [.noRule]] := by
  decide +kernel
#guard (runOps (init { mode := .NON_TEE, w := 6 }) [.seatPut 1]).2 == [.refused [.noRule]]

-- Q-003: a header with a lower board position than one already judged is refused
theorem pin_order : (obs [.dealC .BIP340 3 1, .openC 2 20 [(.BIP340, 3, 1)], .openC 1 10 [(.BIP340, 3, 1)]]).getLast? =
    some (.refused [.noRule]) := by decide +kernel
#guard (obs [.dealC .BIP340 3 1, .openC 2 20 [(.BIP340, 3, 1)], .openC 1 10 [(.BIP340, 3, 1)]]).getLast? == some (.refused [.noRule])

-- domain: B = 0 and a repeated slot in one header
theorem pin_domain : (apply s0 (.judge true 1 2 [] 0 1 [1])).2 = .refused [.outsideCapability] ∧
    (obs [.dealC .BIP340 3 1, .openC 1 10 [(.BIP340, 3, 1), (.BIP340, 3, 1)]]).getLast? = some (.refused [.outsideCapability]) := by
  decide +kernel
#guard (apply s0 (.judge true 1 2 [] 0 1 [1])).2 == .refused [.outsideCapability]

theorem pin_codes : [Refusal.noRule, .outsideCapability, .outsideStateDomain, .slotBound].map Refusal.code =
    ["no-rule", "outside-capability", "outside-state-domain", "slot_bound"] ∧
    [Verdict.inWindow, .slotTaken, .aboveWindow, .poolUnlisted].map Verdict.code =
    ["in_window", "SLOT_TAKEN", "above_window", "pool_unlisted"] := by decide +kernel
#guard ["no-rule", "outside-capability", "outside-state-domain", "slot_bound"].mergeSort ==
    ["no-rule", "outside-capability", "outside-state-domain", "slot_bound"]

/-! ## Witnesses: the conditional requirements fire from `init` -/

/-- C12 is not vacuous: a run from `init` releases a partial on a seat slot. -/
theorem witness_release : ∃ ops, (run s0 ops).seat.map (·.signed) = [[7]] := ⟨_, pin_one_ticket⟩

/-- C13 is not vacuous: a run from `init` burns ECDSA slots at the end of their reserver. -/
theorem witness_ecdsa_burn : ∃ ops, (es ops).map (·.2.1) = [.BURNED, .BURNED, .BURNED] :=
  ⟨ecdsaFinal, by decide +kernel⟩

/-- SL-007's hypothesis holds on a reachable state: the spam namer is never in force. -/
theorem witness_spam : ∀ r, (9, r) ∉ (run s0 (spam.take 2)).inForce := by
  intro r
  have h : (run s0 (spam.take 2)).inForce = [] := by decide +kernel
  simp [h]

end SplitSlots
