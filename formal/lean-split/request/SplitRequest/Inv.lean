import SplitRequest.Spec

/-!
# The invariant domain is closed under every event

`reqStep_inv`: an accepted event keeps a request inside `reqInv`.
-/

namespace SplitRequest

set_option linter.unusedSimpArgs false

/-- Split `reqInv r = true` and the goal `reqInv r' = true` into their 22 clauses. -/
syntax "inv_split" : tactic
set_option hygiene false in
macro_rules
  | `(tactic| inv_split) => `(tactic| (
      simp only [reqInv, endFinal, endVoid, Bool.and_eq_true] at hi ⊢
      obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩, h10⟩, h11⟩, h12⟩, h13⟩, h14⟩,
        h15⟩, h16⟩, h17⟩, h18⟩, h19⟩, h20⟩, h21⟩, h22⟩ := hi
      refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩,
        ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩))

theorem phase_beq (a b : Phase) : (a == b) = decide (a = b) := rfl
theorem outcome_beq (a b : Outcome) : (a == b) = decide (a = b) := rfl
theorem reason_beq (a b : Reason) : (a == b) = decide (a = b) := rfl

theorem inRange_select (k : Nat) (rates : List Nat) (m : Nat) (hk : 1 ≤ k) (hl : rates.length = k) :
    inRange k (some (select k rates m)) = true := by
  have := select_range k rates m hk hl
  simp [inRange]; omega

theorem endOutcome_ne (r : Req) : (endOutcome r != .NONE) = true := by
  have := endOutcome_ne_none r; simpa using this

theorem endOutcome_void_ok (r : Req) : (endOutcome r != .VOID || (!r.anyRelease && !r.restartEnd)) = true := by
  unfold endOutcome
  cases hr : r.restartEnd <;> cases ha : r.anyRelease <;> cases hc : r.confirmed <;> simp

theorem inv_order (c : Ctx) (r r' : Req) (e : Nat) (qc : Bool) (p : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.order e qc p) = .ok r') : reqInv r' = true := by
  simp only [reqStep] at h
  split at h
  · rename_i hn
    have hp : r.phase = .POSTED := by simpa [phase_beq] using (orNoRule_nil _ _ hn).2
    cases h
    inv_split
    all_goals simp_all [Phase.terminal, Phase.rank, phase_beq, outcome_beq, reason_beq]
  · simp at h

set_option maxHeartbeats 1000000 in
theorem inv_openHdr (c : Ctx) (r r' : Req) (e k l : Nat) (coll : Bool) (np : Nat) (rates : List Nat) (hi : reqInv r = true)
    (h : reqStep c r (.openHdr e k l coll np rates) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_complaint (c : Ctx) (r r' : Req) (e : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.complaint e) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_frame (c : Ctx) (r r' : Req) (e : Nat) (fr : Frame) (hi : reqInv r = true)
    (h : reqStep c r (.frame e fr) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_detach (c : Ctx) (r r' : Req) (e pos : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.detach e pos) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_voteOpened (c : Ctx) (r r' : Req) (e node hash : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.voteOpened e node hash) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_voteAdmit (c : Ctx) (r r' : Req) (e node hash hh : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.voteAdmit e node hash hh) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_obs2 (c : Ctx) (r r' : Req) (e : Nat) (m : Bool) (hs : List Nat) (hi : reqInv r = true)
    (h : reqStep c r (.obs2 e m hs) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_release (c : Ctx) (r r' : Req) (e g j : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.release e g j) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_postFinal (c : Ctx) (r r' : Req) (e ep m ct : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.postFinal e ep m ct) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_postVoid (c : Ctx) (r r' : Req) (e ep m : Nat) (rs : Reason) (hi : reqInv r = true)
    (h : reqStep c r (.postVoid e ep m rs) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact tombReason_ne_none _ _ _
    | (simp only [tombReason_ne_none, Bool.true_or, Bool.or_true, beq_self_eq_true, bne_self_eq_false]; done)
    | (cases hA : r.anyRelease <;> simp_all [tombReason_ne_stalled]; done)
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_restartBurn (c : Ctx) (r r' : Req) (e : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.restartBurn e) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_confirm (c : Ctx) (r r' : Req) (e : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.confirm e) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

set_option maxHeartbeats 1000000 in
theorem inv_carry (c : Ctx) (r r' : Req) (e : Nat) (hi : reqInv r = true)
    (h : reqStep c r (.carry e) = .ok r') : reqInv r' = true := by
  cases hp : r.phase <;> simp only [reqStep, hp] at h <;> (repeat' split at h) <;>
    first
    | (simp at h; done)
    | (cases h; inv_split)
  all_goals first
    | assumption
    | exact endOutcome_void_ok _
    | exact endOutcome_ne _
    | (simp [Phase.terminal, endOutcome_ne]; done)
    | (simp_all [Phase.terminal, Phase.rank, anchorsOk, opt, orNoRule, inRange, phase_beq, outcome_beq,
        reason_beq]; done)
    | (apply inRange_select <;> simp_all [Phase.rank, Phase.terminal, phase_beq] <;> omega)
    | (simp [inRange, Phase.rank, Phase.terminal, gMax, kMax, phase_beq] at * <;> omega)

/-- RQ-029, RQ-049 to RQ-052, RQ-056, RQ-057, RQ-064 to RQ-067: every accepted
event keeps the request in its invariant domain. -/
theorem reqStep_inv (c : Ctx) (r r' : Req) (op : Op) (hi : reqInv r = true) (h : reqStep c r op = .ok r') :
    reqInv r' = true := by
  cases op with
  | order => exact inv_order (hi := hi) (h := h)
  | openHdr => exact inv_openHdr (hi := hi) (h := h)
  | complaint => exact inv_complaint (hi := hi) (h := h)
  | frame => exact inv_frame (hi := hi) (h := h)
  | detach => exact inv_detach (hi := hi) (h := h)
  | voteOpened => exact inv_voteOpened (hi := hi) (h := h)
  | voteAdmit => exact inv_voteAdmit (hi := hi) (h := h)
  | obs2 => exact inv_obs2 (hi := hi) (h := h)
  | release => exact inv_release (hi := hi) (h := h)
  | postFinal => exact inv_postFinal (hi := hi) (h := h)
  | postVoid => exact inv_postVoid (hi := hi) (h := h)
  | restartBurn => exact inv_restartBurn (hi := hi) (h := h)
  | confirm => exact inv_confirm (hi := hi) (h := h)
  | carry => exact inv_carry (hi := hi) (h := h)
  | _ => simp [reqStep] at h

end SplitRequest
