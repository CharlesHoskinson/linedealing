import SplitRequest.Inv

/-!
# Claims of split-request

* the board record: every request of every run from `init` stays in `reqInv`
  (`run_reqInv`); C11 and C20 follow from its clauses, and C11's settled leaf
  does not move (`C11_held_leaf_stable`);
* the honest node: C6, C7, C8, C9 and C20 as properties of `nodeAct`.
-/

namespace SplitRequest

set_option linter.unusedSimpArgs false

/-! ## The board record -/

theorem newReq_inv (e ep x : Nat) (ty : RType) (pr : Profile) : reqInv (newReq e ep x ty pr) = true := by
  simp [reqInv, newReq, Phase.terminal, Phase.rank, inRange, anchorsOk, kMax, gMax, phase_beq, outcome_beq,
    reason_beq]

theorem expire_inv (h : Nat) (r : Req) (hi : reqInv r = true) : reqInv (expire h r) = true := by
  unfold expire
  split
  · rename_i hc
    have hnt : r.phase.terminal = false := by simp_all
    simp only [reqInv, Bool.and_eq_true] at hi ⊢
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩, h10⟩, h11⟩, h12⟩, h13⟩, h14⟩,
      h15⟩, h16⟩, h17⟩, h18⟩, h19⟩, h20⟩, h21⟩ := hi
    refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩,
      ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩
    all_goals first
      | assumption
      | exact endOutcome_void_ok _
      | (simp [Phase.terminal, endOutcome_ne]; done)
      | (cases hp : r.phase <;> simp_all [Phase.terminal, Phase.rank, anchorsOk, inRange, phase_beq, outcome_beq,
          reason_beq, endOutcome] <;> done)
      | (cases hp : r.phase <;> simp_all [Phase.terminal, Phase.rank, phase_beq, outcome_beq, reason_beq,
          endOutcome] <;> split <;> simp_all)
  · exact hi

/-- The requests of a state, all in the invariant domain. -/
def allInv (s : St) : Prop := ∀ x ∈ s.reqs, reqInv x = true

theorem find_mem (s : St) (e : Nat) (r : Req) (h : find s e = some r) : r ∈ s.reqs :=
  List.mem_of_find?_eq_some h

theorem replace_mem (e : Nat) (r' : Req) (rs : List Req) (x : Req) (h : x ∈ replace e r' rs) :
    x = r' ∨ x ∈ rs := by
  unfold replace at h
  obtain ⟨y, hy, hx⟩ := List.mem_map.1 h
  split at hx
  · exact .inl hx.symm
  · exact .inr (hx ▸ hy)

theorem step_inv (s s' : St) (op : Op) (hs : allInv s) (h : step s op = .ok s') : allInv s' := by
  cases op with
  | post e ep x ty pr =>
    simp only [step] at h
    split at h
    · simp at h
    · cases h
      intro y hy
      rcases List.mem_append.1 hy with hy | hy
      · exact hs y hy
      · simp at hy; subst hy; exact newReq_inv _ _ _ _ _
  | tick hh =>
    simp only [step] at h
    split at h
    · simp at h
    · cases h
      intro x hx
      obtain ⟨y, hy, rfl⟩ := List.mem_map.1 hx
      exact expire_inv _ _ (hs y hy)
  | rotate e n f =>
    simp only [step] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · cases h; exact hs
  | landCp hh =>
    simp only [step] at h
    split at h
    · simp at h
    · cases h; exact hs
  | hostFee hh m =>
    simp only [step] at h
    split at h
    · split at h
      · cases h; exact hs
      · simp at h
    · cases h; exact hs
  | _ =>
    simp only [step, Op.target] at h
    split at h
    · simp at h
    · rename_i r hf
      split at h
      · rename_i r' hr
        cases h
        intro x hx
        rcases replace_mem _ _ _ _ hx with rfl | hx
        · exact reqStep_inv _ _ _ _ (hs r (find_mem _ _ _ hf)) hr
        · exact hs x hx
      · simp at h

theorem apply_inv (s : St) (op : Op) (hs : allInv s) : allInv (apply s op).1 := by
  unfold apply
  split
  · rename_i s' h
    split <;> exact step_inv _ _ _ hs h
  · exact hs

theorem runOps_inv (s : St) (ops : List Op) (hs : allInv s) : allInv (runOps s ops).1 := by
  induction ops generalizing s with
  | nil => exact hs
  | cons op ops ih => exact ih _ (apply_inv s op hs)

/-- RQ-029, RQ-049 to RQ-052, RQ-056, RQ-057, RQ-064 to RQ-067: every request
of every run from `init` is in the invariant domain. -/
theorem run_reqInv (p : Params) (es : List (Nat × Nat × Nat)) (ops : List Op) :
    ∀ x ∈ (run (init p es) ops).reqs, reqInv x = true :=
  runOps_inv _ ops (by intro x hx; simp [init] at hx)

/-- C11, RQ-051, RQ-052: in every run, a request that released a generation,
or that a restart burn ended, never settles VOID. -/
theorem C11_released_never_void (p : Params) (es : List (Nat × Nat × Nat)) (ops : List Op)
    (x : Req) (hx : x ∈ (run (init p es) ops).reqs) (hr : x.anyRelease = true ∨ x.restartEnd = true) :
    x.outcome ≠ .VOID := by
  have hi := run_reqInv p es ops x hx
  simp only [reqInv, Bool.and_eq_true] at hi
  have h19 := hi.1.1.2
  intro hv
  rcases hr with hr | hr <;> simp_all [outcome_beq]

/-- C20, RQ-073, RQ-074 (DECISIONS 64): in every run, a request whose RELEASE
committed never has reason STALLED, so the stalled gate of AU-021 sees STALLED
only on a request that released nothing. -/
theorem rq073_no_stalled_after_release (p : Params) (es : List (Nat × Nat × Nat)) (ops : List Op)
    (x : Req) (hx : x ∈ (run (init p es) ops).reqs) (hs : x.reason = .STALLED) : x.anyRelease = false := by
  have hi := run_reqInv p es ops x hx
  simp only [reqInv, Bool.and_eq_true] at hi
  have h22 := hi.2
  simp_all

/-- C13, C20, RQ-071 (DECISIONS 61): a MIXED tombstone reads as none of
STALLED, SLOT_TAKEN and REVOKED. -/
theorem rq071_mixed_reads_none (x : Reason) : readsAs .MIXED x = false := by
  cases x <;> rfl

/-- C20, RQ-057: in every run, no request holds an anchor or a release before
admission. A request that ends before ADMITTED (STALLED among them) released
nothing. -/
theorem C20_no_release_before_admission (p : Params) (es : List (Nat × Nat × Nat)) (ops : List Op)
    (x : Req) (hx : x ∈ (run (init p es) ops).reqs) (hr : x.phase.rank < 4) :
    x.anchor1 = none ∧ x.anchor2 = none ∧ x.anyRelease = false := by
  have hi := run_reqInv p es ops x hx
  simp only [reqInv, Bool.and_eq_true] at hi
  have h12 := hi.1.1.1.1.1.1.1.1.1.2
  have : ¬ (4 ≤ x.phase.rank) := by omega
  simp_all

/-- RQ-049, RQ-064: in every run, a FINAL request has outcome FINAL. -/
theorem rq049_final_outcome (p : Params) (es : List (Nat × Nat × Nat)) (ops : List Op)
    (x : Req) (hx : x ∈ (run (init p es) ops).reqs) (hf : x.phase = .FINAL) : x.outcome = .FINAL := by
  have hi := run_reqInv p es ops x hx
  simp only [reqInv, Bool.and_eq_true] at hi
  have h18 := hi.1.1.1.2
  simp_all [phase_beq, outcome_beq]

/-- C11, RQ-054, D-058: once Midnight holds the settlement leaf of an ended
request, no event changes its outcome. -/
theorem C11_held_leaf_stable (c : Ctx) (r r' : Req) (op : Op) (ht : r.phase.terminal = true)
    (hl : leafHeld c r = true) (h : reqStep c r op = .ok r') : r'.outcome = r.outcome := by
  by_cases hx : ∃ e, op = .restartBurn e ∨ op = .confirm e ∨ op = .carry e
  · obtain ⟨e, hx | hx | hx⟩ := hx <;> subst hx
    · simp only [reqStep, ht, hl, Bool.not_true, Bool.false_eq_true, ite_false, ite_true] at h
      split at h <;> simp at h
    · simp only [reqStep] at h; cases h; rfl
    · simp only [reqStep] at h
      split at h
      · cases h; rfl
      · simp at h
  · simp only [not_exists, not_or] at hx
    obtain ⟨rs, hrs⟩ := terminal_refused c r op ht hx
    rw [hrs] at h; cases h

/-- RQ-005: an event on a terminal request, other than the restart re-end of
RQ-068 and the host and Midnight facts, is refused, and `terminal` is among
the codes. Board-wide events (`post`, `tick`, `rotate`, `land_checkpoint`,
`host_fee`) name no request. -/
theorem rq005_terminal_code (c : Ctx) (r : Req) (op : Op) (ht : r.phase.terminal = true)
    (hn : op.target.isSome = true) (hop : ∀ e, op ≠ .restartBurn e ∧ op ≠ .confirm e ∧ op ≠ .carry e) :
    ∃ rs, reqStep c r op = .error rs ∧ Refusal.terminal ∈ rs := by
  cases op with
  | restartBurn e => exact absurd rfl (hop e).1
  | confirm e => exact absurd rfl (hop e).2.1
  | carry e => exact absurd rfl (hop e).2.2
  | order _ qc _ => cases qc <;> simp [reqStep, ht, opt, orNoRule]
  | postFinal _ e _ _ =>
    cases he : epochOf c e <;> simp [reqStep, ht, opt, he]
  | postVoid _ e _ _ =>
    cases he : epochOf c e <;> simp [reqStep, ht, opt, he]
  | post | tick | rotate | landCp | hostFee => simp [Op.target] at hn
  | _ => simp [reqStep, ht]

/-! ## The honest node -/

theorem voids_no_release (c : Ctx) (r : Req) (v : View) (g j : Nat) : Act.release g j ∉ voids c r v := by
  simp [voids]

theorem votes_no_release (r : Req) (v : View) (g j : Nat) : Act.release g j ∉ votes r v := by
  unfold votes
  repeat' split
  all_goals simp

theorem releases_mem (p : Params) (r : Req) (v : View) (g j : Nat) (h : Act.release g j ∈ releases p r v) :
    anchorOf r g = some j ∧ g ≤ r.G ∧ releaseOk p r v g = true ∧ (p.mode = .NON_TEE → releasedOf r g = some j) := by
  unfold releases at h
  rw [List.mem_filterMap] at h
  obtain ⟨a, -, hf⟩ := h
  split at hf
  · rename_i j' hj
    split at hf
    · rename_i hc
      split at hf
      · split at hf <;> simp at hf
      · rename_i hn
        simp only [Option.some.injEq, Act.release.injEq] at hf
        obtain ⟨rfl, rfl⟩ := hf
        simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
        refine ⟨hj, hc.1.1, hc.2, fun hm => ?_⟩
        simp only [hm] at hn
        simpa using hn
    · simp at hf
  · simp at hf

theorem releases_no_void (p : Params) (r : Req) (v : View) (x : Reason) : Act.postVoid x ∉ releases p r v := by
  unfold releases
  rw [List.mem_filterMap]
  rintro ⟨a, -, hf⟩
  repeat' split at hf
  all_goals simp at hf

theorem release_mem (c : Ctx) (r : Req) (v : View) (g j : Nat) (h : Act.release g j ∈ nodeAct c r v) :
    r.phase = .ADMITTED ∧ anchorOf r g = some j ∧ g ≤ r.G ∧ releaseOk c.params r v g = true
      ∧ (c.params.mode = .NON_TEE → releasedOf r g = some j) := by
  cases hp : r.phase <;> simp only [nodeAct, hp, Phase.terminal] at h
  all_goals by_cases hs : r.rtype.signing = true <;>
    simp [hs, phase_beq, voids_no_release, votes_no_release] at h
  all_goals first
    | (obtain ⟨_, h⟩ := h; split at h <;> simp at h)
    | exact ⟨rfl, releases_mem _ _ _ _ _ h⟩

/-- RQ-069, C11 (DECISIONS 59): in NON_TEE mode an honest node sends the
partials of generation `g` only after its RELEASE for `(g, j)` has committed
(`released[g] = j`), so a request whose partials left a node has
`any_release = true` and never settles VOID. -/
theorem rq069_send_after_record (c : Ctx) (r : Req) (v : View) (g j : Nat) (hm : c.params.mode = .NON_TEE)
    (h : Act.release g j ∈ nodeAct c r v) : releasedOf r g = some j :=
  (release_mem c r v g j h).2.2.2.2 hm

/-- RQ-057: an honest node sends no partial for a request that has not reached
ADMITTED. -/
theorem rq057_release_needs_admitted (c : Ctx) (r : Req) (v : View) (g j : Nat)
    (h : Act.release g j ∈ nodeAct c r v) : r.phase = .ADMITTED :=
  (release_mem c r v g j h).1

/-- C8, RQ-008: an honest node sends nothing for a request that is not ordered. -/
theorem C8_sealed_until_order (c : Ctx) (r : Req) (v : View) (hp : r.phase = .POSTED) : nodeAct c r v = [] := by
  simp [nodeAct, hp, Phase.terminal]

/-- C6, RQ-024, RQ-030: an honest node releases only for an admitted request
whose authorization it reads in force. -/
theorem C6_release_in_force (c : Ctx) (r : Req) (v : View) (g j : Nat) (h : Act.release g j ∈ nodeAct c r v) :
    r.phase = .ADMITTED ∧ v.auth = .inForce := by
  have ⟨hp, _, _, hok, _⟩ := release_mem c r v g j h
  simp [releaseOk] at hok
  exact ⟨hp, hok.1.1.1.1⟩

/-- C9, RQ-030: an honest node releases only the variant the board anchored for
that generation. -/
theorem C9_release_only_anchor (c : Ctx) (r : Req) (v : View) (g j : Nat) (h : Act.release g j ∈ nodeAct c r v) :
    anchorOf r g = some j ∧ g ≤ r.G :=
  have ⟨_, ha, hg, _, _⟩ := release_mem c r v g j h
  ⟨ha, hg⟩

/-- C7, RQ-032, RQ-059: an honest node releases a generation only when it reads
Midnight at least as new as every OBS report of it and finds no revocation at
or below that height. -/
theorem C7_no_release_after_revocation (c : Ctx) (r : Req) (v : View) (g j : Nat)
    (h : Act.release g j ∈ nodeAct c r v) : revocationClear v g = true := by
  have ⟨_, _, _, hok, _⟩ := release_mem c r v g j h
  simp only [releaseOk, Bool.and_eq_true] at hok
  exact hok.1.1.1.2

/-- C7, RQ-033: for a P2 request, generation 1 is released only after `Δ_hold`
Midnight blocks. -/
theorem C7_hold_p2 (c : Ctx) (r : Req) (v : View) (j : Nat) (hp : r.profile = .P2)
    (h : Act.release 1 j ∈ nodeAct c r v) : c.params.deltaHold ≤ v.holdAge := by
  have ⟨_, _, _, hok, _⟩ := release_mem c r v 1 j h
  simp [releaseOk, hp] at hok
  exact hok.1.2

/-- RQ-035: in TEE mode a generation is released only with `w` acks and a
current `slot_bind`. -/
theorem rq035_tee_acks (c : Ctx) (r : Req) (v : View) (g j : Nat) (hm : c.params.mode = .TEE)
    (h : Act.release g j ∈ nodeAct c r v) :
    c.params.w ≤ (if g = 1 then v.acks1 else v.acks2) ∧ v.bound = true := by
  have ⟨_, _, _, hok, _⟩ := release_mem c r v g j h
  simp [releaseOk, hm] at hok
  exact hok.2

/-- C20, RQ-047: a node that posts VOID STALLED for a request releases nothing
for it. -/
theorem C20_stalled_releases_nothing (c : Ctx) (r : Req) (v : View) (g j : Nat)
    (hs : Act.postVoid .STALLED ∈ nodeAct c r v) : Act.release g j ∉ nodeAct c r v := by
  intro h
  have ⟨hp, _⟩ := release_mem c r v g j h
  simp [nodeAct, hp, Phase.terminal, voids, phase_beq, releases_no_void] at hs

end SplitRequest
