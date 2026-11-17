import SplitAuthorization.Spec

/-!
# Theorems

Each claim theorem is stated for every run from `init` over any operation list.

* `C11_nf_once` (AU-008): no nullifier is used by two accepted `authorize` calls.
* `C11_one_final` (AU-024): a Midnight-first record has at most one authorization
  that settled FINAL, over all its successors (the record states that follow
  from it by settlement). Board-first records are left out: the contract holds
  roots and not nullifiers there, and the claim for them is open item O29.
* `C11_released_never_fresh` (AU-025): a record with an authorization that
  settled RELEASED never holds a fresh nullifier again.
* `C11_bf_first_only` (AU-015, AU-016): the node holds at most one in-force
  board-first call per nullifier.
* `C6_no_force_without_finalize` (AU-010): an authorization whose transaction no
  `finalize` made final is in force at no Midnight height.
-/

namespace SplitAuthorization

/-! ## Counting -/

def cnt (p : Auth → Bool) : List Auth → Nat
  | [] => 0
  | b :: l => (if p b then 1 else 0) + cnt p l

theorem cnt_pos {p : Auth → Bool} : ∀ {l : List Auth}, 1 ≤ cnt p l → ∃ b ∈ l, p b = true
  | [], h => by simp [cnt] at h
  | b :: l, h => by
    by_cases hb : p b = true
    · exact ⟨b, by simp, hb⟩
    · have : 1 ≤ cnt p l := by simp [cnt, hb] at h; omega
      obtain ⟨x, hx, hp⟩ := cnt_pos this
      exact ⟨x, by simp [hx], hp⟩

theorem cnt_of_mem {p : Auth → Bool} : ∀ {l : List Auth} {b : Auth}, b ∈ l → p b = true → 1 ≤ cnt p l
  | [], _, h, _ => by simp at h
  | x :: l, b, h, hp => by
    simp at h
    rcases h with rfl | h
    · simp [cnt, hp]
    · have := cnt_of_mem (p := p) h hp; simp [cnt]; omega

theorem cnt_any {p : Auth → Bool} (l : List Auth) (h : l.any p = true) : 1 ≤ cnt p l := by
  obtain ⟨b, hb, hp⟩ := List.any_eq_true.mp h
  exact cnt_of_mem hb hp

theorem cnt_map_same (g : Auth → Auth) (p : Auth → Bool) (hg : ∀ b, p (g b) = p b) :
    ∀ l : List Auth, cnt p (l.map g) = cnt p l
  | [] => rfl
  | b :: l => by simp [cnt, hg, cnt_map_same g p hg l]

theorem isNone_isFinal (o : Settled) (h : o.isNone = true) : o.isFinal = false := by cases o <;> simp_all [Settled.isNone, Settled.isFinal]

theorem isNone_isRel (o : Settled) (h : o.isNone = true) : o.isRel = false := by cases o <;> simp_all [Settled.isNone, Settled.isRel]

theorem upd_sel {a : Nat} {o : Settled} {b : Auth} (h : sel a b = true) : upd a o b = { b with settled := o } := by
  simp [upd, h]

theorem upd_nsel {a : Nat} {o : Settled} {b : Auth} (h : ¬ sel a b = true) : upd a o b = b := by
  simp [upd, h]

theorem sel_none {a : Nat} {b : Auth} (h : sel a b = true) : b.settled.isNone = true := by
  simp [sel] at h; exact h.2

theorem cnt_none_upd (a : Nat) (o : Settled) (ho : o.isNone = false) :
    ∀ l : List Auth, cnt (·.settled.isNone) (l.map (upd a o)) + cnt (sel a) l = cnt (·.settled.isNone) l
  | [] => rfl
  | b :: l => by
    have ih := cnt_none_upd a o ho l
    simp only [List.map, cnt]
    by_cases hs : sel a b = true
    · rw [upd_sel hs]
      simp only [hs, sel_none hs, ho, ite_true, Bool.false_eq_true, ite_false]
      omega
    · rw [upd_nsel hs]
      simp only [hs, Bool.false_eq_true, ite_false]
      omega

theorem cnt_final_upd (a : Nat) (o : Settled) :
    ∀ l : List Auth, cnt (·.settled.isFinal) (l.map (upd a o))
      = cnt (·.settled.isFinal) l + (if o.isFinal then cnt (sel a) l else 0)
  | [] => by cases o <;> rfl
  | b :: l => by
    have ih := cnt_final_upd a o l
    simp only [List.map, cnt]
    by_cases hs : sel a b = true
    · rw [upd_sel hs]
      have : b.settled.isFinal = false := isNone_isFinal _ (sel_none hs)
      simp only [hs, this, ite_true, Bool.false_eq_true, ite_false] at ih ⊢
      cases hf : o.isFinal
      · simp only [hf, Bool.false_eq_true, ite_false] at ih ⊢; omega
      · simp only [hf, ite_true] at ih ⊢; omega
    · rw [upd_nsel hs]
      simp only [hs, Bool.false_eq_true, ite_false]
      cases hf : o.isFinal
      · simp only [hf, Bool.false_eq_true, ite_false] at ih ⊢; omega
      · simp only [hf, ite_true] at ih ⊢; omega

theorem cnt_final_FINAL (a : Nat) (l : List Auth) :
    cnt (·.settled.isFinal) (l.map (upd a .FINAL)) = cnt (·.settled.isFinal) l + cnt (sel a) l := by
  have := cnt_final_upd a .FINAL l
  have h : Settled.FINAL.isFinal = true := rfl
  simp only [h, ite_true] at this
  exact this

theorem cnt_final_nf (a : Nat) (o : Settled) (ho : o.isFinal = false) (l : List Auth) :
    cnt (·.settled.isFinal) (l.map (upd a o)) = cnt (·.settled.isFinal) l := by
  have := cnt_final_upd a o l
  simp only [ho, Bool.false_eq_true, ite_false, Nat.add_zero] at this
  exact this

theorem cnt_zero {p : Auth → Bool} {l : List Auth} (h : cnt p l = 0) : ∀ b ∈ l, p b = false := by
  intro b hb
  cases hp : p b
  · rfl
  · have := cnt_of_mem hb hp; omega

/-! ## The record invariant of C11 (AU-008, AU-024) -/

/-- At most one unsettled and at most one FINAL authorization; a FINAL one means
the record is spent, an unsettled one that it is not; an unsettled one holds the
record's current nullifier, which an accepted `authorize` used. -/
def RInv (used : List (Nf × Nat)) (r : Rec) : Prop :=
  cnt (·.settled.isNone) r.auths ≤ 1 ∧ cnt (·.settled.isFinal) r.auths ≤ 1
    ∧ (1 ≤ cnt (·.settled.isFinal) r.auths → r.spent = true)
    ∧ (1 ≤ cnt (·.settled.isNone) r.auths → r.spent = false)
    ∧ (∀ b ∈ r.auths, b.settled.isNone = true → b.nf = r.nf ∧ b.nf ∈ used.map Prod.fst)

def Inv (s : St) : Prop := ∀ r ∈ s.records, r.boardFirst = false → RInv s.used r

theorem rinv_mono (used : List (Nf × Nat)) (x : Nf × Nat) (r : Rec) (h : RInv used r) :
    RInv (x :: used) r := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  refine ⟨h1, h2, h3, h4, fun b hb hn => ?_⟩
  obtain ⟨e, m⟩ := h5 b hb hn
  exact ⟨e, by simp [m]⟩

theorem rinv_same (used : List (Nf × Nat)) (g : Auth → Auth)
    (hg : ∀ b, (g b).settled = b.settled ∧ (g b).nf = b.nf) (r : Rec) (h : RInv used r) :
    RInv used { r with auths := r.auths.map g } := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  have e1 := cnt_map_same g (·.settled.isNone) (fun b => by simp [(hg b).1]) r.auths
  have e2 := cnt_map_same g (·.settled.isFinal) (fun b => by simp [(hg b).1]) r.auths
  refine ⟨by simp only [e1]; exact h1, by simp only [e2]; exact h2, fun x => h3 (by simp only [e2] at x; exact x),
    fun x => h4 (by simp only [e1] at x; exact x), fun b hb hn => ?_⟩
  simp only [List.mem_map] at hb
  obtain ⟨b0, hb0, rfl⟩ := hb
  rw [(hg b0).1] at hn
  rw [(hg b0).2]
  exact h5 b0 hb0 hn

theorem rinv_settleIn (used : List (Nf × Nat)) (a : Nat) (o : Settled) (r : Rec) (h : RInv used r) :
    RInv used (settleIn a o r) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  unfold settleIn
  split
  · rename_i hany
    have hsel := cnt_any r.auths hany
    -- after the settlement no authorization of the record is unsettled
    have gen : ∀ o' : Settled, o'.isNone = false →
        cnt (·.settled.isNone) (r.auths.map (upd a o')) = 0 ∧
        ∀ b ∈ r.auths.map (upd a o'), b.settled.isNone = false := by
      intro o' ho'
      have hn := cnt_none_upd a o' ho' r.auths
      have hz : cnt (·.settled.isNone) (r.auths.map (upd a o')) = 0 := by omega
      exact ⟨hz, cnt_zero hz⟩
    cases o with
    | NONE => exact ⟨h1, h2, h3, h4, h5⟩
    | FINAL =>
      obtain ⟨hz, hall⟩ := gen .FINAL rfl
      have hf := cnt_final_FINAL a r.auths
      have hn := cnt_none_upd a .FINAL rfl r.auths
      have hsp : r.spent = false := h4 (by omega)
      have hf0 : cnt (·.settled.isFinal) r.auths = 0 := by
        cases hc : cnt (·.settled.isFinal) r.auths with
        | zero => rfl
        | succ k => have := h3 (by omega); simp [hsp] at this
      refine ⟨?_, ?_, fun _ => rfl, fun x => ?_, fun b hb hb2 => ?_⟩
      · show cnt _ (r.auths.map (upd a .FINAL)) ≤ 1; omega
      · show cnt _ (r.auths.map (upd a .FINAL)) ≤ 1; omega
      · change 1 ≤ cnt _ (r.auths.map (upd a .FINAL)) at x; omega
      · have := hall b hb; simp [hb2] at this
    | VOID =>
      obtain ⟨hz, hall⟩ := gen .VOID rfl
      have hf := cnt_final_nf a .VOID rfl r.auths
      refine ⟨?_, ?_, fun x => ?_, fun x => ?_, fun b hb hb2 => ?_⟩
      · show cnt _ (r.auths.map (upd a .VOID)) ≤ 1; omega
      · show cnt _ (r.auths.map (upd a .VOID)) ≤ 1; omega
      · change 1 ≤ cnt _ (r.auths.map (upd a .VOID)) at x; exact h3 (by omega)
      · change 1 ≤ cnt _ (r.auths.map (upd a .VOID)) at x; omega
      · have := hall b hb; simp [hb2] at this
    | RELEASED =>
      obtain ⟨hz, hall⟩ := gen .RELEASED rfl
      have hf := cnt_final_nf a .RELEASED rfl r.auths
      refine ⟨?_, ?_, fun x => ?_, fun x => ?_, fun b hb hb2 => ?_⟩
      · show cnt _ (r.auths.map (upd a .RELEASED)) ≤ 1; omega
      · show cnt _ (r.auths.map (upd a .RELEASED)) ≤ 1; omega
      · change 1 ≤ cnt _ (r.auths.map (upd a .RELEASED)) at x; exact h3 (by omega)
      · change 1 ≤ cnt _ (r.auths.map (upd a .RELEASED)) at x; omega
      · have := hall b hb; simp [hb2] at this
  · exact ⟨h1, h2, h3, h4, h5⟩

theorem settleIn_bf (a : Nat) (o : Settled) (r : Rec) : (settleIn a o r).boardFirst = r.boardFirst := by
  unfold settleIn; split
  · cases o <;> rfl
  · rfl

theorem settleLeaves_bf : ∀ (ls : List (Nat × Settled)) (r : Rec), (settleLeaves ls r).boardFirst = r.boardFirst
  | [], _ => rfl
  | l :: ls, r => by
    simp only [settleLeaves, List.foldl] at *
    have := settleLeaves_bf ls (settleIn l.1 l.2 r)
    simp only [settleLeaves] at this
    rw [this, settleIn_bf]

theorem rinv_settleLeaves (used : List (Nf × Nat)) :
    ∀ (ls : List (Nat × Settled)) (r : Rec), RInv used r → RInv used (settleLeaves ls r)
  | [], _, h => h
  | l :: ls, r, h => by
    have := rinv_settleLeaves used ls (settleIn l.1 l.2 r) (rinv_settleIn used _ _ r h)
    simpa [settleLeaves, List.foldl] using this

theorem bfIn_direct (t : BfTuple) (r : Rec) (h : r.boardFirst = false) : bfIn t r = r := by
  simp [bfIn, h]

theorem bfIn_bf (t : BfTuple) (r : Rec) : (bfIn t r).boardFirst = r.boardFirst := by
  unfold bfIn; split <;> rfl

theorem bfAll_direct : ∀ (ts : List BfTuple) (r : Rec), r.boardFirst = false → bfAll ts r = r
  | [], _, _ => rfl
  | t :: ts, r, h => by
    have := bfAll_direct ts r h
    simp only [bfAll, List.foldl, bfIn_direct t r h] at *
    exact this

theorem bfAll_bf : ∀ (ts : List BfTuple) (r : Rec), (bfAll ts r).boardFirst = r.boardFirst
  | [], _ => rfl
  | t :: ts, r => by
    have := bfAll_bf ts (bfIn t r)
    simp only [bfAll, List.foldl] at *
    rw [this, bfIn_bf]

theorem inv_map (s : St) (f : Rec → Rec) (used : List (Nf × Nat))
    (hb : ∀ r, (f r).boardFirst = r.boardFirst)
    (hf : ∀ r ∈ s.records, r.boardFirst = false → RInv s.used r → RInv used (f r)) (h : Inv s) :
    ∀ r' ∈ s.records.map f, r'.boardFirst = false → RInv used r' := by
  intro r' hr' hbf
  simp only [List.mem_map] at hr'
  obtain ⟨r, hr, rfl⟩ := hr'
  rw [hb] at hbf
  exact hf r hr hbf (h r hr hbf)

theorem inv_settleAll (s : St) (a : Nat) (o : Settled) (h : Inv s) : Inv (settleAll s a o) :=
  inv_map s (settleIn a o) s.used (settleIn_bf a o) (fun r _ _ hr => rinv_settleIn _ a o r hr) h

theorem inv_afterCarry (s : St) (c : Call) (h : Inv s) : Inv (afterCarry s c) := by
  unfold afterCarry
  split
  · split
    · exact inv_settleAll s _ _ h
    · exact h
  · exact h

theorem cnt_cons_newAuth (p : Auth → Bool) (c : Call) (l : List Auth) :
    cnt p (newAuth c :: l) = (if p (newAuth c) then 1 else 0) + cnt p l := rfl

theorem rinv_addAuth (used : List (Nf × Nat)) (c : Call) (r : Rec) (h : RInv used r)
    (hr : r.rid = c.rid → c.nf = r.nf ∧ r.spent = false) (hu : c.nf ∉ used.map Prod.fst) :
    RInv ((c.nf, c.auth) :: used) (addAuth c r) := by
  unfold addAuth
  split
  · rename_i hrid
    obtain ⟨hnf, hsp⟩ := hr (by simpa using hrid)
    obtain ⟨h1, h2, h3, h4, h5⟩ := h
    have h0 : cnt (·.settled.isNone) r.auths = 0 := by
      cases hc : cnt (·.settled.isNone) r.auths with
      | zero => rfl
      | succ k =>
        obtain ⟨b, hb, hn⟩ := cnt_pos (p := (·.settled.isNone)) (l := r.auths) (by omega)
        obtain ⟨e, m⟩ := h5 b hb hn
        rw [e, ← hnf] at m
        exact absurd m hu
    have hn1 : (newAuth c).settled.isNone = true := rfl
    have hf1 : (newAuth c).settled.isFinal = false := rfl
    refine ⟨?_, ?_, fun x => ?_, fun _ => hsp, fun b hb hn => ?_⟩
    · show cnt _ (newAuth c :: r.auths) ≤ 1
      rw [cnt_cons_newAuth]; simp only [hn1, ite_true]; omega
    · show cnt _ (newAuth c :: r.auths) ≤ 1
      rw [cnt_cons_newAuth]; simp only [hf1, Bool.false_eq_true, ite_false]; omega
    · change 1 ≤ cnt _ (newAuth c :: r.auths) at x
      rw [cnt_cons_newAuth] at x; simp only [hf1, Bool.false_eq_true, ite_false] at x
      exact h3 (by omega)
    · change b ∈ newAuth c :: r.auths at hb
      rcases List.mem_cons.mp hb with rfl | hb
      · exact ⟨hnf, List.mem_cons_self⟩
      · have := cnt_zero h0 b hb; simp [hn] at this
  · exact rinv_mono used _ r h

theorem addAuth_bf (c : Call) (r : Rec) : (addAuth c r).boardFirst = r.boardFirst := by
  unfold addAuth; split <;> rfl

theorem opt_eq_nil (b : Bool) (r : Refusal) : opt b r = [] ↔ b = false := by cases b <;> simp [opt]

/-- The facts that an accepted `authorize` gives about its record. -/
theorem authorize_ok (s : St) (c : Call) (h : authorizeRefusals s c = []) :
    (∀ r ∈ (afterCarry s c).records, r.rid = c.rid → c.nf = r.nf ∧ r.spent = false)
      ∧ c.nf ∉ (afterCarry s c).used.map Prod.fst := by
  simp only [authorizeRefusals, List.append_eq_nil_iff, opt_eq_nil, and_assoc] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  refine ⟨fun r hr hrid => ?_, ?_⟩
  · simp only [Bool.or_eq_false_iff, List.any_eq_false, Bool.not_eq_eq_eq_not, Bool.not_true] at h4
    have hm : r ∈ recOf (afterCarry s c) c.rid := by simp [recOf, hr, hrid]
    have := h4.2 r hm
    simp [statementOk] at this
    exact ⟨this.1, this.2.1⟩
  · simpa using h3

theorem inv_authorize (s : St) (c : Call) (h : Inv s) (hr : authorizeRefusals s c = []) :
    Inv (exec s (.authorize c)).1 := by
  obtain ⟨hrec, hu⟩ := authorize_ok s c hr
  have h1 := inv_afterCarry s c h
  simp only [exec]
  exact inv_map (afterCarry s c) (addAuth c) _ (addAuth_bf c)
    (fun r hm _ hri => rinv_addAuth _ c r hri (hrec r hm) hu) h1

theorem rinv_nil (used : List (Nf × Nat)) (r : Rec) (h : r.auths = []) : RInv used r := by
  have e : ∀ p, cnt p r.auths = 0 := fun p => by rw [h]; rfl
  refine ⟨by rw [e]; omega, by rw [e]; omega, fun x => by rw [e] at x; omega, fun x => by rw [e] at x; omega,
    fun b hb _ => by rw [h] at hb; simp at hb⟩

theorem finalIn_same (a h : Nat) (b : Auth) : (finalIn a h b).settled = b.settled ∧ (finalIn a h b).nf = b.nf := by
  unfold finalIn; split <;> exact ⟨rfl, rfl⟩

theorem revokeIn_same (a : Nat) (b : Auth) : (revokeIn a b).settled = b.settled ∧ (revokeIn a b).nf = b.nf := by
  unfold revokeIn; split <;> exact ⟨rfl, rfl⟩

/-- Every operation keeps the record invariant of C11. -/
theorem apply_inv (s : St) (op : Op) (h : Inv s) : Inv (apply s op).1 := by
  unfold apply
  split
  · rename_i heq
    cases op with
    | charter => exact h
    | record rid cid cmAddr nf tag slrOwn slrG =>
      simp only [exec]
      split
      · exact h
      · intro r hr hbf
        rcases List.mem_append.mp hr with hr | hr
        · exact h r hr hbf
        · simp at hr; subst hr; exact rinv_nil _ _ rfl
    | authorize c => exact inv_authorize s c h heq
    | finalize a fh =>
      exact inv_map s _ s.used (fun _ => rfl) (fun r _ _ hr => rinv_same _ _ (finalIn_same a fh) r hr) h
    | revoke a tag =>
      exact inv_map s _ s.used (fun _ => rfl) (fun r _ _ hr => rinv_same _ _ (revokeIn_same a) r hr) h
    | settleRoot ls =>
      exact inv_map s _ s.used (settleLeaves_bf ls) (fun r _ _ hr => rinv_settleLeaves _ ls r hr) h
    | bfRoot ts =>
      exact inv_map s _ s.used (bfAll_bf ts) (fun r _ hb hr => by rw [bfAll_direct ts r hb]; exact hr) h
    | recover => exact h
    | bfCall c => exact h
    | query a qh => exact h
    | seizure a d => exact h
  · exact h

theorem runOps_preserve (P : St → Prop) (hp : ∀ s op, P s → P (apply s op).1) :
    ∀ (s : St) (ops : List Op), P s → P (runOps s ops).1
  | _, [], h => h
  | s, op :: ops, h => runOps_preserve P hp (apply s op).1 ops (hp s op h)

theorem cnt_eq_filter (p : Auth → Bool) : ∀ l : List Auth, cnt p l = (l.filter p).length
  | [] => rfl
  | b :: l => by
    simp only [cnt, List.filter_cons]
    cases hb : p b <;> simp [cnt_eq_filter p l] <;> omega

/-- C11 (AU-024): in every run, a Midnight-first record has at most one
authorization that settled FINAL, over all the successors of its record states. -/
theorem C11_one_final (p : Params) (ops : List Op) :
    ∀ r ∈ (run (init p) ops).records, r.boardFirst = false →
      (r.auths.filter (·.settled.isFinal)).length ≤ 1 := by
  intro r hr hb
  have := runOps_preserve Inv apply_inv (init p) ops (fun r hr => by simp [init] at hr) r hr hb
  rw [← cnt_eq_filter]
  exact this.2.1

/-! ## AU-008: one accepted `authorize` per nullifier -/

theorem afterCarry_used (s : St) (c : Call) : (afterCarry s c).used = s.used := by
  unfold afterCarry; split
  · split <;> rfl
  · rfl

theorem apply_used_nodup (s : St) (op : Op) (h : (s.used.map Prod.fst).Nodup) :
    ((apply s op).1.used.map Prod.fst).Nodup := by
  unfold apply
  split
  · rename_i heq
    cases op with
    | record => simp only [exec]; split <;> exact h
    | authorize c =>
      have hu := (authorize_ok s c heq).2
      rw [afterCarry_used] at hu
      simp only [exec, List.map_cons, afterCarry_used]
      exact List.nodup_cons.mpr ⟨hu, h⟩
    | _ => exact h
  · exact h

/-- C11 (AU-008): in every run, no nullifier is used by two accepted `authorize` calls. -/
theorem C11_nf_once (p : Params) (ops : List Op) : ((run (init p) ops).used.map Prod.fst).Nodup :=
  runOps_preserve (fun s => (s.used.map Prod.fst).Nodup) apply_used_nodup (init p) ops List.nodup_nil

/-! ## AU-025: released never unspent with a fresh nullifier -/

def RelInv (r : Rec) : Prop := r.auths.any (·.settled.isRel) = true → r.nf.isFresh = false

theorem any_rel_map (g : Auth → Auth) (hg : ∀ b, (g b).settled.isRel = b.settled.isRel) (l : List Auth) :
    (l.map g).any (·.settled.isRel) = l.any (·.settled.isRel) := by
  induction l with
  | nil => rfl
  | cons b l ih => simp only [List.map, List.any_cons, hg, ih]

theorem relInv_settleIn (a : Nat) (o : Settled) (r : Rec) (h : RelInv r) : RelInv (settleIn a o r) := by
  unfold settleIn
  split
  · cases o with
    | NONE => exact h
    | FINAL =>
      intro x
      have e := any_rel_map (upd a .FINAL) (fun b => by
        unfold upd; split
        · rename_i hs
          have := isNone_isRel _ (sel_none hs)
          rw [this]; rfl
        · rfl) r.auths
      dsimp only at x ⊢
      exact h (by rw [e] at x; exact x)
    | VOID => intro _; rfl
    | RELEASED => intro _; rfl
  · exact h

theorem relInv_same (g : Auth → Auth) (hg : ∀ b, (g b).settled = b.settled) (r : Rec) (h : RelInv r) :
    RelInv { r with auths := r.auths.map g } := by
  intro x
  have e := any_rel_map g (fun b => by rw [hg]) r.auths
  exact h (by change (r.auths.map g).any _ = true at x; rw [e] at x; exact x)

theorem relInv_addAuth (c : Call) (r : Rec) (h : RelInv r) : RelInv (addAuth c r) := by
  unfold addAuth; split
  · intro x
    change (newAuth c :: r.auths).any _ = true at x
    simp only [List.any_cons] at x
    exact h (by simpa [newAuth, Settled.isRel] using x)
  · exact h

theorem relInv_bfIn (t : BfTuple) (r : Rec) (h : RelInv r) : RelInv (bfIn t r) := by
  unfold bfIn; split
  · intro x
    simp only [List.any_cons, Settled.isRel, Bool.false_or] at x
    exact h x
  · exact h

theorem relInv_bfAll : ∀ (ts : List BfTuple) (r : Rec), RelInv r → RelInv (bfAll ts r)
  | [], _, h => h
  | t :: ts, r, h => by
    have := relInv_bfAll ts (bfIn t r) (relInv_bfIn t r h)
    simpa [bfAll, List.foldl] using this

theorem relInv_settleLeaves : ∀ (ls : List (Nat × Settled)) (r : Rec), RelInv r → RelInv (settleLeaves ls r)
  | [], _, h => h
  | l :: ls, r, h => by
    have := relInv_settleLeaves ls (settleIn l.1 l.2 r) (relInv_settleIn _ _ r h)
    simpa [settleLeaves, List.foldl] using this

def RelAll (s : St) : Prop := ∀ r ∈ s.records, RelInv r

theorem relAll_map (s : St) (f : Rec → Rec) (hf : ∀ r, RelInv r → RelInv (f r)) (h : RelAll s) :
    ∀ r ∈ s.records.map f, RelInv r := by
  intro r hr
  simp only [List.mem_map] at hr
  obtain ⟨r0, hr0, rfl⟩ := hr
  exact hf r0 (h r0 hr0)

theorem apply_relAll (s : St) (op : Op) (h : RelAll s) : RelAll (apply s op).1 := by
  unfold apply
  split
  · cases op with
    | record rid cid cmAddr nf tag slrOwn slrG =>
      simp only [exec]
      split
      · exact h
      · intro r hr
        rcases List.mem_append.mp hr with hr | hr
        · exact h r hr
        · simp at hr; subst hr; intro x; simp [newRec] at x
    | authorize c =>
      have h1 : RelAll (afterCarry s c) := by
        unfold afterCarry; split
        · split
          · exact relAll_map s _ (fun r hr => relInv_settleIn _ _ r hr) h
          · exact h
        · exact h
      exact relAll_map (afterCarry s c) (addAuth c) (relInv_addAuth c) h1
    | finalize a fh => exact relAll_map s _ (relInv_same _ (fun b => (finalIn_same a fh b).1)) h
    | revoke a tag => exact relAll_map s _ (relInv_same _ (fun b => (revokeIn_same a b).1)) h
    | settleRoot ls => exact relAll_map s _ (relInv_settleLeaves ls) h
    | bfRoot ts => exact relAll_map s _ (relInv_bfAll ts) h
    | charter => exact h
    | recover => exact h
    | bfCall c => exact h
    | query a qh => exact h
    | seizure a d => exact h
  · exact h

/-- C11 (AU-025): in every run, a record with an authorization that settled
RELEASED never holds a fresh nullifier, so it never returns to UNSPENT with a
fresh nullifier. -/
theorem C11_released_never_fresh (p : Params) (ops : List Op) :
    ∀ r ∈ (run (init p) ops).records, r.auths.any (·.settled.isRel) = true → r.nf.isFresh = false :=
  runOps_preserve RelAll apply_relAll (init p) ops (fun r hr => by simp [init] at hr)

/-! ## AU-025, AU-029: a pinned record never returns to UNSPENT -/

def LockInv (r : Rec) : Prop := r.pin.isSome = true → r.rstate ≠ .UNSPENT

theorem lockInv_settleIn (a : Nat) (o : Settled) (r : Rec) (h : LockInv r) : LockInv (settleIn a o r) := by
  unfold settleIn
  split
  · cases o with
    | NONE => exact h
    | FINAL => exact h
    | VOID =>
      intro hp
      simp only [lockedAtAccept] at hp ⊢
      simp [hp]
    | RELEASED => intro _; simp
  · exact h

theorem lockInv_same (g : Auth → Auth) (r : Rec) (h : LockInv r) : LockInv { r with auths := r.auths.map g } := h

theorem lockInv_addAuth (c : Call) (r : Rec) (h : LockInv r) : LockInv (addAuth c r) := by
  unfold addAuth; split
  · intro _; simp
  · exact h

theorem lockInv_bfIn (t : BfTuple) (r : Rec) (h : LockInv r) : LockInv (bfIn t r) := by
  unfold bfIn; split
  · intro _; simp
  · exact h

theorem lockInv_bfAll : ∀ (ts : List BfTuple) (r : Rec), LockInv r → LockInv (bfAll ts r)
  | [], _, h => h
  | t :: ts, r, h => by
    have := lockInv_bfAll ts (bfIn t r) (lockInv_bfIn t r h)
    simpa [bfAll, List.foldl] using this

theorem lockInv_settleLeaves : ∀ (ls : List (Nat × Settled)) (r : Rec), LockInv r → LockInv (settleLeaves ls r)
  | [], _, h => h
  | l :: ls, r, h => by
    have := lockInv_settleLeaves ls (settleIn l.1 l.2 r) (lockInv_settleIn _ _ r h)
    simpa [settleLeaves, List.foldl] using this

def LockAll (s : St) : Prop := ∀ r ∈ s.records, LockInv r

theorem lockAll_map (s : St) (f : Rec → Rec) (hf : ∀ r, LockInv r → LockInv (f r)) (h : LockAll s) :
    ∀ r ∈ s.records.map f, LockInv r := by
  intro r hr
  simp only [List.mem_map] at hr
  obtain ⟨r0, hr0, rfl⟩ := hr
  exact hf r0 (h r0 hr0)

theorem apply_lockAll (s : St) (op : Op) (h : LockAll s) : LockAll (apply s op).1 := by
  unfold apply
  split
  · cases op with
    | record rid cid cmAddr nf tag slrOwn slrG =>
      simp only [exec]
      split
      · exact h
      · intro r hr
        rcases List.mem_append.mp hr with hr | hr
        · exact h r hr
        · simp at hr; subst hr; intro x; simp [newRec] at x
    | authorize c =>
      have h1 : LockAll (afterCarry s c) := by
        unfold afterCarry; split
        · split
          · exact lockAll_map s _ (fun r hr => lockInv_settleIn _ _ r hr) h
          · exact h
        · exact h
      exact lockAll_map (afterCarry s c) (addAuth c) (lockInv_addAuth c) h1
    | finalize a fh => exact lockAll_map s _ (lockInv_same _) h
    | revoke a tag => exact lockAll_map s _ (lockInv_same _) h
    | settleRoot ls => exact lockAll_map s _ (lockInv_settleLeaves ls) h
    | bfRoot ts => exact lockAll_map s _ (lockInv_bfAll ts) h
    | charter => exact h
    | recover => exact h
    | bfCall c => exact h
    | query a qh => exact h
    | seizure a d => exact h
  · exact h

/-- C11 (AU-025, AU-029, DECISIONS 60): in every run, a record that holds a pin
(it settled RELEASED, and every later successor that is not the change record of
a FINAL settlement) is never UNSPENT: a VOID settlement of a re-post keeps it
LOCKED to the same pin, so a later authorization spends only that pin (AU-009). -/
theorem C11_pinned_never_unspent (p : Params) (ops : List Op) :
    ∀ r ∈ (run (init p) ops).records, r.pin.isSome = true → r.rstate ≠ .UNSPENT :=
  runOps_preserve LockAll apply_lockAll (init p) ops (fun r hr => by simp [init] at hr)

/-! ## AU-010: in force only after finality -/

def NoFinal (x : Nat) (s : St) : Prop := ∀ r ∈ s.records, ∀ b ∈ r.auths, b.auth = x → b.finalHeight = none

def FhKeep (x : Nat) (f : Rec → Rec) : Prop :=
  ∀ r, (∀ b ∈ r.auths, b.auth = x → b.finalHeight = none) → ∀ b ∈ (f r).auths, b.auth = x → b.finalHeight = none

theorem noFinal_map (x : Nat) (s : St) (f : Rec → Rec) (hf : FhKeep x f) (h : NoFinal x s) :
    ∀ r ∈ s.records.map f, ∀ b ∈ r.auths, b.auth = x → b.finalHeight = none := by
  intro r hr
  simp only [List.mem_map] at hr
  obtain ⟨r0, hr0, rfl⟩ := hr
  exact hf r0 (h r0 hr0)

theorem fhKeep_auths (x : Nat) (g : Auth → Auth) (hg : ∀ b, (g b).auth = b.auth ∧ (b.auth = x → (g b).finalHeight = b.finalHeight)) :
    FhKeep x (fun r => { r with auths := r.auths.map g }) := by
  intro r h b hb hx
  change b ∈ r.auths.map g at hb
  simp only [List.mem_map] at hb
  obtain ⟨b0, hb0, rfl⟩ := hb
  rw [(hg b0).1] at hx
  rw [(hg b0).2 hx]
  exact h b0 hb0 hx

theorem fhKeep_settleIn (x a : Nat) (o : Settled) : FhKeep x (settleIn a o) := by
  intro r h b hb hx
  unfold settleIn at hb
  split at hb
  · have key : ∀ b ∈ r.auths.map (upd a o), b.auth = x → b.finalHeight = none := by
      intro b hb hx
      simp only [List.mem_map] at hb
      obtain ⟨b0, hb0, rfl⟩ := hb
      unfold upd at hx ⊢
      split at hx <;> simp_all
    cases o <;> first | exact h b hb hx | exact key b hb hx
  · exact h b hb hx

theorem fhKeep_settleLeaves (x : Nat) : ∀ ls : List (Nat × Settled), FhKeep x (settleLeaves ls)
  | [] => fun _ h => h
  | l :: ls => fun r h => by
    have := fhKeep_settleLeaves x ls (settleIn l.1 l.2 r) (fhKeep_settleIn x _ _ r h)
    simpa [settleLeaves, List.foldl] using this

theorem fhKeep_bfIn (x : Nat) (t : BfTuple) : FhKeep x (bfIn t) := by
  intro r h b hb hx
  unfold bfIn at hb
  split at hb
  · simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · rfl
    · exact h b hb hx
  · exact h b hb hx

theorem fhKeep_bfAll (x : Nat) : ∀ ts : List BfTuple, FhKeep x (bfAll ts)
  | [] => fun _ h => h
  | t :: ts => fun r h => by
    have := fhKeep_bfAll x ts (bfIn t r) (fhKeep_bfIn x t r h)
    simpa [bfAll, List.foldl] using this

theorem fhKeep_addAuth (x : Nat) (c : Call) : FhKeep x (addAuth c) := by
  intro r h b hb hx
  unfold addAuth at hb
  split at hb
  · simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · rfl
    · exact h b hb hx
  · exact h b hb hx

theorem apply_noFinal (x : Nat) (s : St) (op : Op) (hop : ∀ fh, op ≠ .finalize x fh) (h : NoFinal x s) :
    NoFinal x (apply s op).1 := by
  unfold apply
  split
  · cases op with
    | record rid cid cmAddr nf tag slrOwn slrG =>
      simp only [exec]
      split
      · exact h
      · intro r hr
        rcases List.mem_append.mp hr with hr | hr
        · exact h r hr
        · simp at hr; subst hr; intro b hb; simp [newRec] at hb
    | authorize c =>
      have h1 : NoFinal x (afterCarry s c) := by
        unfold afterCarry; split
        · split
          · exact noFinal_map x s _ (fhKeep_settleIn x _ _) h
          · exact h
        · exact h
      exact noFinal_map x (afterCarry s c) _ (fhKeep_addAuth x c) h1
    | finalize a fh =>
      have ha : a ≠ x := fun e => hop fh (by rw [e])
      exact noFinal_map x s _ (fhKeep_auths x (finalIn a fh) (fun b => by
        unfold finalIn; split
        · rename_i hc; simp at hc; exact ⟨rfl, fun e => absurd (hc.1.symm.trans e) (Ne.symm ha ∘ Eq.symm)⟩
        · exact ⟨rfl, fun _ => rfl⟩)) h
    | revoke a tag => exact noFinal_map x s _ (fhKeep_auths x (revokeIn a) (fun b => by
        unfold revokeIn; split <;> exact ⟨rfl, fun _ => rfl⟩)) h
    | settleRoot ls => exact noFinal_map x s _ (fhKeep_settleLeaves x ls) h
    | bfRoot ts => exact noFinal_map x s _ (fhKeep_bfAll x ts) h
    | charter => exact h
    | recover => exact h
    | bfCall c => exact h
    | query a qh => exact h
    | seizure a d => exact h
  · exact h

theorem runOps_noFinal (x : Nat) :
    ∀ (s : St) (ops : List Op), (∀ op ∈ ops, ∀ fh, op ≠ .finalize x fh) → NoFinal x s → NoFinal x (runOps s ops).1
  | _, [], _, h => h
  | s, op :: ops, hops, h =>
    runOps_noFinal x (apply s op).1 ops (fun o ho => hops o (by simp [ho]))
      (apply_noFinal x s op (hops op (by simp)) h)

/-- C6 (AU-010): an authorization whose `authorize` transaction no `finalize`
made final is in force at no Midnight height, inclusion alone included. -/
theorem C6_no_force_without_finalize (p : Params) (ops : List Op) (x mh : Nat)
    (hops : ∀ op ∈ ops, ∀ fh, op ≠ .finalize x fh) :
    inForceMidnight (run (init p) ops) x mh = false := by
  have h := runOps_noFinal x (init p) ops hops (fun r hr => by simp [init] at hr)
  simp only [inForceMidnight, allAuths, List.any_eq_false, List.mem_flatMap]
  intro b ⟨r, hr, hb⟩ hx
  simp only [Bool.and_eq_true, beq_iff_eq] at hx
  have := h r hr b hb hx.1
  simp [finalAt, this] at hx

/-! ## AU-015, AU-016: one in-force board-first call per nullifier -/

def NInv (n : Node) : Prop :=
  (∀ y ∈ n.inForce, y.2 ∈ n.pending ∨ y.2 ∈ n.landed) ∧ (n.inForce.map Prod.snd).Nodup

theorem afterCarry_node (s : St) (c : Call) : (afterCarry s c).node = s.node := by
  unfold afterCarry; split
  · split <;> rfl
  · rfl

theorem apply_nInv (s : St) (op : Op) (h : NInv s.node) : NInv (apply s op).1.node := by
  unfold apply
  split
  · rename_i heq
    cases op with
    | record => simp only [exec]; split <;> exact h
    | authorize c => simp only [exec, afterCarry_node]; exact h
    | bfCall c =>
      simp only [opRefusals, List.append_eq_nil_iff, opt_eq_nil] at heq
      obtain ⟨h1, h2⟩ := heq
      simp only [Bool.not_eq_false'] at h1
      simp only [h1, Bool.true_and] at h2
      have hl : s.node.landed.contains c.nf = false := by
        simp only [bfChecks, Bool.and_eq_true] at h1
        simpa using h1.1.2
      obtain ⟨hm, hnd⟩ := h
      refine ⟨fun y hy => ?_, ?_⟩
      · simp only [exec, List.mem_cons] at hy ⊢
        rcases hy with rfl | hy
        · exact Or.inl (Or.inl rfl)
        · rcases hm y hy with e | e
          · exact Or.inl (Or.inr e)
          · exact Or.inr e
      · simp only [exec, List.map_cons]
        refine List.nodup_cons.mpr ⟨fun hin => ?_, hnd⟩
        simp only [List.mem_map] at hin
        obtain ⟨y, hy, e⟩ := hin
        rcases hm y hy with e2 | e2
        · rw [e] at e2; simp [e2] at h2
        · rw [e] at e2; simp [e2] at hl
    | bfRoot ts =>
      obtain ⟨hm, hnd⟩ := h
      refine ⟨fun y hy => ?_, hnd⟩
      simp only [exec, List.mem_filter, List.mem_append] at hy ⊢
      rcases hm y hy with e | e
      · by_cases hin : (ts.map (·.nf)).contains y.2 = true
        · exact Or.inr (Or.inr (by simpa using hin))
        · exact Or.inl ⟨e, by simpa using hin⟩
      · exact Or.inr (Or.inl e)
    | _ => exact h
  · exact h

/-- C11 and C6 (AU-015, AU-016): in every run the node holds at most one
in-force board-first call per nullifier. -/
theorem C11_bf_first_only (p : Params) (ops : List Op) :
    ((run (init p) ops).node.inForce.map Prod.snd).Nodup :=
  (runOps_preserve (fun s => NInv s.node) apply_nInv (init p) ops
    ⟨fun y hy => by simp [init] at hy, List.nodup_nil⟩).2

end SplitAuthorization
