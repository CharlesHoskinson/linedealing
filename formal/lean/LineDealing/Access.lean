import LineDealing.Basic

/-!
# Split-line dealing: access structures

`design/enhancement/DESIGN.md` §2.4, §3.1 step 1 and §3.8, DECISIONS 22. A charter's access
structure `Γ` is a formula of three gates over leaves.

- `and2 l r`: additive, the gate's secret is the sum of the children's secrets.
- `thr ids k child`: a `k`-of-`#ids` group; the children with ids `i ∈ ids` hold `p(i)` for a
  polynomial `p` of degree below `k` whose constant term is the gate's secret (Shamir).
- `or2 l r`: escrow, each child holds the whole gate secret.

Gates nest. `Dealt γ s x` says that the leaf secrets `x` deal the secret `s` through `γ`.
`Reach γ w A` says that the signing set `A` reaches the root of `γ` with leaf weights `w`: every
threshold gate on a path names `k` children and contributes their Lagrange coefficients, every OR
gate names one child. `Covers C γ` says that the set of leaves `C` satisfies `γ`, so a coalition
outside `Γ` is a set `C` with `¬ Covers C γ`.

The main theorems are the weighted sum `x = Σ_a λ_a x_a` for every signing set
(`D22_access_weighted_sum`) and secrecy in algebraic form (`C17_access_secrecy`): the leaf
secrets of a coalition outside `Γ` are consistent with every value of the root secret. Secrecy is
a statement about scalars; the public points `X_a = x_a • g` fix the secret, and hiding it from
them needs the discrete-log assumption, which is not formalized.
-/

open Polynomial Finset

set_option linter.unusedSectionVars false

namespace LineDealing.Split

variable {q : ℕ} [Fact q.Prime] {ι : Type*}

/-- An access formula with leaves in `ι` and member ids in `ZMod q`. -/
inductive Gate (q : ℕ) (ι : Type*) where
  | leaf (a : ι)
  | and2 (l r : Gate q ι)
  | or2 (l r : Gate q ι)
  | thr (ids : Finset (ZMod q)) (k : ℕ) (child : ZMod q → Gate q ι)

namespace Gate

/-- `Dealt γ s x`: the leaf secrets `x` deal the secret `s` through the formula `γ`. -/
inductive Dealt : Gate q ι → ZMod q → (ι → ZMod q) → Prop
  | leaf {a : ι} {s : ZMod q} {x : ι → ZMod q} : x a = s → Dealt (leaf a) s x
  | and2 {l r : Gate q ι} {s₁ s₂ : ZMod q} {x : ι → ZMod q} :
      Dealt l s₁ x → Dealt r s₂ x → Dealt (and2 l r) (s₁ + s₂) x
  | or2 {l r : Gate q ι} {s : ZMod q} {x : ι → ZMod q} :
      Dealt l s x → Dealt r s x → Dealt (or2 l r) s x
  | thr {ids : Finset (ZMod q)} {k : ℕ} {child : ZMod q → Gate q ι} {x : ι → ZMod q}
      (p : (ZMod q)[X]) : p.degree < k → (∀ i ∈ ids, Dealt (child i) (p.eval i) x) →
      Dealt (thr ids k child) (p.eval 0) x

/-- `Reach γ w A`: the signing set `A` reaches the root of `γ` with leaf weights `w`. -/
inductive Reach : Gate q ι → (ι →₀ ZMod q) → Set ι → Prop
  | leaf (a : ι) : Reach (leaf a) (Finsupp.single a 1) {a}
  | and2 {l r : Gate q ι} {w₁ w₂ : ι →₀ ZMod q} {A₁ A₂ : Set ι} :
      Reach l w₁ A₁ → Reach r w₂ A₂ → Reach (and2 l r) (w₁ + w₂) (A₁ ∪ A₂)
  | orL {l r : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι} : Reach l w A → Reach (or2 l r) w A
  | orR {l r : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι} : Reach r w A → Reach (or2 l r) w A
  | thr {ids : Finset (ZMod q)} {k : ℕ} {child : ZMod q → Gate q ι} (T : Finset (ZMod q))
      (w : ZMod q → ι →₀ ZMod q) (A : ZMod q → Set ι) : T ⊆ ids → #T = k →
      (∀ i ∈ T, Reach (child i) (w i) (A i)) →
      Reach (thr ids k child) (∑ i ∈ T, lam T i • w i) (⋃ i ∈ T, A i)

/-- `Covers C γ`: the leaves in `C` satisfy the formula `γ`. -/
inductive Covers (C : Set ι) : Gate q ι → Prop
  | leaf {a : ι} : a ∈ C → Covers C (leaf a)
  | and2 {l r : Gate q ι} : Covers C l → Covers C r → Covers C (and2 l r)
  | orL {l r : Gate q ι} : Covers C l → Covers C (or2 l r)
  | orR {l r : Gate q ι} : Covers C r → Covers C (or2 l r)
  | thr {ids : Finset (ZMod q)} {k : ℕ} {child : ZMod q → Gate q ι} (T : Finset (ZMod q)) :
      T ⊆ ids → k ≤ #T → (∀ i ∈ T, Covers C (child i)) → Covers C (thr ids k child)

/-- The leaves of a formula. -/
def leaves : Gate q ι → Set ι
  | leaf a => {a}
  | and2 l r => leaves l ∪ leaves r
  | or2 l r => leaves l ∪ leaves r
  | thr ids _ child => ⋃ i ∈ ids, leaves (child i)

/-- Well-formed: the children of every gate have disjoint leaves, and no member id is `0`
(the point where the group's secret sits). -/
def WF : Gate q ι → Prop
  | leaf _ => True
  | and2 l r => Disjoint (leaves l) (leaves r) ∧ WF l ∧ WF r
  | or2 l r => Disjoint (leaves l) (leaves r) ∧ WF l ∧ WF r
  | thr ids _ child => (0 : ZMod q) ∉ ids ∧
      (∀ i ∈ ids, ∀ j ∈ ids, i ≠ j → Disjoint (leaves (child i)) (leaves (child j))) ∧
      ∀ i ∈ ids, WF (child i)

theorem Covers.mono {C C' : Set ι} (h : C ⊆ C') {γ : Gate q ι} (hc : Covers C γ) :
    Covers C' γ := by
  induction hc with
  | leaf ha => exact .leaf (h ha)
  | and2 _ _ ihl ihr => exact .and2 ihl ihr
  | orL _ ih => exact .orL ih
  | orR _ ih => exact .orR ih
  | thr T hT hk _ ih => exact .thr T hT hk ih

/-- A dealing depends only on the secrets of the formula's own leaves. -/
theorem Dealt.congr {γ : Gate q ι} {s : ZMod q} {x : ι → ZMod q} (h : Dealt γ s x)
    {x' : ι → ZMod q} (hx : ∀ a ∈ leaves γ, x' a = x a) : Dealt γ s x' := by
  induction h with
  | leaf ha => exact .leaf ((hx _ rfl).trans ha)
  | and2 _ _ ihl ihr =>
      exact .and2 (ihl fun a ha ↦ hx a (Or.inl ha)) (ihr fun a ha ↦ hx a (Or.inr ha))
  | or2 _ _ ihl ihr =>
      exact .or2 (ihl fun a ha ↦ hx a (Or.inl ha)) (ihr fun a ha ↦ hx a (Or.inr ha))
  | thr p hp _ ih =>
      exact .thr p hp fun i hi ↦ ih i hi fun a ha ↦ hx a (Set.mem_biUnion hi ha)

end Gate

open Gate

/-! ## The three gates alone -/

/-- **D22, AND gate.** The gate's secret is the sum of the children's secrets, and the signing set
`{l, r}` gives it with weight one each. -/
theorem D22_and_gate {a b : ι} {s : ZMod q} {x : ι → ZMod q}
    (h : Dealt (and2 (leaf a) (leaf b) : Gate q ι) s x) : x a + x b = s := by
  cases h with
  | and2 hl hr =>
    cases hl with
    | leaf h1 => cases hr with
      | leaf h2 => rw [h1, h2]

/-- **D22, threshold gate.** Any `k` members of a `k`-of-`m` group combine their shares with the
Lagrange coefficients of their own subset to the group's secret. -/
theorem D22_threshold_gate (T : Finset (ZMod q)) {k : ℕ} (hT : #T = k) {p : (ZMod q)[X]}
    (hp : p.degree < k) : ∑ i ∈ T, lam T i * p.eval i = p.eval 0 :=
  sum_lam_mul_eval T (hT ▸ hp)

/-- **D22, OR gate by escrow.** Each child holds the whole secret, so either child alone gives
it. -/
theorem D22_or_gate {a b : ι} {s : ZMod q} {x : ι → ZMod q}
    (h : Dealt (or2 (leaf a) (leaf b) : Gate q ι) s x) : x a = s ∧ x b = s := by
  cases h with
  | or2 hl hr =>
    cases hl with
    | leaf h1 => cases hr with
      | leaf h2 => exact ⟨h1, h2⟩

/-! ## Nested gates: correctness -/

/-- **D22 and §2.4, the weighted sum.** For every formula, every dealing and every signing set,
the weighted leaf secrets sum to the root secret: `Σ_a λ_a x_a = s`, where `λ_a` is the product
of the Lagrange coefficients along the leaf's path. -/
theorem D22_access_weighted_sum {γ : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι}
    (hr : Reach γ w A) {s : ZMod q} {x : ι → ZMod q} (hd : Dealt γ s x) :
    Finsupp.linearCombination (ZMod q) x w = s := by
  induction hr generalizing s with
  | leaf a =>
      cases hd with
      | leaf ha => simp [Finsupp.linearCombination_single, ha]
  | and2 _ _ ihl ihr =>
      cases hd with
      | and2 hl hr => rw [map_add, ihl hl, ihr hr]
  | orL _ ih =>
      cases hd with
      | or2 hl _ => exact ih hl
  | orR _ ih =>
      cases hd with
      | or2 _ hr => exact ih hr
  | thr T w A hT hk _ ih =>
      cases hd with
      | thr p hp hch =>
          rw [map_sum]
          simp only [map_smul, smul_eq_mul]
          rw [sum_congr rfl fun i hi ↦ by rw [ih i hi (hch i (hT hi))]]
          exact sum_lam_mul_eval T (hk ▸ hp)

/-- **D22, the weighted sum in the exponent.** With leaf points `X_a = x_a • g`, the weighted
points sum to `s • g`. -/
theorem D22_access_weighted_point {G : Type*} [AddCommGroup G] [Module (ZMod q) G]
    {γ : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι} (hr : Reach γ w A) {s : ZMod q}
    {x : ι → ZMod q} (hd : Dealt γ s x) (g : G) :
    Finsupp.linearCombination (ZMod q) (fun a ↦ x a • g) w = s • g := by
  rw [← D22_access_weighted_sum hr hd, Finsupp.linearCombination_apply,
    Finsupp.linearCombination_apply, Finsupp.sum, Finsupp.sum, sum_smul]
  exact sum_congr rfl fun a _ ↦ by rw [smul_smul, smul_eq_mul]

/-- **D21 and D22, the address key under any signing set.** The address key
`x = x_f + tw + s`, with `s` the actors' secret dealt through `Γ`, equals
`x_f + tw + Σ_{a ∈ S} λ_a x_a` for every signing set `S` (§2.4). -/
theorem D22_address_key {γ : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι} (hr : Reach γ w A)
    {s : ZMod q} {x : ι → ZMod q} (hd : Dealt γ s x) (xf tw : ZMod q) :
    xf + tw + Finsupp.linearCombination (ZMod q) x w = xf + tw + s := by
  rw [D22_access_weighted_sum hr hd]

/-- **D22, a signing set satisfies the formula.** -/
theorem D22_reach_covers {γ : Gate q ι} {w : ι →₀ ZMod q} {A : Set ι} (hr : Reach γ w A) :
    Covers A γ := by
  induction hr with
  | leaf a => exact .leaf rfl
  | and2 _ _ ihl ihr =>
      exact .and2 (ihl.mono Set.subset_union_left) (ihr.mono Set.subset_union_right)
  | orL _ ih => exact .orL ih
  | orR _ ih => exact .orR ih
  | thr T w A hT hk _ ih =>
      exact .thr T hT hk.ge fun i hi ↦ (ih i hi).mono (Set.subset_biUnion_of_mem hi)

/-- **D22, a set that satisfies the formula contains a signing set.** -/
theorem D22_covers_reach {C : Set ι} {γ : Gate q ι} (hc : Covers C γ) :
    ∃ w A, A ⊆ C ∧ Reach γ w A := by
  induction hc with
  | leaf ha => exact ⟨_, _, Set.singleton_subset_iff.mpr ha, .leaf _⟩
  | and2 _ _ ihl ihr =>
      obtain ⟨w₁, A₁, h₁, r₁⟩ := ihl
      obtain ⟨w₂, A₂, h₂, r₂⟩ := ihr
      exact ⟨_, _, Set.union_subset h₁ h₂, .and2 r₁ r₂⟩
  | orL _ ih =>
      obtain ⟨w, A, h, r⟩ := ih
      exact ⟨w, A, h, .orL r⟩
  | orR _ ih =>
      obtain ⟨w, A, h, r⟩ := ih
      exact ⟨w, A, h, .orR r⟩
  | @thr ids k child T hT hk _ ih =>
      obtain ⟨T', hT', hcard⟩ := exists_subset_card_eq hk
      have : ∀ i, ∃ (w : ι →₀ ZMod q) (A : Set ι), i ∈ T' → A ⊆ C ∧ Reach (child i) w A := by
        intro i
        by_cases hi : i ∈ T'
        · obtain ⟨w, A, h, r⟩ := ih i (hT' hi)
          exact ⟨w, A, fun _ ↦ ⟨h, r⟩⟩
        · exact ⟨0, ∅, fun h ↦ (hi h).elim⟩
      choose w A hwA using this
      exact ⟨_, _, Set.iUnion₂_subset fun i hi ↦ (hwA i hi).1,
        .thr T' w A (hT'.trans hT) hcard fun i hi ↦ (hwA i hi).2⟩

/-! ## Secrecy in algebraic form -/

/-- The polynomial that is `1` at `0` and `0` on `T`, of degree `#T`, for `0 ∉ T`. -/
noncomputable def zeroBasis (T : Finset (ZMod q)) : (ZMod q)[X] :=
  Lagrange.basis (insert 0 T) id 0

theorem zeroBasis_eval_zero (T : Finset (ZMod q)) : (zeroBasis T).eval 0 = 1 :=
  Lagrange.eval_basis_self (v := id) Function.injective_id.injOn (mem_insert_self 0 T)

theorem zeroBasis_eval_of_mem {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T) {i : ZMod q}
    (hi : i ∈ T) : (zeroBasis T).eval i = 0 :=
  Lagrange.eval_basis_of_ne (v := id) (fun h ↦ h0 (h ▸ hi)) (mem_insert_of_mem hi)

theorem zeroBasis_degree {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T) :
    (zeroBasis T).degree = #T := by
  rw [zeroBasis, Lagrange.degree_basis (v := id) Function.injective_id.injOn
    (mem_insert_self 0 T), card_insert_of_notMem h0]
  simp

/-- The share polynomial moved to the constant term `s'` without changing its values on `T`. -/
noncomputable def shift (T : Finset (ZMod q)) (p : (ZMod q)[X]) (s' : ZMod q) : (ZMod q)[X] :=
  p + C (s' - p.eval 0) * zeroBasis T

theorem shift_eval_zero (T : Finset (ZMod q)) (p : (ZMod q)[X]) (s' : ZMod q) :
    (shift T p s').eval 0 = s' := by
  simp [shift, zeroBasis_eval_zero]

theorem shift_eval_of_mem {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T) (p : (ZMod q)[X])
    (s' : ZMod q) {i : ZMod q} (hi : i ∈ T) : (shift T p s').eval i = p.eval i := by
  simp [shift, zeroBasis_eval_of_mem h0 hi]

theorem shift_degree_lt {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T) {k : ℕ} (hT : #T < k)
    {p : (ZMod q)[X]} (hp : p.degree < k) (s' : ZMod q) : (shift T p s').degree < k := by
  refine lt_of_le_of_lt (degree_add_le _ _) (max_lt hp ?_)
  refine lt_of_le_of_lt (degree_mul_le _ _) ?_
  refine lt_of_le_of_lt (add_le_add degree_C_le (le_of_eq (zeroBasis_degree h0))) ?_
  rw [zero_add]
  exact_mod_cast hT

/-- **C17, threshold secrecy.** Fewer than `k` shares of a `k`-of-`m` group, at nonzero ids, are
consistent with every value of the group's secret: for every `s'` there is a polynomial of degree
below `k` with the same shares and constant term `s'`. -/
theorem C17_threshold_secrecy {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T) {k : ℕ}
    (hT : #T < k) {p : (ZMod q)[X]} (hp : p.degree < k) (s' : ZMod q) :
    ∃ p' : (ZMod q)[X], p'.degree < k ∧ p'.eval 0 = s' ∧ ∀ i ∈ T, p'.eval i = p.eval i :=
  ⟨shift T p s', shift_degree_lt h0 hT hp s', shift_eval_zero T p s',
    fun _ hi ↦ shift_eval_of_mem h0 p s' hi⟩

/-- The share polynomials of degree below `k` with the shares `y` on `T` and constant term `s`. -/
def Completions (T : Finset (ZMod q)) (k : ℕ) (y : ZMod q → ZMod q) (s : ZMod q) :
    Set (ZMod q)[X] :=
  {p | p.degree < k ∧ p.eval 0 = s ∧ ∀ i ∈ T, p.eval i = y i}

/-- **C17, threshold secrecy in counting form.** For fewer than `k` shares at nonzero ids, the
completions with constant term `s` and those with constant term `s'` are in bijection, by adding
`(s' − s)` times the polynomial that is `1` at `0` and `0` on `T`. Under a uniform choice of the
dealt polynomial the shares on `T` therefore have the same law for every secret. -/
noncomputable def C17_threshold_completions_equiv {T : Finset (ZMod q)} (h0 : (0 : ZMod q) ∉ T)
    {k : ℕ} (hT : #T < k) (y : ZMod q → ZMod q) (s s' : ZMod q) :
    Completions T k y s ≃ Completions T k y s' where
  toFun p := ⟨p.1 + C (s' - s) * zeroBasis T, by
    obtain ⟨hp, hp0, hpT⟩ := p.2
    have := shift_degree_lt h0 hT hp s'
    refine ⟨?_, ?_, fun i hi ↦ ?_⟩
    · simpa [shift, hp0] using this
    · simp [zeroBasis_eval_zero, hp0]
    · simp [zeroBasis_eval_of_mem h0 hi, hpT i hi]⟩
  invFun p := ⟨p.1 + C (s - s') * zeroBasis T, by
    obtain ⟨hp, hp0, hpT⟩ := p.2
    have := shift_degree_lt h0 hT hp s
    refine ⟨?_, ?_, fun i hi ↦ ?_⟩
    · simpa [shift, hp0] using this
    · simp [zeroBasis_eval_zero, hp0]
    · simp [zeroBasis_eval_of_mem h0 hi, hpT i hi]⟩
  left_inv p := by
    apply Subtype.ext
    simp only
    rw [add_assoc, ← add_mul, ← C_add]
    simp
  right_inv p := by
    apply Subtype.ext
    simp only
    rw [add_assoc, ← add_mul, ← C_add]
    simp

open Classical in
/-- **C17, secrecy of a nested access structure in algebraic form.** Let `γ` be well formed. If
the leaves in `C` do not satisfy `γ`, then for every dealing of `s` and every `s'` there is a
dealing of `s'` that gives every leaf in `C` the same secret. The leaf secrets of a coalition
outside `Γ` are therefore consistent with every value of the root secret. -/
theorem C17_access_secrecy {C : Set ι} {γ : Gate q ι} (hwf : γ.WF) (hc : ¬ Covers C γ)
    {s : ZMod q} {x : ι → ZMod q} (hd : Dealt γ s x) (s' : ZMod q) :
    ∃ x' : ι → ZMod q, (∀ a ∈ C, x' a = x a) ∧ Dealt γ s' x' := by
  induction γ generalizing s x s' with
  | leaf a =>
      have ha : a ∉ C := fun ha ↦ hc (.leaf ha)
      refine ⟨Function.update x a s', fun b hb ↦ ?_, .leaf (Function.update_self _ _ _)⟩
      exact Function.update_of_ne (by rintro rfl; exact ha hb) _ _
  | and2 l r ihl ihr =>
      obtain ⟨hdis, hwl, hwr⟩ := hwf
      cases hd with
      | @and2 _ _ s₁ s₂ _ hl hr =>
        by_cases hcl : Covers C l
        · have hcr : ¬ Covers C r := fun h ↦ hc (.and2 hcl h)
          obtain ⟨xr, hxr, hdr⟩ := ihr hwr hcr hr (s' - s₁)
          let x' : ι → ZMod q := fun a ↦ if a ∈ leaves r then xr a else x a
          have h1 : Dealt l s₁ x' := hl.congr fun a ha ↦ ite_eq_right (Set.disjoint_left.mp hdis ha)
          have h2 : Dealt r (s' - s₁) x' := hdr.congr fun a ha ↦ ite_eq_left ha
          refine ⟨x', fun a ha ↦ ?_, ?_⟩
          · by_cases h : a ∈ leaves r
            · exact (ite_eq_left h).trans (hxr a ha)
            · exact ite_eq_right h
          · have := Dealt.and2 h1 h2
            rwa [add_sub_cancel] at this
        · obtain ⟨xl, hxl, hdl⟩ := ihl hwl hcl hl (s' - s₂)
          let x' : ι → ZMod q := fun a ↦ if a ∈ leaves l then xl a else x a
          have h1 : Dealt l (s' - s₂) x' := hdl.congr fun a ha ↦ ite_eq_left ha
          have h2 : Dealt r s₂ x' := hr.congr fun a ha ↦ ite_eq_right (Set.disjoint_right.mp hdis ha)
          refine ⟨x', fun a ha ↦ ?_, ?_⟩
          · by_cases h : a ∈ leaves l
            · exact (ite_eq_left h).trans (hxl a ha)
            · exact ite_eq_right h
          · have := Dealt.and2 h1 h2
            rwa [sub_add_cancel] at this
  | or2 l r ihl ihr =>
      obtain ⟨hdis, hwl, hwr⟩ := hwf
      cases hd with
      | or2 hl hr =>
        obtain ⟨xl, hxl, hdl⟩ := ihl hwl (fun h ↦ hc (.orL h)) hl s'
        obtain ⟨xr, hxr, hdr⟩ := ihr hwr (fun h ↦ hc (.orR h)) hr s'
        let x' : ι → ZMod q := fun a ↦ if a ∈ leaves l then xl a else xr a
        have h1 : Dealt l s' x' := hdl.congr fun a ha ↦ ite_eq_left ha
        have h2 : Dealt r s' x' := hdr.congr fun a ha ↦ ite_eq_right (Set.disjoint_right.mp hdis ha)
        refine ⟨x', fun a ha ↦ ?_, .or2 h1 h2⟩
        by_cases h : a ∈ leaves l
        · exact (ite_eq_left h).trans (hxl a ha)
        · exact (ite_eq_right h).trans (hxr a ha)
  | thr ids k child ih =>
      obtain ⟨h0, hdis, hwc⟩ := hwf
      cases hd with
      | thr p hp hch =>
        set T0 := ids.filter fun i ↦ Covers C (child i) with hT0
        have h0T : (0 : ZMod q) ∉ T0 := fun h ↦ h0 (mem_filter.mp h).1
        have hT0k : #T0 < k := by
          by_contra hk
          exact hc (.thr T0 (filter_subset _ _) (not_lt.mp hk) fun i hi ↦ (mem_filter.mp hi).2)
        set p' := shift T0 p s'
        have hp' : p'.degree < k := shift_degree_lt h0T hT0k hp s'
        have hrest : ∀ i, ∃ xi : ι → ZMod q, i ∈ ids → i ∉ T0 →
            (∀ a ∈ C, xi a = x a) ∧ Dealt (child i) (p'.eval i) xi := by
          intro i
          by_cases hi : i ∈ ids ∧ i ∉ T0
          · have hci : ¬ Covers C (child i) := fun h ↦ hi.2 (mem_filter.mpr ⟨hi.1, h⟩)
            obtain ⟨xi, h1, h2⟩ := ih i (hwc i hi.1) hci (hch i hi.1) (p'.eval i)
            exact ⟨xi, fun _ _ ↦ ⟨h1, h2⟩⟩
          · exact ⟨x, fun h1 h2 ↦ (hi ⟨h1, h2⟩).elim⟩
        choose X hX using hrest
        let x' : ι → ZMod q := fun a ↦
          if h : ∃ i, i ∈ ids ∧ i ∉ T0 ∧ a ∈ leaves (child i) then X h.choose a else x a
        have hx'_out : ∀ i ∈ ids, i ∉ T0 → ∀ a ∈ leaves (child i), x' a = X i a := by
          intro i hi hiT a ha
          have hex : ∃ i, i ∈ ids ∧ i ∉ T0 ∧ a ∈ leaves (child i) := ⟨i, hi, hiT, ha⟩
          have hspec := hex.choose_spec
          have heq : hex.choose = i := by
            by_contra hne
            exact Set.disjoint_left.mp (hdis _ hspec.1 i hi hne) hspec.2.2 ha
          simp only [x', dite_eq_left hex, heq]
        have hx'_in : ∀ i ∈ ids, i ∈ T0 → ∀ a ∈ leaves (child i), x' a = x a := by
          intro i hi hiT a ha
          have hex : ¬ ∃ j, j ∈ ids ∧ j ∉ T0 ∧ a ∈ leaves (child j) := by
            rintro ⟨j, hj, hjT, hja⟩
            have hne : j ≠ i := fun h ↦ hjT (h ▸ hiT)
            exact Set.disjoint_left.mp (hdis j hj i hi hne) hja ha
          simp only [x', dite_eq_right hex]
        refine ⟨x', fun a ha ↦ ?_, ?_⟩
        · by_cases hex : ∃ i, i ∈ ids ∧ i ∉ T0 ∧ a ∈ leaves (child i)
          · simp only [x', dite_eq_left hex]
            exact (hX _ hex.choose_spec.1 hex.choose_spec.2.1).1 a ha
          · simp only [x', dite_eq_right hex]
        · have := Dealt.thr (ids := ids) (child := child) p' hp' fun i hi ↦ by
            by_cases hiT : i ∈ T0
            · rw [shift_eval_of_mem h0T p s' hiT]
              exact (hch i hi).congr (hx'_in i hi hiT)
            · exact (hX i hi hiT).2.congr (hx'_out i hi hiT)
          rwa [shift_eval_zero] at this

/-! ## `user OR G` -/

/-- The P2 seizure gate `user OR G`, with `G` a `k`-of-`#ids` group whose members are the leaves
`guardian i`. -/
def userOrG (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ) : Gate q ι :=
  or2 (leaf user) (thr ids k fun i ↦ leaf (guardian i))

/-- **D22 and §3.8, `user OR G`.** In a dealing of the user shard `s` through `user OR G`, the
user's leaf is `s`, and any `k` guardians combine their escrow shares to `s`. -/
theorem D22_user_or_G {user : ι} {guardian : ZMod q → ι} {ids : Finset (ZMod q)} {k : ℕ}
    {s : ZMod q} {x : ι → ZMod q} (hd : Dealt (userOrG user guardian ids k) s x)
    (T : Finset (ZMod q)) (hT : T ⊆ ids) (hk : #T = k) :
    x user = s ∧ ∑ i ∈ T, lam T i * x (guardian i) = s := by
  cases hd with
  | or2 hu hg =>
    cases hu with
    | leaf hu =>
      refine ⟨hu, ?_⟩
      cases hg with
      | thr p hp hch =>
        rw [← D22_threshold_gate T hk hp]
        refine sum_congr rfl fun i hi ↦ ?_
        cases hch i (hT hi) with
        | leaf h => rw [h]

open Classical in
/-- **C17 and §3.8, fewer than `k` guardians without the user.** A coalition of fewer than `k`
guardians that does not contain the user does not satisfy `user OR G`. -/
theorem C17_user_or_G_coalition {user : ι} {guardian : ZMod q → ι} {ids : Finset (ZMod q)}
    {k : ℕ} {C : Set ι} (hu : user ∉ C) (hC : #(ids.filter fun i ↦ guardian i ∈ C) < k) :
    ¬ Covers C (userOrG user guardian ids k) := by
  intro h
  cases h with
  | orL hl =>
    cases hl with
    | leaf ha => exact hu ha
  | orR hg =>
    cases hg with
    | thr T hT hk hch =>
      have hsub : T ⊆ ids.filter fun i ↦ guardian i ∈ C := fun i hi ↦ by
        refine mem_filter.mpr ⟨hT hi, ?_⟩
        cases hch i hi with
        | leaf ha => exact ha
      exact absurd (hk.trans (card_le_card hsub)) (not_le.mpr hC)

end LineDealing.Split
