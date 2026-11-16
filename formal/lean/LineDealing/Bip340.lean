import LineDealing.Sealed

/-!
# BIP340 even-y and open Schnorr partials

Item 8. Parity of the y-coordinate is an abstract predicate on points.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- **Item 8, negated nonce.** With `k → -k` and `R → -R`, the scalar `s = -k + c * x`
satisfies `s • g = R' + c • X` for `R' = -R`. -/
theorem bip340_negate {g : G} {k x c : ZMod q} {R X : G} (hR : R = k • g) (hX : X = x • g) :
    schnorrVerify g X (-R) c (-k + c * x) := by
  rw [schnorrVerify, hR, hX, add_smul, neg_smul, mul_smul]

/-- The unnegated case, for reference: `s = k + c * x` verifies against `R`. -/
theorem schnorr_honest {g : G} {k x c : ZMod q} {R X : G} (hR : R = k • g) (hX : X = x • g) :
    schnorrVerify g X R c (k + c * x) := by
  rw [schnorrVerify, hR, hX, add_smul, mul_smul]

/-- Item 8 with abstract parity. `evenY` is any predicate under which exactly one of `P`, `-P`
is even for `P ≠ 0`. For every nonzero nonce one of `k`, `-k` gives an even-y nonce point with
a signature that verifies against that point. The challenge `c` is a free scalar, so it may be
the one computed from the even-y point. -/
theorem bip340_even_nonce {g : G} (hg : g ≠ 0) (evenY : G → Prop)
    (hpar : ∀ P : G, P ≠ 0 → (evenY (-P) ↔ ¬ evenY P)) {k x : ZMod q} (hk : k ≠ 0) {X : G}
    (hX : X = x • g) :
    ∃ k' : ZMod q, (k' = k ∨ k' = -k) ∧ evenY (k' • g) ∧
      ∀ c : ZMod q, schnorrVerify g X (k' • g) c (k' + c * x) := by
  have hne : k • g ≠ 0 := fun h0 ↦ hk (smul_eq_zero_of_ne_zero hg h0)
  by_cases he : evenY (k • g)
  · exact ⟨k, Or.inl rfl, he, fun c ↦ schnorr_honest rfl hX⟩
  · refine ⟨-k, Or.inr rfl, ?_, fun c ↦ schnorr_honest rfl hX⟩
    rw [neg_smul]
    exact (hpar _ hne).mpr he

/-- Open Schnorr partial check soundness (SCHEME 3.8), with the sign `sg` (`1` or `-1`, any
scalar here). `Cd`, `Ce`, `Cx` are arbitrary families of points with constant terms `D`, `E`,
`X`. Partials that pass `σ i • g = sg • (D_i + ρ • E_i) + c • X_i` interpolate to a Schnorr
signature for the nonce point `sg • (D + ρ • E)`. -/
theorem open_schnorr_partial_sound (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    {g X D E : G} (sg ρ c : ZMod q) (Cd Ce Cx : ℕ → G) (hCd : Cd 0 = D) (hCe : Ce 0 = E)
    (hCx : Cx 0 = X) (σ : ZMod q → ZMod q)
    (hchk : ∀ i ∈ s, σ i • g =
      sg • (feldmanEval t Cd i + ρ • feldmanEval t Ce i) + c • feldmanEval t Cx i) :
    schnorrVerify g X (sg • (D + ρ • E)) c (∑ i ∈ s, lam s i * σ i) := by
  rw [schnorrVerify, sum_lam_mul_smul, sum_congr rfl fun i hi ↦ by rw [hchk i hi, smul_add,
    smul_comm (lam s i) sg, smul_add, smul_comm (lam s i) ρ, smul_comm (lam s i) c],
    sum_add_distrib, ← smul_sum, ← smul_sum, sum_add_distrib, ← smul_sum,
    sum_lam_smul_feldmanEval s ht0 ht, sum_lam_smul_feldmanEval s ht0 ht,
    sum_lam_smul_feldmanEval s ht0 ht, hCd, hCe, hCx]

end LineDealing
