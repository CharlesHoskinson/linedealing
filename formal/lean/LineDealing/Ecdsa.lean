import LineDealing.Basic

/-!
# Open ECDSA lines: Lagrange linearity, binding and the public partial check

Items 1, 2 and 3. `r` is a free scalar here; the rule `r = x(R) mod q` is not modelled.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- **Item 1, Lagrange linearity.** The partials `s_i = h * w_i + r * μ_i` from any `t` distinct
ids combine to `h * w(0) + r * μ(0)`. -/
theorem partial_combine {t : ℕ} (s : Finset (ZMod q)) (hs : #s = t) {w mu : (ZMod q)[X]}
    (hw : w.degree < t) (hmu : mu.degree < t) (h r : ZMod q) :
    ∑ i ∈ s, lam s i * (h * w.eval i + r * mu.eval i) = h * w.eval 0 + r * mu.eval 0 := by
  subst hs
  rw [← sum_lam_mul_eval s hw, ← sum_lam_mul_eval s hmu, mul_sum, mul_sum, ← sum_add_distrib]
  exact sum_congr rfl fun i _ ↦ by ring

/-- **Item 2, open ECDSA binding.** If `R = k • g` with `k ≠ 0`, `w(0) • R = g` and
`μ(0) • R = X = x • g`, then `w(0) = k⁻¹` and `μ(0) = x * k⁻¹`. -/
theorem open_ecdsa_binding {g : G} (hg : g ≠ 0) {k x w0 mu0 : ZMod q} {R X : G}
    (hR : R = k • g) (hk : k ≠ 0) (hX : X = x • g) (hw : w0 • R = g) (hmu : mu0 • R = X) :
    w0 = k⁻¹ ∧ mu0 = x * k⁻¹ := by
  subst hR hX
  rw [smul_smul] at hw hmu
  have h1 : w0 * k = 1 := smul_left_inj' hg (by rw [hw, one_smul])
  have h2 : mu0 * k = x := smul_left_inj' hg hmu
  exact ⟨eq_inv_of_mul_eq_one_left h1, by rw [← h2, mul_inv_cancel_right₀ hk]⟩

/-- **Item 2, signature equation.** With the constant terms forced to `g` and `X` in base `R`,
`s = h * w(0) + r * μ(0)` satisfies `s • R = h • g + r • X` for every `h`. -/
theorem open_ecdsa_equation {g X R : G} {w0 mu0 : ZMod q} (hw : w0 • R = g) (hmu : mu0 • R = X)
    (h r : ZMod q) : (h * w0 + r * mu0) • R = h • g + r • X := by
  rw [add_smul, mul_smul, mul_smul, hw, hmu]

/-- The ECDSA verifier's group equation: `s ≠ 0` and `(h / s) • g + (r / s) • X = R`. The real
verifier also checks `r ≠ 0` and `r = x(R) mod q`; that link between `r` and `R` is abstracted. -/
def ecdsaVerify (g X R : G) (h r s : ZMod q) : Prop :=
  s ≠ 0 ∧ (h * s⁻¹) • g + (r * s⁻¹) • X = R

/-- For `s ≠ 0` the verifier equation is the same as `s • R = h • g + r • X`. -/
theorem ecdsaVerify_iff {g X R : G} {h r s : ZMod q} (hs : s ≠ 0) :
    ecdsaVerify g X R h r s ↔ s • R = h • g + r • X := by
  constructor
  · rintro ⟨_, rfl⟩
    rw [smul_add, smul_smul, smul_smul, mul_comm h, mul_comm r, mul_inv_cancel_left₀ hs,
      mul_inv_cancel_left₀ hs]
  · intro e
    refine ⟨hs, ?_⟩
    have : R = s⁻¹ • (h • g + r • X) := by rw [← e, smul_smul, inv_mul_cancel₀ hs, one_smul]
    rw [this, smul_add, smul_smul, smul_smul, mul_comm h, mul_comm r]

/-- **Item 2, ECDSA verification.** The combined open signature passes the ECDSA verifier
equation whenever it is nonzero (`s = 0` kills the generation, SCHEME 3.8). -/
theorem open_ecdsa_verifies {g X R : G} {w0 mu0 : ZMod q} (hw : w0 • R = g) (hmu : mu0 • R = X)
    (h r : ZMod q) (hs : h * w0 + r * mu0 ≠ 0) :
    ecdsaVerify g X R h r (h * w0 + r * mu0) :=
  (ecdsaVerify_iff hs).mpr (open_ecdsa_equation hw hmu h r)

/-- Moving the Lagrange combination through the base point. -/
theorem sum_lam_mul_smul (s : Finset (ZMod q)) (σ : ZMod q → ZMod q) (B : G) :
    (∑ i ∈ s, lam s i * σ i) • B = ∑ i ∈ s, lam s i • σ i • B := by
  rw [sum_smul]
  exact sum_congr rfl fun i _ ↦ mul_smul _ _ _

/-- **Item 3, public partial check soundness.** `Cw` and `Cm` are arbitrary families of points
whose constant terms are `g` and `X`; nothing says a share of them exists. If every released
`σ i` passes `σ i • R = h • W_i + r • M_i`, with `W_i`, `M_i` the Feldman evaluations, then the
interpolated `s` satisfies `s • R = h • g + r • X`. -/
theorem partial_check_sound (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    {g X R : G} (h r : ZMod q) (Cw Cm : ℕ → G) (hCw : Cw 0 = g) (hCm : Cm 0 = X)
    (σ : ZMod q → ZMod q)
    (hchk : ∀ i ∈ s, σ i • R = h • feldmanEval t Cw i + r • feldmanEval t Cm i) :
    (∑ i ∈ s, lam s i * σ i) • R = h • g + r • X := by
  rw [sum_lam_mul_smul, sum_congr rfl fun i hi ↦ by rw [hchk i hi, smul_add,
    smul_comm (lam s i) h, smul_comm (lam s i) r], sum_add_distrib, ← smul_sum, ← smul_sum,
    sum_lam_smul_feldmanEval s ht0 ht, sum_lam_smul_feldmanEval s ht0 ht, hCw, hCm]

/-- Item 3 in verifier form: checked partials interpolate to a signature that the ECDSA verifier
equation accepts, unless it is zero. -/
theorem partial_check_verifies (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    {g X R : G} (h r : ZMod q) (Cw Cm : ℕ → G) (hCw : Cw 0 = g) (hCm : Cm 0 = X)
    (σ : ZMod q → ZMod q)
    (hchk : ∀ i ∈ s, σ i • R = h • feldmanEval t Cw i + r • feldmanEval t Cm i)
    (hne : ∑ i ∈ s, lam s i * σ i ≠ 0) :
    ecdsaVerify g X R h r (∑ i ∈ s, lam s i * σ i) :=
  (ecdsaVerify_iff hne).mpr (partial_check_sound s ht0 ht h r Cw Cm hCw hCm σ hchk)

/-- Completeness of the partial check: honest partials from honest commitments in base `R`
pass it. -/
theorem partial_check_complete {t : ℕ} {w mu : (ZMod q)[X]} (hw : w.degree < t)
    (hmu : mu.degree < t) (R : G) (h r i : ZMod q) :
    (h * w.eval i + r * mu.eval i) • R =
      h • feldmanEval t (commit R w) i + r • feldmanEval t (commit R mu) i := by
  rw [feldmanEval_commit R hw, feldmanEval_commit R hmu, add_smul, mul_smul, mul_smul]

end LineDealing
