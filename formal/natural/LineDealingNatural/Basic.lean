import LineDealing.Basic
import LineDealingNatural.Prelude

/-!
# Line dealing in Natural Lean: group model, Lagrange coefficients, Feldman evaluation

Port of `formal/lean/LineDealing/Basic.lean`.
-/

open Polynomial Finset
open LineDealing (lam feldmanEval commit)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

Theorem "A nonzero point has no nonzero scalar that kills it".
  Let g : G.  Let a : ZMod(q).  If g ≠ 0 and a • g = 0 then a = 0.  [smul_eq_zero_of_ne_zero]

Proof.  Suppose that g ≠ 0 and a • g = 0.  Assume that a ≠ 0.  Then

    g = (a⁻¹ · a) • g by [rw [inv_mul_cancel₀ ‹a ≠ 0›, one_smul]]
      = a⁻¹ • a • g by mul_smul
      = a⁻¹ • 0
      = 0 by smul_zero.

  Hence g = 0, which is a contradiction.  Thus a = 0.

example : type_of% (@smul_eq_zero_of_ne_zero q _ G _ _) ↔
    type_of% (@LineDealing.smul_eq_zero_of_ne_zero q _ G _ _) := by nl_same

Theorem "Scalar multiplication of a nonzero point is injective in the scalar".
  Let g : G.  Let a, b : ZMod(q).  If g ≠ 0 and a • g = b • g then a = b.  [smul_left_inj']

Proof.  Suppose that g ≠ 0 and a • g = b • g.  Then

    (a - b) • g = a • g - b • g by sub_smul
                = 0 by sub_self.

  Hence a - b = 0 by smul_eq_zero_of_ne_zero.  Thus a = b by sub_eq_zero.

example : type_of% (@smul_left_inj' q _ G _ _) ↔
    type_of% (@LineDealing.smul_left_inj' q _ G _ _) := by nl_same

/-! `lam`, `feldmanEval` and `commit` are the native definitions of `LineDealing.Basic`;
Natural Lean cannot define a function that is not an operator. -/

Theorem "Lagrange interpolation at zero".
  Let s : Finset(ZMod(q)).  Let p : Polynomial(ZMod(q)).  If degree(p) < #s then

    ∑ i ∈ s, lam(s, i) · eval(i, p) = eval(0, p).  [sum_lam_mul_eval]

Proof.  By [(
  intro s p hp
  have h := Lagrange.eq_interpolate (s := s) (v := id) Function.injective_id.injOn hp
  conv_rhs => rw [h]
  simp [Lagrange.interpolate_apply, eval_finsetSum, lam, mul_comm])].

example : type_of% (@sum_lam_mul_eval q _) ↔ type_of% (@LineDealing.sum_lam_mul_eval q _) :=
  Iff.rfl

Theorem "The Lagrange coefficients sum to one and annihilate every power 1 ≤ u < #s".
  Let s : Finset(ZMod(q)).  Let u : Nat.  If u < #s then

    u = 0 implies ∑ i ∈ s, lam(s, i) · i ^ u = 1, and
    u ≠ 0 implies ∑ i ∈ s, lam(s, i) · i ^ u = 0.  [sum_lam_mul_pow]

Proof.  By [(
  intro s u hu
  have hdeg : ((X : (ZMod q)[X]) ^ u).degree < #s := by
    rw [degree_X_pow]; exact_mod_cast hu
  have h := sum_lam_mul_eval s _ hdeg
  simp only [eval_pow, eval_X] at h
  constructor
  · rintro rfl; simpa using h
  · intro hne; simpa [hne] using h)].

-- The native statement gives the value as `if u = 0 then 1 else 0`. Natural Lean has no
-- conditional expression, so the natural statement gives the two cases.
example : type_of% (@sum_lam_mul_pow q _) ↔ type_of% (@LineDealing.sum_lam_mul_pow q _) := by
  constructor
  · intro h s u hu
    split_ifs with h0
    · exact (h s u hu).1 h0
    · exact (h s u hu).2 h0
  · intro h s u hu
    have := h s hu
    constructor
    · intro h0; rw [this, ite_eq_left_of_eq_true _ _ (eq_true h0)]
    · intro h0; rw [this, ite_eq_right_of_eq_false _ _ (eq_false h0)]

Theorem "Lagrange interpolation in the exponent".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let K : Nat → G.  If 0 < t ≤ #s then

    ∑ i ∈ s, lam(s, i) • feldmanEval(t, K, i) = K(0).  [sum_lam_smul_feldmanEval]

Proof.  Suppose that 0 < t ≤ #s.  Then

    ∑ i ∈ s, lam(s, i) • feldmanEval(t, K, i)
      = ∑ i ∈ s, ∑ u ∈ range(t), (lam(s, i) · i ^ u) • K(u)
          by [simp only [feldmanEval, smul_sum, smul_smul]]
      = ∑ u ∈ range(t), ∑ i ∈ s, (lam(s, i) · i ^ u) • K(u) by sum_comm
      = ∑ u ∈ range(t), (∑ i ∈ s, lam(s, i) · i ^ u) • K(u) by [simp only [sum_smul]]
      = (∑ i ∈ s, lam(s, i) · i ^ 0) • K(0)
          by [exact sum_eq_single_of_mem 0 (by simp; omega) fun u hu hne ↦ by
            rw [(sum_lam_mul_pow s u (by have := mem_range.mp hu; omega)).2 hne, zero_smul]]
      = K(0) by [rw [(sum_lam_mul_pow s 0 (by omega)).1 rfl, one_smul]].

example : type_of% (@sum_lam_smul_feldmanEval q _ G _ _) ↔
    type_of% (@LineDealing.sum_lam_smul_feldmanEval q _ G _ _) := by nl_same

Theorem "The Feldman evaluation of an honest commitment is the share times the base".
  Let B : G.  Let p : Polynomial(ZMod(q)).  Let t : Nat.  Let i : ZMod(q).  If degree(p) < t then

    feldmanEval(t, commit(B, p), i) = eval(i, p) • B.  [feldmanEval_commit]

Proof.  By [(
  intro B p t i hp
  simp only [feldmanEval, commit, smul_smul, ← sum_smul]
  congr 1
  rcases eq_or_ne p 0 with rfl | hp0
  · simp
  · rw [eval_eq_sum_range' ((natDegree_lt_iff_degree_lt hp0).mpr hp)]
    exact sum_congr rfl fun u _ ↦ mul_comm _ _)].

example : type_of% (@feldmanEval_commit q _ G _ _) ↔
    type_of% (@LineDealing.feldmanEval_commit q _ G _ _) := by nl_same

end LineDealingNatural
