import Mathlib

/-!
# Line dealing: group model, Lagrange coefficients and Feldman evaluation

The scalar field is `F = ZMod q` with `q` prime. The group `G` is any additive commutative group
that is a module over `F`, with a fixed nonzero generator `g`. `G` is not assumed cyclic. Node ids
are elements of a finite set `s : Finset (ZMod q)`, so they are distinct by construction.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- A nonzero point has no nonzero scalar that kills it. -/
theorem smul_eq_zero_of_ne_zero {g : G} (hg : g ≠ 0) {a : ZMod q} (h : a • g = 0) : a = 0 := by
  by_contra ha
  apply hg
  have h2 : a⁻¹ • a • g = 0 := by rw [h, smul_zero]
  rwa [smul_smul, inv_mul_cancel₀ ha, one_smul] at h2

/-- Scalar multiplication of a nonzero point is injective in the scalar. -/
theorem smul_left_inj' {g : G} (hg : g ≠ 0) {a b : ZMod q} (h : a • g = b • g) : a = b := by
  have h0 : (a - b) • g = 0 := by rw [sub_smul, h, sub_self]
  exact sub_eq_zero.mp (smul_eq_zero_of_ne_zero hg h0)

/-- The Lagrange coefficient at zero of node `i` in the node set `s`. -/
noncomputable def lam (s : Finset (ZMod q)) (i : ZMod q) : ZMod q :=
  (Lagrange.basis s id i).eval 0

/-- Lagrange interpolation at zero: `t` evaluations of a polynomial of degree below `t` combine
to its constant term. -/
theorem sum_lam_mul_eval (s : Finset (ZMod q)) {p : (ZMod q)[X]} (hp : p.degree < #s) :
    ∑ i ∈ s, lam s i * p.eval i = p.eval 0 := by
  have h := Lagrange.eq_interpolate (s := s) (v := id) Function.injective_id.injOn hp
  conv_rhs => rw [h]
  simp [Lagrange.interpolate_apply, eval_finsetSum, lam, mul_comm]

/-- The Lagrange coefficients annihilate every power `1 ≤ u < #s` and sum to one. -/
theorem sum_lam_mul_pow (s : Finset (ZMod q)) {u : ℕ} (hu : u < #s) :
    ∑ i ∈ s, lam s i * i ^ u = if u = 0 then 1 else 0 := by
  have hdeg : ((X : (ZMod q)[X]) ^ u).degree < #s := by
    rw [degree_X_pow]; exact_mod_cast hu
  have h := sum_lam_mul_eval s hdeg
  simpa [eval_pow, zero_pow_eq] using h

/-- Feldman evaluation `Eval(C_0, C, i) = Σ_{u < t} i^u • C_u`. The commitment `C` is any family
of points; `C 0` is the constant-term commitment. -/
def feldmanEval (t : ℕ) (C : ℕ → G) (i : ZMod q) : G :=
  ∑ u ∈ range t, i ^ u • C u

/-- Lagrange interpolation in the exponent: the Feldman evaluations at `t` or more ids combine
to the constant-term commitment, for any family of points. -/
theorem sum_lam_smul_feldmanEval (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    (C : ℕ → G) : ∑ i ∈ s, lam s i • feldmanEval t C i = C 0 := by
  simp only [feldmanEval, smul_sum, smul_smul]
  rw [sum_comm]
  have : ∀ u ∈ range t,
      ∑ i ∈ s, (lam s i * i ^ u) • C u = (if u = 0 then 1 else 0 : ZMod q) • C u := by
    intro u hu
    rw [← sum_smul, sum_lam_mul_pow s (lt_of_lt_of_le (mem_range.mp hu) ht)]
  rw [sum_congr rfl this]
  simp [ite_smul, ht0]

/-- An honest commitment in base `B` to the polynomial `p`: `C_u = a_u • B`. -/
noncomputable def commit (B : G) (p : (ZMod q)[X]) (u : ℕ) : G := p.coeff u • B

/-- The Feldman evaluation of an honest commitment is the share times the base. -/
theorem feldmanEval_commit (B : G) {p : (ZMod q)[X]} {t : ℕ} (hp : p.degree < t) (i : ZMod q) :
    feldmanEval t (commit B p) i = p.eval i • B := by
  simp only [feldmanEval, commit, smul_smul, ← sum_smul]
  congr 1
  rcases eq_or_ne p 0 with rfl | hp0
  · simp
  · rw [eval_eq_sum_range' ((natDegree_lt_iff_degree_lt hp0).mpr hp)]
    exact sum_congr rfl fun u _ ↦ mul_comm _ _

end LineDealing
