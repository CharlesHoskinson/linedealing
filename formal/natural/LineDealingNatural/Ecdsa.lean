import LineDealing.Ecdsa
import LineDealingNatural.Basic

/-!
# Line dealing in Natural Lean: open ECDSA lines

Port of `formal/lean/LineDealing/Ecdsa.lean` (items 1, 2 and 3).
-/

open Polynomial Finset
open LineDealing (lam feldmanEval commit ecdsaVerify)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

Theorem "Item 1, Lagrange linearity".
  Let t : Nat.  Let s : Finset(ZMod(q)).  Let w, mu : Polynomial(ZMod(q)).  Let h, r : ZMod(q).
  If #s = t and degree(w) < t and degree(mu) < t then

    ∑ i ∈ s, lam(s, i) · (h · eval(i, w) + r · eval(i, mu)) = h · eval(0, w) + r · eval(0, mu).
  [partial_combine]

Proof.  Suppose that #s = t and degree(w) < t and degree(mu) < t.  Then degree(w) < #s and
  degree(mu) < #s.  Hence

    ∑ i ∈ s, lam(s, i) · (h · eval(i, w) + r · eval(i, mu))
      = h · (∑ i ∈ s, lam(s, i) · eval(i, w)) + r · (∑ i ∈ s, lam(s, i) · eval(i, mu))
          by [(rw [mul_sum, mul_sum, ← sum_add_distrib]; exact sum_congr rfl fun i _ ↦ by ring)]
      = h · eval(0, w) + r · eval(0, mu) by sum_lam_mul_eval.

example : type_of% (@partial_combine q _) ↔ type_of% (@LineDealing.partial_combine q _) := by
  nl_same

Theorem "Item 2, open ECDSA binding".
  Let g, R, X : G.  Let k, x, w0, mu0 : ZMod(q).
  If g ≠ 0 and R = k • g and k ≠ 0 and X = x • g and w0 • R = g and mu0 • R = X then
  w0 = k⁻¹ and mu0 = x · k⁻¹.  [open_ecdsa_binding]

Proof.  Suppose that g ≠ 0 and R = k • g and k ≠ 0 and X = x • g and w0 • R = g and mu0 • R = X.
  Then k ≠ 0.  First,

    (w0 · k) • g = w0 • k • g by mul_smul
                 = w0 • R
                 = g.

  Hence (w0 · k - 1) • g = (w0 · k) • g - g by [rw [sub_smul, one_smul]]
                         = 0 by sub_self.

  So w0 · k - 1 = 0 by smul_eq_zero_of_ne_zero.  Then w0 · k = 1 by sub_eq_zero.  Thus
  w0 = k⁻¹ by eq_inv_of_mul_eq_one_left.  Second,

    (mu0 · k) • g = mu0 • k • g by mul_smul
                  = mu0 • R
                  = X
                  = x • g.

  Hence mu0 · k = x by smul_left_inj'.  So
  mu0 = x · k⁻¹ by [rw [← ‹mu0 * k = x›, mul_inv_cancel_right₀ ‹k ≠ 0›]].  Therefore
  w0 = k⁻¹ and mu0 = x · k⁻¹.

example : type_of% (@open_ecdsa_binding q _ G _ _) ↔
    type_of% (@LineDealing.open_ecdsa_binding q _ G _ _) := by nl_same

Theorem "Item 2, signature equation".
  Let g, X, R : G.  Let w0, mu0, h, r : ZMod(q).  If w0 • R = g and mu0 • R = X then

    (h · w0 + r · mu0) • R = h • g + r • X.  [open_ecdsa_equation]

Proof.  Suppose that w0 • R = g and mu0 • R = X.  Then

    (h · w0 + r · mu0) • R = (h · w0) • R + (r · mu0) • R by add_smul
                           = h • w0 • R + r • mu0 • R by [rw [mul_smul, mul_smul]]
                           = h • g + r • X.

example : type_of% (@open_ecdsa_equation q _ G _ _) ↔
    type_of% (@LineDealing.open_ecdsa_equation q _ G _ _) := by nl_same

/-! `ecdsaVerify` is the native definition of `LineDealing.Ecdsa`. -/

Theorem "For s ≠ 0 the verifier equation is the same as s • R = h • g + r • X".
  Let g, X, R : G.  Let h, r, s : ZMod(q).  If s ≠ 0 then

    ecdsaVerify(g, X, R, h, r, s) is true iff s • R = h • g + r • X.  [ecdsaVerify_iff]

Proof.  Let g, X, R : G and let h, r, s : ZMod(q) and suppose that s ≠ 0.

  Assume that ecdsaVerify(g, X, R, h, r, s) is true.  Then
  (h · s⁻¹) • g + (r · s⁻¹) • X = R by ecdsaVerify.  Hence

    s • R = s • ((h · s⁻¹) • g + (r · s⁻¹) • X)
          = (s · (h · s⁻¹)) • g + (s · (r · s⁻¹)) • X by [rw [smul_add, smul_smul, smul_smul]]
          = h • g + r • X
              by [rw [mul_comm h, mul_comm r, mul_inv_cancel_left₀ ‹s ≠ 0›,
                mul_inv_cancel_left₀ ‹s ≠ 0›]].

  Conversely, assume that s • R = h • g + r • X.  Then

    (h · s⁻¹) • g + (r · s⁻¹) • X = s⁻¹ • (h • g + r • X)
          by [rw [smul_add, smul_smul, smul_smul, mul_comm h, mul_comm r]]
      = s⁻¹ • s • R
      = R by [rw [smul_smul, inv_mul_cancel₀ ‹s ≠ 0›, one_smul]].

  Hence ecdsaVerify(g, X, R, h, r, s) is true by ecdsaVerify.

example : type_of% (@ecdsaVerify_iff q _ G _ _) ↔
    type_of% (@LineDealing.ecdsaVerify_iff q _ G _ _) := Iff.rfl

Theorem "Item 2, ECDSA verification".
  Let g, X, R : G.  Let w0, mu0, h, r : ZMod(q).
  If w0 • R = g and mu0 • R = X and h · w0 + r · mu0 ≠ 0 then
  ecdsaVerify(g, X, R, h, r, h · w0 + r · mu0) is true.  [open_ecdsa_verifies]

Proof.  Suppose that w0 • R = g and mu0 • R = X and h · w0 + r · mu0 ≠ 0.  Then
  (h · w0 + r · mu0) • R = h • g + r • X by open_ecdsa_equation.  Hence
  ecdsaVerify(g, X, R, h, r, h · w0 + r · mu0) is true by ecdsaVerify_iff.

example : type_of% (@open_ecdsa_verifies q _ G _ _) ↔
    type_of% (@LineDealing.open_ecdsa_verifies q _ G _ _) := by nl_same

Theorem "Moving the Lagrange combination through the base point".
  Let s : Finset(ZMod(q)).  Let σ : ZMod(q) → ZMod(q).  Let B : G.

    (∑ i ∈ s, lam(s, i) · σ(i)) • B = ∑ i ∈ s, lam(s, i) • σ(i) • B.  [sum_lam_mul_smul]

Proof.  (∑ i ∈ s, lam(s, i) · σ(i)) • B = ∑ i ∈ s, (lam(s, i) · σ(i)) • B by sum_smul
      = ∑ i ∈ s, lam(s, i) • σ(i) • B by [simp only [mul_smul]].

example : type_of% (@sum_lam_mul_smul q _ G _ _) ↔
    type_of% (@LineDealing.sum_lam_mul_smul q _ G _ _) := Iff.rfl

Theorem "Item 3, public partial check soundness".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let g, X, R : G.  Let h, r : ZMod(q).
  Let Cw, Cm : Nat → G.  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and Cw(0) = g and Cm(0) = X and
  for all i ∈ s, σ(i) • R = h • feldmanEval(t, Cw, i) + r • feldmanEval(t, Cm, i), then

    (∑ i ∈ s, lam(s, i) · σ(i)) • R = h • g + r • X.  [partial_check_sound]

Proof.  Suppose that 0 < t ≤ #s and Cw(0) = g and Cm(0) = X and
  for all i ∈ s, σ(i) • R = h • feldmanEval(t, Cw, i) + r • feldmanEval(t, Cm, i).  Then
  0 < t and t ≤ #s.  Hence

    (∑ i ∈ s, lam(s, i) · σ(i)) • R
      = ∑ i ∈ s, lam(s, i) • σ(i) • R by sum_lam_mul_smul
      = ∑ i ∈ s, lam(s, i) • (h • feldmanEval(t, Cw, i) + r • feldmanEval(t, Cm, i))
          by [(nl_hyps; exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim)]
      = h • (∑ i ∈ s, lam(s, i) • feldmanEval(t, Cw, i))
          + r • (∑ i ∈ s, lam(s, i) • feldmanEval(t, Cm, i))
          by [(rw [smul_sum, smul_sum, ← sum_add_distrib]
               exact sum_congr rfl fun i _ ↦ by
                 rw [smul_add, smul_comm (lam s i) h, smul_comm (lam s i) r])]
      = h • Cw(0) + r • Cm(0)
          by [rw [sum_lam_smul_feldmanEval s t Cw ‹_›, sum_lam_smul_feldmanEval s t Cm ‹_›]]
      = h • g + r • X.

example : type_of% (@partial_check_sound q _ G _ _) ↔
    type_of% (@LineDealing.partial_check_sound q _ G _ _) := by nl_same

Theorem "Item 3 in verifier form".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let g, X, R : G.  Let h, r : ZMod(q).
  Let Cw, Cm : Nat → G.  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and Cw(0) = g and Cm(0) = X and ∑ i ∈ s, lam(s, i) · σ(i) ≠ 0 and
  for all i ∈ s, σ(i) • R = h • feldmanEval(t, Cw, i) + r • feldmanEval(t, Cm, i), then
  ecdsaVerify(g, X, R, h, r, ∑ i ∈ s, lam(s, i) · σ(i)) is true.  [partial_check_verifies]

Proof.  Suppose that 0 < t ≤ #s and Cw(0) = g and Cm(0) = X and ∑ i ∈ s, lam(s, i) · σ(i) ≠ 0 and
  for all i ∈ s, σ(i) • R = h • feldmanEval(t, Cw, i) + r • feldmanEval(t, Cm, i).  Then
  (∑ i ∈ s, lam(s, i) · σ(i)) • R = h • g + r • X by partial_check_sound.  Hence
  ecdsaVerify(g, X, R, h, r, ∑ i ∈ s, lam(s, i) · σ(i)) is true by ecdsaVerify_iff.

example : type_of% (@partial_check_verifies q _ G _ _) ↔
    type_of% (@LineDealing.partial_check_verifies q _ G _ _) := by nl_same

Theorem "Completeness of the partial check".
  Let t : Nat.  Let w, mu : Polynomial(ZMod(q)).  Let R : G.  Let h, r, i : ZMod(q).
  If degree(w) < t and degree(mu) < t then

    (h · eval(i, w) + r · eval(i, mu)) • R
      = h • feldmanEval(t, commit(R, w), i) + r • feldmanEval(t, commit(R, mu), i).
  [partial_check_complete]

Proof.  Suppose that degree(w) < t and degree(mu) < t.  Then
  feldmanEval(t, commit(R, w), i) = eval(i, w) • R by feldmanEval_commit.  Also
  feldmanEval(t, commit(R, mu), i) = eval(i, mu) • R by feldmanEval_commit.  Hence

    (h · eval(i, w) + r · eval(i, mu)) • R
      = (h · eval(i, w)) • R + (r · eval(i, mu)) • R by add_smul
      = h • eval(i, w) • R + r • eval(i, mu) • R by [rw [mul_smul, mul_smul]]
      = h • feldmanEval(t, commit(R, w), i) + r • feldmanEval(t, commit(R, mu), i).

example : type_of% (@partial_check_complete q _ G _ _) ↔
    type_of% (@LineDealing.partial_check_complete q _ G _ _) := by nl_same

end LineDealingNatural
