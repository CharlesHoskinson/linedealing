import LineDealing.Sealed
import LineDealingNatural.Ecdsa

/-!
# Line dealing in Natural Lean: sealed points

Port of `formal/lean/LineDealing/Sealed.lean` (item 4).
-/

open Polynomial Finset
open LineDealing (lam feldmanEval commit ecdsaVerify schnorrVerify)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

/-! `schnorrVerify` is the native definition of `LineDealing.Sealed`. -/

Theorem "Shares that pass the Feldman check interpolate to a scalar s with s • B = K(0)".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let B : G.  Let K : Nat → G.
  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and for all i ∈ s, σ(i) • B = feldmanEval(t, K, i), then

    (∑ i ∈ s, lam(s, i) · σ(i)) • B = K(0).  [sealed_release_sound]

Proof.  Suppose that 0 < t ≤ #s and for all i ∈ s, σ(i) • B = feldmanEval(t, K, i).  Then

    (∑ i ∈ s, lam(s, i) · σ(i)) • B
      = ∑ i ∈ s, lam(s, i) • σ(i) • B by sum_lam_mul_smul
      = ∑ i ∈ s, lam(s, i) • feldmanEval(t, K, i)
          by [(nl_hyps; exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim)]
      = K(0) by sum_lam_smul_feldmanEval.

example : type_of% (@sealed_release_sound q _ G _ _) ↔
    type_of% (@LineDealing.sealed_release_sound q _ G _ _) := by nl_same

Theorem "Feldman commitments fix the constant term of the polynomial".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let B : G.  Let K : Nat → G.
  Let p : Polynomial(ZMod(q)).
  If 0 < t and #s = t and degree(p) < t and
  for all i ∈ s, eval(i, p) • B = feldmanEval(t, K, i), then

    eval(0, p) • B = K(0).  [feldman_binds_constant]

Proof.  Suppose that 0 < t and #s = t and degree(p) < t and
  for all i ∈ s, eval(i, p) • B = feldmanEval(t, K, i).  Then degree(p) < #s.  Also 0 < t and
  t ≤ #s.  Hence

    eval(0, p) • B
      = (∑ i ∈ s, lam(s, i) · eval(i, p)) • B by sum_lam_mul_eval
      = ∑ i ∈ s, lam(s, i) • eval(i, p) • B by [exact sum_lam_mul_smul s (fun i ↦ eval i p) B]
      = ∑ i ∈ s, lam(s, i) • feldmanEval(t, K, i)
          by [(nl_hyps; exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim)]
      = K(0) by sum_lam_smul_feldmanEval.

example : type_of% (@feldman_binds_constant q _ G _ _) ↔
    type_of% (@LineDealing.feldman_binds_constant q _ G _ _) := by nl_same

Theorem "Item 4, Schnorr form".
  Let g, X, R : G.  Let c, p0 : ZMod(q).  If p0 • g = R + c • X then
  schnorrVerify(g, X, R, c, p0) is true.  [sealed_schnorr_binding]

Proof.  By schnorrVerify.

example : type_of% (@sealed_schnorr_binding q _ G _ _) ↔
    type_of% (@LineDealing.sealed_schnorr_binding q _ G _ _) := Iff.rfl

Theorem "Item 4, Schnorr form, from the checks a node runs".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let g, X, R : G.  Let c : ZMod(q).  Let K : Nat → G.
  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and K(0) = R + c • X and for all i ∈ s, σ(i) • g = feldmanEval(t, K, i), then
  schnorrVerify(g, X, R, c, ∑ i ∈ s, lam(s, i) · σ(i)) is true.  [sealed_schnorr_release]

Proof.  Suppose that 0 < t ≤ #s and K(0) = R + c • X and
  for all i ∈ s, σ(i) • g = feldmanEval(t, K, i).  Then
  (∑ i ∈ s, lam(s, i) · σ(i)) • g = K(0) by [nl_apply sealed_release_sound].  Hence
  (∑ i ∈ s, lam(s, i) · σ(i)) • g = R + c • X.  Thus
  schnorrVerify(g, X, R, c, ∑ i ∈ s, lam(s, i) · σ(i)) is true by schnorrVerify.

example : type_of% (@sealed_schnorr_release q _ G _ _) ↔
    type_of% (@LineDealing.sealed_schnorr_release q _ G _ _) := by nl_same

Theorem "Item 4, ECDSA form".
  Let g, X, R : G.  Let h, r, p0 : ZMod(q).
  If p0 • R = h • g + r • X and h • g + r • X ≠ 0 then
  p0 ≠ 0 and ecdsaVerify(g, X, R, h, r, p0) is true.  [sealed_ecdsa_binding]

Proof.  Suppose that p0 • R = h • g + r • X and h • g + r • X ≠ 0.  Assume that p0 = 0.  Then
  p0 • R = 0 by zero_smul.  Hence h • g + r • X = 0, which is a contradiction.  Thus p0 ≠ 0.
  Hence ecdsaVerify(g, X, R, h, r, p0) is true by ecdsaVerify_iff.  Therefore
  p0 ≠ 0 and ecdsaVerify(g, X, R, h, r, p0) is true.

example : type_of% (@sealed_ecdsa_binding q _ G _ _) ↔
    type_of% (@LineDealing.sealed_ecdsa_binding q _ G _ _) := by nl_same

Theorem "Item 4, ECDSA form, from the checks a node runs".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let g, X, R : G.  Let h, r : ZMod(q).
  Let K : Nat → G.  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and K(0) = h • g + r • X and h • g + r • X ≠ 0 and
  for all i ∈ s, σ(i) • R = feldmanEval(t, K, i), then
  ecdsaVerify(g, X, R, h, r, ∑ i ∈ s, lam(s, i) · σ(i)) is true.  [sealed_ecdsa_release]

Proof.  Suppose that 0 < t ≤ #s and K(0) = h • g + r • X and h • g + r • X ≠ 0 and
  for all i ∈ s, σ(i) • R = feldmanEval(t, K, i).  Then
  (∑ i ∈ s, lam(s, i) · σ(i)) • R = K(0) by [nl_apply sealed_release_sound].  Hence
  (∑ i ∈ s, lam(s, i) · σ(i)) • R = h • g + r • X.  Thus
  ecdsaVerify(g, X, R, h, r, ∑ i ∈ s, lam(s, i) · σ(i)) is true by sealed_ecdsa_binding.

example : type_of% (@sealed_ecdsa_release q _ G _ _) ↔
    type_of% (@LineDealing.sealed_ecdsa_release q _ G _ _) := by nl_same

Theorem "The honest sealed ECDSA scalar satisfies s • R = h • g + r • X".
  Let g : G.  Let k, x, h, r : ZMod(q).  If k ≠ 0 then

    (k⁻¹ · (h + r · x)) • (k • g) = h • g + r • (x • g).  [sealed_ecdsa_honest]

Proof.  Suppose that k ≠ 0.  Then

    (k⁻¹ · (h + r · x)) • (k • g)
      = (k⁻¹ · (h + r · x) · k) • g by smul_smul
      = (h + r · x) • g by [(congr 1; field_simp)]
      = h • g + (r · x) • g by add_smul
      = h • g + r • (x • g) by [rw [mul_smul]].

example : type_of% (@sealed_ecdsa_honest q _ G _ _) ↔
    type_of% (@LineDealing.sealed_ecdsa_honest q _ G _ _) := Iff.rfl

end LineDealingNatural
