import LineDealing.Bip340
import LineDealingNatural.Sealed

/-!
# Line dealing in Natural Lean: BIP340 even-y and open Schnorr partials

Port of `formal/lean/LineDealing/Bip340.lean` (item 8).
-/

open Polynomial Finset
open LineDealing (lam feldmanEval commit ecdsaVerify schnorrVerify)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

Theorem "Item 8, negated nonce".
  Let g, R, X : G.  Let k, x, c : ZMod(q).  If R = k • g and X = x • g then
  schnorrVerify(g, X, -R, c, -k + c · x) is true.  [bip340_negate]

Proof.  Suppose that R = k • g and X = x • g.  Then

    (-k + c · x) • g = (-k) • g + (c · x) • g by add_smul
                     = -(k • g) + c • x • g by [rw [neg_smul, mul_smul]]
                     = -R + c • X.

  Hence schnorrVerify(g, X, -R, c, -k + c · x) is true by schnorrVerify.

example : type_of% (@bip340_negate q _ G _ _) ↔
    type_of% (@LineDealing.bip340_negate q _ G _ _) := by nl_same

Theorem "The unnegated case".
  Let g, R, X : G.  Let k, x, c : ZMod(q).  If R = k • g and X = x • g then
  schnorrVerify(g, X, R, c, k + c · x) is true.  [schnorr_honest]

Proof.  Suppose that R = k • g and X = x • g.  Then

    (k + c · x) • g = k • g + (c · x) • g by add_smul
                    = k • g + c • x • g by [rw [mul_smul]]
                    = R + c • X.

  Hence schnorrVerify(g, X, R, c, k + c · x) is true by schnorrVerify.

example : type_of% (@schnorr_honest q _ G _ _) ↔
    type_of% (@LineDealing.schnorr_honest q _ G _ _) := by nl_same

Theorem "Item 8 with abstract parity".
  Let g, X : G.  Let E : G → Prop.  Let k, x : ZMod(q).
  If g ≠ 0 and k ≠ 0 and X = x • g and
  for all P : G, if P ≠ 0 then E(-P) is true iff E(P) is false, then
  there is some k' : ZMod(q) such that k' = k or k' = -k, and E(k' • g) is true, and
  for all c : ZMod(q), schnorrVerify(g, X, k' • g, c, k' + c · x) is true.  [bip340_even_nonce]

Proof.  Suppose that g ≠ 0 and k ≠ 0 and X = x • g and
  for all P : G, if P ≠ 0 then E(-P) is true iff E(P) is false.
  Then k • g ≠ 0 by smul_eq_zero_of_ne_zero.

  Assume that E(k • g) is true.  Then
  for all c : ZMod(q), schnorrVerify(g, X, k • g, c, k + c · x) is true by schnorr_honest.

  Otherwise E(k • g) is false.  Then E(-(k • g)) is true.  So E((-k) • g) is true by neg_smul.
  Also for all c : ZMod(q), schnorrVerify(g, X, (-k) • g, c, -k + c · x) is true
  by schnorr_honest.

  In either case there is some k' : ZMod(q) such that k' = k or k' = -k, and
  E(k' • g) is true, and
  for all c : ZMod(q), schnorrVerify(g, X, k' • g, c, k' + c · x) is true.

example : type_of% (@bip340_even_nonce q _ G _ _) ↔
    type_of% (@LineDealing.bip340_even_nonce q _ G _ _) := by nl_same

Theorem "Open Schnorr partial check soundness".
  Let s : Finset(ZMod(q)).  Let t : Nat.  Let g, X, D, E : G.  Let sg, ρ, c : ZMod(q).
  Let Cd, Ce, Cx : Nat → G.  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #s and Cd(0) = D and Ce(0) = E and Cx(0) = X and
  for all i ∈ s,
    σ(i) • g = sg • (feldmanEval(t, Cd, i) + ρ • feldmanEval(t, Ce, i)) + c • feldmanEval(t, Cx, i),
  then schnorrVerify(g, X, sg • (D + ρ • E), c, ∑ i ∈ s, lam(s, i) · σ(i)) is true.
  [open_schnorr_partial_sound]

Proof.  Suppose that 0 < t ≤ #s and Cd(0) = D and Ce(0) = E and Cx(0) = X and
  for all i ∈ s,
    σ(i) • g = sg • (feldmanEval(t, Cd, i) + ρ • feldmanEval(t, Ce, i)) + c • feldmanEval(t, Cx, i).
  Then 0 < t and t ≤ #s.  Hence

    (∑ i ∈ s, lam(s, i) · σ(i)) • g
      = ∑ i ∈ s, lam(s, i) • σ(i) • g by sum_lam_mul_smul
      = ∑ i ∈ s, lam(s, i) •
          (sg • (feldmanEval(t, Cd, i) + ρ • feldmanEval(t, Ce, i)) + c • feldmanEval(t, Cx, i))
          by [(nl_hyps; exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim)]
      = sg • ((∑ i ∈ s, lam(s, i) • feldmanEval(t, Cd, i))
            + ρ • (∑ i ∈ s, lam(s, i) • feldmanEval(t, Ce, i)))
          + c • (∑ i ∈ s, lam(s, i) • feldmanEval(t, Cx, i))
          by [(simp only [smul_add, smul_sum, ← sum_add_distrib]
               exact sum_congr rfl fun i _ ↦ by module)]
      = sg • (Cd(0) + ρ • Ce(0)) + c • Cx(0)
          by [rw [sum_lam_smul_feldmanEval s t Cd ‹_›, sum_lam_smul_feldmanEval s t Ce ‹_›,
            sum_lam_smul_feldmanEval s t Cx ‹_›]]
      = sg • (D + ρ • E) + c • X.

  Thus schnorrVerify(g, X, sg • (D + ρ • E), c, ∑ i ∈ s, lam(s, i) · σ(i)) is true
  by schnorrVerify.

example : type_of% (@open_schnorr_partial_sound q _ G _ _) ↔
    type_of% (@LineDealing.open_schnorr_partial_sound q _ G _ _) := by nl_same

end LineDealingNatural
