import LineDealing.NonceReuse
import LineDealingNatural.Ecdsa

/-!
# Line dealing in Natural Lean: nonce reuse

Port of `formal/lean/LineDealing/NonceReuse.lean` (item 5).
-/

open Finset
open LineDealing (det3)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

Theorem "Item 5, ECDSA nonce reuse".
  Let g, R, X : G.  Let k, x, r, h1, h2, s1, s2 : ZMod(q).
  If g ≠ 0 and R = k • g and X = x • g and r ≠ 0 and h1 ≠ h2 and
  s1 • R = h1 • g + r • X and s2 • R = h2 • g + r • X then
  s1 ≠ s2 and k = (h1 - h2) / (s1 - s2) and x = (s1 · k - h1) / r.  [ecdsa_nonce_reuse]

Proof.  Suppose that g ≠ 0 and R = k • g and X = x • g and r ≠ 0 and h1 ≠ h2 and
  s1 • R = h1 • g + r • X and s2 • R = h2 • g + r • X.  Then r ≠ 0.  First,

    (s1 · k) • g = s1 • k • g by mul_smul
                 = s1 • R
                 = h1 • g + r • X
                 = h1 • g + r • x • g
                 = h1 • g + (r · x) • g by [rw [mul_smul]]
                 = (h1 + r · x) • g by add_smul.

  Hence s1 · k = h1 + r · x by smul_left_inj'.  Second,

    (s2 · k) • g = s2 • k • g by mul_smul
                 = s2 • R
                 = h2 • g + r • X
                 = h2 • g + r • x • g
                 = h2 • g + (r · x) • g by [rw [mul_smul]]
                 = (h2 + r · x) • g by add_smul.

  Hence s2 · k = h2 + r · x by smul_left_inj'.

  Assume that s1 = s2.  Then h1 + r · x = h2 + r · x.  So h1 = h2, which is a contradiction.
  Thus s1 ≠ s2.  Hence s1 - s2 ≠ 0 by sub_ne_zero.

  Now k · (s1 - s2) = h1 - h2.  So k = (h1 - h2) / (s1 - s2) by eq_div_iff.
  Also x · r = s1 · k - h1.  So x = (s1 · k - h1) / r by eq_div_iff.
  Therefore s1 ≠ s2 and k = (h1 - h2) / (s1 - s2) and x = (s1 · k - h1) / r.

example : type_of% (@ecdsa_nonce_reuse q _ G _ _) ↔
    type_of% (@LineDealing.ecdsa_nonce_reuse q _ G _ _) := by nl_same

Theorem "One-nonce Schnorr, for contrast".
  Let d, x, c1, c2, s1, s2 : ZMod(q).
  If c1 ≠ c2 and s1 = d + c1 · x and s2 = d + c2 · x then x = (s1 - s2) / (c1 - c2).
  [schnorr_one_nonce_reuse]

Proof.  Suppose that c1 ≠ c2 and s1 = d + c1 · x and s2 = d + c2 · x.  Then
  c1 - c2 ≠ 0 by sub_ne_zero.  Also x · (c1 - c2) = s1 - s2.  Hence
  x = (s1 - s2) / (c1 - c2) by eq_div_iff.

example : type_of% (@schnorr_one_nonce_reuse q _) ↔
    type_of% (@LineDealing.schnorr_one_nonce_reuse q _) := by nl_same

Theorem "Item 5, two-nonce Schnorr, the one-parameter family".
  Let a1, b1, c1, a2, b2, c2, s1, s2, x' : ZMod(q).  If a1 · b2 - a2 · b1 ≠ 0 then
  there is some d, e : ZMod(q) such that
    a1 · d + b1 · e + c1 · x' = s1 and a2 · d + b2 · e + c2 · x' = s2, and
    for all u, v : ZMod(q),
      if a1 · u + b1 · v + c1 · x' = s1 and a2 · u + b2 · v + c2 · x' = s2 then u = d and v = e.
  [schnorr_two_sigs_family]

Proof.  By [(
  intro a1 b1 c1 a2 b2 c2 s1 s2 x' hdet
  refine ⟨((s1 - c1 * x') * b2 - (s2 - c2 * x') * b1) / (a1 * b2 - a2 * b1),
    (a1 * (s2 - c2 * x') - a2 * (s1 - c1 * x')) / (a1 * b2 - a2 * b1), ⟨?_, ?_⟩, ?_⟩
  · rw [← mul_div_assoc, ← mul_div_assoc, ← add_div, ← eq_sub_iff_add_eq, div_eq_iff hdet]
    ring
  · rw [← mul_div_assoc, ← mul_div_assoc, ← add_div, ← eq_sub_iff_add_eq, div_eq_iff hdet]
    ring
  · rintro u v ⟨h1, h2⟩
    constructor
    · rw [eq_div_iff hdet]
      linear_combination b2 * h1 - b1 * h2
    · rw [eq_div_iff hdet]
      linear_combination a1 * h2 - a2 * h1)].

-- The native statement is `∃! de : ZMod q × ZMod q, ...` with `de.1` and `de.2`. Natural Lean
-- has no `∃!` and no projections, so the natural statement names the two scalars and states
-- uniqueness in words.
example : type_of% (@schnorr_two_sigs_family q _) ↔
    type_of% (@LineDealing.schnorr_two_sigs_family q _) := by
  constructor
  · intro h a1 b1 c1 a2 b2 c2 s1 s2 hdet x'
    obtain ⟨d, e, he, hu⟩ := h a1 b1 c1 a2 b2 c2 s1 s2 x' hdet
    exact ⟨(d, e), he, fun ⟨u, v⟩ huv ↦ Prod.ext (hu u v huv).1 (hu u v huv).2⟩
  · intro h a1 b1 c1 a2 b2 c2 s1 s2 x' hdet
    obtain ⟨⟨d, e⟩, he, hu⟩ := h (c1 := c1) (c2 := c2) (s1 := s1) (s2 := s2) hdet x'
    exact ⟨d, e, he, fun u v huv ↦ Prod.mk.inj (hu (u, v) huv)⟩

Theorem "Item 5, two signatures do not determine x".
  Let a1, b1, c1, a2, b2, c2, d, e, x : ZMod(q).  If a1 · b2 - a2 · b1 ≠ 0 then
  there is some d', e', x' : ZMod(q) such that x' ≠ x and
    a1 · d' + b1 · e' + c1 · x' = a1 · d + b1 · e + c1 · x and
    a2 · d' + b2 · e' + c2 · x' = a2 · d + b2 · e + c2 · x.
  [schnorr_two_sigs_not_determine]

Proof.  Suppose that a1 · b2 - a2 · b1 ≠ 0.  Then
  there is some u, v : ZMod(q) such that
    a1 · u + b1 · v + c1 · (x + 1) = a1 · d + b1 · e + c1 · x and
    a2 · u + b2 · v + c2 · (x + 1) = a2 · d + b2 · e + c2 · x
  by [(obtain ⟨u, v, h, -⟩ := schnorr_two_sigs_family a1 b1 c1 a2 b2 c2
         (a1 * d + b1 * e + c1 * x) (a2 * d + b2 * e + c2 * x) (x + 1) ‹_›
       exact ⟨u, v, h⟩)].
  Also x + 1 ≠ x by [simp].  Hence there is some d', e', x' : ZMod(q) such that x' ≠ x and
    a1 · d' + b1 · e' + c1 · x' = a1 · d + b1 · e + c1 · x and
    a2 · d' + b2 · e' + c2 · x' = a2 · d + b2 · e + c2 · x
  by [exact ⟨u, v, x + 1, ‹x + 1 ≠ x›, ‹_ ∧ _›⟩].

example : type_of% (@schnorr_two_sigs_not_determine q _) ↔
    type_of% (@LineDealing.schnorr_two_sigs_not_determine q _) := by nl_same

Theorem "Item 5, extractor form".
  Let a1, b1, c1, a2, b2, c2 : ZMod(q).  If a1 · b2 - a2 · b1 ≠ 0 then
  there is no f : ZMod(q) → ZMod(q) → ZMod(q) such that
    for all d, e, x : ZMod(q), f(a1 · d + b1 · e + c1 · x, a2 · d + b2 · e + c2 · x) = x.
  [schnorr_two_sigs_no_extractor]

Proof.  Suppose that a1 · b2 - a2 · b1 ≠ 0.  Assume that
  there is some f : ZMod(q) → ZMod(q) → ZMod(q) such that
    for all d, e, x : ZMod(q), f(a1 · d + b1 · e + c1 · x, a2 · d + b2 · e + c2 · x) = x.
  Then there is some u, v, w : ZMod(q) such that w ≠ 0 and
    a1 · u + b1 · v + c1 · w = a1 · 0 + b1 · 0 + c1 · 0 and
    a2 · u + b2 · v + c2 · w = a2 · 0 + b2 · 0 + c2 · 0
  by [exact schnorr_two_sigs_not_determine a1 b1 c1 a2 b2 c2 0 0 0 ‹_›].
  Then f(a1 · u + b1 · v + c1 · w, a2 · u + b2 · v + c2 · w) = w by [apply_assumption].
  Also f(a1 · 0 + b1 · 0 + c1 · 0, a2 · 0 + b2 · 0 + c2 · 0) = 0 by [apply_assumption].
  Hence w = 0, which is a contradiction.  Thus
  there is no f : ZMod(q) → ZMod(q) → ZMod(q) such that
    for all d, e, x : ZMod(q), f(a1 · d + b1 · e + c1 · x, a2 · d + b2 · e + c2 · x) = x.

example : type_of% (@schnorr_two_sigs_no_extractor q _) ↔
    type_of% (@LineDealing.schnorr_two_sigs_no_extractor q _) := Iff.rfl

/-! `det3` is the native definition of `LineDealing.NonceReuse`.

`det3_eq_det` stays native: its statement contains the matrix literal `!![a1, b1, c1; ...]`,
which Natural Lean cannot write. -/

theorem det3_eq_det (a1 b1 c1 a2 b2 c2 a3 b3 c3 : ZMod q) :
    det3 a1 b1 c1 a2 b2 c2 a3 b3 c3 = Matrix.det !![a1, b1, c1; a2, b2, c2; a3, b3, c3] := by
  simp only [Matrix.det_fin_three, det3, Matrix.of_apply, Matrix.cons_val', Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val, Matrix.cons_val_fin_one]
  ring

example : type_of% (@det3_eq_det q _) = type_of% (@LineDealing.det3_eq_det q _) := rfl

Theorem "Item 5, three generic signatures determine x".
  Let a1, b1, c1, a2, b2, c2, a3, b3, c3, s1, s2, s3, d, e, x : ZMod(q).
  If det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) ≠ 0 and a1 · d + b1 · e + c1 · x = s1 and
  a2 · d + b2 · e + c2 · x = s2 and a3 · d + b3 · e + c3 · x = s3 then

    x = det3(a1, b1, s1, a2, b2, s2, a3, b3, s3) / det3(a1, b1, c1, a2, b2, c2, a3, b3, c3).
  [schnorr_three_sigs_determine]

Proof.  Suppose that det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) ≠ 0 and
  a1 · d + b1 · e + c1 · x = s1 and a2 · d + b2 · e + c2 · x = s2 and
  a3 · d + b3 · e + c3 · x = s3.  Then det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) ≠ 0.  Also

    x · det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) = det3(a1, b1, s1, a2, b2, s2, a3, b3, s3)
      by [(obtain ⟨-, h1, h2, h3⟩ := ‹_ ∧ _ ∧ _ ∧ _›
           unfold det3
           linear_combination (a2 * b3 - a3 * b2) * h1 - (a1 * b3 - a3 * b1) * h2
             + (a1 * b2 - a2 * b1) * h3)].

  Hence x = det3(a1, b1, s1, a2, b2, s2, a3, b3, s3) / det3(a1, b1, c1, a2, b2, c2, a3, b3, c3)
  by eq_div_iff.

example : type_of% (@schnorr_three_sigs_determine q _) ↔
    type_of% (@LineDealing.schnorr_three_sigs_determine q _) := by nl_same

Theorem "Three generic signatures leave one key".
  Let a1, b1, c1, a2, b2, c2, a3, b3, c3, d, e, x, d', e', x' : ZMod(q).
  If det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) ≠ 0 and
  a1 · d + b1 · e + c1 · x = a1 · d' + b1 · e' + c1 · x' and
  a2 · d + b2 · e + c2 · x = a2 · d' + b2 · e' + c2 · x' and
  a3 · d + b3 · e + c3 · x = a3 · d' + b3 · e' + c3 · x' then x = x'.
  [schnorr_three_sigs_unique]

Proof.  Suppose that det3(a1, b1, c1, a2, b2, c2, a3, b3, c3) ≠ 0 and
  a1 · d + b1 · e + c1 · x = a1 · d' + b1 · e' + c1 · x' and
  a2 · d + b2 · e + c2 · x = a2 · d' + b2 · e' + c2 · x' and
  a3 · d + b3 · e + c3 · x = a3 · d' + b3 · e' + c3 · x'.  Then

    x = det3(a1, b1, a1 · d' + b1 · e' + c1 · x', a2, b2, a2 · d' + b2 · e' + c2 · x',
          a3, b3, a3 · d' + b3 · e' + c3 · x') / det3(a1, b1, c1, a2, b2, c2, a3, b3, c3)
          by [nl_apply schnorr_three_sigs_determine]
      = x' by [(symm; nl_apply schnorr_three_sigs_determine (d := d') (e := e'))].

example : type_of% (@schnorr_three_sigs_unique q _) ↔
    type_of% (@LineDealing.schnorr_three_sigs_unique q _) := by nl_same

end LineDealingNatural
