import LineDealing.Ecdsa

/-!
# Nonce reuse

Item 5. ECDSA: two signatures under one `R` give `k` and `x`. Two-nonce Schnorr: a signature on
a slot is `s = a * d + b * e + c * x` with public `a = σ`, `b = σ * ρ`, `c`. Two such signatures
leave a one-parameter family of `(d, e, x)`; three with a nonzero determinant fix `x`.
-/

open Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- **Item 5, ECDSA nonce reuse.** Two signatures with the same `R` and `r ≠ 0` on `h1 ≠ h2`
have `s1 ≠ s2` and determine `k = (h1 - h2) / (s1 - s2)` and `x = (s1 * k - h1) / r`. -/
theorem ecdsa_nonce_reuse {g : G} (hg : g ≠ 0) {k x r h1 h2 s1 s2 : ZMod q} {R X : G}
    (hR : R = k • g) (hX : X = x • g) (hr : r ≠ 0) (hh : h1 ≠ h2)
    (e1 : s1 • R = h1 • g + r • X) (e2 : s2 • R = h2 • g + r • X) :
    s1 ≠ s2 ∧ k = (h1 - h2) / (s1 - s2) ∧ x = (s1 * k - h1) / r := by
  subst hR hX
  rw [smul_smul, smul_smul, ← add_smul] at e1 e2
  have f1 : s1 * k = h1 + r * x := smul_left_inj' hg e1
  have f2 : s2 * k = h2 + r * x := smul_left_inj' hg e2
  have hs : s1 ≠ s2 := by
    rintro rfl
    exact hh (by linear_combination f2 - f1)
  refine ⟨hs, ?_, ?_⟩
  · rw [eq_div_iff (sub_ne_zero.mpr hs)]
    linear_combination f1 - f2
  · rw [eq_div_iff hr]
    linear_combination -f1

/-- One-nonce Schnorr, for contrast: two signatures `s_j = d + c_j * x` with `c1 ≠ c2` give
`x = (s1 - s2) / (c1 - c2)`. -/
theorem schnorr_one_nonce_reuse {d x c1 c2 s1 s2 : ZMod q} (hc : c1 ≠ c2) (h1 : s1 = d + c1 * x)
    (h2 : s2 = d + c2 * x) : x = (s1 - s2) / (c1 - c2) := by
  rw [eq_div_iff (sub_ne_zero.mpr hc)]
  linear_combination h2 - h1

/-- **Item 5, two-nonce Schnorr, the one-parameter family.** Given two signatures on one slot
with `a1 * b2 - a2 * b1 ≠ 0`, every candidate key `x'` has exactly one nonce pair `(d', e')`
that explains both signatures. -/
theorem schnorr_two_sigs_family {a1 b1 c1 a2 b2 c2 s1 s2 : ZMod q}
    (hdet : a1 * b2 - a2 * b1 ≠ 0) (x' : ZMod q) :
    ∃! de : ZMod q × ZMod q,
      a1 * de.1 + b1 * de.2 + c1 * x' = s1 ∧ a2 * de.1 + b2 * de.2 + c2 * x' = s2 := by
  refine ⟨(((s1 - c1 * x') * b2 - (s2 - c2 * x') * b1) / (a1 * b2 - a2 * b1),
    (a1 * (s2 - c2 * x') - a2 * (s1 - c1 * x')) / (a1 * b2 - a2 * b1)), ⟨?_, ?_⟩, ?_⟩
  · rw [← mul_div_assoc, ← mul_div_assoc, ← add_div, ← eq_sub_iff_add_eq, div_eq_iff hdet]
    ring
  · rw [← mul_div_assoc, ← mul_div_assoc, ← add_div, ← eq_sub_iff_add_eq, div_eq_iff hdet]
    ring
  · rintro ⟨d, e⟩ ⟨h1, h2⟩
    simp only at h1 h2
    refine Prod.ext ?_ ?_
    · simp only
      rw [eq_div_iff hdet]
      linear_combination b2 * h1 - b1 * h2
    · simp only
      rw [eq_div_iff hdet]
      linear_combination a1 * h2 - a2 * h1

/-- **Item 5, two signatures do not determine `x`.** For the real `(d, e, x)` there is another
triple with a different key that gives the same two signatures. -/
theorem schnorr_two_sigs_not_determine {a1 b1 c1 a2 b2 c2 : ZMod q}
    (hdet : a1 * b2 - a2 * b1 ≠ 0) (d e x : ZMod q) :
    ∃ d' e' x', x' ≠ x ∧
      a1 * d' + b1 * e' + c1 * x' = a1 * d + b1 * e + c1 * x ∧
      a2 * d' + b2 * e' + c2 * x' = a2 * d + b2 * e + c2 * x := by
  obtain ⟨⟨d', e'⟩, ⟨h1, h2⟩, -⟩ := schnorr_two_sigs_family (c1 := c1) (c2 := c2)
    (s1 := a1 * d + b1 * e + c1 * x) (s2 := a2 * d + b2 * e + c2 * x) hdet (x + 1)
  exact ⟨d', e', x + 1, by simp, h1, h2⟩

/-- Item 5, extractor form: no function of two signature scalars returns the key for all
`(d, e, x)`. The public coefficients are fixed, so the function may depend on them. -/
theorem schnorr_two_sigs_no_extractor {a1 b1 c1 a2 b2 c2 : ZMod q}
    (hdet : a1 * b2 - a2 * b1 ≠ 0) :
    ¬ ∃ f : ZMod q → ZMod q → ZMod q,
      ∀ d e x, f (a1 * d + b1 * e + c1 * x) (a2 * d + b2 * e + c2 * x) = x := by
  rintro ⟨f, hf⟩
  obtain ⟨d', e', x', hx, h1, h2⟩ :=
    schnorr_two_sigs_not_determine (c1 := c1) (c2 := c2) hdet 0 0 0
  have := hf d' e' x'
  rw [h1, h2, hf 0 0 0] at this
  exact hx this.symm

/-- The determinant of the three signature rows `(a_j, b_j, c_j)`. -/
def det3 (a1 b1 c1 a2 b2 c2 a3 b3 c3 : ZMod q) : ZMod q :=
  a1 * (b2 * c3 - b3 * c2) - b1 * (a2 * c3 - a3 * c2) + c1 * (a2 * b3 - a3 * b2)

/-- `det3` is the matrix determinant. -/
theorem det3_eq_det (a1 b1 c1 a2 b2 c2 a3 b3 c3 : ZMod q) :
    det3 a1 b1 c1 a2 b2 c2 a3 b3 c3 = Matrix.det !![a1, b1, c1; a2, b2, c2; a3, b3, c3] := by
  simp only [Matrix.det_fin_three, det3, Matrix.of_apply, Matrix.cons_val', Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val, Matrix.cons_val_fin_one]
  ring

/-- **Item 5, three generic signatures determine `x`.** If the three coefficient rows have a
nonzero determinant, Cramer's rule gives the key from public values. -/
theorem schnorr_three_sigs_determine {a1 b1 c1 a2 b2 c2 a3 b3 c3 s1 s2 s3 d e x : ZMod q}
    (hdet : det3 a1 b1 c1 a2 b2 c2 a3 b3 c3 ≠ 0)
    (h1 : a1 * d + b1 * e + c1 * x = s1) (h2 : a2 * d + b2 * e + c2 * x = s2)
    (h3 : a3 * d + b3 * e + c3 * x = s3) :
    x = det3 a1 b1 s1 a2 b2 s2 a3 b3 s3 / det3 a1 b1 c1 a2 b2 c2 a3 b3 c3 := by
  rw [eq_div_iff hdet]
  unfold det3
  linear_combination (a2 * b3 - a3 * b2) * h1 - (a1 * b3 - a3 * b1) * h2
    + (a1 * b2 - a2 * b1) * h3

/-- Three generic signatures leave one key: two explanations of the same three signatures have
the same `x`. -/
theorem schnorr_three_sigs_unique {a1 b1 c1 a2 b2 c2 a3 b3 c3 d e x d' e' x' : ZMod q}
    (hdet : det3 a1 b1 c1 a2 b2 c2 a3 b3 c3 ≠ 0)
    (h1 : a1 * d + b1 * e + c1 * x = a1 * d' + b1 * e' + c1 * x')
    (h2 : a2 * d + b2 * e + c2 * x = a2 * d' + b2 * e' + c2 * x')
    (h3 : a3 * d + b3 * e + c3 * x = a3 * d' + b3 * e' + c3 * x') : x = x' := by
  rw [schnorr_three_sigs_determine hdet h1 h2 h3,
    ← schnorr_three_sigs_determine hdet (d := d') (e := e') (x := x') rfl rfl rfl]

end LineDealing
