import LineDealing.Ecdsa

/-!
# Sealed points: the committed secret is a signature

Item 4. The challenge `c` and the sighash `h` are free scalars; hashing is not modelled.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- The Schnorr verifier's group equation `s • g = R + c • X`. The challenge `c` is the suite
hash of `(R, X, m)` in the scheme and a free scalar here. -/
def schnorrVerify (g X R : G) (c s : ZMod q) : Prop :=
  s • g = R + c • X

/-- Shares that pass the Feldman check `σ i • B = Eval(F_0, C, i)` at `t` or more ids
interpolate to a scalar `s` with `s • B = F_0`. `C` is any family of points. -/
theorem sealed_release_sound (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s) (B : G)
    (C : ℕ → G) (σ : ZMod q → ZMod q) (hchk : ∀ i ∈ s, σ i • B = feldmanEval t C i) :
    (∑ i ∈ s, lam s i * σ i) • B = C 0 := by
  rw [sum_lam_mul_smul, sum_congr rfl fun i hi ↦ by rw [hchk i hi],
    sum_lam_smul_feldmanEval s ht0 ht]

/-- Feldman commitments fix the polynomial's constant term: if the shares of a polynomial `p` of
degree below `t` pass the check at `t` ids, then `p(0) • B` is the constant-term commitment. -/
theorem feldman_binds_constant (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (hs : #s = t) (B : G)
    (C : ℕ → G) {p : (ZMod q)[X]} (hp : p.degree < t)
    (hchk : ∀ i ∈ s, p.eval i • B = feldmanEval t C i) : p.eval 0 • B = C 0 := by
  subst hs
  rw [← sum_lam_mul_eval s hp]
  exact sealed_release_sound s ht0 le_rfl B C _ hchk

/-- **Item 4, Schnorr form.** If `p(0) • g = R + c • X` then `(R, p(0))` satisfies the Schnorr
verification equation. This is the definition unfolded. -/
theorem sealed_schnorr_binding {g X R : G} {c p0 : ZMod q} (h : p0 • g = R + c • X) :
    schnorrVerify g X R c p0 := h

/-- Item 4, Schnorr form, from the checks a node runs: the implied constant term is
`F_0 = R + c • X`, the shares pass the Feldman check in base `g`, so the interpolated scalar is
a Schnorr signature. -/
theorem sealed_schnorr_release (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    {g X R : G} (c : ZMod q) (C : ℕ → G) (hC : C 0 = R + c • X) (σ : ZMod q → ZMod q)
    (hchk : ∀ i ∈ s, σ i • g = feldmanEval t C i) :
    schnorrVerify g X R c (∑ i ∈ s, lam s i * σ i) := by
  rw [schnorrVerify, sealed_release_sound s ht0 ht g C σ hchk, hC]

/-- **Item 4, ECDSA form.** If `p(0) • R = h • g + r • X` and that point is not the identity
(Step A check 6), then `p(0) ≠ 0` and `(r, p(0))` passes the ECDSA verifier equation. -/
theorem sealed_ecdsa_binding {g X R : G} {h r p0 : ZMod q} (he : p0 • R = h • g + r • X)
    (hF : h • g + r • X ≠ 0) : p0 ≠ 0 ∧ ecdsaVerify g X R h r p0 := by
  have hp : p0 ≠ 0 := by
    rintro rfl
    rw [zero_smul] at he
    exact hF he.symm
  exact ⟨hp, (ecdsaVerify_iff hp).mpr he⟩

/-- Item 4, ECDSA form, from the checks a node runs: commitments in base `R`, implied constant
term `F_0 = h • g + r • X ≠ 0`, shares pass the Feldman check, so the interpolated scalar is an
ECDSA signature. -/
theorem sealed_ecdsa_release (s : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #s)
    {g X R : G} (h r : ZMod q) (C : ℕ → G) (hC : C 0 = h • g + r • X)
    (hF : h • g + r • X ≠ 0) (σ : ZMod q → ZMod q)
    (hchk : ∀ i ∈ s, σ i • R = feldmanEval t C i) :
    ecdsaVerify g X R h r (∑ i ∈ s, lam s i * σ i) :=
  (sealed_ecdsa_binding (by rw [sealed_release_sound s ht0 ht R C σ hchk, hC]) hF).2

/-- The honest sealed ECDSA scalar `s = k⁻¹ * (h + r * x)` satisfies `s • R = h • g + r • X`
(SCHEME 3.3, "this equals `s • R`"). -/
theorem sealed_ecdsa_honest {g : G} {k x h r : ZMod q} (hk : k ≠ 0) :
    (k⁻¹ * (h + r * x)) • (k • g) = h • g + r • (x • g) := by
  rw [smul_smul, smul_smul, ← add_smul]
  congr 1
  field_simp

end LineDealing
