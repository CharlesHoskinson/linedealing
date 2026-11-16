import LineDealing.Gaps
import LineDealingNatural.Ecdsa

/-!
# Line dealing in Natural Lean: algebra behind two gaps of PROOF-CHECK.md

Port of `formal/lean/LineDealing/Gaps.lean`.
-/

open LineDealing (ecdsaVerify dleqVerify)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

/-! `dleqVerify` is the native definition of `LineDealing.Gaps`. -/

Theorem "Completeness of the equal-exponent proof".
  Let g, g' : G.  Let β, a, c : ZMod(q).

    dleqVerify(g, g', β • g, β • g', a • g, a • g', c, a + c · β) is true.  [dleq_complete]

Proof.  Let g, g' : G and let β, a, c : ZMod(q).  Then

    (a + c · β) • g = a • g + (c · β) • g by add_smul
                    = a • g + c • β • g by [rw [mul_smul]].

  Also

    (a + c · β) • g' = a • g' + (c · β) • g' by add_smul
                     = a • g' + c • β • g' by [rw [mul_smul]].

  Hence dleqVerify(g, g', β • g, β • g', a • g, a • g', c, a + c · β) is true by dleqVerify.

example : type_of% (@dleq_complete q _ G _ _) ↔
    type_of% (@LineDealing.dleq_complete q _ G _ _) := Iff.rfl

Theorem "Special soundness of the equal-exponent proof".
  Let g, g', v, v', A, A' : G.  Let c1, c2, z1, z2 : ZMod(q).
  If c1 ≠ c2 and dleqVerify(g, g', v, v', A, A', c1, z1) is true and
  dleqVerify(g, g', v, v', A, A', c2, z2) is true then
  v = ((z1 - z2) / (c1 - c2)) • g and v' = ((z1 - z2) / (c1 - c2)) • g'.  [dleq_special_sound]

Proof.  Suppose that c1 ≠ c2 and dleqVerify(g, g', v, v', A, A', c1, z1) is true and
  dleqVerify(g, g', v, v', A, A', c2, z2) is true.  Then c1 - c2 ≠ 0 by sub_ne_zero.
  Also z1 • g = A + c1 • v and z1 • g' = A' + c1 • v' by dleqVerify.
  Also z2 • g = A + c2 • v and z2 • g' = A' + c2 • v' by dleqVerify.  First,

    (z1 - z2) • g = z1 • g - z2 • g by sub_smul
                  = (A + c1 • v) - (A + c2 • v)
                  = c1 • v - c2 • v by [abel]
                  = (c1 - c2) • v by sub_smul.

  Hence

    ((z1 - z2) / (c1 - c2)) • g
      = (c1 - c2)⁻¹ • (z1 - z2) • g by [rw [div_eq_inv_mul, mul_smul]]
      = (c1 - c2)⁻¹ • (c1 - c2) • v
      = v by [rw [smul_smul, inv_mul_cancel₀ ‹c1 - c2 ≠ 0›, one_smul]].

  Second,

    (z1 - z2) • g' = z1 • g' - z2 • g' by sub_smul
                   = (A' + c1 • v') - (A' + c2 • v')
                   = c1 • v' - c2 • v' by [abel]
                   = (c1 - c2) • v' by sub_smul.

  Hence

    ((z1 - z2) / (c1 - c2)) • g'
      = (c1 - c2)⁻¹ • (z1 - z2) • g' by [rw [div_eq_inv_mul, mul_smul]]
      = (c1 - c2)⁻¹ • (c1 - c2) • v'
      = v' by [rw [smul_smul, inv_mul_cancel₀ ‹c1 - c2 ≠ 0›, one_smul]].

  Therefore v = ((z1 - z2) / (c1 - c2)) • g and v' = ((z1 - z2) / (c1 - c2)) • g'.

example : type_of% (@dleq_special_sound q _ G _ _) ↔
    type_of% (@LineDealing.dleq_special_sound q _ G _ _) := by nl_same

Theorem "Decryption without the key".
  Let g, ustar : G.  Let β, σ', lam' : ZMod(q).

    β • (ustar + σ' • g) = β • (ustar + lam' • g) + (σ' - lam') • (β • g).  [dh_from_enc_proof]

Proof.  By [(intros; module)].

example : type_of% (@dh_from_enc_proof q _ G _ _) ↔
    type_of% (@LineDealing.dh_from_enc_proof q _ G _ _) := Iff.rfl

Theorem "The key holder computes the same value".
  Let g : G.  Let α, β : ZMod(q).  α • (β • g) = β • (α • g).  [dh_comm]

Proof.  By smul_comm.

example : type_of% (@dh_comm q _ G _ _) ↔ type_of% (@LineDealing.dh_comm q _ G _ _) :=
  Iff.rfl

Theorem "A sound ephemeral-key proof implies simulated decryption".
  Let g, ustar, v, v', A, A' : G.  Let α, σ', lam', c1, c2, z1, z2 : ZMod(q).
  If α • g = ustar + σ' • g and c1 ≠ c2 and
  dleqVerify(g, ustar + lam' • g, v, v', A, A', c1, z1) is true and
  dleqVerify(g, ustar + lam' • g, v, v', A, A', c2, z2) is true then

    α • v = v' + (σ' - lam') • v.  [decryption_value_from_transcripts]

Proof.  Suppose that α • g = ustar + σ' • g and c1 ≠ c2 and
  dleqVerify(g, ustar + lam' • g, v, v', A, A', c1, z1) is true and
  dleqVerify(g, ustar + lam' • g, v, v', A, A', c2, z2) is true.  Then
  v = ((z1 - z2) / (c1 - c2)) • g and v' = ((z1 - z2) / (c1 - c2)) • (ustar + lam' • g)
  by [nl_apply dleq_special_sound (G := G) g (ustar + lam' • g) v v' A A' c1 c2 z1 z2].  Hence

    α • v = α • ((z1 - z2) / (c1 - c2)) • g
          = ((z1 - z2) / (c1 - c2)) • α • g by smul_comm
          = ((z1 - z2) / (c1 - c2)) • (ustar + σ' • g)
          = ((z1 - z2) / (c1 - c2)) • (ustar + lam' • g)
              + (σ' - lam') • ((z1 - z2) / (c1 - c2)) • g by dh_from_enc_proof
          = v' + (σ' - lam') • v.

example : type_of% (@decryption_value_from_transcripts q _ G _ _) ↔
    type_of% (@LineDealing.decryption_value_from_transcripts q _ G _ _) := by nl_same

Theorem "Multiplicative re-randomization, equation".
  Let g, X, R' : G.  Let w0, μ0, δ, h, r : ZMod(q).
  If δ ≠ 0 and w0 • R' = g and μ0 • R' = X then

    (δ⁻¹ · (h · w0 + r · μ0)) • (δ • R') = h • g + r • X.  [rerand_mul_equation]

Proof.  Suppose that δ ≠ 0 and w0 • R' = g and μ0 • R' = X.  Then δ ≠ 0.  Hence

    (δ⁻¹ · (h · w0 + r · μ0)) • (δ • R')
      = (δ⁻¹ · (h · w0 + r · μ0) · δ) • R' by smul_smul
      = (h · w0 + r · μ0) • R' by [(congr 1; field_simp)]
      = h • g + r • X by open_ecdsa_equation.

example : type_of% (@rerand_mul_equation q _ G _ _) ↔
    type_of% (@LineDealing.rerand_mul_equation q _ G _ _) := by nl_same

Theorem "Multiplicative re-randomization, verifier form".
  Let g, X, R' : G.  Let w0, μ0, δ, h, r : ZMod(q).
  If δ ≠ 0 and w0 • R' = g and μ0 • R' = X and δ⁻¹ · (h · w0 + r · μ0) ≠ 0 then
  ecdsaVerify(g, X, δ • R', h, r, δ⁻¹ · (h · w0 + r · μ0)) is true.  [rerand_mul_verifies]

Proof.  Suppose that δ ≠ 0 and w0 • R' = g and μ0 • R' = X and
  δ⁻¹ · (h · w0 + r · μ0) ≠ 0.  Then
  (δ⁻¹ · (h · w0 + r · μ0)) • (δ • R') = h • g + r • X by rerand_mul_equation.  Hence
  ecdsaVerify(g, X, δ • R', h, r, δ⁻¹ · (h · w0 + r · μ0)) is true by ecdsaVerify_iff.

example : type_of% (@rerand_mul_verifies q _ G _ _) ↔
    type_of% (@LineDealing.rerand_mul_verifies q _ G _ _) := by nl_same

Theorem "The commitments move with δ".
  Let R', Wi, Mi : G.  Let δ, σi, h, r : ZMod(q).
  If δ ≠ 0 and σi • R' = h • Wi + r • Mi then

    (δ⁻¹ · σi) • (δ • R') = h • Wi + r • Mi.  [rerand_mul_partial_check]

Proof.  Suppose that δ ≠ 0 and σi • R' = h • Wi + r • Mi.  Then δ ≠ 0.  Hence

    (δ⁻¹ · σi) • (δ • R') = (δ⁻¹ · σi · δ) • R' by smul_smul
                          = σi • R' by [(congr 1; field_simp)]
                          = h • Wi + r • Mi.

example : type_of% (@rerand_mul_partial_check q _ G _ _) ↔
    type_of% (@LineDealing.rerand_mul_partial_check q _ G _ _) := by nl_same

end LineDealingNatural
