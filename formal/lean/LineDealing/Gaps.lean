import LineDealing.Ecdsa

/-!
# Algebra behind two gaps of PROOF-CHECK.md

PROOF-CHECK.md section 8 lists what closes each gap. Two entries have an algebraic core.

* Entry 3, share encryption. The ephemeral-key proof of ePrint 2022/506 section 4.1 is a proof
  that `v = β • g` and `v' = β • g'` have the same exponent, for `g' = H_G(ad, v)`. This file
  proves completeness and special soundness of the equal-exponent proof and the identity
  `dh(u, v) = v' + (σ - λ) • v` with which the reduction of Theorem 2 answers decryption-proof
  queries without the secret key.
* Entry 4, multiplicative re-randomization `R = δ • R'`. This file proves that the dealt line
  still gives a valid signature equation after scaling by `δ⁻¹`.

These are the calculations only. The security statements of both entries stay open.
-/

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-! ## The equal-exponent proof -/

/-- The verifier of the equal-exponent proof for the statement `(g, g', v, v')`: commitment
`(A, A')`, challenge `c`, response `z`. -/
def dleqVerify (g g' v v' A A' : G) (c z : ZMod q) : Prop :=
  z • g = A + c • v ∧ z • g' = A' + c • v'

/-- **Completeness.** The honest prover with witness `β` and commitment randomness `a` passes
for every challenge. -/
theorem dleq_complete (g g' : G) (β a c : ZMod q) :
    dleqVerify g g' (β • g) (β • g') (a • g) (a • g') c (a + c * β) := by
  constructor <;> rw [add_smul, mul_smul]

/-- **Special soundness.** Two accepting transcripts with one commitment and different
challenges give the scalar `β = (z1 - z2) / (c1 - c2)` with `v = β • g` and `v' = β • g'`.
No relation between `g` and `g'` is assumed. -/
theorem dleq_special_sound {g g' v v' A A' : G} {c1 c2 z1 z2 : ZMod q} (hc : c1 ≠ c2)
    (h1 : dleqVerify g g' v v' A A' c1 z1) (h2 : dleqVerify g g' v v' A A' c2 z2) :
    v = ((z1 - z2) / (c1 - c2)) • g ∧ v' = ((z1 - z2) / (c1 - c2)) • g' := by
  have hc' : c1 - c2 ≠ 0 := sub_ne_zero.mpr hc
  have key : ∀ {B P C : G} {y1 y2 : ZMod q}, y1 • B = C + c1 • P → y2 • B = C + c2 • P →
      P = ((y1 - y2) / (c1 - c2)) • B := by
    intro B P C y1 y2 e1 e2
    have e : (y1 - y2) • B = (c1 - c2) • P := by
      rw [sub_smul, sub_smul, e1, e2]; abel
    rw [div_eq_inv_mul, mul_smul, e, smul_smul, inv_mul_cancel₀ hc', one_smul]
  exact ⟨key h1.1 h2.1, key h1.2 h2.2⟩

/-- **Decryption without the key (2022/506, proof of Theorem 2).** The reduction programs
`g' = ustar + λ • g` and the honest public key `u = ustar + σ • g`. For an ephemeral key
`v = β • g` with `v' = β • g'`, the Diffie-Hellman value `β • u` equals `v' + (σ - λ) • v`. The
right side uses public values and the reduction's own `σ`, `λ` only. -/
theorem dh_from_enc_proof {g ustar : G} {β σ' lam' : ZMod q} :
    β • (ustar + σ' • g) = β • (ustar + lam' • g) + (σ' - lam') • (β • g) := by
  simp only [smul_add, smul_smul]
  rw [add_assoc, ← add_smul]
  congr 2
  ring

/-- The same value is what the key holder computes: with `u = α • g` and `v = β • g`,
`α • v = β • u`. -/
theorem dh_comm (g : G) (α β : ZMod q) : α • (β • g) = β • (α • g) := smul_comm α β g

/-- **Sound ephemeral-key proof implies simulated decryption.** If `(v, v')` has two accepting
transcripts for the bases `g` and `g' = ustar + λ • g`, and the honest key is
`u = α • g = ustar + σ • g`, then the decryption value `α • v` equals `v' + (σ - λ) • v`. -/
theorem decryption_value_from_transcripts {g ustar v v' A A' : G} {α σ' lam' c1 c2 z1 z2 : ZMod q}
    (hu : α • g = ustar + σ' • g) (hc : c1 ≠ c2)
    (h1 : dleqVerify g (ustar + lam' • g) v v' A A' c1 z1)
    (h2 : dleqVerify g (ustar + lam' • g) v v' A A' c2 z2) :
    α • v = v' + (σ' - lam') • v := by
  obtain ⟨hv, hv'⟩ := dleq_special_sound hc h1 h2
  set β := (z1 - z2) / (c1 - c2)
  rw [hv', hv, dh_comm, hu]
  exact dh_from_enc_proof

/-! ## Multiplicative re-randomization -/

/-- **Multiplicative re-randomization, equation.** The dealt line has constant terms `w0`, `μ0`
with `w0 • R' = g` and `μ0 • R' = X`. For `R = δ • R'` with `δ ≠ 0`, the scalar
`s = δ⁻¹ * (h * w0 + r * μ0)` satisfies `s • R = h • g + r • X`. Each partial is scaled by the
public `δ⁻¹`, so the shares stay linear. -/
theorem rerand_mul_equation {g X R' : G} {w0 μ0 δ : ZMod q} (hδ : δ ≠ 0) (hw : w0 • R' = g)
    (hμ : μ0 • R' = X) (h r : ZMod q) :
    (δ⁻¹ * (h * w0 + r * μ0)) • (δ • R') = h • g + r • X := by
  rw [smul_smul, mul_comm, ← mul_assoc, mul_inv_cancel₀ hδ, one_mul, add_smul, mul_smul,
    mul_smul, hw, hμ]

/-- The same in verifier form, for a nonzero result. -/
theorem rerand_mul_verifies {g X R' : G} {w0 μ0 δ : ZMod q} (hδ : δ ≠ 0) (hw : w0 • R' = g)
    (hμ : μ0 • R' = X) (h r : ZMod q) (hs : δ⁻¹ * (h * w0 + r * μ0) ≠ 0) :
    ecdsaVerify g X (δ • R') h r (δ⁻¹ * (h * w0 + r * μ0)) :=
  (ecdsaVerify_iff hs).mpr (rerand_mul_equation hδ hw hμ h r)

/-- The commitments move with `δ`: a partial `σ_i` that passes the public check in base `R'`
passes it, scaled by `δ⁻¹`, in base `R = δ • R'` against the same evaluations `W_i`, `M_i`. -/
theorem rerand_mul_partial_check {R' Wi Mi : G} {δ σi h r : ZMod q} (hδ : δ ≠ 0)
    (hchk : σi • R' = h • Wi + r • Mi) : (δ⁻¹ * σi) • (δ • R') = h • Wi + r • Mi := by
  rw [smul_smul, mul_comm, ← mul_assoc, mul_inv_cancel₀ hδ, one_mul, hchk]

end LineDealing
