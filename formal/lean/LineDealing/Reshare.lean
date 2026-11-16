import LineDealing.Ecdsa

/-!
# Resharing preserves the constant terms

Item 7 (SCHEME section 5). Old node `i ∈ Q` deals a sharing of its share. The new shares and the
new commitments are the Lagrange combination over `Q`.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- The combined polynomial `Σ_{i ∈ Q} λ_i • g_i` of a resharing. -/
noncomputable def resharePoly (Q : Finset (ZMod q)) (gs : ZMod q → (ZMod q)[X]) : (ZMod q)[X] :=
  ∑ i ∈ Q, C (lam Q i) * gs i

/-- The new share of node `j` is `v'_j = Σ_{i ∈ Q} λ_i * g_i(j)`. -/
theorem resharePoly_eval (Q : Finset (ZMod q)) (gs : ZMod q → (ZMod q)[X]) (j : ZMod q) :
    (resharePoly Q gs).eval j = ∑ i ∈ Q, lam Q i * (gs i).eval j := by
  simp [resharePoly, eval_finsetSum]

/-- **Item 7, scalar form.** If each dealer `i ∈ Q` shares its own share `p(i)`, the combined
polynomial has constant term `p(0)`, the original secret. -/
theorem reshare_constant {t : ℕ} (Q : Finset (ZMod q)) (hQ : #Q = t) {p : (ZMod q)[X]}
    (hp : p.degree < t) (gs : ZMod q → (ZMod q)[X]) (hgs : ∀ i ∈ Q, (gs i).eval 0 = p.eval i) :
    (resharePoly Q gs).eval 0 = p.eval 0 := by
  subst hQ
  rw [resharePoly_eval, ← sum_lam_mul_eval Q hp]
  exact sum_congr rfl fun i hi ↦ by rw [hgs i hi]

/-- The combined polynomial has degree below the new threshold `t'`. -/
theorem resharePoly_degree_lt (Q : Finset (ZMod q)) (gs : ZMod q → (ZMod q)[X]) {t' : ℕ}
    (hgs : ∀ i ∈ Q, (gs i).degree < t') : (resharePoly Q gs).degree < t' := by
  refine lt_of_le_of_lt (degree_sum_le _ _) ?_
  rw [Finset.sup_lt_iff (WithBot.bot_lt_coe _)]
  exact fun i hi ↦ lt_of_le_of_lt (by rw [C_mul']; exact degree_smul_le _ _) (hgs i hi)

/-- The new commitment: the same Lagrange combination of the dealers' commitments. -/
noncomputable def reshareCommit (Q : Finset (ZMod q)) (Cd : ZMod q → ℕ → G) (u : ℕ) : G :=
  ∑ i ∈ Q, lam Q i • Cd i u

/-- **Item 7, commitment form.** Each dealer's constant-term commitment is forced to
`Eval(C_old, i)`. Then the new constant-term commitment equals the old one, for any old
commitment `Cold` and with no assumption on what the dealers shared. -/
theorem reshare_commit_constant (Q : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #Q)
    (Cold : ℕ → G) (Cd : ZMod q → ℕ → G) (hCd : ∀ i ∈ Q, Cd i 0 = feldmanEval t Cold i) :
    reshareCommit Q Cd 0 = Cold 0 := by
  rw [reshareCommit, sum_congr rfl fun i hi ↦ by rw [hCd i hi],
    sum_lam_smul_feldmanEval Q ht0 ht]

/-- Item 7 for open ECDSA: after a resharing the committed constant terms are still `g` and `X`
in base `R`. -/
theorem reshare_keeps_g_and_X (Q : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t) (ht : t ≤ #Q)
    {g X : G} (Cw Cm : ℕ → G) (hCw : Cw 0 = g) (hCm : Cm 0 = X) (Dw Dm : ZMod q → ℕ → G)
    (hDw : ∀ i ∈ Q, Dw i 0 = feldmanEval t Cw i) (hDm : ∀ i ∈ Q, Dm i 0 = feldmanEval t Cm i) :
    reshareCommit Q Dw 0 = g ∧ reshareCommit Q Dm 0 = X :=
  ⟨by rw [reshare_commit_constant Q ht0 ht Cw Dw hDw, hCw],
    by rw [reshare_commit_constant Q ht0 ht Cm Dm hDm, hCm]⟩

/-- Feldman evaluation commutes with the resharing combination. -/
theorem feldmanEval_reshareCommit (Q : Finset (ZMod q)) (Cd : ZMod q → ℕ → G) (t' : ℕ)
    (j : ZMod q) :
    feldmanEval t' (reshareCommit Q Cd) j = ∑ i ∈ Q, lam Q i • feldmanEval t' (Cd i) j := by
  simp only [feldmanEval, reshareCommit, smul_sum]
  rw [sum_comm]
  exact sum_congr rfl fun i _ ↦ sum_congr rfl fun u _ ↦ smul_comm _ _ _

/-- New shares verify against the new commitments: if every sub-share `v i j` passes its
dealer's Feldman check in base `B`, the combined share passes the check of the combined
commitment. -/
theorem reshare_share_check (Q : Finset (ZMod q)) (B : G) (Cd : ZMod q → ℕ → G) (t' : ℕ)
    (v : ZMod q → ZMod q → ZMod q) (j : ZMod q)
    (hv : ∀ i ∈ Q, v i j • B = feldmanEval t' (Cd i) j) :
    (∑ i ∈ Q, lam Q i * v i j) • B = feldmanEval t' (reshareCommit Q Cd) j := by
  rw [feldmanEval_reshareCommit, sum_lam_mul_smul]
  exact sum_congr rfl fun i hi ↦ by rw [hv i hi]

/-- Item 7 end to end for open ECDSA: partials that pass the public check against the reshared
commitments interpolate, over any `t'` new ids, to a scalar with `s • R = h • g + r • X`. -/
theorem reshare_then_sign_sound (Q S : Finset (ZMod q)) {t t' : ℕ} (ht0 : 0 < t) (ht : t ≤ #Q)
    (ht0' : 0 < t') (ht' : t' ≤ #S) {g X R : G} (h r : ZMod q) (Cw Cm : ℕ → G)
    (hCw : Cw 0 = g) (hCm : Cm 0 = X) (Dw Dm : ZMod q → ℕ → G)
    (hDw : ∀ i ∈ Q, Dw i 0 = feldmanEval t Cw i) (hDm : ∀ i ∈ Q, Dm i 0 = feldmanEval t Cm i)
    (σ : ZMod q → ZMod q)
    (hchk : ∀ j ∈ S, σ j • R = h • feldmanEval t' (reshareCommit Q Dw) j
      + r • feldmanEval t' (reshareCommit Q Dm) j) :
    (∑ j ∈ S, lam S j * σ j) • R = h • g + r • X :=
  have hc := reshare_keeps_g_and_X Q ht0 ht Cw Cm hCw hCm Dw Dm hDw hDm
  partial_check_sound S ht0' ht' h r _ _ hc.1 hc.2 σ hchk

end LineDealing
