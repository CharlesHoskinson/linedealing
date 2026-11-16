import LineDealing.Basic
import LineDealing.Ecdsa

/-!
# Split-line dealing: the n-shard key split

`design/enhancement/DESIGN.md` §2.2, §3.1 and §4.2 to §4.4, DECISIONS 1, 21 and 24. The address
key is `x = x_f + tw + Σ_a x_a` over the top-level shards `x_a` of the actors, and the address
point is `X = X_f + tw • g + Σ_a X_a`. The committee half `x_f` is Shamir-shared at threshold
`t`. Theorem names carry the claim (`C*`) or decision (`D*`) they support.
-/

open Polynomial Finset

namespace LineDealing.Split

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]
variable {ι : Type*}

/-- **D21, address point.** With `X_f = x_f • g` and `X_a = x_a • g` for every actor of `A`, the
address point `X_f + tw • g + Σ_a X_a` is `(x_f + tw + Σ_a x_a) • g`. -/
theorem D21_address_point (A : Finset ι) {g Xf : G} {xf tw : ZMod q} (x : ι → ZMod q)
    (X : ι → G) (hXf : Xf = xf • g) (hX : ∀ a ∈ A, X a = x a • g) :
    Xf + tw • g + ∑ a ∈ A, X a = (xf + tw + ∑ a ∈ A, x a) • g := by
  rw [add_smul, add_smul, sum_smul, hXf, sum_congr rfl hX]

/-- **D21, actors' part.** `Y_A = X − X_f` is `x_A • g` with `x_A = tw + Σ_a x_a`. -/
theorem D21_actor_part (A : Finset ι) {g Xf : G} {xf tw : ZMod q} (x : ι → ZMod q)
    (X : ι → G) (hXf : Xf = xf • g) (hX : ∀ a ∈ A, X a = x a • g) :
    (Xf + tw • g + ∑ a ∈ A, X a) - Xf = (tw + ∑ a ∈ A, x a) • g := by
  rw [D21_address_point A x X hXf hX, hXf, ← sub_smul]
  congr 1
  ring

/-- **D21, reconstruction.** `t` committee shares of `x_f = p(0)` (degree of `p` below `t`)
together with the tweak and every shard give the address key. -/
theorem D21_reconstruct (A : Finset ι) (Q : Finset (ZMod q)) {t : ℕ} (hQ : #Q = t)
    {p : (ZMod q)[X]} (hp : p.degree < t) (tw : ZMod q) (x : ι → ZMod q) :
    ∑ i ∈ Q, lam Q i * p.eval i + tw + ∑ a ∈ A, x a = p.eval 0 + tw + ∑ a ∈ A, x a := by
  rw [sum_lam_mul_eval Q (hQ ▸ hp)]

/-- **D21, reconstruction in the exponent.** For any committee commitment family `Cf` with
constant term `X_f`, the Feldman points of `t` or more nodes combine with the tweak point and the
shard points to the address point. No dealer is assumed honest. -/
theorem D21_reconstruct_point (A : Finset ι) (Q : Finset (ZMod q)) {t : ℕ} (ht0 : 0 < t)
    (ht : t ≤ #Q) (Cf : ℕ → G) (g : G) (tw : ZMod q) (X : ι → G) :
    ∑ i ∈ Q, lam Q i • feldmanEval t Cf i + tw • g + ∑ a ∈ A, X a = Cf 0 + tw • g + ∑ a ∈ A, X a := by
  rw [sum_lam_smul_feldmanEval Q ht0 ht]

/-- **C1, the address key is unique.** Over a nonzero generator, two scalars for one address point
are equal. -/
theorem C1_address_key_unique {g : G} (hg : g ≠ 0) {x x' : ZMod q} (h : x • g = x' • g) : x = x' :=
  smul_left_inj' hg h

/-- **C2, rogue key without proofs of possession.** The last actor `r` to publish can choose its
point so that the address point is `z • g` for a `z` it picked, whatever the other points are.
This is the attack the proofs of possession stop (§3.1 step 3). -/
theorem C2_rogue_key_without_pop [DecidableEq ι] (A : Finset ι) {r : ι} (hr : r ∈ A)
    (g Xf : G) (tw z : ZMod q) (X : ι → G) :
    Xf + tw • g + ∑ a ∈ A, Function.update X r (z • g - Xf - tw • g - ∑ a ∈ A.erase r, X a) a =
      z • g := by
  rw [← add_sum_erase A _ hr, Function.update_self]
  have : ∀ a ∈ A.erase r, Function.update X r (z • g - Xf - tw • g - ∑ a ∈ A.erase r, X a) a = X a :=
    fun a ha ↦ Function.update_of_ne (ne_of_mem_erase ha) _ _
  rw [sum_congr rfl this]
  abel

/-- **C1 and C2, the extraction step.** If the address point is `z • g` for a known `z`, and the
corrupt actors' shards `x_a` (`a ∈ Cor`) are extracted from their proofs, then the committee half
plus the honest shards is a known scalar: `x_f + Σ_{a ∈ Hon} x_a = z − tw − Σ_{a ∈ Cor} x_a`. A
coalition that knows `z` therefore solves the discrete log of `X_f + Σ_{Hon} X_a`. -/
theorem C2_extraction [DecidableEq ι] (Hon Cor : Finset ι) (hd : Disjoint Hon Cor) {g : G} (hg : g ≠ 0)
    {xf tw z : ZMod q} (x : ι → ZMod q)
    (hX : (xf + tw + ∑ a ∈ Hon ∪ Cor, x a) • g = z • g) :
    xf + ∑ a ∈ Hon, x a = z - tw - ∑ a ∈ Cor, x a := by
  have h := smul_left_inj' hg hX
  rw [sum_union hd] at h
  rw [← h]
  ring

/-! ## Signing algebra of the split (§4.2 to §4.4) -/

/-- **C4 and C17, Schnorr combine with weighted leaves.** A signing set `S` with weights `λ_a`
whose weighted leaf secrets give the actors' part (`tw + Σ_{a∈S} λ_a x_a = x_A`), contributions
`s_a = k_a + c λ_a x_a`, the tweak term `c tw` placed once, and the committee half
`s_f = k_f + c x_f` combine to a signature: `s • g = R + c • X` with `R = (k_f + Σ_a k_a) • g` and
`X = (x_f + x_A) • g`. This is the Ed25519 form of §4.3; the BIP340 form adds the signs. -/
theorem C4_schnorr_combine (S : Finset ι) (g : G) (lam' x k : ι → ZMod q)
    (kf xf tw c : ZMod q) :
    ((kf + c * xf) + c * tw + ∑ a ∈ S, (k a + c * (lam' a * x a))) • g =
      (kf + ∑ a ∈ S, k a) • g + c • ((xf + (tw + ∑ a ∈ S, lam' a * x a)) • g) := by
  rw [smul_smul, ← add_smul]
  congr 1
  rw [sum_add_distrib, ← mul_sum]
  ring

/-- **C4, the tweak term is placed once.** With the tweak term `c tw` in two contributions the
combined scalar misses the verification equation by `(c tw) • g`, which is nonzero when `c`, `tw`
and `g` are. -/
theorem C4_tweak_twice_fails (S : Finset ι) {g : G} (hg : g ≠ 0) (lam' x k : ι → ZMod q)
    {kf xf tw c : ZMod q} (hc : c ≠ 0) (htw : tw ≠ 0) :
    ((kf + c * xf) + c * tw + c * tw + ∑ a ∈ S, (k a + c * (lam' a * x a))) • g ≠
      (kf + ∑ a ∈ S, k a) • g + c • ((xf + (tw + ∑ a ∈ S, lam' a * x a)) • g) := by
  rw [← C4_schnorr_combine S g lam' x k kf xf tw c]
  intro h
  have h2 := smul_left_inj' hg h
  have : c * tw = 0 := by linear_combination h2
  exact mul_ne_zero hc htw this

/-- **D24, ECDSA split halves.** If the additive halves of a slot satisfy
`w_f + Σ_p w_p = k⁻¹` and `μ_f + Σ_p μ_p = k⁻¹ x` (§3.6), with `R = k • g`, `k ≠ 0` and
`X = x • g`, then the sum of the contributions `s_p = h w_p + r μ_p` and the committee half
`s_f = h w_f + r μ_f` satisfies the ECDSA equation `s • R = h • g + r • X`. -/
theorem D24_ecdsa_split_sign (P : Finset ι) {g R X : G} {k x wf μf h r : ZMod q}
    (w μ : ι → ZMod q) (hk : k ≠ 0) (hR : R = k • g) (hX : X = x • g)
    (hw : wf + ∑ p ∈ P, w p = k⁻¹) (hμ : μf + ∑ p ∈ P, μ p = k⁻¹ * x) :
    (∑ p ∈ P, (h * w p + r * μ p) + (h * wf + r * μf)) • R = h • g + r • X := by
  have hs : ∑ p ∈ P, (h * w p + r * μ p) + (h * wf + r * μf) =
      h * (wf + ∑ p ∈ P, w p) + r * (μf + ∑ p ∈ P, μ p) := by
    rw [sum_add_distrib, ← mul_sum, ← mul_sum]; ring
  rw [hs, hw, hμ, hR, hX, smul_smul, smul_smul]
  have : (h * k⁻¹ + r * (k⁻¹ * x)) * k = h + r * x := by field_simp
  rw [this, add_smul]

end LineDealing.Split
