import LineDealing.Ecdsa

/-!
# Share pads

Item 6. A ciphertext is `share + pad`. The pad is the hash output `Hq_enc(...)` in the scheme
and a free scalar here. With one pad for both ECDSA components an observer gets `x` from the
ciphertexts and one signature. With independent uniform pads the ciphertexts carry no
information about the shares; this is stated in counting form.
-/

open Polynomial Finset

namespace LineDealing

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- The observer's interpolated ciphertext difference `δ`, from public values. -/
noncomputable def padDelta (s : Finset (ZMod q)) (ctw ctm : ZMod q → ZMod q) : ZMod q :=
  ∑ i ∈ s, lam s i * (ctm i - ctw i)

/-- The observer's key computation of ledger check D1, from public values only:
`w' = (sig - r δ) / (h + r)` and `x' = 1 + δ / w'`. -/
noncomputable def padReuseExtract (s : Finset (ZMod q)) (ctw ctm : ZMod q → ZMod q)
    (h r sig : ZMod q) : ZMod q :=
  1 + padDelta s ctw ctm / ((sig - r * padDelta s ctw ctm) / (h + r))

/-- With a shared pad the public differences interpolate to `μ(0) - w(0)`. -/
theorem padDelta_shared_pad {t : ℕ} (s : Finset (ZMod q)) (hs : #s = t) {w mu : (ZMod q)[X]}
    (hw : w.degree < t) (hmu : mu.degree < t) (pad ctw ctm : ZMod q → ZMod q)
    (hctw : ∀ i ∈ s, ctw i = w.eval i + pad i) (hctm : ∀ i ∈ s, ctm i = mu.eval i + pad i) :
    padDelta s ctw ctm = mu.eval 0 - w.eval 0 := by
  subst hs
  rw [← sum_lam_mul_eval s hw, ← sum_lam_mul_eval s hmu, ← sum_sub_distrib, padDelta]
  exact sum_congr rfl fun i hi ↦ by rw [hctw i hi, hctm i hi]; ring

/-- **Item 6, pad reuse is fatal.** If `ct_w,i = w_i + p_i` and `ct_μ,i = μ_i + p_i` use the
same pad, then the ciphertexts of `t` nodes and one signature `sig = h * w(0) + r * μ(0)` with
`h + r ≠ 0` give the key `x`. -/
theorem pad_reuse_recovers_key {g : G} (hg : g ≠ 0) {t : ℕ} (s : Finset (ZMod q)) (hs : #s = t)
    {w mu : (ZMod q)[X]} (hw : w.degree < t) (hmu : mu.degree < t) {k x h r sig : ZMod q}
    {R X : G} (hR : R = k • g) (hk : k ≠ 0) (hX : X = x • g) (hwR : w.eval 0 • R = g)
    (hmR : mu.eval 0 • R = X) (hhr : h + r ≠ 0) (pad ctw ctm : ZMod q → ZMod q)
    (hctw : ∀ i ∈ s, ctw i = w.eval i + pad i) (hctm : ∀ i ∈ s, ctm i = mu.eval i + pad i)
    (hsig : sig = h * w.eval 0 + r * mu.eval 0) :
    padReuseExtract s ctw ctm h r sig = x := by
  obtain ⟨hw0, hmu0⟩ := open_ecdsa_binding hg hR hk hX hwR hmR
  rw [padReuseExtract, padDelta_shared_pad s hs hw hmu pad ctw ctm hctw hctm, hsig, hw0, hmu0]
  have h1 : (h * k⁻¹ + r * (x * k⁻¹) - r * (x * k⁻¹ - k⁻¹)) / (h + r) = k⁻¹ := by
    rw [div_eq_iff hhr]
    ring
  rw [h1, sub_div, mul_div_assoc, div_self (inv_ne_zero hk)]
  ring

/-- **Item 6, independent pads, bijection form.** For any index set `ι` (node and component)
and any shares `v`, adding the pad vector is a bijection onto ciphertext vectors. -/
theorem pad_bijective {ι : Type*} (v : ι → ZMod q) :
    Function.Bijective fun pad : ι → ZMod q ↦ v + pad :=
  (Equiv.addLeft v).bijective

/-- **Item 6, independent pads, counting form.** Every ciphertext vector `c` arises from exactly
one pad vector, whatever the shares `v` are. Under uniform independent pads the ciphertext
vector is therefore uniform with the same law for all `v`, so it is independent of `v`. -/
theorem pad_count_eq_one {ι : Type*} [Fintype ι] [DecidableEq ι] (v c : ι → ZMod q) :
    #{pad : ι → ZMod q | v + pad = c} = 1 := by
  rw [card_eq_one]
  refine ⟨c - v, ?_⟩
  ext pad
  simp [eq_sub_iff_add_eq']

/-- Item 6 for one node's ciphertext pair: for any `(w_i, μ_i)` and any ciphertext pair there is
exactly one pad pair. -/
theorem pad_pair_unique (w mu cw cm : ZMod q) :
    ∃! p : ZMod q × ZMod q, (w + p.1, mu + p.2) = (cw, cm) := by
  refine ⟨(cw - w, cm - mu), by simp, ?_⟩
  rintro ⟨p, p'⟩ hp
  simp only [Prod.mk.injEq] at hp
  rw [Prod.mk.injEq]
  exact ⟨by linear_combination hp.1, by linear_combination hp.2⟩

/-- **Item 6, independent pads, the public difference.** With independent pads the difference
is `μ_i - w_i + (p'_i - p_i)`. Each value `d` of it arises from exactly `q` of the `q²` pad
pairs, whatever `(w_i, μ_i)` are, so the difference is uniform and independent of the shares. -/
theorem pad_diff_count (w mu d : ZMod q) :
    #{p : ZMod q × ZMod q | (mu + p.2) - (w + p.1) = d} = q := by
  have : ({p : ZMod q × ZMod q | (mu + p.2) - (w + p.1) = d} : Finset _) =
      univ.image fun p : ZMod q ↦ (p, d + w + p - mu) := by
    ext ⟨p, p'⟩
    simp only [mem_filter, mem_univ, true_and, mem_image, Prod.mk.injEq, exists_eq_left]
    constructor
    · intro e
      linear_combination -e
    · intro e
      linear_combination -e
  rw [this, card_image_of_injective _ fun a b hab ↦ (Prod.mk.inj hab).1, card_univ, ZMod.card]

end LineDealing
