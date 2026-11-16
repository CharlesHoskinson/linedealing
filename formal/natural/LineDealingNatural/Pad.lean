import LineDealing.Pad
import LineDealingNatural.Ecdsa

/-!
# Line dealing in Natural Lean: share pads

Port of `formal/lean/LineDealing/Pad.lean` (item 6).
-/

open Polynomial Finset
open LineDealing (lam padDelta padReuseExtract)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

/-! `padDelta` and `padReuseExtract` are the native definitions of `LineDealing.Pad`. -/

Theorem "With a shared pad the public differences interpolate to μ(0) - w(0)".
  Let t : Nat.  Let s : Finset(ZMod(q)).  Let w, mu : Polynomial(ZMod(q)).
  Let pad, ctw, ctm : ZMod(q) → ZMod(q).
  If #s = t and degree(w) < t and degree(mu) < t and
  for all i ∈ s, ctw(i) = eval(i, w) + pad(i) and ctm(i) = eval(i, mu) + pad(i), then

    padDelta(s, ctw, ctm) = eval(0, mu) - eval(0, w).  [padDelta_shared_pad]

Proof.  Suppose that #s = t and degree(w) < t and degree(mu) < t and
  for all i ∈ s, ctw(i) = eval(i, w) + pad(i) and ctm(i) = eval(i, mu) + pad(i).  Then
  degree(w) < #s and degree(mu) < #s.  Hence

    padDelta(s, ctw, ctm)
      = ∑ i ∈ s, lam(s, i) · (ctm(i) - ctw(i)) by [rfl]
      = ∑ i ∈ s, lam(s, i) · (eval(i, mu) - eval(i, w))
          by [exact sum_congr rfl fun i hi ↦ by grind]
      = (∑ i ∈ s, lam(s, i) · eval(i, mu)) - (∑ i ∈ s, lam(s, i) · eval(i, w))
          by [(rw [← sum_sub_distrib]; exact sum_congr rfl fun i _ ↦ by ring)]
      = eval(0, mu) - eval(0, w) by sum_lam_mul_eval.

-- The native statement has one hypothesis for each ciphertext family. In Natural Lean a
-- `for all` hypothesis runs to the end of the hypothesis list, so the two are one `for all`.
example : type_of% (@padDelta_shared_pad q _) ↔
    type_of% (@LineDealing.padDelta_shared_pad q _) := by
  constructor
  · intro h t s hs w mu hw hmu pad ctw ctm hctw hctm
    exact h t s w mu pad ctw ctm ⟨hs, hw, hmu, fun i hi ↦ ⟨hctw i hi, hctm i hi⟩⟩
  · rintro h t s w mu pad ctw ctm ⟨hs, hw, hmu, hc⟩
    exact h s hs hw hmu pad ctw ctm (fun i hi ↦ (hc i hi).1) (fun i hi ↦ (hc i hi).2)

Theorem "Item 6, pad reuse is fatal".
  Let g, R, X : G.  Let t : Nat.  Let s : Finset(ZMod(q)).  Let w, mu : Polynomial(ZMod(q)).
  Let k, x, h, r, sig : ZMod(q).  Let pad, ctw, ctm : ZMod(q) → ZMod(q).
  If g ≠ 0 and #s = t and degree(w) < t and degree(mu) < t and R = k • g and k ≠ 0 and
  X = x • g and eval(0, w) • R = g and eval(0, mu) • R = X and h + r ≠ 0 and
  sig = h · eval(0, w) + r · eval(0, mu) and
  for all i ∈ s, ctw(i) = eval(i, w) + pad(i) and ctm(i) = eval(i, mu) + pad(i), then

    padReuseExtract(s, ctw, ctm, h, r, sig) = x.  [pad_reuse_recovers_key]

Proof.  Suppose that g ≠ 0 and #s = t and degree(w) < t and degree(mu) < t and R = k • g and
  k ≠ 0 and X = x • g and eval(0, w) • R = g and eval(0, mu) • R = X and h + r ≠ 0 and
  sig = h · eval(0, w) + r · eval(0, mu) and
  for all i ∈ s, ctw(i) = eval(i, w) + pad(i) and ctm(i) = eval(i, mu) + pad(i).
  Then eval(0, w) = k⁻¹ and eval(0, mu) = x · k⁻¹ by [nl_apply open_ecdsa_binding (G := G) g R X].
  Also padDelta(s, ctw, ctm) = eval(0, mu) - eval(0, w) by [nl_apply padDelta_shared_pad].
  Hence padDelta(s, ctw, ctm) = x · k⁻¹ - k⁻¹.  Also sig = h · k⁻¹ + r · (x · k⁻¹).
  Also k ≠ 0 and h + r ≠ 0.  Therefore

    padReuseExtract(s, ctw, ctm, h, r, sig)
      = 1 + (x · k⁻¹ - k⁻¹) / ((h · k⁻¹ + r · (x · k⁻¹) - r · (x · k⁻¹ - k⁻¹)) / (h + r))
          by [rw [padReuseExtract, ‹padDelta s ctw ctm = x * k⁻¹ - k⁻¹›,
            ‹sig = h * k⁻¹ + r * (x * k⁻¹)›]]
      = 1 + (x · k⁻¹ - k⁻¹) / k⁻¹
          by [(obtain ⟨hk, hhr⟩ := ‹k ≠ 0 ∧ h + r ≠ 0›
               congr 2
               rw [div_eq_iff hhr]
               ring)]
      = x by [(obtain ⟨hk, hhr⟩ := ‹k ≠ 0 ∧ h + r ≠ 0›
               rw [sub_div, mul_div_assoc, div_self (inv_ne_zero hk)]
               ring)].

example : type_of% (@pad_reuse_recovers_key q _ G _ _) ↔
    type_of% (@LineDealing.pad_reuse_recovers_key q _ G _ _) := by
  constructor
  · intro h g hg t s hs w mu hw hmu k x h' r sig R X hR hk hX hwR hmR hhr pad ctw ctm hctw hctm
      hsig
    exact h g R X t s w mu k x h' r sig pad ctw ctm
      ⟨hg, hs, hw, hmu, hR, hk, hX, hwR, hmR, hhr, hsig, fun i hi ↦ ⟨hctw i hi, hctm i hi⟩⟩
  · rintro h g R X t s w mu k x h' r sig pad ctw ctm
      ⟨hg, hs, hw, hmu, hR, hk, hX, hwR, hmR, hhr, hsig, hc⟩
    exact h hg s hs hw hmu hR hk hX hwR hmR hhr pad ctw ctm (fun i hi ↦ (hc i hi).1)
      (fun i hi ↦ (hc i hi).2) hsig

/-! `pad_bijective` and `pad_count_eq_one` stay native. Their statements need a function
literal (`fun pad ↦ v + pad`), an index type with `Fintype` and `DecidableEq` instances, and
the size of a set given by a condition (`#{pad | v + pad = c}`). Natural Lean has none of
these. -/

theorem pad_bijective {ι : Type*} (v : ι → ZMod q) :
    Function.Bijective fun pad : ι → ZMod q ↦ v + pad :=
  (Equiv.addLeft v).bijective

example {ι : Type*} : type_of% (@pad_bijective q _ ι) = type_of% (@LineDealing.pad_bijective q _ ι) :=
  rfl

theorem pad_count_eq_one {ι : Type*} [Fintype ι] [DecidableEq ι] (v c : ι → ZMod q) :
    #{pad : ι → ZMod q | v + pad = c} = 1 := by
  rw [card_eq_one]
  refine ⟨c - v, ?_⟩
  ext pad
  simp [eq_sub_iff_add_eq']

example {ι : Type*} [Fintype ι] [DecidableEq ι] :
    type_of% (@pad_count_eq_one q _ ι _ _) = type_of% (@LineDealing.pad_count_eq_one q _ ι _ _) :=
  rfl

Theorem "Item 6 for one node's ciphertext pair".
  Let w, mu, cw, cm : ZMod(q).
  There is some a, b : ZMod(q) such that (w + a, mu + b) = (cw, cm), and
  for all u, v : ZMod(q), if (w + u, mu + v) = (cw, cm) then u = a and v = b.  [pad_pair_unique]

Proof.  Let w, mu, cw, cm : ZMod(q).  Then (w + (cw - w), mu + (cm - mu)) = (cw, cm) by [simp].
  Now let u, v : ZMod(q) and suppose that (w + u, mu + v) = (cw, cm).  Then w + u = cw and
  mu + v = cm.  Hence u = cw - w and v = cm - mu.
  Therefore there is some a, b : ZMod(q) such that (w + a, mu + b) = (cw, cm), and
  for all u, v : ZMod(q), if (w + u, mu + v) = (cw, cm) then u = a and v = b
  by [exact ⟨cw - w, cm - mu, ‹_›, ‹_›⟩].

-- The native statement is `∃! p : ZMod q × ZMod q, (w + p.1, mu + p.2) = (cw, cm)`. Natural
-- Lean has no `∃!` and no projections, so the natural statement names the two pads.
example : type_of% (@pad_pair_unique q _) ↔ type_of% (@LineDealing.pad_pair_unique q _) := by
  constructor
  · intro h w mu cw cm
    obtain ⟨a, b, he, hu⟩ := h w mu cw cm
    exact ⟨(a, b), he, fun ⟨u, v⟩ huv ↦ Prod.ext (hu u v huv).1 (hu u v huv).2⟩
  · intro h w mu cw cm
    obtain ⟨⟨a, b⟩, he, hu⟩ := h w mu cw cm
    exact ⟨a, b, he, fun u v huv ↦ Prod.mk.inj (hu (u, v) huv)⟩

/-! `pad_diff_count` stays native: its statement is the size of a set of pairs given by a
condition, `#{p : ZMod q × ZMod q | (mu + p.2) - (w + p.1) = d} = q`. -/

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

example : type_of% (@pad_diff_count q _) = type_of% (@LineDealing.pad_diff_count q _) := rfl

end LineDealingNatural
