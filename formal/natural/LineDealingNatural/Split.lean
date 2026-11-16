import LineDealing.KeySplit
import LineDealing.Access
import LineDealing.Slots
import LineDealing.Profiles
import LineDealingNatural.Ecdsa

/-!
# Split-line dealing in Natural Lean

Port of `formal/lean/LineDealing/KeySplit.lean`, `Access.lean`, `Slots.lean` and
`Profiles.lean`. The key-split algebra, the flat threshold gate and the two-subset algebra of
DECISIONS 43 have natural statements. The access formulas, the slot models and the profile map
are inductive types, inductive relations and structures. Natural Lean cannot define them and has
no field access or pattern matching, so those theorems stay native and this file gives each one
under its natural name.
-/

open Polynomial Finset
open LineDealing (lam feldmanEval)

namespace LineDealingNatural.Split

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G] {ι : Type*}

set_option autoImplicit true

Theorem "D21, address point".
  Let A : Finset(ι).  Let g, Xf : G.  Let xf, tw : ZMod(q).  Let x : ι → ZMod(q).
  Let X : ι → G.  If Xf = xf • g and for all a ∈ A, X(a) = x(a) • g, then

    Xf + tw • g + ∑ a ∈ A, X(a) = (xf + tw + ∑ a ∈ A, x(a)) • g.  [D21_address_point]

Proof.  By [(
  intro A g Xf xf tw x X h
  obtain ⟨hXf, hX⟩ := h
  rw [add_smul, add_smul, sum_smul, hXf, sum_congr rfl hX])].

example : type_of% (@D21_address_point q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.D21_address_point q _ G _ _ ι) := by nl_same

Theorem "D21, reconstruction".
  Let A : Finset(ι).  Let Q : Finset(ZMod(q)).  Let t : Nat.  Let p : Polynomial(ZMod(q)).
  Let tw : ZMod(q).  Let x : ι → ZMod(q).  If #Q = t and degree(p) < t then

    ∑ i ∈ Q, lam(Q, i) · eval(i, p) + tw + ∑ a ∈ A, x(a) = eval(0, p) + tw + ∑ a ∈ A, x(a).
  [D21_reconstruct]

Proof.  Suppose that #Q = t and degree(p) < t.  Then degree(p) < #Q.  Hence
  ∑ i ∈ Q, lam(Q, i) · eval(i, p) = eval(0, p) by sum_lam_mul_eval.  Therefore
  ∑ i ∈ Q, lam(Q, i) · eval(i, p) + tw + ∑ a ∈ A, x(a) = eval(0, p) + tw + ∑ a ∈ A, x(a).

example : type_of% (@D21_reconstruct q _ ι) ↔
    type_of% (@LineDealing.Split.D21_reconstruct q _ ι) := by nl_same

Theorem "C1, the address key is unique".
  Let g : G.  Let x, x' : ZMod(q).  If g ≠ 0 and x • g = x' • g then x = x'.
  [C1_address_key_unique]

Proof.  Suppose that g ≠ 0 and x • g = x' • g.  Then x = x' by smul_left_inj'.

example : type_of% (@C1_address_key_unique q _ G _ _) ↔
    type_of% (@LineDealing.Split.C1_address_key_unique q _ G _ _) := by nl_same

Theorem "C4, Schnorr combine with weighted leaves".
  Let S : Finset(ι).  Let g : G.  Let w, x, k : ι → ZMod(q).  Let kf, xf, tw, c : ZMod(q).
  Then

    (kf + c · xf + c · tw + ∑ a ∈ S, (k(a) + c · (w(a) · x(a)))) • g
      = (kf + ∑ a ∈ S, k(a)) • g + c • ((xf + (tw + ∑ a ∈ S, w(a) · x(a))) • g).
  [C4_schnorr_combine]

Proof.  By [(
  intro S g w x k kf xf tw c
  rw [smul_smul, ← add_smul]
  congr 1
  rw [sum_add_distrib, ← mul_sum]
  ring)].

example : type_of% (@C4_schnorr_combine q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.C4_schnorr_combine q _ G _ _ ι) := Iff.rfl

Theorem "D24, ECDSA split halves".
  Let P : Finset(ι).  Let g, R, X : G.  Let k, x, wf, μf, h, r : ZMod(q).
  Let w, μ : ι → ZMod(q).
  If k ≠ 0 and R = k • g and X = x • g and wf + ∑ p ∈ P, w(p) = k⁻¹ and
  μf + ∑ p ∈ P, μ(p) = k⁻¹ · x then

    (∑ p ∈ P, (h · w(p) + r · μ(p)) + (h · wf + r · μf)) • R = h • g + r • X.
  [D24_ecdsa_split_sign]

Proof.  By [(
  intro P g R X k x wf μf h r w μ hyp
  obtain ⟨hk, hR, hX, hw, hμ⟩ := hyp
  have hs : ∑ p ∈ P, (h * w p + r * μ p) + (h * wf + r * μf) =
      h * (wf + ∑ p ∈ P, w p) + r * (μf + ∑ p ∈ P, μ p) := by
    rw [sum_add_distrib, ← mul_sum, ← mul_sum]; ring
  rw [hs, hw, hμ, hR, hX, smul_smul, smul_smul]
  have : (h * k⁻¹ + r * (k⁻¹ * x)) * k = h + r * x := by field_simp
  rw [this, add_smul])].

example : type_of% (@D24_ecdsa_split_sign q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.D24_ecdsa_split_sign q _ G _ _ ι) := by nl_same

Theorem "D22, threshold gate".
  Let T : Finset(ZMod(q)).  Let k : Nat.  Let p : Polynomial(ZMod(q)).
  If #T = k and degree(p) < k then ∑ i ∈ T, lam(T, i) · eval(i, p) = eval(0, p).
  [D22_threshold_gate]

Proof.  Suppose that #T = k and degree(p) < k.  Then degree(p) < #T.  Hence
  ∑ i ∈ T, lam(T, i) · eval(i, p) = eval(0, p) by sum_lam_mul_eval.

example : type_of% (@D22_threshold_gate q _) ↔
    type_of% (@LineDealing.Split.D22_threshold_gate q _) := by nl_same

Theorem "D43, the half line and every other half give the key".
  Let k, x, wγ, μγ, wo, μo : ZMod(q).
  If k ≠ 0 and wγ + wo = k⁻¹ and μγ + μo = k⁻¹ · x then x = (μγ + μo) / (wγ + wo).
  [D43_line_gives_key]

Proof.  Suppose that k ≠ 0 and wγ + wo = k⁻¹ and μγ + μo = k⁻¹ · x.  Then
  (μγ + μo) / (wγ + wo) = (k⁻¹ · x) / k⁻¹
                         = x by [(nl_hyps; field_simp)].

example : type_of% (@D43_line_gives_key q _) ↔
    type_of% (@LineDealing.Split.D43_line_gives_key q _) := by nl_same

Theorem "D21, actors' part".
  Let A : Finset(ι).  Let g, Xf : G.  Let xf, tw : ZMod(q).  Let x : ι → ZMod(q).
  Let X : ι → G.  If Xf = xf • g and for all a ∈ A, X(a) = x(a) • g, then

    (Xf + tw • g + ∑ a ∈ A, X(a)) - Xf = (tw + ∑ a ∈ A, x(a)) • g.  [D21_actor_part]

Proof.  Suppose that Xf = xf • g and for all a ∈ A, X(a) = x(a) • g.  Then

    (Xf + tw • g + ∑ a ∈ A, X(a)) - Xf = (xf + tw + ∑ a ∈ A, x(a)) • g - xf • g
          by [(nl_hyps; rw [D21_address_point A g Xf xf tw x X ⟨‹_›, ‹_›⟩, ‹Xf = _›])]
      = (tw + ∑ a ∈ A, x(a)) • g by [(rw [← sub_smul]; congr 1; ring)].

example : type_of% (@D21_actor_part q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.D21_actor_part q _ G _ _ ι) := by nl_same

Theorem "D21, reconstruction in the exponent".
  Let A : Finset(ι).  Let Q : Finset(ZMod(q)).  Let t : Nat.  Let K : Nat → G.  Let g : G.
  Let tw : ZMod(q).  Let X : ι → G.  If 0 < t ≤ #Q then

    ∑ i ∈ Q, lam(Q, i) • feldmanEval(t, K, i) + tw • g + ∑ a ∈ A, X(a)
      = K(0) + tw • g + ∑ a ∈ A, X(a).  [D21_reconstruct_point]

Proof.  Suppose that 0 < t ≤ #Q.  Then
  ∑ i ∈ Q, lam(Q, i) • feldmanEval(t, K, i) = K(0) by sum_lam_smul_feldmanEval.  Therefore
  ∑ i ∈ Q, lam(Q, i) • feldmanEval(t, K, i) + tw • g + ∑ a ∈ A, X(a)
    = K(0) + tw • g + ∑ a ∈ A, X(a).

example : type_of% (@D21_reconstruct_point q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.D21_reconstruct_point q _ G _ _ ι) := by nl_same

section

variable [DecidableEq ι]

Theorem "C2, the extraction step".
  Let Hon, Cor : Finset(ι).  Let g : G.  Let xf, tw, z : ZMod(q).  Let x : ι → ZMod(q).
  If Disjoint(Hon, Cor) is true and g ≠ 0 and
  (xf + tw + ∑ a ∈ Hon ∪ Cor, x(a)) • g = z • g then

    xf + ∑ a ∈ Hon, x(a) = z - tw - ∑ a ∈ Cor, x(a).  [C2_extraction]

Proof.  Suppose that Disjoint(Hon, Cor) is true and g ≠ 0 and
  (xf + tw + ∑ a ∈ Hon ∪ Cor, x(a)) • g = z • g.  Then
  xf + tw + ∑ a ∈ Hon ∪ Cor, x(a) = z by smul_left_inj'.  Hence
  xf + tw + (∑ a ∈ Hon, x(a) + ∑ a ∈ Cor, x(a)) = z by [(nl_hyps; rwa [← sum_union ‹_›])].
  Therefore xf + ∑ a ∈ Hon, x(a) = z - tw - ∑ a ∈ Cor, x(a) by [(nl_hyps; linear_combination ‹_ = z›)].

example : type_of% (@C2_extraction q _ G _ _ ι _) ↔
    type_of% (@LineDealing.Split.C2_extraction q _ G _ _ ι _) := by nl_same

end

Theorem "C4, the tweak term is placed once".
  Let S : Finset(ι).  Let g : G.  Let w, x, k : ι → ZMod(q).  Let kf, xf, tw, c : ZMod(q).
  If g ≠ 0 and c ≠ 0 and tw ≠ 0 then

    (kf + c · xf + c · tw + c · tw + ∑ a ∈ S, (k(a) + c · (w(a) · x(a)))) • g
      ≠ (kf + ∑ a ∈ S, k(a)) • g + c • ((xf + (tw + ∑ a ∈ S, w(a) · x(a))) • g).
  [C4_tweak_twice_fails]

Proof.  By [(
  intro S g w x k kf xf tw c hyp
  obtain ⟨hg, hc, htw⟩ := hyp
  rw [← C4_schnorr_combine S g w x k kf xf tw c]
  intro h
  have h2 := LineDealingNatural.smul_left_inj' _ _ _ ⟨hg, h⟩
  have : c * tw = 0 := by linear_combination h2
  exact mul_ne_zero hc htw this)].

example : type_of% (@C4_tweak_twice_fails q _ G _ _ ι) ↔
    type_of% (@LineDealing.Split.C4_tweak_twice_fails q _ G _ _ ι) := by nl_same

Theorem "D43, two subsets reveal the group's half line".
  Let T, T2 : Finset(ZMod(q)).  Let k : Nat.  Let w, μ : Polynomial(ZMod(q)).
  Let h, h2, r, u, u2 : ZMod(q).
  If #T = k and #T2 = k and degree(w) < k and degree(μ) < k and h ≠ h2 and
  u = ∑ i ∈ T, lam(T, i) · (h · eval(i, w) + r · eval(i, μ)) and
  u2 = ∑ i ∈ T2, lam(T2, i) · (h2 · eval(i, w) + r · eval(i, μ)) then

    eval(0, w) = (u - u2) / (h - h2), and
    r ≠ 0 implies eval(0, μ) = (u - h · eval(0, w)) / r.  [D43_two_subsets_reveal_line]

Proof.  By [(
  intro T T' k w μ h h' r u u' hyp
  obtain ⟨hT, hT', hw, hμ, hh, hu, hu'⟩ := hyp
  rw [LineDealingNatural.partial_combine k T w μ h r ⟨hT, hw, hμ⟩] at hu
  rw [LineDealingNatural.partial_combine k T' w μ h' r ⟨hT', hw, hμ⟩] at hu'
  have hsub : h - h' ≠ 0 := sub_ne_zero.mpr hh
  refine ⟨?_, fun hr ↦ ?_⟩
  · rw [eq_div_iff hsub, hu, hu']; ring
  · rw [eq_div_iff hr, hu]; ring)].

-- The hypotheses differ only in grouping; `nl_same` does not find the instance because two
-- hypotheses have the shape `u = ∑ ...`, so the check is written out.
example : type_of% (@D43_two_subsets_reveal_line q _) ↔
    type_of% (@LineDealing.Split.D43_two_subsets_reveal_line q _) := by
  constructor
  · intro hn T T' k hT hT' w μ hw hμ h h' r u u' hh hu hu'
    exact hn T T' k w μ h h' r u u' ⟨hT, hT', hw, hμ, hh, hu, hu'⟩
  · intro hn T T' k w μ h h' r u u' hyp
    obtain ⟨hT, hT', hw, hμ, hh, hu, hu'⟩ := hyp
    exact hn T T' hT hT' hw hμ hh hu hu'

Theorem "C17, threshold secrecy".
  Let T : Finset(ZMod(q)).  Let k : Nat.  Let p : Polynomial(ZMod(q)).  Let s' : ZMod(q).
  If 0 ∉ T and #T < k and degree(p) < k then there is some p' : Polynomial(ZMod(q)) such that
  degree(p') < k and eval(0, p') = s' and for all i ∈ T, eval(i, p') = eval(i, p).
  [C17_threshold_secrecy]

Proof.  By [(
  intro T k p s' hyp
  obtain ⟨h0, hT, hp⟩ := hyp
  exact ⟨LineDealing.Split.shift T p s', LineDealing.Split.shift_degree_lt h0 hT hp s',
    LineDealing.Split.shift_eval_zero T p s',
    fun _ hi ↦ LineDealing.Split.shift_eval_of_mem h0 p s' hi⟩)].

example : type_of% (@C17_threshold_secrecy q _) ↔
    type_of% (@LineDealing.Split.C17_threshold_secrecy q _) := by nl_same

/-! ## Native only

The statements below use `Finsupp`, the inductive types and relations `Gate`, `Dealt`, `Reach`,
`Covers`, `Step`, the structures `SlotAnswers` and `Precedence.State` with field access, a
`match` (`viewUpTo`), `Function.update`, an `if` expression, `let` in the statement, `Set`
images or an `Equiv`. -/

alias C2_rogue_key_without_pop := LineDealing.Split.C2_rogue_key_without_pop
alias D22_and_gate := LineDealing.Split.D22_and_gate
alias D22_or_gate := LineDealing.Split.D22_or_gate
alias D22_access_weighted_sum := LineDealing.Split.D22_access_weighted_sum
alias D22_access_weighted_point := LineDealing.Split.D22_access_weighted_point
alias D22_address_key := LineDealing.Split.D22_address_key
alias D22_reach_covers := LineDealing.Split.D22_reach_covers
alias D22_covers_reach := LineDealing.Split.D22_covers_reach
alias C17_access_secrecy := LineDealing.Split.C17_access_secrecy
alias D22_user_or_G := LineDealing.Split.D22_user_or_G
alias C17_user_or_G_coalition := LineDealing.Split.C17_user_or_G_coalition
alias C12_one_digest_per_slot := LineDealing.Split.C12_one_digest_per_slot
alias D43_bound_slot_refuses := LineDealing.Split.D43_bound_slot_refuses
alias D43_one_full_request := LineDealing.Split.D43_one_full_request
alias D43_without_binding_two_full := LineDealing.Split.D43_without_binding_two_full
alias D44_prec_first_namer := LineDealing.Split.Precedence.D44_prec_first_namer
alias D44_honest_vote_first_namer := LineDealing.Split.Precedence.D44_honest_vote_first_namer
alias D44_one_request_per_slot := LineDealing.Split.Precedence.D44_one_request_per_slot
alias D44_later_never_reserves := LineDealing.Split.Precedence.D44_later_never_reserves
alias D44_burn_persists := LineDealing.Split.Precedence.D44_burn_persists
alias D44_in_force_rule_takes_later := LineDealing.Split.Precedence.D44_in_force_rule_takes_later
alias C16_cold_start_no_reuse := LineDealing.Split.ColdStart.C16_cold_start_no_reuse
alias C16_without_burn_reuse := LineDealing.Split.ColdStart.C16_without_burn_reuse
alias D19_signing_profile_free := LineDealing.Split.D19_signing_profile_free
alias D19_user_signs := LineDealing.Split.D19_user_signs
alias D19_P2_extends_P1 := LineDealing.Split.D19_P2_extends_P1
alias D19_P2_signing_sets := LineDealing.Split.D19_P2_signing_sets
alias D19_P1_no_seizure := LineDealing.Split.D19_P1_no_seizure
alias D19_P2_guardians_seize := LineDealing.Split.D19_P2_guardians_seize

/-! Lemmas of the native files, given under their natural names so the map is complete. -/

alias C17_threshold_completions_equiv := LineDealing.Split.C17_threshold_completions_equiv
alias Gate.Covers.mono := LineDealing.Split.Gate.Covers.mono
alias Gate.Dealt.congr := LineDealing.Split.Gate.Dealt.congr
alias zeroBasis_eval_zero := LineDealing.Split.zeroBasis_eval_zero
alias zeroBasis_eval_of_mem := LineDealing.Split.zeroBasis_eval_of_mem
alias zeroBasis_degree := LineDealing.Split.zeroBasis_degree
alias shift_eval_zero := LineDealing.Split.shift_eval_zero
alias shift_eval_of_mem := LineDealing.Split.shift_eval_of_mem
alias shift_degree_lt := LineDealing.Split.shift_degree_lt
alias Precedence.inv_init := LineDealing.Split.Precedence.inv_init
alias Precedence.inv_step := LineDealing.Split.Precedence.inv_step
alias Precedence.inv_of_reachable := LineDealing.Split.Precedence.inv_of_reachable
alias Precedence.ordInv_step := LineDealing.Split.Precedence.ordInv_step
alias Precedence.ordInv_of_reachable := LineDealing.Split.Precedence.ordInv_of_reachable
alias Precedence.ord_inj := LineDealing.Split.Precedence.ord_inj
alias reach_leaf := LineDealing.Split.reach_leaf

end LineDealingNatural.Split
