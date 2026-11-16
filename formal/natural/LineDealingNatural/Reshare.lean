import LineDealing.Reshare
import LineDealingNatural.Ecdsa

/-!
# Line dealing in Natural Lean: resharing preserves the constant terms

Port of `formal/lean/LineDealing/Reshare.lean` (item 7).
-/

open Polynomial Finset
open LineDealing (lam feldmanEval commit resharePoly reshareCommit)

namespace LineDealingNatural

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

set_option autoImplicit true

/-! `resharePoly` and `reshareCommit` are the native definitions of `LineDealing.Reshare`. -/

Theorem "The new share of node j".
  Let Q : Finset(ZMod(q)).  Let gs : ZMod(q) → Polynomial(ZMod(q)).  Let j : ZMod(q).

    eval(j, resharePoly(Q, gs)) = ∑ i ∈ Q, lam(Q, i) · eval(j, gs(i)).  [resharePoly_eval]

Proof.  By [(intros; simp [resharePoly, eval_finsetSum])].

example : type_of% (@resharePoly_eval q _) ↔ type_of% (@LineDealing.resharePoly_eval q _) :=
  Iff.rfl

Theorem "Item 7, scalar form".
  Let t : Nat.  Let Q : Finset(ZMod(q)).  Let p : Polynomial(ZMod(q)).
  Let gs : ZMod(q) → Polynomial(ZMod(q)).
  If #Q = t and degree(p) < t and for all i ∈ Q, eval(0, gs(i)) = eval(i, p), then

    eval(0, resharePoly(Q, gs)) = eval(0, p).  [reshare_constant]

Proof.  Suppose that #Q = t and degree(p) < t and
  for all i ∈ Q, eval(0, gs(i)) = eval(i, p).  Then degree(p) < #Q.  Hence

    eval(0, resharePoly(Q, gs))
      = ∑ i ∈ Q, lam(Q, i) · eval(0, gs(i)) by resharePoly_eval
      = ∑ i ∈ Q, lam(Q, i) · eval(i, p) by [exact sum_congr rfl fun i hi ↦ by grind]
      = eval(0, p) by sum_lam_mul_eval.

example : type_of% (@reshare_constant q _) ↔ type_of% (@LineDealing.reshare_constant q _) := by
  nl_same

Theorem "The combined polynomial has degree below the new threshold".
  Let Q : Finset(ZMod(q)).  Let gs : ZMod(q) → Polynomial(ZMod(q)).  Let t' : Nat.
  If for all i ∈ Q, degree(gs(i)) < t', then degree(resharePoly(Q, gs)) < t'.
  [resharePoly_degree_lt]

Proof.  By [(
  intro Q gs t' hgs
  refine lt_of_le_of_lt (degree_sum_le _ _) ?_
  rw [Finset.sup_lt_iff (WithBot.bot_lt_coe _)]
  exact fun i hi ↦ lt_of_le_of_lt (by rw [C_mul']; exact degree_smul_le _ _) (hgs i hi))].

example : type_of% (@resharePoly_degree_lt q _) ↔
    type_of% (@LineDealing.resharePoly_degree_lt q _) := Iff.rfl

Theorem "Item 7, commitment form".
  Let Q : Finset(ZMod(q)).  Let t : Nat.  Let Cold : Nat → G.  Let Cd : ZMod(q) → Nat → G.
  If 0 < t ≤ #Q and for all i ∈ Q, Cd(i, 0) = feldmanEval(t, Cold, i), then

    reshareCommit(Q, Cd, 0) = Cold(0).  [reshare_commit_constant]

Proof.  Suppose that 0 < t ≤ #Q and for all i ∈ Q, Cd(i, 0) = feldmanEval(t, Cold, i).  Then

    reshareCommit(Q, Cd, 0)
      = ∑ i ∈ Q, lam(Q, i) • Cd(i, 0) by [rfl]
      = ∑ i ∈ Q, lam(Q, i) • feldmanEval(t, Cold, i)
          by [(nl_hyps; exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim)]
      = Cold(0) by sum_lam_smul_feldmanEval.

example : type_of% (@reshare_commit_constant q _ G _ _) ↔
    type_of% (@LineDealing.reshare_commit_constant q _ G _ _) := by nl_same

Theorem "Item 7 for open ECDSA".
  Let Q : Finset(ZMod(q)).  Let t : Nat.  Let g, X : G.  Let Cw, Cm : Nat → G.
  Let Dw, Dm : ZMod(q) → Nat → G.
  If 0 < t ≤ #Q and Cw(0) = g and Cm(0) = X and
  for all i ∈ Q, Dw(i, 0) = feldmanEval(t, Cw, i) and Dm(i, 0) = feldmanEval(t, Cm, i), then
  reshareCommit(Q, Dw, 0) = g and reshareCommit(Q, Dm, 0) = X.  [reshare_keeps_g_and_X]

Proof.  Suppose that 0 < t ≤ #Q and Cw(0) = g and Cm(0) = X and
  for all i ∈ Q, Dw(i, 0) = feldmanEval(t, Cw, i) and Dm(i, 0) = feldmanEval(t, Cm, i).
  Then 0 < t and t ≤ #Q.  Also for all i ∈ Q, Dw(i, 0) = feldmanEval(t, Cw, i).
  Also for all i ∈ Q, Dm(i, 0) = feldmanEval(t, Cm, i).
  Hence reshareCommit(Q, Dw, 0) = Cw(0) by [nl_apply reshare_commit_constant].
  Also reshareCommit(Q, Dm, 0) = Cm(0) by [nl_apply reshare_commit_constant].
  Therefore reshareCommit(Q, Dw, 0) = g and reshareCommit(Q, Dm, 0) = X.

example : type_of% (@reshare_keeps_g_and_X q _ G _ _) ↔
    type_of% (@LineDealing.reshare_keeps_g_and_X q _ G _ _) := by
  constructor
  · intro h Q t ht0 ht g X Cw Cm hCw hCm Dw Dm hDw hDm
    exact h Q t g X Cw Cm Dw Dm ⟨⟨ht0, ht⟩, hCw, hCm, fun i hi ↦ ⟨hDw i hi, hDm i hi⟩⟩
  · rintro h Q t g X Cw Cm Dw Dm ⟨⟨ht0, ht⟩, hCw, hCm, hD⟩
    exact h Q ht0 ht Cw Cm hCw hCm Dw Dm (fun i hi ↦ (hD i hi).1) (fun i hi ↦ (hD i hi).2)

Theorem "Feldman evaluation commutes with the resharing combination".
  Let Q : Finset(ZMod(q)).  Let Cd : ZMod(q) → Nat → G.  Let t' : Nat.  Let j : ZMod(q).

    feldmanEval(t', reshareCommit(Q, Cd), j) = ∑ i ∈ Q, lam(Q, i) • feldmanEval(t', Cd(i), j).
  [feldmanEval_reshareCommit]

Proof.  By [(
  intro Q Cd t' j
  simp only [feldmanEval, reshareCommit, smul_sum]
  rw [sum_comm]
  exact sum_congr rfl fun i _ ↦ sum_congr rfl fun u _ ↦ smul_comm _ _ _)].

example : type_of% (@feldmanEval_reshareCommit q _ G _ _) ↔
    type_of% (@LineDealing.feldmanEval_reshareCommit q _ G _ _) := Iff.rfl

Theorem "New shares verify against the new commitments".
  Let Q : Finset(ZMod(q)).  Let B : G.  Let Cd : ZMod(q) → Nat → G.  Let t' : Nat.
  Let v : ZMod(q) → ZMod(q) → ZMod(q).  Let j : ZMod(q).
  If for all i ∈ Q, v(i, j) • B = feldmanEval(t', Cd(i), j), then

    (∑ i ∈ Q, lam(Q, i) · v(i, j)) • B = feldmanEval(t', reshareCommit(Q, Cd), j).
  [reshare_share_check]

Proof.  Suppose that for all i ∈ Q, v(i, j) • B = feldmanEval(t', Cd(i), j).  Then

    (∑ i ∈ Q, lam(Q, i) · v(i, j)) • B
      = ∑ i ∈ Q, lam(Q, i) • v(i, j) • B by [exact sum_lam_mul_smul Q (fun i ↦ v i j) B]
      = ∑ i ∈ Q, lam(Q, i) • feldmanEval(t', Cd(i), j)
          by [exact sum_congr rfl fun i hi ↦ by congr 1; solve_by_elim]
      = feldmanEval(t', reshareCommit(Q, Cd), j) by feldmanEval_reshareCommit.

example : type_of% (@reshare_share_check q _ G _ _) ↔
    type_of% (@LineDealing.reshare_share_check q _ G _ _) := Iff.rfl

Theorem "Item 7 end to end for open ECDSA".
  Let Q, S : Finset(ZMod(q)).  Let t, t' : Nat.  Let g, X, R : G.  Let h, r : ZMod(q).
  Let Cw, Cm : Nat → G.  Let Dw, Dm : ZMod(q) → Nat → G.  Let σ : ZMod(q) → ZMod(q).
  If 0 < t ≤ #Q and 0 < t' ≤ #S and Cw(0) = g and Cm(0) = X and
  for all i ∈ Q, Dw(i, 0) = feldmanEval(t, Cw, i) and Dm(i, 0) = feldmanEval(t, Cm, i),
  then if for all j ∈ S,
    σ(j) • R = h • feldmanEval(t', reshareCommit(Q, Dw), j)
      + r • feldmanEval(t', reshareCommit(Q, Dm), j),
  then (∑ j ∈ S, lam(S, j) · σ(j)) • R = h • g + r • X.  [reshare_then_sign_sound]

Proof.  Suppose that 0 < t ≤ #Q and 0 < t' ≤ #S and Cw(0) = g and Cm(0) = X and
  for all i ∈ Q, Dw(i, 0) = feldmanEval(t, Cw, i) and Dm(i, 0) = feldmanEval(t, Cm, i).
  Suppose that for all j ∈ S,
    σ(j) • R = h • feldmanEval(t', reshareCommit(Q, Dw), j)
      + r • feldmanEval(t', reshareCommit(Q, Dm), j).
  Then reshareCommit(Q, Dw, 0) = g and reshareCommit(Q, Dm, 0) = X
  by [nl_apply reshare_keeps_g_and_X Q t g X Cw Cm Dw Dm].  Also 0 < t' and t' ≤ #S.  Hence
  (∑ j ∈ S, lam(S, j) · σ(j)) • R = h • g + r • X
  by [(nl_hyps
       exact partial_check_sound S t' g X R h r (reshareCommit Q Dw) (reshareCommit Q Dm) σ
         ⟨⟨‹_›, ‹_›⟩, ‹_›, ‹_›, ‹_›⟩)].

example : type_of% (@reshare_then_sign_sound q _ G _ _) ↔
    type_of% (@LineDealing.reshare_then_sign_sound q _ G _ _) := by
  constructor
  · intro H Q S t t' ht0 ht ht0' ht' g X R h r Cw Cm hCw hCm Dw Dm hDw hDm σ hchk
    exact H Q S t t' g X R h r Cw Cm Dw Dm σ
      ⟨⟨ht0, ht⟩, ⟨ht0', ht'⟩, hCw, hCm, fun i hi ↦ ⟨hDw i hi, hDm i hi⟩⟩ hchk
  · rintro H Q S t t' g X R h r Cw Cm Dw Dm σ ⟨⟨ht0, ht⟩, ⟨ht0', ht'⟩, hCw, hCm, hD⟩ hchk
    exact H Q S ht0 ht ht0' ht' h r Cw Cm hCw hCm Dw Dm (fun i hi ↦ (hD i hi).1)
      (fun i hi ↦ (hD i hi).2) σ hchk

end LineDealingNatural
