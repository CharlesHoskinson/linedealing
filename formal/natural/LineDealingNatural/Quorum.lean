import LineDealing.Quorum
import LineDealingNatural.Prelude

/-!
# Line dealing in Natural Lean: quorum intersection

Port of `formal/lean/LineDealing/Quorum.lean`.
-/

open Finset

namespace LineDealingNatural

variable {ι : Type*} [DecidableEq ι]

set_option autoImplicit true

Theorem "The counting lemma".
  Let U, A, B : Finset(ι).  If A ⊆ U and B ⊆ U then #A + #B ≤ #U + #(A ∩ B).
  [card_add_card_le_card_add_inter]

Proof.  Suppose that A ⊆ U and B ⊆ U.  Then
  #(A ∪ B) + #(A ∩ B) = #A + #B by card_union_add_card_inter.  Also A ∪ B ⊆ U by union_subset.
  Hence #(A ∪ B) ≤ #U by card_le_card.  Therefore #A + #B ≤ #U + #(A ∩ B).

example : type_of% (@card_add_card_le_card_add_inter ι _) ↔
    type_of% (@LineDealing.card_add_card_le_card_add_inter ι _) := by nl_same

Theorem "General quorum intersection".
  Let U, A, B : Finset(ι).  Let f, k : Nat.
  If A ⊆ U and B ⊆ U and #U + f < 2 · k and k ≤ #A and k ≤ #B then f + 1 ≤ #(A ∩ B).
  [quorum_inter_card_general]

Proof.  Suppose that A ⊆ U and B ⊆ U and #U + f < 2 · k and k ≤ #A and k ≤ #B.  Then
  #A + #B ≤ #U + #(A ∩ B) by card_add_card_le_card_add_inter.  Hence f + 1 ≤ #(A ∩ B).

example : type_of% (@quorum_inter_card_general ι _) ↔
    type_of% (@LineDealing.quorum_inter_card_general ι _) := by nl_same

set_option linter.unusedSectionVars false in
Theorem "A set of at least f + 1 nodes has a node outside every set of at most f nodes".
  Let f : Nat.  Let T, Byz : Finset(ι).  If f + 1 ≤ #T and #Byz ≤ f then
  there is some i ∈ T such that i ∉ Byz.  [exists_not_mem_of_card_lt]

Proof.  Suppose that f + 1 ≤ #T and #Byz ≤ f.  Assume that
  there is no i ∈ T such that i ∉ Byz.  Then T ⊆ Byz.  Hence #T ≤ #Byz by card_le_card.
  So f + 1 ≤ f, which is a contradiction.  Thus there is some i ∈ T such that i ∉ Byz.

example : type_of% (@exists_not_mem_of_card_lt ι _) ↔
    type_of% (@LineDealing.exists_not_mem_of_card_lt ι _) := by nl_same

/-! ## The quorum size `q = ⌈(n + f + 1)/2⌉` for `n ≥ 3f + 1` (LOOP item 4b)

`quorum(n, f)` is the native definition `LineDealing.quorum`. -/

open LineDealing (quorum)

Theorem "The quorum is the ceiling of (n + f + 1)/2".
  Let n, f : Nat.  Then n + f + 1 ≤ 2 · quorum(n, f) and 2 · quorum(n, f) ≤ n + f + 2.
  [quorum_spec]

Proof.  By [(intro n f; unfold LineDealing.quorum; omega)].

example : type_of% @quorum_spec ↔ type_of% @LineDealing.quorum_spec := Iff.rfl

Theorem "Two quorums together exceed n + f".
  Let n, f : Nat.  Then n + f < 2 · quorum(n, f).  [lt_two_mul_quorum]

Proof.  Let n, f : Nat.  Then n + f + 1 ≤ 2 · quorum(n, f) by [exact (quorum_spec n f).1].
  Hence n + f < 2 · quorum(n, f).

example : type_of% @lt_two_mul_quorum ↔ type_of% @LineDealing.lt_two_mul_quorum := Iff.rfl

Theorem "The quorum is the least size k with n + f < 2k".
  Let n, f, k : Nat.  If n + f < 2 · k then quorum(n, f) ≤ k.  [quorum_le_of_lt_two_mul]

Proof.  Let n, f, k : Nat.  Suppose that n + f < 2 · k.  Then
  2 · quorum(n, f) ≤ n + f + 2 by [exact (quorum_spec n f).2].  Hence quorum(n, f) ≤ k.

example : type_of% @quorum_le_of_lt_two_mul ↔ type_of% @LineDealing.quorum_le_of_lt_two_mul :=
  Iff.rfl

Theorem "For n = 3f + 1 the quorum is 2f + 1".
  Let f : Nat.  Then quorum(3 · f + 1, f) = 2 · f + 1.  [quorum_three_mul_add_one]

Proof.  Let f : Nat.  Then 3 · f + 1 + f + 1 ≤ 2 · quorum(3 · f + 1, f) by [exact (quorum_spec _ f).1].
  Also 2 · quorum(3 · f + 1, f) ≤ 3 · f + 1 + f + 2 by [exact (quorum_spec _ f).2].
  Hence quorum(3 · f + 1, f) = 2 · f + 1.

example : type_of% @quorum_three_mul_add_one ↔ type_of% @LineDealing.quorum_three_mul_add_one :=
  Iff.rfl

Theorem "Liveness bound: the quorum is at most n - f".
  Let n, f : Nat.  If 3 · f + 1 ≤ n then quorum(n, f) + f ≤ n.  [quorum_add_le]

Proof.  Let n, f : Nat.  Suppose that 3 · f + 1 ≤ n.  Then
  2 · quorum(n, f) ≤ n + f + 2 by [exact (quorum_spec n f).2].  Hence quorum(n, f) + f ≤ n.

example : type_of% @quorum_add_le ↔ type_of% @LineDealing.quorum_add_le := Iff.rfl

Theorem "Anchor bound: the quorum is at least 2f + 1".
  Let n, f : Nat.  If 3 · f + 1 ≤ n then 2 · f + 1 ≤ quorum(n, f).  [two_mul_add_one_le_quorum]

Proof.  Let n, f : Nat.  Suppose that 3 · f + 1 ≤ n.  Then
  n + f + 1 ≤ 2 · quorum(n, f) by [exact (quorum_spec n f).1].  Hence 2 · f + 1 ≤ quorum(n, f).

example : type_of% @two_mul_add_one_le_quorum ↔
    type_of% @LineDealing.two_mul_add_one_le_quorum := Iff.rfl

Theorem "Quorum intersection for q, size".
  Let U, A, B : Finset(ι).  Let n, f : Nat.
  If A ⊆ U and B ⊆ U and #U ≤ n and quorum(n, f) ≤ #A and quorum(n, f) ≤ #B then
  f + 1 ≤ #(A ∩ B).  [quorum_inter_card_q]

Proof.  Suppose that A ⊆ U and B ⊆ U and #U ≤ n and quorum(n, f) ≤ #A and
  quorum(n, f) ≤ #B.  Then n + f < 2 · quorum(n, f) by lt_two_mul_quorum.
  Hence #U + f < 2 · quorum(n, f).  Hence
  f + 1 ≤ #(A ∩ B) by [nl_apply quorum_inter_card_general U A B f (quorum n f)].

example : type_of% (@quorum_inter_card_q ι _) ↔ type_of% (@LineDealing.quorum_inter_card_q ι _) := by
  nl_same

Theorem "Quorum intersection for q, honest node".
  Let n, f : Nat.  Let U, A, B, Byz : Finset(ι).
  If A ⊆ U and B ⊆ U and #U ≤ n and quorum(n, f) ≤ #A and quorum(n, f) ≤ #B and #Byz ≤ f then
  there is some i : ι such that i ∈ A ∩ B and i ∉ Byz.  [quorum_inter_honest_q]

Proof.  Suppose that A ⊆ U and B ⊆ U and #U ≤ n and quorum(n, f) ≤ #A and
  quorum(n, f) ≤ #B and #Byz ≤ f.  Then
  f + 1 ≤ #(A ∩ B) by [nl_apply quorum_inter_card_q U A B n f].  Hence
  there is some i : ι such that i ∈ A ∩ B and i ∉ Byz
  by [nl_apply exists_not_mem_of_card_lt f (A ∩ B) Byz].

example : type_of% (@quorum_inter_honest_q ι _) ↔
    type_of% (@LineDealing.quorum_inter_honest_q ι _) := by nl_same

/-! `quorum_inter_honest_univ_q` stays native for the reason given at `quorum_inter_honest_univ`
below (instance argument, `Fintype.card ι`). The set difference `U \ Byz` of the next two
statements is written as the call `SDiff.sdiff(U, Byz)`. -/

alias quorum_inter_honest_univ_q := LineDealing.quorum_inter_honest_univ_q

set_option linter.unusedSectionVars false in
Theorem "The honest nodes fill a quorum".
  Let f : Nat.  Let U, Byz : Finset(ι).  If 3 · f + 1 ≤ #U and #Byz ≤ f then
  quorum(#U, f) ≤ #(SDiff.sdiff(U, Byz)).  [quorum_le_card_honest]

Proof.  Suppose that 3 · f + 1 ≤ #U and #Byz ≤ f.  Then quorum(#U, f) + f ≤ #U by quorum_add_le.
  Also #U - #Byz ≤ #(SDiff.sdiff(U, Byz)) by le_card_sdiff.
  Hence quorum(#U, f) ≤ #(SDiff.sdiff(U, Byz)).

example : type_of% (@quorum_le_card_honest ι _) ↔
    type_of% (@LineDealing.quorum_le_card_honest ι _) := by nl_same

set_option linter.unusedSectionVars false in
Theorem "A quorum holds f + 1 honest nodes".
  Let n, f : Nat.  Let A, Byz : Finset(ι).
  If 3 · f + 1 ≤ n and quorum(n, f) ≤ #A and #Byz ≤ f then f + 1 ≤ #(SDiff.sdiff(A, Byz)).
  [quorum_honest_card]

Proof.  Suppose that 3 · f + 1 ≤ n and quorum(n, f) ≤ #A and #Byz ≤ f.  Then
  2 · f + 1 ≤ quorum(n, f) by two_mul_add_one_le_quorum.  Also
  #A - #Byz ≤ #(SDiff.sdiff(A, Byz)) by le_card_sdiff.  Hence f + 1 ≤ #(SDiff.sdiff(A, Byz)).

example : type_of% (@quorum_honest_card ι _) ↔ type_of% (@LineDealing.quorum_honest_card ι _) := by
  nl_same

Theorem "Tightness of q".
  Let f, n : Nat.  If f ≤ n then
  there is some A, B, Byz : Finset(Nat) such that A ⊆ range(n) and B ⊆ range(n) and
  Byz ⊆ range(n) and #A = quorum(n, f) - 1 and #B = quorum(n, f) - 1 and #Byz ≤ f and
  A ∩ B ⊆ Byz.  [quorum_inter_fails_below]

Proof.  By [(
  intro f n hf
  have hq : n + f + 1 ≤ 2 * quorum n f ∧ 2 * quorum n f ≤ n + f + 2 := by
    unfold LineDealing.quorum; omega
  refine ⟨range (quorum n f - 1), Ico (n - (quorum n f - 1)) n,
    Ico (n - (quorum n f - 1)) (quorum n f - 1), ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp only [Nat.card_Ico]; omega
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega)].

example : type_of% @quorum_inter_fails_below ↔
    type_of% @LineDealing.quorum_inter_fails_below := Iff.rfl

/-! ## The case `n = 3f + 1` -/

Theorem "Quorum intersection, size".
  Let U, A, B : Finset(ι).  Let f : Nat.
  If A ⊆ U and B ⊆ U and #U ≤ 3 · f + 1 and 2 · f + 1 ≤ #A and 2 · f + 1 ≤ #B then
  f + 1 ≤ #(A ∩ B).  [quorum_inter_card]

Proof.  Suppose that A ⊆ U and B ⊆ U and #U ≤ 3 · f + 1 and 2 · f + 1 ≤ #A and
  2 · f + 1 ≤ #B.  Then #U + f < 2 · (2 · f + 1).  Hence
  f + 1 ≤ #(A ∩ B) by [nl_apply quorum_inter_card_general U A B f (2 * f + 1)].

example : type_of% (@quorum_inter_card ι _) ↔ type_of% (@LineDealing.quorum_inter_card ι _) := by
  nl_same

Theorem "Quorum intersection, honest node".
  Let f : Nat.  Let U, A, B, Byz : Finset(ι).
  If A ⊆ U and B ⊆ U and #U ≤ 3 · f + 1 and 2 · f + 1 ≤ #A and 2 · f + 1 ≤ #B and #Byz ≤ f then
  there is some i : ι such that i ∈ A ∩ B and i ∉ Byz.  [quorum_inter_honest]

Proof.  Suppose that A ⊆ U and B ⊆ U and #U ≤ 3 · f + 1 and 2 · f + 1 ≤ #A and
  2 · f + 1 ≤ #B and #Byz ≤ f.  Then
  f + 1 ≤ #(A ∩ B) by [nl_apply quorum_inter_card U A B f].  Hence
  there is some i : ι such that i ∈ A ∩ B and i ∉ Byz
  by [nl_apply exists_not_mem_of_card_lt f (A ∩ B) Byz].

example : type_of% (@quorum_inter_honest ι _) ↔
    type_of% (@LineDealing.quorum_inter_honest ι _) := by nl_same

/-! `quorum_inter_honest_univ` stays native: it needs the instance argument `[Fintype ι]` and
the type `ι` as a term (`Fintype.card ι`). A natural statement can bind variables and
hypotheses, not instances. -/

theorem quorum_inter_honest_univ [Fintype ι] {A B Byz : Finset ι} {f : ℕ}
    (hn : Fintype.card ι ≤ 3 * f + 1) (hqA : 2 * f + 1 ≤ #A) (hqB : 2 * f + 1 ≤ #B)
    (hByz : #Byz ≤ f) : ∃ i ∈ A ∩ B, i ∉ Byz :=
  quorum_inter_honest f univ A B Byz
    ⟨subset_univ A, subset_univ B, by simpa using hn, hqA, hqB, hByz⟩

example [Fintype ι] : type_of% (@quorum_inter_honest_univ ι _ _) =
    type_of% (@LineDealing.quorum_inter_honest_univ ι _ _) := rfl

Theorem "Tightness, too many nodes".
  Let f, n : Nat.  If 3 · f + 2 ≤ n then
  there is some A, B, Byz : Finset(Nat) such that A ⊆ range(n) and B ⊆ range(n) and
  Byz ⊆ range(n) and #A = 2 · f + 1 and #B = 2 · f + 1 and #Byz = f and A ∩ B ⊆ Byz.
  [quorum_inter_fails_of_large]

Proof.  By [(
  intro f n hn
  refine ⟨range (2 * f + 1), Ico (f + 1) (3 * f + 2), Ico (f + 1) (2 * f + 1), ?_, ?_, ?_, ?_,
    ?_, ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp only [Nat.card_Ico]; omega
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega)].

example : type_of% @quorum_inter_fails_of_large ↔
    type_of% @LineDealing.quorum_inter_fails_of_large := Iff.rfl

Theorem "Tightness, too few nodes".
  Let f, n : Nat.  If n ≤ 3 · f then
  there is some A, B, Byz : Finset(Nat) such that A ⊆ range(n) and B ⊆ range(n) and
  Byz ⊆ range(n) and #A = n - f and #B = n - f and #Byz ≤ f and A ∩ B ⊆ Byz.
  [quorum_inter_fails_of_small]

Proof.  By [(
  intro f n hn
  refine ⟨range (n - f), Ico f n, Ico f (n - f), ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega)].

example : type_of% @quorum_inter_fails_of_small ↔
    type_of% @LineDealing.quorum_inter_fails_of_small := Iff.rfl

end LineDealingNatural
