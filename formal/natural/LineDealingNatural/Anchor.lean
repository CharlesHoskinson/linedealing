import LineDealing.Anchor
import LineDealingNatural.Prelude

/-!
# Line dealing in Natural Lean: the anchor rule

Port of `formal/lean/LineDealing/Anchor.lean`.

Nine of the thirteen theorems stay native. Their statements use list notation
(`l₁ ++ a :: l₂`, `[9, 9, 5]`), counting with a function literal
(`countP (fun x ↦ a ≤ x)`), a cast of a list to a multiset, or a filter with a section
(`S.filter (· ∈ Byz)`). Natural Lean has none of these. For those nine this file gives the
native theorem under the natural name, so the theorem map is complete. The `_index`, `_ge` and
`_quorum` theorems are the forms for `n ≥ 3f + 1` (LOOP item 4b); the others are the case of
exactly `2f + 1` reports.
-/

open Finset

namespace LineDealingNatural

set_option autoImplicit true

alias sorted_split_count := LineDealing.sorted_split_count

alias sorted_getElem?_count := LineDealing.sorted_getElem?_count

alias anchor_between_honest_of_sorted_index := LineDealing.anchor_between_honest_of_sorted_index

alias anchor_between_honest_of_sorted_ge := LineDealing.anchor_between_honest_of_sorted_ge

alias anchor_between_honest_of_sorted := LineDealing.anchor_between_honest_of_sorted

Theorem "Anchor rule for at least 2f + 1 reports".
  Let f : Nat.  Let H, B : Multiset(Nat).  Let a : Nat.
  If 2 · f + 1 ≤ Multiset.card(H) + Multiset.card(B) and Multiset.card(B) ≤ f and
  getElem?(Multiset.sort(H + B, GE.ge), f) = some(a) then
  x ≤ a for some x ∈ H, and a ≤ y for some y ∈ H.  [anchor_between_honest_ge]

Proof.  By [(
  rintro f H B a ⟨hcard, hB, ha⟩
  exact anchor_between_honest_of_sorted_ge (Multiset.sort_eq _ _) (Multiset.pairwise_sort _ _)
    hcard hB ha)].

example : type_of% @anchor_between_honest_ge ↔ type_of% @LineDealing.anchor_between_honest_ge := by
  nl_same

Theorem "The anchor height exists for at least 2f + 1 reports".
  Let f : Nat.  Let M : Multiset(Nat).  If 2 · f + 1 ≤ Multiset.card(M) then
  there is some a : Nat such that getElem?(Multiset.sort(M, GE.ge), f) = some(a).
  [anchor_exists_ge]

Proof.  By [(
  intro f M hcard
  have hlen : (M.sort GE.ge).length = M.card := Multiset.length_sort _
  exact ⟨(M.sort GE.ge)[f]'(by omega), List.getElem?_eq_getElem (by omega)⟩)].

example : type_of% @anchor_exists_ge ↔ type_of% @LineDealing.anchor_exists_ge := Iff.rfl

Theorem "Anchor rule (SCHEME 3.6)".
  Let f : Nat.  Let H, B : Multiset(Nat).  Let a : Nat.
  If Multiset.card(H) + Multiset.card(B) = 2 · f + 1 and Multiset.card(B) ≤ f and
  getElem?(Multiset.sort(H + B, GE.ge), f) = some(a) then
  x ≤ a for some x ∈ H, and a ≤ y for some y ∈ H.  [anchor_between_honest]

Proof.  By [(
  rintro f H B a ⟨hcard, hB, ha⟩
  exact anchor_between_honest_of_sorted (Multiset.sort_eq _ _) (Multiset.pairwise_sort _ _)
    hcard hB ha)].

-- The native statement writes the sorted list as `(H + B).sort (· ≥ ·)` and its entry as
-- `[f]?`. The natural statement names the same functions: `Multiset.sort(H + B, GE.ge)` and
-- `getElem?`.
example : type_of% @anchor_between_honest ↔ type_of% @LineDealing.anchor_between_honest := by
  nl_same

Theorem "The anchor height exists".
  Let f : Nat.  Let M : Multiset(Nat).  If Multiset.card(M) = 2 · f + 1 then
  there is some a : Nat such that getElem?(Multiset.sort(M, GE.ge), f) = some(a).
  [anchor_exists]

Proof.  By [(
  intro f M hcard
  have hlen : (Multiset.sort M GE.ge).length = 2 * f + 1 := by
    rw [Multiset.length_sort, hcard]
  exact ⟨(Multiset.sort M GE.ge)[f]'(by omega), List.getElem?_eq_getElem (by omega)⟩)].

example : type_of% @anchor_exists ↔ type_of% @LineDealing.anchor_exists := Iff.rfl

alias anchor_between_honest_nodes_ge := LineDealing.anchor_between_honest_nodes_ge

alias anchor_between_honest_nodes_quorum := LineDealing.anchor_between_honest_nodes_quorum

alias anchor_between_honest_nodes := LineDealing.anchor_between_honest_nodes

alias anchor_fails_with_f_add_one_byzantine := LineDealing.anchor_fails_with_f_add_one_byzantine

end LineDealingNatural
