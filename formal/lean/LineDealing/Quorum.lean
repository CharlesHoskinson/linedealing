import LineDealing.Basic

/-!
# Quorum intersection

SCHEME 2 uses a committee of `n ≥ 3f + 1` nodes and quorums of `q = ⌈(n + f + 1)/2⌉` nodes
(`quorum n f`). For `n = 3f + 1` this is `2f + 1`. This file proves the counting facts behind
"two quorums share an honest node", the three properties of `q` that the protocol uses (two
quorums share `f + 1` nodes, the honest nodes alone fill a quorum, `q ≥ 2f + 1`), and tightness:
`q` is the least size with the intersection property, a fixed size of `2f + 1` fails for
`n ≥ 3f + 2`, and no size works for `n ≤ 3f`.
-/

open Finset

namespace LineDealing

variable {ι : Type*} [DecidableEq ι]

/-- The counting lemma: two subsets of a universe `U` overlap in at least `#A + #B - #U`
elements. -/
theorem card_add_card_le_card_add_inter {U A B : Finset ι} (hA : A ⊆ U) (hB : B ⊆ U) :
    #A + #B ≤ #U + #(A ∩ B) := by
  have h := card_union_add_card_inter A B
  have hU : #(A ∪ B) ≤ #U := card_le_card (union_subset hA hB)
  omega

/-- General quorum intersection: in a universe of `n` nodes with quorums of size at least `k`
and `n + f < 2 * k`, two quorums share at least `f + 1` nodes. -/
theorem quorum_inter_card_general {U A B : Finset ι} {f k : ℕ} (hA : A ⊆ U) (hB : B ⊆ U)
    (hk : #U + f < 2 * k) (hqA : k ≤ #A) (hqB : k ≤ #B) : f + 1 ≤ #(A ∩ B) := by
  have h := card_add_card_le_card_add_inter hA hB
  omega

/-- A set of at least `f + 1` nodes contains a node outside every set of at most `f` nodes. -/
theorem exists_not_mem_of_card_lt {C Byz : Finset ι} {f : ℕ} (hC : f + 1 ≤ #C)
    (hByz : #Byz ≤ f) : ∃ i ∈ C, i ∉ Byz := by
  by_contra hcon
  push Not at hcon
  have : #C ≤ #Byz := card_le_card hcon
  omega

/-! ## The case `n = 3f + 1`, where `q = 2f + 1` -/

/-- **Quorum intersection, size.** With at most `3f + 1` nodes, two sets of `2f + 1` nodes share
at least `f + 1` nodes. -/
theorem quorum_inter_card {U A B : Finset ι} {f : ℕ} (hA : A ⊆ U) (hB : B ⊆ U)
    (hU : #U ≤ 3 * f + 1) (hqA : 2 * f + 1 ≤ #A) (hqB : 2 * f + 1 ≤ #B) :
    f + 1 ≤ #(A ∩ B) :=
  quorum_inter_card_general hA hB (by omega) hqA hqB

/-- **Quorum intersection, honest node.** With at most `3f + 1` nodes of which at most `f` are
Byzantine, two sets of `2f + 1` nodes share a node that is not Byzantine. -/
theorem quorum_inter_honest {U A B Byz : Finset ι} {f : ℕ} (hA : A ⊆ U) (hB : B ⊆ U)
    (hU : #U ≤ 3 * f + 1) (hqA : 2 * f + 1 ≤ #A) (hqB : 2 * f + 1 ≤ #B) (hByz : #Byz ≤ f) :
    ∃ i ∈ A ∩ B, i ∉ Byz :=
  exists_not_mem_of_card_lt (quorum_inter_card hA hB hU hqA hqB) hByz

/-- The same over a finite node type. -/
theorem quorum_inter_honest_univ [Fintype ι] {A B Byz : Finset ι} {f : ℕ}
    (hn : Fintype.card ι ≤ 3 * f + 1) (hqA : 2 * f + 1 ≤ #A) (hqB : 2 * f + 1 ≤ #B)
    (hByz : #Byz ≤ f) : ∃ i ∈ A ∩ B, i ∉ Byz :=
  quorum_inter_honest (subset_univ A) (subset_univ B) (by simpa using hn) hqA hqB hByz

/-! ## The quorum size for `n ≥ 3f + 1` -/

/-- The quorum size `q = ⌈(n + f + 1)/2⌉` of a committee of `n` nodes with at most `f` Byzantine
nodes (SCHEME 2). -/
def quorum (n f : ℕ) : ℕ := (n + f + 2) / 2

/-- `quorum n f` is the ceiling of `(n + f + 1)/2`: it is the integer `q` with
`n + f + 1 ≤ 2q ≤ n + f + 2`. -/
theorem quorum_spec (n f : ℕ) : n + f + 1 ≤ 2 * quorum n f ∧ 2 * quorum n f ≤ n + f + 2 := by
  unfold quorum; omega

/-- Two quorums together exceed `n + f`. This holds for every `n` and `f`. -/
theorem lt_two_mul_quorum (n f : ℕ) : n + f < 2 * quorum n f := by
  unfold quorum; omega

/-- `quorum n f` is the least size `k` with `n + f < 2k`. -/
theorem quorum_le_of_lt_two_mul {n f k : ℕ} (hk : n + f < 2 * k) : quorum n f ≤ k := by
  unfold quorum; omega

/-- For `n = 3f + 1` the quorum is `2f + 1`. -/
theorem quorum_three_mul_add_one (f : ℕ) : quorum (3 * f + 1) f = 2 * f + 1 := by
  unfold quorum; omega

/-- **Liveness bound.** With `n ≥ 3f + 1` the quorum is at most `n - f`. -/
theorem quorum_add_le {n f : ℕ} (hn : 3 * f + 1 ≤ n) : quorum n f + f ≤ n := by
  unfold quorum; omega

/-- **Anchor bound.** With `n ≥ 3f + 1` the quorum is at least `2f + 1`. -/
theorem two_mul_add_one_le_quorum {n f : ℕ} (hn : 3 * f + 1 ≤ n) : 2 * f + 1 ≤ quorum n f := by
  unfold quorum; omega

/-- **Quorum intersection for `q`, size.** Among at most `n` nodes, two sets of `quorum n f`
nodes share at least `f + 1` nodes. No bound on `n` is needed. -/
theorem quorum_inter_card_q {U A B : Finset ι} {n f : ℕ} (hA : A ⊆ U) (hB : B ⊆ U)
    (hU : #U ≤ n) (hqA : quorum n f ≤ #A) (hqB : quorum n f ≤ #B) : f + 1 ≤ #(A ∩ B) :=
  quorum_inter_card_general hA hB (by have := lt_two_mul_quorum n f; omega) hqA hqB

/-- **Quorum intersection for `q`, honest node.** Among at most `n` nodes of which at most `f`
are Byzantine, two sets of `quorum n f` nodes share a node that is not Byzantine. -/
theorem quorum_inter_honest_q {U A B Byz : Finset ι} {n f : ℕ} (hA : A ⊆ U) (hB : B ⊆ U)
    (hU : #U ≤ n) (hqA : quorum n f ≤ #A) (hqB : quorum n f ≤ #B) (hByz : #Byz ≤ f) :
    ∃ i ∈ A ∩ B, i ∉ Byz :=
  exists_not_mem_of_card_lt (quorum_inter_card_q hA hB hU hqA hqB) hByz

/-- The same over a finite node type, with `n` the number of nodes. `Votes.lean` uses this
form. -/
theorem quorum_inter_honest_univ_q [Fintype ι] {A B Byz : Finset ι} {f : ℕ}
    (hqA : quorum (Fintype.card ι) f ≤ #A) (hqB : quorum (Fintype.card ι) f ≤ #B)
    (hByz : #Byz ≤ f) : ∃ i ∈ A ∩ B, i ∉ Byz :=
  quorum_inter_honest_q (subset_univ A) (subset_univ B) (by simp) hqA hqB hByz

/-- **The honest nodes fill a quorum.** With `n ≥ 3f + 1` nodes of which at most `f` are
Byzantine, the nodes that are not Byzantine number at least `quorum n f`. -/
theorem quorum_le_card_honest {U Byz : Finset ι} {f : ℕ} (hn : 3 * f + 1 ≤ #U)
    (hByz : #Byz ≤ f) : quorum #U f ≤ #(U \ Byz) := by
  have h1 := le_card_sdiff Byz U
  have h2 := quorum_add_le hn
  omega

/-- A quorum holds at least `f + 1` nodes that are not Byzantine (`n ≥ 3f + 1`). These are
enough partials for the threshold `t = f + 1`. -/
theorem quorum_honest_card {A Byz : Finset ι} {n f : ℕ} (hn : 3 * f + 1 ≤ n)
    (hqA : quorum n f ≤ #A) (hByz : #Byz ≤ f) : f + 1 ≤ #(A \ Byz) := by
  have h1 := le_card_sdiff Byz A
  have h2 := two_mul_add_one_le_quorum hn
  omega

/-- **Tightness of `q`.** With `n` nodes and `f ≤ n` there are two sets of exactly
`quorum n f - 1` nodes whose intersection lies inside a set of at most `f` nodes. So no quorum
size below `quorum n f` puts an honest node in every intersection. -/
theorem quorum_inter_fails_below (f n : ℕ) (hf : f ≤ n) :
    ∃ A B Byz : Finset ℕ, A ⊆ range n ∧ B ⊆ range n ∧ Byz ⊆ range n ∧
      #A = quorum n f - 1 ∧ #B = quorum n f - 1 ∧ #Byz ≤ f ∧ A ∩ B ⊆ Byz := by
  have hq := quorum_spec n f
  refine ⟨range (quorum n f - 1), Ico (n - (quorum n f - 1)) n,
    Ico (n - (quorum n f - 1)) (quorum n f - 1), ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp only [Nat.card_Ico]; omega
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega

/-! ## Tightness of the bound on `n` -/

/-- **Tightness, too many nodes for `2f + 1`.** With `n ≥ 3f + 2` nodes (the nodes are
`0, …, n - 1`) there are two sets of exactly `2f + 1` nodes whose intersection lies inside a set
of exactly `f` nodes. If that set is Byzantine, the two quorums share no honest node. This is
why a committee with `n > 3f + 1` uses `quorum n f` and not `2f + 1`. -/
theorem quorum_inter_fails_of_large (f n : ℕ) (hn : 3 * f + 2 ≤ n) :
    ∃ A B Byz : Finset ℕ, A ⊆ range n ∧ B ⊆ range n ∧ Byz ⊆ range n ∧
      #A = 2 * f + 1 ∧ #B = 2 * f + 1 ∧ #Byz = f ∧ A ∩ B ⊆ Byz := by
  refine ⟨range (2 * f + 1), Ico (f + 1) (3 * f + 2), Ico (f + 1) (2 * f + 1), ?_, ?_, ?_, ?_, ?_,
    ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp only [Nat.card_Ico]; omega
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega

/-- **Tightness, too few nodes.** With `n ≤ 3f` nodes a quorum that `n - f` honest nodes can
fill has at most `n - f` members. There are two sets of exactly `n - f` nodes whose intersection
lies inside a set of at most `f` nodes. So no quorum size gives both progress without the
Byzantine nodes and an honest node in every intersection. -/
theorem quorum_inter_fails_of_small (f n : ℕ) (hn : n ≤ 3 * f) :
    ∃ A B Byz : Finset ℕ, A ⊆ range n ∧ B ⊆ range n ∧ Byz ⊆ range n ∧
      #A = n - f ∧ #B = n - f ∧ #Byz ≤ f ∧ A ∩ B ⊆ Byz := by
  refine ⟨range (n - f), Ico f n, Ico f (n - f), ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro x; simp only [mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · intro x; simp only [mem_Ico, mem_range]; omega
  · simp
  · simp
  · simp only [Nat.card_Ico]; omega
  · intro x; simp only [mem_inter, mem_range, mem_Ico]; omega

end LineDealing
