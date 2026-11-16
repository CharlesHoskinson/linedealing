import LineDealing.Quorum

/-!
# One digest per slot

SCHEME 3.8 and 3.9 for a single slot `(rid, g)`. Each node has a durable slot ledger, the board
is append-only, and a node can be restored from a backup that predates its ledger entry.

* Rule 1: an honest node prevotes only when its ledger has no entry, and writes the entry.
* Rules 2 and 3: an honest node posts a partial only for a locked digest that equals its ledger
  entry, or, when it has not voted, after writing that digest to its ledger.
* Rule 4: a node whose ledger has no entry while the board shows its own PREVOTE or PARTIAL
  abstains. The step relation takes this rule as the parameter `rule4`.

With rule 4 on, at most `f` Byzantine nodes among `n` and locks of `quorum n f` votes, at most
one digest is ever locked and honest partials exist for at most one digest. With rule 4 off, a
restored node votes twice and both digests get honest partials.
-/

open Finset

namespace LineDealing.Votes

variable {ι D : Type*} [DecidableEq ι] [DecidableEq D]

/-- The state of one slot `(rid, g)`. `ledger i` is node `i`'s durable ledger entry. `prevotes i`
and `partials i` are the digests of the PREVOTE and PARTIAL posts of node `i` on the board. -/
structure State (ι D : Type*) where
  /-- The slot ledger entry of each node. -/
  ledger : ι → Option D
  /-- The digests each node has posted a PREVOTE for. -/
  prevotes : ι → Finset D
  /-- The digests each node has posted a PARTIAL for. -/
  partials : ι → Finset D

/-- The initial state: empty ledgers and an empty board. -/
def init : State ι D := ⟨fun _ ↦ none, fun _ ↦ ∅, fun _ ↦ ∅⟩

/-- Node `i` writes `d` to its ledger. -/
def writeLedger (s : State ι D) (i : ι) (d : D) : State ι D :=
  { s with ledger := Function.update s.ledger i (some d) }

/-- A PREVOTE of node `i` for `d` is added to the board. -/
def postPrevote (s : State ι D) (i : ι) (d : D) : State ι D :=
  { s with prevotes := Function.update s.prevotes i (insert d (s.prevotes i)) }

/-- A PARTIAL of node `i` for `d` is added to the board. -/
def postPartial (s : State ι D) (i : ι) (d : D) : State ι D :=
  { s with partials := Function.update s.partials i (insert d (s.partials i)) }

/-- Node `i` is restored from a backup taken before its ledger entry. The board keeps its
posts. -/
def rollback (s : State ι D) (i : ι) : State ι D :=
  { s with ledger := Function.update s.ledger i none }

/-- The nodes whose PREVOTE for `d` is on the board. -/
def voters [Fintype ι] (s : State ι D) (d : D) : Finset ι := univ.filter fun i ↦ d ∈ s.prevotes i

/-- `LOCK`: `q = quorum n f` distinct nodes have a PREVOTE for `d` on the board, where `n` is the
number of nodes (`2f + 1` for `n = 3f + 1`). -/
def Locked [Fintype ι] (f : ℕ) (s : State ι D) (d : D) : Prop :=
  quorum (Fintype.card ι) f ≤ #(voters s d)

instance [Fintype ι] (f : ℕ) (s : State ι D) (d : D) : Decidable (Locked f s d) := by
  unfold Locked; infer_instance

/-- Rule 4 as a guard: when the rule is on, node `i` acts on an empty ledger only if the board
shows no PREVOTE and no PARTIAL of its own. -/
def Rule4Guard (rule4 : Prop) (s : State ι D) (i : ι) : Prop :=
  rule4 → s.prevotes i = ∅ ∧ s.partials i = ∅

/-- One step of the slot. `Byz` is the set of Byzantine nodes and `rule4` switches rule 4. -/
inductive Step [Fintype ι] (f : ℕ) (Byz : Finset ι) (rule4 : Prop) :
    State ι D → State ι D → Prop
  /-- An honest node with an empty ledger writes `d` and posts its PREVOTE (rule 1). -/
  | prevote (s : State ι D) (i : ι) (d : D) : i ∉ Byz → s.ledger i = none →
      Rule4Guard rule4 s i → Step f Byz rule4 s (postPrevote (writeLedger s i d) i d)
  /-- An honest node posts a PARTIAL for the locked digest in its ledger (rules 2, 3). -/
  | signVoted (s : State ι D) (i : ι) (d : D) : i ∉ Byz → s.ledger i = some d →
      Locked f s d → Step f Byz rule4 s (postPartial s i d)
  /-- An honest node that has not voted writes the locked digest and posts a PARTIAL. -/
  | signLate (s : State ι D) (i : ι) (d : D) : i ∉ Byz → s.ledger i = none →
      Rule4Guard rule4 s i → Locked f s d →
      Step f Byz rule4 s (postPartial (writeLedger s i d) i d)
  /-- Any node is restored from a backup without the ledger entry. -/
  | restore (s : State ι D) (i : ι) : Step f Byz rule4 s (rollback s i)
  /-- A Byzantine node posts any PREVOTE. -/
  | byzPrevote (s : State ι D) (i : ι) (d : D) : i ∈ Byz → Step f Byz rule4 s (postPrevote s i d)
  /-- A Byzantine node posts any PARTIAL. -/
  | byzPartial (s : State ι D) (i : ι) (d : D) : i ∈ Byz → Step f Byz rule4 s (postPartial s i d)

/-- The states reachable from the initial state. -/
def Reachable [Fintype ι] (f : ℕ) (Byz : Finset ι) (rule4 : Prop) (s : State ι D) : Prop :=
  Relation.ReflTransGen (Step f Byz rule4) init s

/-! ## The static core -/

/-- **No two locks, static form.** If every honest node has at most one PREVOTE digest on the
board, at most `f` nodes are Byzantine, and `d` and `d'` both have `quorum n f` PREVOTE posts,
then `d = d'`. The number of nodes `n` is arbitrary. -/
theorem locked_unique_of_prevote_once [Fintype ι] {f : ℕ} {Byz : Finset ι} {s : State ι D}
    (hByz : #Byz ≤ f)
    (honce : ∀ i, i ∉ Byz → ∀ d ∈ s.prevotes i, ∀ d' ∈ s.prevotes i, d = d')
    {d d' : D} (hd : Locked f s d) (hd' : Locked f s d') : d = d' := by
  obtain ⟨i, hi, hiB⟩ := quorum_inter_honest_univ_q hd hd' hByz
  simp only [voters, mem_inter, mem_filter, mem_univ, true_and] at hi
  exact honce i hiB d hi.1 d' hi.2

/-! ## The invariant under rule 4 -/

/-- The board only grows, so a lock stays a lock. -/
theorem Step.prevotes_mono [Fintype ι] {f : ℕ} {Byz : Finset ι} {rule4 : Prop}
    {s s' : State ι D} (h : Step f Byz rule4 s s') (j : ι) : s.prevotes j ⊆ s'.prevotes j := by
  cases h with
  | prevote i d _ _ _ =>
    by_cases hji : j = i
    · subst hji; simp [postPrevote, writeLedger]
    · simp [postPrevote, writeLedger, Function.update_of_ne hji]
  | byzPrevote i d _ =>
    by_cases hji : j = i
    · subst hji; simp [postPrevote]
    · simp [postPrevote, Function.update_of_ne hji]
  | signVoted i d _ _ _ => simp [postPartial]
  | signLate i d _ _ _ _ => simp [postPartial, writeLedger]
  | restore i => simp [rollback]
  | byzPartial i d _ => simp [postPartial]

omit [DecidableEq ι] in
/-- A lock survives every extension of the board. -/
theorem Locked.mono [Fintype ι] {f : ℕ} {s s' : State ι D}
    (h : ∀ j, s.prevotes j ⊆ s'.prevotes j) {d : D} (hd : Locked f s d) : Locked f s' d := by
  refine le_trans hd (card_le_card ?_)
  intro j hj
  simp only [voters, mem_filter, mem_univ, true_and] at hj ⊢
  exact h j hj

/-- The invariant of an honest node `i`: all its posts carry one digest, that digest is its
ledger entry if it has one, and every digest it posted a PARTIAL for is locked. -/
def NodeInv [Fintype ι] (f : ℕ) (s : State ι D) (i : ι) : Prop :=
  (∀ d ∈ s.prevotes i ∪ s.partials i, ∀ d' ∈ s.prevotes i ∪ s.partials i, d = d') ∧
    (∀ d, s.ledger i = some d → ∀ d' ∈ s.prevotes i ∪ s.partials i, d' = d) ∧
    (∀ d ∈ s.partials i, Locked f s d)

theorem Step.nodeInv [Fintype ι] {f : ℕ} {Byz : Finset ι} {s s' : State ι D}
    (h : Step f Byz True s s') {j : ι} (hj : j ∉ Byz) (inv : NodeInv f s j) :
    NodeInv f s' j := by
  obtain ⟨i1, i2, i3⟩ := inv
  have mono := h.prevotes_mono
  have i3' : ∀ d ∈ s.partials j, Locked f s' d := fun d hd ↦ (i3 d hd).mono mono
  cases h with
  | prevote i d hi hl hg =>
    by_cases hji : j = i
    · subst hji
      obtain ⟨e1, e2⟩ := hg trivial
      refine ⟨?_, ?_, ?_⟩ <;> simp [postPrevote, writeLedger, e1, e2]
    · exact ⟨by simpa [postPrevote, writeLedger, Function.update_of_ne hji] using i1,
        by simpa [postPrevote, writeLedger, Function.update_of_ne hji] using i2,
        by simpa [postPrevote, writeLedger] using i3'⟩
  | signVoted i d hi hl hlock =>
    by_cases hji : j = i
    · subst hji
      have hsub := i2 d hl
      refine ⟨?_, ?_, ?_⟩
      · intro a ha b hb
        simp only [postPartial, Function.update_self, mem_union, mem_insert] at ha hb
        have ea : a = d := by
          rcases ha with ha | rfl | ha
          · exact hsub a (mem_union_left _ ha)
          · rfl
          · exact hsub a (mem_union_right _ ha)
        have eb : b = d := by
          rcases hb with hb | rfl | hb
          · exact hsub b (mem_union_left _ hb)
          · rfl
          · exact hsub b (mem_union_right _ hb)
        rw [ea, eb]
      · intro e he b hb
        simp only [postPartial] at he
        have hed : e = d := by rw [hl] at he; exact (Option.some.inj he).symm
        simp only [postPartial, Function.update_self, mem_union, mem_insert] at hb
        rw [hed]
        rcases hb with hb | rfl | hb
        · exact hsub b (mem_union_left _ hb)
        · rfl
        · exact hsub b (mem_union_right _ hb)
      · intro a ha
        simp only [postPartial, Function.update_self, mem_insert] at ha
        rcases ha with rfl | ha
        · exact hlock.mono mono
        · exact i3' a ha
    · exact ⟨by simpa [postPartial, Function.update_of_ne hji] using i1,
        by simpa [postPartial, Function.update_of_ne hji] using i2,
        by simpa [postPartial, Function.update_of_ne hji] using i3'⟩
  | signLate i d hi hl hg hlock =>
    by_cases hji : j = i
    · subst hji
      obtain ⟨e1, e2⟩ := hg trivial
      refine ⟨?_, ?_, ?_⟩
      · simp [postPartial, writeLedger, e1, e2]
      · simp [postPartial, writeLedger, e1, e2]
      · intro a ha
        simp only [postPartial, writeLedger, Function.update_self, e2, insert_empty_eq,
          mem_singleton] at ha
        subst ha
        exact hlock.mono mono
    · exact ⟨by simpa [postPartial, writeLedger, Function.update_of_ne hji] using i1,
        by simpa [postPartial, writeLedger, Function.update_of_ne hji] using i2,
        by simpa [postPartial, writeLedger, Function.update_of_ne hji] using i3'⟩
  | restore i =>
    by_cases hji : j = i
    · subst hji
      exact ⟨by simpa [rollback] using i1, by simp [rollback],
        by simpa [rollback] using i3'⟩
    · exact ⟨by simpa [rollback] using i1,
        by simpa [rollback, Function.update_of_ne hji] using i2,
        by simpa [rollback] using i3'⟩
  | byzPrevote i d hi =>
    have hji : j ≠ i := fun e ↦ hj (e ▸ hi)
    exact ⟨by simpa [postPrevote, Function.update_of_ne hji] using i1,
      by simpa [postPrevote, Function.update_of_ne hji] using i2,
      by simpa [postPrevote] using i3'⟩
  | byzPartial i d hi =>
    have hji : j ≠ i := fun e ↦ hj (e ▸ hi)
    exact ⟨by simpa [postPartial, Function.update_of_ne hji] using i1,
      by simpa [postPartial, Function.update_of_ne hji] using i2,
      by simpa [postPartial, Function.update_of_ne hji] using i3'⟩

/-- Every reachable state under rule 4 satisfies the invariant at every honest node. -/
theorem Reachable.nodeInv [Fintype ι] {f : ℕ} {Byz : Finset ι} {s : State ι D}
    (h : Reachable f Byz True s) {j : ι} (hj : j ∉ Byz) : NodeInv f s j := by
  induction h with
  | refl => exact ⟨by simp [init], by simp [init], by simp [init]⟩
  | tail _ hstep ih => exact hstep.nodeInv hj ih

/-! ## The theorems under rule 4 -/

/-- **Rule 1 holds on the board.** Under rule 4 an honest node has at most one PREVOTE digest
on the board in every reachable state, restores included. -/
theorem honest_prevotes_once [Fintype ι] {f : ℕ} {Byz : Finset ι} {s : State ι D}
    (h : Reachable f Byz True s) {i : ι} (hi : i ∉ Byz) {d d' : D} (hd : d ∈ s.prevotes i)
    (hd' : d' ∈ s.prevotes i) : d = d' :=
  (h.nodeInv hi).1 d (mem_union_left _ hd) d' (mem_union_left _ hd')

/-- **At most one lock per slot.** Under rule 4, with at most `f` Byzantine nodes among `n`, no
two different digests both get `quorum n f` PREVOTE posts. -/
theorem locked_unique [Fintype ι] {f : ℕ} {Byz : Finset ι} {s : State ι D}
    (hByz : #Byz ≤ f) (h : Reachable f Byz True s) {d d' : D}
    (hd : Locked f s d) (hd' : Locked f s d') : d = d' :=
  locked_unique_of_prevote_once hByz
    (fun _ hi _ hd _ hd' ↦ honest_prevotes_once h hi hd hd') hd hd'

/-- **One digest per slot.** Under rule 4, with at most `f` Byzantine nodes among `n` and
locks of `quorum n f` PREVOTE posts, the PARTIAL posts of honest nodes all carry one digest. -/
theorem one_digest_per_slot [Fintype ι] {f : ℕ} {Byz : Finset ι} {s : State ι D}
    (hByz : #Byz ≤ f) (h : Reachable f Byz True s) {i j : ι}
    (hi : i ∉ Byz) (hj : j ∉ Byz) {d d' : D} (hd : d ∈ s.partials i) (hd' : d' ∈ s.partials j) :
    d = d' :=
  locked_unique hByz h ((h.nodeInv hi).2.2 d hd) ((h.nodeInv hj).2.2 d' hd')

/-! ## Without rule 4 -/

/-- **Rule 4 is needed.** Four nodes, `f = 1`, node `3` Byzantine, digests `false` and `true`,
rule 4 off. Nodes `0`, `1` and `3` prevote `false`; node `1` signs it. Node `0` is restored and,
with nodes `2` and `3`, prevotes `true`; node `2` signs it. Both digests are locked and each has
a PARTIAL from an honest node. -/
theorem two_digests_without_rule4 :
    ∃ s : State (Fin 4) Bool, Reachable 1 {3} False s ∧ Locked 1 s false ∧ Locked 1 s true ∧
      (1 : Fin 4) ∉ ({3} : Finset (Fin 4)) ∧ (2 : Fin 4) ∉ ({3} : Finset (Fin 4)) ∧
      false ∈ s.partials 1 ∧ true ∈ s.partials 2 := by
  let B : Finset (Fin 4) := {3}
  let s1 : State (Fin 4) Bool := postPrevote (writeLedger init 0 false) 0 false
  let s2 : State (Fin 4) Bool := postPrevote (writeLedger s1 1 false) 1 false
  let s3 : State (Fin 4) Bool := postPrevote s2 3 false
  let s4 : State (Fin 4) Bool := postPartial s3 1 false
  let s5 : State (Fin 4) Bool := rollback s4 0
  let s6 : State (Fin 4) Bool := postPrevote (writeLedger s5 0 true) 0 true
  let s7 : State (Fin 4) Bool := postPrevote (writeLedger s6 2 true) 2 true
  let s8 : State (Fin 4) Bool := postPrevote s7 3 true
  let s9 : State (Fin 4) Bool := postPartial s8 2 true
  have g : ∀ (s : State (Fin 4) Bool) (i : Fin 4), Rule4Guard False s i := fun _ _ h ↦ h.elim
  have t1 : Step 1 B False init s1 := Step.prevote _ 0 false (by decide) rfl (g _ _)
  have t2 : Step 1 B False s1 s2 := Step.prevote _ 1 false (by decide) (by decide) (g _ _)
  have t3 : Step 1 B False s2 s3 := Step.byzPrevote _ 3 false (by decide)
  have t4 : Step 1 B False s3 s4 := Step.signVoted _ 1 false (by decide) (by decide) (by decide)
  have t5 : Step 1 B False s4 s5 := Step.restore _ 0
  have t6 : Step 1 B False s5 s6 := Step.prevote _ 0 true (by decide) (by decide) (g _ _)
  have t7 : Step 1 B False s6 s7 := Step.prevote _ 2 true (by decide) (by decide) (g _ _)
  have t8 : Step 1 B False s7 s8 := Step.byzPrevote _ 3 true (by decide)
  have t9 : Step 1 B False s8 s9 := Step.signVoted _ 2 true (by decide) (by decide) (by decide)
  refine ⟨s9, ?_, by decide, by decide, by decide, by decide, by decide, by decide⟩
  exact ((((((((Relation.ReflTransGen.single t1).tail t2).tail t3).tail t4).tail t5).tail
    t6).tail t7).tail t8).tail t9

end LineDealing.Votes
