import LineDealing.Ecdsa
import LineDealing.Quorum
import LineDealing.Votes

/-!
# Split-line dealing: slot rules

`design/enhancement/DESIGN.md` §3.6 step 7, §4.1, §4.4 and §7.11, DECISIONS 43, 44 and 46 (3).

- One digest per slot: the committee half of a slot signs one digest (`C12`). The step relation of
  `Votes.lean` proves it; `C12_one_digest_per_slot` restates it under the claim's name.
- An ECDSA slot is bound to one leaf set (DECISIONS 43). Two subsets of one group on one slot give
  the group's half line, and with every other half the key; a member that answers once and only
  for the slot's leaf set leaves at most one request with a full set of answers.
- Slot precedence by board order (DECISIONS 44). Honest nodes vote to reserve a slot only for the
  earliest live request in board order that names it, and a slot that an ended request named is
  burned. Then at most one request ever reserves the slot, and it is the first request in board
  order that named it.
- Cold-start burn (DECISIONS 46 (3), C16). When the recovery group has no verified board record
  up to the outage, it keeps no slot that was unclaimed at the checkpoint.

Each rule has a companion that shows what fails without it.
-/

open Polynomial Finset

set_option linter.unusedSectionVars false

namespace LineDealing.Split

variable {q : ℕ} [Fact q.Prime]

/-! ## One digest per slot -/

/-- **C12, one digest per slot.** In the slot model of `Votes.lean`, with rule 4 and at most `f`
Byzantine nodes, the PARTIAL posts of honest nodes on a slot all carry one digest. -/
theorem C12_one_digest_per_slot {ι D : Type*} [DecidableEq ι] [DecidableEq D] [Fintype ι]
    {f : ℕ} {Byz : Finset ι} {s : Votes.State ι D} (hByz : #Byz ≤ f)
    (h : Votes.Reachable f Byz True s) {i j : ι} (hi : i ∉ Byz) (hj : j ∉ Byz) {d d' : D}
    (hd : d ∈ s.partials i) (hd' : d' ∈ s.partials j) : d = d' :=
  Votes.one_digest_per_slot hByz h hi hj hd hd'

/-! ## DECISIONS 43: an ECDSA slot is bound to one leaf set -/

/-- **D43, two subsets reveal the group's half line.** Let a group hold Shamir shares `w(i)`,
`μ(i)` (degree below `k`) of its ECDSA half `(w(0), μ(0))` on one slot. If the subset `T` answers
a request with hash `h` and the subset `T'` a request with hash `h' ≠ h`, both with the slot's
`r`, the two combined contributions `u`, `u'` give `w(0) = (u − u')/(h − h')`, and for `r ≠ 0`
also `μ(0) = (u − h w(0))/r`. -/
theorem D43_two_subsets_reveal_line (T T' : Finset (ZMod q)) {k : ℕ} (hT : #T = k)
    (hT' : #T' = k) {w μ : (ZMod q)[X]} (hw : w.degree < k) (hμ : μ.degree < k)
    {h h' r u u' : ZMod q} (hh : h ≠ h')
    (hu : u = ∑ i ∈ T, lam T i * (h * w.eval i + r * μ.eval i))
    (hu' : u' = ∑ i ∈ T', lam T' i * (h' * w.eval i + r * μ.eval i)) :
    w.eval 0 = (u - u') / (h - h') ∧ (r ≠ 0 → μ.eval 0 = (u - h * w.eval 0) / r) := by
  rw [partial_combine T hT hw hμ] at hu
  rw [partial_combine T' hT' hw hμ] at hu'
  have hsub : h - h' ≠ 0 := sub_ne_zero.mpr hh
  refine ⟨?_, fun hr ↦ ?_⟩
  · rw [eq_div_iff hsub, hu, hu']; ring
  · rw [eq_div_iff hr, hu]; ring

/-- **D43, the half line and every other half give the key.** If the group's half `(w_γ, μ_γ)` and
the sum `(w_o, μ_o)` of every other half of the slot (the other actors' and the committee's) are
known, with `w_γ + w_o = k⁻¹`, `μ_γ + μ_o = k⁻¹ x` and `k ≠ 0`, then
`x = (μ_γ + μ_o)/(w_γ + w_o)`. Without the other actors' halves the group's line alone does not
give `x`. -/
theorem D43_line_gives_key {k x wγ μγ wo μo : ZMod q} (hk : k ≠ 0) (hw : wγ + wo = k⁻¹)
    (hμ : μγ + μo = k⁻¹ * x) : x = (μγ + μo) / (wγ + wo) := by
  rw [hw, hμ]
  field_simp

/-- The answers on one ECDSA slot. `leafSet r` is the subset of the group that request `r` names
on the slot. `ans i r` says that member `i` contributed to `r` on the slot. -/
structure SlotAnswers (M R : Type*) where
  leafSet : R → Finset M
  ans : M → R → Bool

/-- Request `r` has a contribution from every member of its leaf set. -/
def SlotAnswers.Full {M R : Type*} (V : SlotAnswers M R) (r : R) : Prop :=
  ∀ i ∈ V.leafSet r, V.ans i r = true

instance {M R : Type*} (V : SlotAnswers M R) (r : R) : Decidable (V.Full r) := by
  unfold SlotAnswers.Full; infer_instance

/-- The members' rule of §3.6 step 7: an honest member contributes on the slot only to a request
whose leaf set is the slot's leaf set `T`, and only once. -/
def BoundRule {M R : Type*} (T : Finset M) (Byz : Finset M) (V : SlotAnswers M R) : Prop :=
  ∀ i, i ∉ Byz → ∀ r, V.ans i r = true → V.leafSet r = T ∧ ∀ r', V.ans i r' = true → r' = r

/-- The rule without the leaf-set check: an honest member contributes at most once. -/
def OnceRule {M R : Type*} (Byz : Finset M) (V : SlotAnswers M R) : Prop :=
  ∀ i, i ∉ Byz → ∀ r r', V.ans i r = true → V.ans i r' = true → r' = r

/-- **D43, a bound slot refuses a second subset.** Under the members' rule, a request whose leaf
set differs from the slot's leaf set gets no honest contribution, so if it has a full set of
answers, all of them come from corrupt members. -/
theorem D43_bound_slot_refuses {M R : Type*} {T Byz : Finset M} {V : SlotAnswers M R}
    (hrule : BoundRule T Byz V) {r : R} (hne : V.leafSet r ≠ T) (hfull : V.Full r) :
    V.leafSet r ⊆ Byz := by
  intro i hi
  by_contra hiB
  exact hne (hrule i hiB r (hfull i hi)).1

/-- **D43 and C12, one evaluation of the group's line per slot.** Let every leaf set have `k`
members and let fewer than `k` members be corrupt (a coalition outside the group's gate). Under
the members' rule at most one request on the slot has a full set of answers, so the two
evaluations of `D43_two_subsets_reveal_line` never exist. This holds against a fully corrupt
committee, which may name the slot in any request. -/
theorem D43_one_full_request {M R : Type*} {T Byz : Finset M} {V : SlotAnswers M R} {k : ℕ}
    (hrule : BoundRule T Byz V) (hk : ∀ r, #(V.leafSet r) = k) (hByz : #Byz < k) {r₁ r₂ : R}
    (h₁ : V.Full r₁) (h₂ : V.Full r₂) : r₁ = r₂ := by
  have honest : ∀ r, ∃ i ∈ V.leafSet r, i ∉ Byz := by
    intro r
    by_contra hc
    simp only [not_exists, not_and, not_not] at hc
    exact absurd (card_le_card (s := V.leafSet r) (t := Byz) hc) (by rw [hk r]; omega)
  obtain ⟨i, hi, hiB⟩ := honest r₁
  obtain ⟨j, hj, hjB⟩ := honest r₂
  have hT₁ : V.leafSet r₁ = T := (hrule i hiB r₁ (h₁ i hi)).1
  have hT₂ : V.leafSet r₂ = T := (hrule j hjB r₂ (h₂ j hj)).1
  have hi₂ : i ∈ V.leafSet r₂ := hT₂ ▸ hT₁ ▸ hi
  exact ((hrule i hiB r₁ (h₁ i hi)).2 r₂ (h₂ i hi₂)).symm

/-- The two-subset slot of the review: three members, member `0` corrupt, request `false` names
`{0, 1}` and request `true` names `{0, 2}`. -/
def twoSubsets : SlotAnswers (Fin 3) Bool where
  leafSet r := if r then {0, 2} else {0, 1}
  ans i r := decide (i = 0) || (decide (i = 1) && !r) || (decide (i = 2) && r)

/-- **D43, without the binding two subsets complete.** With the once-only rule and no leaf-set
check, two requests on one slot both get a full set of answers, while each honest member answers
once and only one member is corrupt (fewer than `k = 2`). Their combined contributions are the two
evaluations of `D43_two_subsets_reveal_line`. -/
theorem D43_without_binding_two_full :
    OnceRule {0} twoSubsets ∧ #({0} : Finset (Fin 3)) < 2 ∧
      (∀ r, #(twoSubsets.leafSet r) = 2) ∧ twoSubsets.Full false ∧ twoSubsets.Full true := by
  refine ⟨?_, by decide, by decide, by decide, by decide⟩
  unfold OnceRule
  decide

/-! ## DECISIONS 44: slot precedence by board order -/

namespace Precedence

variable {ι R : Type*} [DecidableEq ι] [DecidableEq R]

/-- The state of one Schnorr committee slot `ℓ`. `ord r` is the board height at which request `r`
was ordered, `ended` holds the requests that ended or lapsed, and `votes i` the requests that node
`i` voted to reserve the slot for. -/
structure State (ι R : Type*) where
  ord : R → Option ℕ
  next : ℕ
  ended : Finset R
  votes : ι → Finset R

/-- The initial state: nothing ordered, nothing ended, no votes. -/
def init : State ι R := ⟨fun _ ↦ none, 0, ∅, fun _ ↦ ∅⟩

/-- Order request `r` at the next board height. -/
def order (s : State ι R) (r : R) : State ι R :=
  { s with ord := Function.update s.ord r (some s.next), next := s.next + 1 }

/-- Request `r` ends or lapses. -/
def finish (s : State ι R) (r : R) : State ι R := { s with ended := insert r s.ended }

/-- Node `i` votes to reserve the slot for `r`. -/
def vote (s : State ι R) (i : ι) (r : R) : State ι R :=
  { s with votes := Function.update s.votes i (insert r (s.votes i)) }

/-- The slot is burned: an ordered request that named it has ended. -/
def Burned (names : R → Bool) (s : State ι R) : Prop :=
  ∃ r, names r = true ∧ s.ord r ≠ none ∧ r ∈ s.ended

/-- DECISIONS 44: `r` has precedence on the slot. It names the slot, it is ordered, every request
ordered before it that names the slot has ended, it is live, and the slot is not burned. -/
def BoardPrec (names : R → Bool) (s : State ι R) (r : R) : Prop :=
  names r = true ∧ (∃ b, s.ord r = some b ∧
    ∀ r' b', names r' = true → s.ord r' = some b' → b' < b → r' ∈ s.ended) ∧
    r ∉ s.ended ∧ ¬ Burned names s

/-- The rule of item 35 that DECISIONS 44 replaced: a node votes for any ordered, live request that
names the slot while its authorization is in force. -/
def InForcePrec (names inForce : R → Bool) (s : State ι R) (r : R) : Prop :=
  names r = true ∧ s.ord r ≠ none ∧ inForce r = true ∧ r ∉ s.ended

/-- One step. `Byz` is the set of corrupt nodes; `rule` is the precedence rule honest nodes
follow. -/
inductive Step (Byz : Finset ι) (rule : State ι R → R → Prop) : State ι R → State ι R → Prop
  | order (s : State ι R) (r : R) : s.ord r = none → Step Byz rule s (order s r)
  | finish (s : State ι R) (r : R) : Step Byz rule s (finish s r)
  | vote (s : State ι R) (i : ι) (r : R) : i ∉ Byz → rule s r → Step Byz rule s (vote s i r)
  | byzVote (s : State ι R) (i : ι) (r : R) : i ∈ Byz → Step Byz rule s (vote s i r)

/-- The states reachable from the initial state. -/
def Reachable (Byz : Finset ι) (rule : State ι R → R → Prop) (s : State ι R) : Prop :=
  Relation.ReflTransGen (Step Byz rule) init s

/-- `r` reserved the slot: `quorum n f` nodes voted for it. -/
def Reserved [Fintype ι] (f : ℕ) (s : State ι R) (r : R) : Prop :=
  quorum (Fintype.card ι) f ≤ #(univ.filter fun i ↦ r ∈ s.votes i)

/-- `r` is the first request in board order that names the slot. -/
def FirstNamer (names : R → Bool) (s : State ι R) (r : R) : Prop :=
  names r = true ∧ ∃ b, s.ord r = some b ∧ ∀ r' b', names r' = true → s.ord r' = some b' → b ≤ b'

/-- The invariant: heights are below `next`, and every honest vote is for the first namer. -/
def Inv (names : R → Bool) (Byz : Finset ι) (s : State ι R) : Prop :=
  (∀ r b, s.ord r = some b → b < s.next) ∧
    ∀ i, i ∉ Byz → ∀ r ∈ s.votes i, FirstNamer names s r

theorem inv_init (names : R → Bool) (Byz : Finset ι) : Inv names Byz (init : State ι R) :=
  ⟨fun _ _ h ↦ by simp [init] at h, fun _ _ _ h ↦ by simp [init] at h⟩

/-- **D44, precedence is held by the first namer.** A request with precedence is the first request
in board order that names the slot: an earlier one would have ended and burned the slot. -/
theorem D44_prec_first_namer {names : R → Bool} {s : State ι R} {r : R}
    (h : BoardPrec names s r) : FirstNamer names s r := by
  obtain ⟨hn, ⟨b, hb, hearly⟩, _, hburn⟩ := h
  refine ⟨hn, b, hb, fun r' b' hn' hb' ↦ ?_⟩
  by_contra hlt
  exact hburn ⟨r', hn', by simp [hb'], hearly r' b' hn' hb' (lt_of_not_ge hlt)⟩

theorem inv_step {names : R → Bool} {Byz : Finset ι} {s s' : State ι R}
    (hs : Inv names Byz s) (h : Step Byz (BoardPrec names) s s') : Inv names Byz s' := by
  obtain ⟨hnext, hv⟩ := hs
  cases h with
  | order r0 hr0 =>
    refine ⟨fun r b hrb ↦ ?_, fun i hi r hr ↦ ?_⟩
    · simp only [order] at hrb ⊢
      by_cases hr : r = r0
      · subst hr; simp at hrb; omega
      · rw [Function.update_of_ne hr] at hrb; have := hnext r b hrb; omega
    · obtain ⟨hn, b, hb, hmin⟩ := hv i hi r hr
      have hrr0 : r ≠ r0 := by rintro rfl; simp [hr0] at hb
      refine ⟨hn, b, by simp [order, Function.update_of_ne hrr0, hb], fun r' b' hn' hb' ↦ ?_⟩
      simp only [order] at hb'
      by_cases h' : r' = r0
      · subst h'; simp at hb'; have := hnext r b hb; omega
      · rw [Function.update_of_ne h'] at hb'; exact hmin r' b' hn' hb'
  | finish r0 => exact ⟨hnext, fun i hi r hr ↦ hv i hi r hr⟩
  | vote i0 r0 hi0 hprec =>
    refine ⟨hnext, fun i hi r hr ↦ ?_⟩
    simp only [vote] at hr
    by_cases hii : i = i0
    · subst hii
      rw [Function.update_self, mem_insert] at hr
      rcases hr with rfl | hr
      · exact D44_prec_first_namer hprec
      · exact hv i hi r hr
    · rw [Function.update_of_ne hii] at hr; exact hv i hi r hr
  | byzVote i0 r0 hi0 =>
    refine ⟨hnext, fun i hi r hr ↦ ?_⟩
    simp only [vote] at hr
    by_cases hii : i = i0
    · subst hii; exact absurd hi0 hi
    · rw [Function.update_of_ne hii] at hr; exact hv i hi r hr

theorem inv_of_reachable {names : R → Bool} {Byz : Finset ι} {s : State ι R}
    (h : Reachable Byz (BoardPrec names) s) : Inv names Byz s := by
  induction h with
  | refl => exact inv_init names Byz
  | tail _ hst ih => exact inv_step ih hst

/-- **D44, honest votes go to the first namer.** In every reachable state each honest vote to
reserve the slot is for the first request in board order that names it. -/
theorem D44_honest_vote_first_namer {names : R → Bool} {Byz : Finset ι} {s : State ι R}
    (h : Reachable Byz (BoardPrec names) s) {i : ι} (hi : i ∉ Byz) {r : R} (hr : r ∈ s.votes i) :
    FirstNamer names s r :=
  (inv_of_reachable h).2 i hi r hr

/-- Heights are below `next` and distinct requests have distinct heights. -/
def OrdInv (s : State ι R) : Prop :=
  (∀ r b, s.ord r = some b → b < s.next) ∧
    ∀ r r' b, s.ord r = some b → s.ord r' = some b → r = r'

theorem ordInv_step {Byz : Finset ι} {rule : State ι R → R → Prop} {s s' : State ι R}
    (hs : OrdInv s) (h : Step Byz rule s s') : OrdInv s' := by
  obtain ⟨hnext, hinj⟩ := hs
  cases h with
  | order r0 hr0 =>
    refine ⟨fun r b hrb ↦ ?_, fun r r' b hrb hr'b ↦ ?_⟩
    · simp only [order] at hrb ⊢
      by_cases hr : r = r0
      · subst hr; simp at hrb; omega
      · rw [Function.update_of_ne hr] at hrb; have := hnext r b hrb; omega
    · simp only [order] at hrb hr'b
      by_cases h1 : r = r0 <;> by_cases h2 : r' = r0
      · rw [h1, h2]
      · subst h1; rw [Function.update_of_ne h2] at hr'b; simp at hrb
        have := hnext r' b hr'b; omega
      · subst h2; rw [Function.update_of_ne h1] at hrb; simp at hr'b
        have := hnext r b hrb; omega
      · rw [Function.update_of_ne h1] at hrb; rw [Function.update_of_ne h2] at hr'b
        exact hinj r r' b hrb hr'b
  | finish => exact ⟨hnext, hinj⟩
  | vote => exact ⟨hnext, hinj⟩
  | byzVote => exact ⟨hnext, hinj⟩

theorem ordInv_of_reachable {Byz : Finset ι} {rule : State ι R → R → Prop} {s : State ι R}
    (h : Reachable Byz rule s) : OrdInv s := by
  induction h with
  | refl => exact ⟨fun _ _ h ↦ by simp [init] at h, fun _ _ _ h ↦ by simp [init] at h⟩
  | tail _ hst ih => exact ordInv_step ih hst

theorem ord_inj {Byz : Finset ι} {rule : State ι R → R → Prop} {s : State ι R}
    (h : Reachable Byz rule s) {r r' : R} {b : ℕ} (hr : s.ord r = some b)
    (hr' : s.ord r' = some b) : r = r' :=
  (ordInv_of_reachable h).2 r r' b hr hr'

/-- **D44 and C12, one request per slot.** With at most `f` corrupt nodes, two requests that both
reserved the slot are the same request. -/
theorem D44_one_request_per_slot [Fintype ι] {names : R → Bool} {Byz : Finset ι} {f : ℕ}
    {s : State ι R} (h : Reachable Byz (BoardPrec names) s) (hByz : #Byz ≤ f) {r r' : R}
    (hr : Reserved f s r) (hr' : Reserved f s r') : r = r' := by
  obtain ⟨i, hi, hiB⟩ := quorum_inter_honest_univ_q hr hr' hByz
  rw [mem_inter, mem_filter, mem_filter] at hi
  obtain ⟨_, b, hb, hmin⟩ := D44_honest_vote_first_namer h hiB hi.1.2
  obtain ⟨hn', b', hb', hmin'⟩ := D44_honest_vote_first_namer h hiB hi.2.2
  have hn : names r = true := (D44_honest_vote_first_namer h hiB hi.1.2).1
  have : b = b' := le_antisymm (hmin r' b' hn' hb') (hmin' r b hn hb)
  exact ord_inj h hb (this ▸ hb')

/-- **D44, a later request never takes the slot.** If `r₁` names the slot and was ordered before
`r₂`, then `r₂` never reserves it, whatever the order in which their authorizations come into
force, with at most `f` corrupt nodes (Quint item Q4). -/
theorem D44_later_never_reserves [Fintype ι] {names : R → Bool} {Byz : Finset ι} {f : ℕ}
    {s : State ι R} (h : Reachable Byz (BoardPrec names) s) (hByz : #Byz ≤ f) {r₁ r₂ : R}
    {a b : ℕ} (hn₁ : names r₁ = true) (ha : s.ord r₁ = some a) (hb : s.ord r₂ = some b)
    (hab : a < b) : ¬ Reserved f s r₂ := by
  intro hr
  obtain ⟨i, hi, hiB⟩ := quorum_inter_honest_univ_q hr hr hByz
  rw [mem_inter, mem_filter] at hi
  obtain ⟨_, b', hb', hmin⟩ := D44_honest_vote_first_namer h hiB hi.1.2
  rw [hb] at hb'
  cases hb'
  exact absurd (hmin r₁ a hn₁ ha) (not_le.mpr hab)

/-- **D44, a burned slot stays burned.** -/
theorem D44_burn_persists {names : R → Bool} {Byz : Finset ι} {rule : State ι R → R → Prop}
    {s s' : State ι R} (hst : Step Byz rule s s') (hb : Burned names s) : Burned names s' := by
  obtain ⟨r, hn, hord, hend⟩ := hb
  cases hst with
  | order r0 hr0 =>
    refine ⟨r, hn, ?_, hend⟩
    have hrr0 : r ≠ r0 := by rintro rfl; exact hord hr0
    simpa [order, Function.update_of_ne hrr0] using hord
  | finish r0 => exact ⟨r, hn, hord, mem_insert_of_mem hend⟩
  | vote => exact ⟨r, hn, hord, hend⟩
  | byzVote => exact ⟨r, hn, hord, hend⟩

/-- Four nodes; request `false` is ordered first and request `true` second, both name the slot,
and only `true`'s authorization is in force. Nodes 0, 1 and 2 vote for `true`. -/
def s1 : State (Fin 4) Bool := order init false
def s2 : State (Fin 4) Bool := order s1 true
def s3 : State (Fin 4) Bool := vote s2 0 true
def s4 : State (Fin 4) Bool := vote s3 1 true
def s5 : State (Fin 4) Bool := vote s4 2 true

/-- **D44, the rule it replaced lets a later request take the slot.** Under item 35's rule (vote
for any live request whose authorization is in force), with one corrupt node of four, the request
ordered second reserves the slot while the request ordered first is live and names it. -/
theorem D44_in_force_rule_takes_later :
    Reachable ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) s5 ∧
      s5.ord false = some 0 ∧ s5.ord true = some 1 ∧ false ∉ s5.ended ∧
      Reserved 1 s5 true := by
  have t1 : Step ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) init s1 :=
    Step.order _ false rfl
  have t2 : Step ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) s1 s2 :=
    Step.order _ true (by decide)
  have hp : ∀ s : State (Fin 4) Bool, s.ord true ≠ none → true ∉ s.ended →
      InForcePrec (fun _ ↦ true) id s true := fun s h1 h2 ↦ ⟨rfl, h1, rfl, h2⟩
  have t3 : Step ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) s2 s3 :=
    Step.vote _ 0 true (by decide) (hp _ (by decide) (by decide))
  have t4 : Step ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) s3 s4 :=
    Step.vote _ 1 true (by decide) (hp _ (by decide) (by decide))
  have t5 : Step ({3} : Finset (Fin 4)) (InForcePrec (fun _ ↦ true) id) s4 s5 :=
    Step.vote _ 2 true (by decide) (hp _ (by decide) (by decide))
  refine ⟨((((Relation.ReflTransGen.single t1).tail t2).tail t3).tail t4).tail t5,
    by decide, by decide, by decide, ?_⟩
  unfold Reserved
  decide

end Precedence

/-! ## Cold start: burn of unclaimed slots (DECISIONS 46 (3), C16) -/

namespace ColdStart

variable {L : Type*}

/-- What a record that covers the board up to height `h` shows of the claim heights `claim`. -/
def viewUpTo (claim : L → Option ℕ) (h : ℕ) (ℓ : L) : Option ℕ :=
  match claim ℓ with
  | some b => if b ≤ h then some b else none
  | none => none

/-- The slots the recovery group keeps after a cold start (§7.11 item 2). With a verified board
record up to the outage height `ot` it keeps the slots that the record shows unclaimed; without
one it burns every slot unclaimed at the checkpoint and every slot of a pending request, so it
keeps none of the old pool. -/
noncomputable def keep (pool : Finset L) (claim : L → Option ℕ) (cover ot : ℕ) : Finset L := by
  classical
  exact if ot ≤ cover then pool.filter fun ℓ ↦ viewUpTo claim cover ℓ = none else ∅

/-- **C16 and DECISIONS 46 (3), no slot is used twice after a cold start.** For every board history
`claim`, which the outage may have lost past the checkpoint, a slot the recovery group keeps was
claimed by no request up to the outage. -/
theorem C16_cold_start_no_reuse (pool : Finset L) (claim : L → Option ℕ) {cover ot : ℕ}
    {ℓ : L} (hℓ : ℓ ∈ keep pool claim cover ot) {b : ℕ} (hb : claim ℓ = some b) : ot < b := by
  classical
  unfold keep at hℓ
  split_ifs at hℓ with hcov
  · rw [mem_filter] at hℓ
    have hv := hℓ.2
    simp only [viewUpTo, hb] at hv
    split_ifs at hv with hle
    omega
  · simp at hℓ

/-- The rule without the burn: keep every slot unclaimed at the checkpoint `ck`. -/
noncomputable def keepAtCheckpoint (pool : Finset L) (claim : L → Option ℕ) (ck : ℕ) : Finset L := by
  classical
  exact pool.filter fun ℓ ↦ viewUpTo claim ck ℓ = none

/-- **C16, without the burn a slot is used twice.** A slot unclaimed at the checkpoint and claimed
in the lost tail before the outage is kept by the rule without the burn. -/
theorem C16_without_burn_reuse :
    ∃ (claim : Unit → Option ℕ) (ck ot b : ℕ), ck < ot ∧ claim () = some b ∧ b ≤ ot ∧
      () ∈ keepAtCheckpoint {()} claim ck := by
  refine ⟨fun _ ↦ some 1, 0, 1, 1, by omega, rfl, le_rfl, ?_⟩
  simp [keepAtCheckpoint, viewUpTo]

end ColdStart

end LineDealing.Split
