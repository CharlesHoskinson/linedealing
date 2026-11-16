import LineDealing.Quorum

/-!
# The anchor rule

SCHEME 3.6, Step B. The OBS set holds `q = quorum n f` reported heights (`2f + 1` for
`n = 3f + 1`). They are sorted highest first and the anchor height is entry number `f + 1`. With
at most `f` Byzantine reports the anchor height lies between two honest reports. Byzantine
reports are arbitrary numbers. The argument needs only `q ≥ 2f + 1`: entry `f + 1` has `f + 1`
entries at or above it and `q - f ≥ f + 1` entries at or below it, and each group holds an
honest report. The same holds for every entry number from `f + 1` to `q - f`.
-/

open Finset

namespace LineDealing

/-- In a list sorted highest first, the entry `a` after a prefix `l₁` has at least
`l₁.length + 1` entries at or above it and at least `l₂.length + 1` entries at or below it. -/
theorem sorted_split_count {l₁ l₂ : List ℕ} {a : ℕ}
    (hs : (l₁ ++ a :: l₂).Pairwise (· ≥ ·)) :
    l₁.length + 1 ≤ (l₁ ++ a :: l₂).countP (fun x ↦ a ≤ x) ∧
      l₂.length + 1 ≤ (l₁ ++ a :: l₂).countP (fun x ↦ x ≤ a) := by
  rw [List.pairwise_append] at hs
  obtain ⟨-, h2, h3⟩ := hs
  rw [List.pairwise_cons] at h2
  have e1 : l₁.countP (fun x ↦ a ≤ x) = l₁.length :=
    List.countP_eq_length.mpr fun x hx ↦ by simpa using h3 x hx a (by simp)
  have e2 : l₂.countP (fun x ↦ x ≤ a) = l₂.length :=
    List.countP_eq_length.mpr fun x hx ↦ by simpa using h2.1 x hx
  constructor
  · rw [List.countP_append, List.countP_cons, e1]
    simp only [le_refl, decide_true, ite_true]
    omega
  · rw [List.countP_append, List.countP_cons, e2]
    simp only [le_refl, decide_true, ite_true]
    omega

/-- Entry `k` (counting from zero) of a list sorted highest first has at least `k + 1` entries
at or above it and at least `length - k` entries at or below it. -/
theorem sorted_getElem?_count {l : List ℕ} (hs : l.Pairwise (· ≥ ·)) {k a : ℕ}
    (hk : l[k]? = some a) :
    k + 1 ≤ l.countP (fun x ↦ a ≤ x) ∧ l.length - k ≤ l.countP (fun x ↦ x ≤ a) := by
  obtain ⟨hlt, rfl⟩ := List.getElem?_eq_some_iff.mp hk
  have hsplit : l = l.take k ++ l[k] :: l.drop (k + 1) := by simp
  have h := sorted_split_count (l₁ := l.take k) (l₂ := l.drop (k + 1)) (a := l[k])
    (by rw [← hsplit]; exact hs)
  rw [← hsplit] at h
  have hl1 : (l.take k).length = k := by simp; omega
  have hl2 : (l.drop (k + 1)).length = l.length - (k + 1) := by simp
  omega

/-- **Anchor rule, any admissible entry.** `H` holds the honest reports and `B` the Byzantine
reports, at most `f` of them. `l` is any arrangement of all reports that is sorted highest
first. Every entry with index `k` (entry number `k + 1`), `f ≤ k` and `k + f` below the number
of reports, is at or above some honest report and at or below some honest report. -/
theorem anchor_between_honest_of_sorted_index {f k : ℕ} {H B : Multiset ℕ} {l : List ℕ}
    (hl : (l : Multiset ℕ) = H + B) (hs : l.Pairwise (· ≥ ·)) (hB : B.card ≤ f) (hfk : f ≤ k)
    (hk : k + f < H.card + B.card) {a : ℕ} (ha : l[k]? = some a) :
    (∃ x ∈ H, x ≤ a) ∧ (∃ y ∈ H, a ≤ y) := by
  have hlen : l.length = H.card + B.card := by
    have := congrArg Multiset.card hl
    simpa using this
  obtain ⟨hge, hle⟩ := sorted_getElem?_count hs ha
  have cge : (H + B).countP (fun x ↦ a ≤ x) = l.countP (fun x ↦ a ≤ x) := by
    rw [← hl, Multiset.coe_countP]
  have cle : (H + B).countP (fun x ↦ x ≤ a) = l.countP (fun x ↦ x ≤ a) := by
    rw [← hl, Multiset.coe_countP]
  rw [Multiset.countP_add] at cge cle
  have b1 := Multiset.countP_le_card (fun x ↦ a ≤ x) B
  have b2 := Multiset.countP_le_card (fun x ↦ x ≤ a) B
  constructor
  · have : 0 < H.countP (fun x ↦ x ≤ a) := by omega
    exact Multiset.countP_pos.mp this
  · have : 0 < H.countP (fun x ↦ a ≤ x) := by omega
    exact Multiset.countP_pos.mp this

/-- **Anchor rule, list form, at least `2f + 1` reports.** `H` holds the honest reports and `B`
the Byzantine reports; together they are at least `2f + 1` reports with at most `f` in `B`. `l`
is any arrangement of all reports that is sorted highest first. Then entry number `f + 1` of `l`
(index `f`) is at or above some honest report and at or below some honest report. -/
theorem anchor_between_honest_of_sorted_ge {f : ℕ} {H B : Multiset ℕ} {l : List ℕ}
    (hl : (l : Multiset ℕ) = H + B) (hs : l.Pairwise (· ≥ ·))
    (hcard : 2 * f + 1 ≤ H.card + B.card) (hB : B.card ≤ f) {a : ℕ} (ha : l[f]? = some a) :
    (∃ x ∈ H, x ≤ a) ∧ (∃ y ∈ H, a ≤ y) :=
  anchor_between_honest_of_sorted_index hl hs hB le_rfl (by omega) ha

/-- **Anchor rule, list form, `2f + 1` reports.** The case of exactly `2f + 1` reports
(`n = 3f + 1`). -/
theorem anchor_between_honest_of_sorted {f : ℕ} {H B : Multiset ℕ} {l : List ℕ}
    (hl : (l : Multiset ℕ) = H + B) (hs : l.Pairwise (· ≥ ·))
    (hcard : H.card + B.card = 2 * f + 1) (hB : B.card ≤ f) {a : ℕ} (ha : l[f]? = some a) :
    (∃ x ∈ H, x ≤ a) ∧ (∃ y ∈ H, a ≤ y) :=
  anchor_between_honest_of_sorted_ge hl hs hcard.ge hB ha

/-- **Anchor rule for at least `2f + 1` reports.** Of at least `2f + 1` reported heights at most
`f` are Byzantine. Sort all reports highest first. Entry number `f + 1` lies between the lowest
and the highest honest report. -/
theorem anchor_between_honest_ge {f : ℕ} {H B : Multiset ℕ}
    (hcard : 2 * f + 1 ≤ H.card + B.card) (hB : B.card ≤ f) {a : ℕ}
    (ha : ((H + B).sort (· ≥ ·))[f]? = some a) : (∃ x ∈ H, x ≤ a) ∧ (∃ y ∈ H, a ≤ y) :=
  anchor_between_honest_of_sorted_ge (Multiset.sort_eq _ _) (Multiset.pairwise_sort _ _) hcard hB
    ha

/-- The anchor height exists: a sorted list of at least `2f + 1` reports has an entry number
`f + 1`. -/
theorem anchor_exists_ge {f : ℕ} {M : Multiset ℕ} (hcard : 2 * f + 1 ≤ M.card) :
    ∃ a, (M.sort (· ≥ ·))[f]? = some a := by
  have hlen : (M.sort (· ≥ ·)).length = M.card := Multiset.length_sort _
  exact ⟨(M.sort (· ≥ ·))[f]'(by omega), List.getElem?_eq_getElem (by omega)⟩

/-- **Anchor rule, node form, at least `2f + 1` reports.** `S` is a set of at least `2f + 1`
distinct nodes, `h i` the height that node `i` reported, and at most `f` nodes of `S` are
Byzantine. Entry number `f + 1` of the sorted heights lies between the reports of two honest
nodes of `S`. -/
theorem anchor_between_honest_nodes_ge {ι : Type*} [DecidableEq ι] {f : ℕ} {S Byz : Finset ι}
    (h : ι → ℕ) (hS : 2 * f + 1 ≤ #S) (hByz : #(S.filter (· ∈ Byz)) ≤ f) {a : ℕ}
    (ha : ((S.val.map h).sort (· ≥ ·))[f]? = some a) :
    (∃ i ∈ S, i ∉ Byz ∧ h i ≤ a) ∧ (∃ j ∈ S, j ∉ Byz ∧ a ≤ h j) := by
  have hsplit : S.val.map h =
      (S.val.filter (· ∉ Byz)).map h + (S.val.filter (· ∈ Byz)).map h := by
    rw [← Multiset.map_add, add_comm, Multiset.filter_add_not]
  have hc : 2 * f + 1 ≤
      ((S.val.filter (· ∉ Byz)).map h).card + ((S.val.filter (· ∈ Byz)).map h).card := by
    rw [← Multiset.card_add, ← hsplit, Multiset.card_map]; exact hS
  have hb : ((S.val.filter (· ∈ Byz)).map h).card ≤ f := by
    rw [Multiset.card_map]; exact hByz
  rw [hsplit] at ha
  obtain ⟨⟨x, hx, hxa⟩, ⟨y, hy, hay⟩⟩ := anchor_between_honest_ge hc hb ha
  rw [Multiset.mem_map] at hx hy
  obtain ⟨i, hi, rfl⟩ := hx
  obtain ⟨j, hj, rfl⟩ := hy
  rw [Multiset.mem_filter] at hi hj
  exact ⟨⟨i, hi.1, hi.2, hxa⟩, ⟨j, hj.1, hj.2, hay⟩⟩

/-- **Anchor rule (SCHEME 3.6), node form for `n ≥ 3f + 1`.** `S` is the OBS set of
`quorum n f` distinct nodes of a committee of `n ≥ 3f + 1` nodes, `h i` the height that node `i`
reported, and at most `f` nodes of `S` are Byzantine. Entry number `f + 1` of the sorted heights
exists and lies between the reports of two honest nodes of `S`. -/
theorem anchor_between_honest_nodes_quorum {ι : Type*} [DecidableEq ι] {n f : ℕ}
    {S Byz : Finset ι} (h : ι → ℕ) (hn : 3 * f + 1 ≤ n) (hS : #S = quorum n f)
    (hByz : #(S.filter (· ∈ Byz)) ≤ f) :
    ∃ a, ((S.val.map h).sort (· ≥ ·))[f]? = some a ∧
      (∃ i ∈ S, i ∉ Byz ∧ h i ≤ a) ∧ (∃ j ∈ S, j ∉ Byz ∧ a ≤ h j) := by
  have hq : 2 * f + 1 ≤ #S := hS ▸ two_mul_add_one_le_quorum hn
  obtain ⟨a, ha⟩ := anchor_exists_ge (M := S.val.map h) (by rw [Multiset.card_map]; exact hq)
  exact ⟨a, ha, anchor_between_honest_nodes_ge h hq hByz ha⟩

/-- **Anchor rule, `2f + 1` reports.** Of `2f + 1` reported heights at most `f` are Byzantine. Sort
all reports highest first. Entry number `f + 1` lies between the lowest and the highest honest
report: some honest node reported a height at or below it and some honest node reported a
height at or above it. -/
theorem anchor_between_honest {f : ℕ} {H B : Multiset ℕ} (hcard : H.card + B.card = 2 * f + 1)
    (hB : B.card ≤ f) {a : ℕ} (ha : ((H + B).sort (· ≥ ·))[f]? = some a) :
    (∃ x ∈ H, x ≤ a) ∧ (∃ y ∈ H, a ≤ y) :=
  anchor_between_honest_of_sorted (Multiset.sort_eq _ _) (Multiset.pairwise_sort _ _) hcard hB ha

/-- The anchor height exists: the sorted list of `2f + 1` reports has an entry number `f + 1`. -/
theorem anchor_exists {f : ℕ} {M : Multiset ℕ} (hcard : M.card = 2 * f + 1) :
    ∃ a, (M.sort (· ≥ ·))[f]? = some a := by
  have hlen : (M.sort (· ≥ ·)).length = 2 * f + 1 := by rw [Multiset.length_sort, hcard]
  exact ⟨(M.sort (· ≥ ·))[f]'(by omega), List.getElem?_eq_getElem (by omega)⟩

/-- **Anchor rule, node form, `2f + 1` reports.** `S` is the OBS set of `2f + 1` distinct nodes
(`n = 3f + 1`), `h i` the height that node `i` reported, and at most `f` nodes of `S` are
Byzantine. Entry number `f + 1` of the sorted heights lies between the reports of two honest
nodes of `S`. -/
theorem anchor_between_honest_nodes {ι : Type*} [DecidableEq ι] {f : ℕ} {S Byz : Finset ι}
    (h : ι → ℕ) (hS : #S = 2 * f + 1) (hByz : #(S.filter (· ∈ Byz)) ≤ f) {a : ℕ}
    (ha : ((S.val.map h).sort (· ≥ ·))[f]? = some a) :
    (∃ i ∈ S, i ∉ Byz ∧ h i ≤ a) ∧ (∃ j ∈ S, j ∉ Byz ∧ a ≤ h j) :=
  anchor_between_honest_nodes_ge h hS.ge hByz ha

/-- **The bound `f` is tight.** With `f = 1` and two Byzantine reports among three, entry
number `f + 1` is above every honest report: the reports are `9, 9` (Byzantine) and `5`
(honest), and the entry is `9`. -/
theorem anchor_fails_with_f_add_one_byzantine :
    ∃ (H B : Multiset ℕ) (l : List ℕ) (a : ℕ), (l : Multiset ℕ) = H + B ∧
      l.Pairwise (· ≥ ·) ∧ H.card + B.card = 2 * 1 + 1 ∧ B.card = 1 + 1 ∧ l[1]? = some a ∧
      ∀ y ∈ H, y < a := by
  refine ⟨{5}, {9, 9}, [9, 9, 5], 9, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · decide
  · decide
  · decide
  · decide
  · decide
  · decide

end LineDealing
