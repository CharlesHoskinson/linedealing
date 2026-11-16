import LineDealing.KeySplit
import LineDealing.Access

/-!
# Split-line dealing: custody profiles do not change the signing algebra

DECISIONS 19 and the owner ruling of 2026-11-14: seizure, freeze and holds are a per-charter
profile, never a protocol requirement. `P0` is line dealing on an existing owner address, `P1`
co-custody with the access formula `user`, `P2` regulated custody with `user OR G`.

The signing algebra below takes no profile. A profile chooses only the access formula, so it
chooses which signing sets exist. For every profile and every signing set the combined signature
verifies under the same address key, every `P1` signing set is a `P2` signing set with the same
weights, and a `P1` charter has no signing set without the user. No theorem about `P0` or `P1`
takes a guardian set or a hold as a hypothesis.
-/

open Finset

set_option linter.unusedSectionVars false

namespace LineDealing.Split

variable {q : ℕ} [Fact q.Prime] {ι : Type*}

/-- The custody profile of a charter. -/
inductive Profile
  | P0
  | P1
  | P2

open Gate

/-- The access formula of the user's charter in `P0` and `P1`. -/
def soleCharter (user : ι) : Gate q ι := leaf user

/-- The access formula of a charter in each profile; only `P2` names the guardian group. -/
def charter (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ) :
    Profile → Gate q ι
  | .P0 => soleCharter user
  | .P1 => soleCharter user
  | .P2 => userOrG user guardian ids k

/-- The combined Schnorr scalar of a signing set with weights `w`: the committee half
`k_f + c x_f`, the tweak term `c tw` once, and the contribution `k_a + c w_a x_a` of each leaf.
It takes no profile. -/
noncomputable def combine (w : ι →₀ ZMod q) (x k : ι → ZMod q) (kf xf tw c : ZMod q) : ZMod q :=
  (kf + c * xf) + c * tw + w.sum fun a wa ↦ k a + c * (wa * x a)

/-- **D19, one signing algebra for every profile.** For every profile, every dealing of the actors'
secret `s` through the profile's formula and every signing set of it, the combined scalar verifies
against the nonce `R = (k_f + Σ_a k_a) • g` and the address key `X = (x_f + tw + s) • g`. -/
theorem D19_signing_profile_free {G : Type*} [AddCommGroup G] [Module (ZMod q) G]
    (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ) (p : Profile)
    {w : ι →₀ ZMod q} {A : Set ι} (hr : Reach (charter user guardian ids k p) w A) {s : ZMod q}
    {x : ι → ZMod q} (hd : Dealt (charter user guardian ids k p) s x) (g : G)
    (kn : ι → ZMod q) (kf xf tw c : ZMod q) :
    combine w x kn kf xf tw c • g =
      (kf + ∑ a ∈ w.support, kn a) • g + c • ((xf + tw + s) • g) := by
  have hs := D22_access_weighted_sum hr hd
  rw [Finsupp.linearCombination_apply, Finsupp.sum] at hs
  simp only [smul_eq_mul] at hs
  rw [combine, Finsupp.sum, C4_schnorr_combine w.support g w x kn kf xf tw c, hs, add_assoc]

/-- **D19, the user signs in every profile.** The user alone, with weight one, is a signing set of
every profile, and under it the actors' secret is the user's shard. -/
theorem D19_user_signs (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ)
    (p : Profile) : Reach (charter user guardian ids k p) (Finsupp.single user 1) {user} := by
  cases p with
  | P0 => exact .leaf user
  | P1 => exact .leaf user
  | P2 => exact .orL (.leaf user)

/-- **D19, P2 adds a branch and changes nothing else.** Every signing set of `P1` is a signing set
of `P2` with the same weights, and every dealing through `P2`'s formula is a dealing through
`P1`'s with the same secret. -/
theorem D19_P2_extends_P1 (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ)
    {w : ι →₀ ZMod q} {A : Set ι} {s : ZMod q} {x : ι → ZMod q} :
    (Reach (charter user guardian ids k .P1) w A → Reach (charter user guardian ids k .P2) w A) ∧
      (Dealt (charter user guardian ids k .P2) s x →
        Dealt (charter user guardian ids k .P1) s x) := by
  refine ⟨fun h ↦ .orL h, fun h ↦ ?_⟩
  cases h with
  | or2 hu _ => exact hu

theorem reach_leaf {a : ι} {w : ι →₀ ZMod q} {A : Set ι} (h : Reach (leaf a : Gate q ι) w A) :
    A = {a} := by
  cases h; rfl

/-- **D19, the signing sets of P2.** A signing set of `P2` is a signing set of `P1` or consists of
guardians only. -/
theorem D19_P2_signing_sets (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q)) (k : ℕ)
    {w : ι →₀ ZMod q} {A : Set ι} (h : Reach (charter user guardian ids k .P2) w A) :
    Reach (charter user guardian ids k .P1) w A ∨ A ⊆ Set.range guardian := by
  cases h with
  | orL hl => exact .inl hl
  | orR hg =>
    right
    cases hg with
    | thr T w' A' _ _ hch =>
      refine Set.iUnion₂_subset fun i hi ↦ ?_
      rw [reach_leaf (hch i hi)]
      exact Set.singleton_subset_iff.mpr ⟨i, rfl⟩

/-- **D19 and §5.8, nobody seizes a P0 or P1 address.** A set of leaves without the user does not
satisfy the formula of `P0` or `P1`. -/
theorem D19_P1_no_seizure (user : ι) {C : Set ι} (hu : user ∉ C) :
    ¬ Covers C (soleCharter (q := q) user) := by
  intro h
  cases h with
  | leaf ha => exact hu ha

/-- **D19 and §5.8, `k` guardians seize a P2 address.** Any `k` guardians of the group satisfy the
formula of `P2`. -/
theorem D19_P2_guardians_seize (user : ι) (guardian : ZMod q → ι) (ids : Finset (ZMod q))
    (k : ℕ) (T : Finset (ZMod q)) (hT : T ⊆ ids) (hk : #T = k) :
    Covers (guardian '' T) (charter user guardian ids k .P2) :=
  .orR (.thr T hT hk.ge fun i hi ↦ .leaf ⟨i, hi, rfl⟩)

end LineDealing.Split
