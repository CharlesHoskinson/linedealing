import PassportShard.Spec

/-!
# Invariants of the shard placement

Every theorem is about the states that `Reach` gives: any interleaving of
honest and adversarial operations from `init`. The cryptography is the set of
named hypotheses of `Spec.lean`; the theorems hold for every protocol whose
primitives satisfy them.
-/

namespace PassportShard

/-- What each recorded source of the root means in the state. -/
def viaOk (s : St) : Via → Prop
  | .originLeak d => d ∈ s.prfLog ∧ s.originCorrupt = true
  | .recoveryLeak _ => s.originCorrupt = true
  | .theft d => d ∈ s.prfLog ∧ d ∈ s.advCred
  | .provider d => d ∈ s.cfg.synced ∧ d ∈ s.advCred
  | .quorum => s.rWrapEver = true ∧ s.cfg.quorum ≤ s.advGuard.length

structure Inv (s : St) : Prop where
  sigUser : ∀ ic, ic ∈ s.sigs → (∃ d, (d, ic) ∈ s.unlockLog) ∨ s.advRoot = true
  sigComm : ∀ ic, ic ∈ s.sigs → (∃ nf, (ic, nf) ∈ s.authorized) ∨ s.advXf = true
  authAssert : ∀ ic nf, (ic, nf) ∈ s.authorized → ∃ d, (d, ic, nf) ∈ s.asserts
  authUsed : ∀ ic nf, (ic, nf) ∈ s.authorized → nf ∈ s.usedNf
  authUnique : ∀ ic1 ic2 nf, (ic1, nf) ∈ s.authorized → (ic2, nf) ∈ s.authorized → ic1 = ic2
  unlockPrf : ∀ d ic, (d, ic) ∈ s.unlockLog → d ∈ s.prfLog
  rootVia : s.advRoot = true → s.via ≠ []
  viaAll : ∀ v, v ∈ s.via → viaOk s v

theorem hasUnlock_iff (s : St) (ic : Nat) :
    hasUnlock s ic = true ↔ ∃ d, (d, ic) ∈ s.unlockLog := by
  unfold hasUnlock
  rw [List.any_eq_true]
  constructor
  · rintro ⟨⟨d, i⟩, hm, he⟩
    simp at he
    exact ⟨d, he ▸ hm⟩
  · rintro ⟨d, hm⟩
    exact ⟨(d, ic), hm, by simp⟩

theorem chk_nil (c : Bool) (r : Refusal) : chk c r = [] ↔ c = true := by
  unfold chk; cases c <;> simp

theorem viaOk_mono {s s' : St} {v : Via}
    (hp : ∀ d, d ∈ s.prfLog → d ∈ s'.prfLog)
    (ha : ∀ d, d ∈ s.advCred → d ∈ s'.advCred)
    (ho : s.originCorrupt = true → s'.originCorrupt = true)
    (hc : s'.cfg = s.cfg)
    (hr : s.rWrapEver = true → s'.rWrapEver = true)
    (hg : s.advGuard.length ≤ s'.advGuard.length)
    (h : viaOk s v) : viaOk s' v := by
  cases v <;> simp only [viaOk] at *
  · exact ⟨hp _ h.1, ho h.2⟩
  · exact ho h
  · exact ⟨hp _ h.1, ha _ h.2⟩
  · exact ⟨by rw [hc]; exact h.1, ha _ h.2⟩
  · exact ⟨hr h.1, by rw [hc]; exact Nat.le_trans h.2 hg⟩

theorem inv_init (c : Cfg) (d0 : Nat) : Inv (init c d0) := by
  constructor <;> simp [init]

theorem inv_leak {s : St} (d : Nat) (v : Via) (h : Inv s)
    (hv : s.originCorrupt = true → viaOk s v) : Inv (leak s d v) := by
  unfold leak
  split
  · rename_i hc
    have ho : s.originCorrupt = true := by
      simp only [Bool.and_eq_true] at hc; exact hc.1
    constructor
    · intro ic hi; exact Or.inr rfl
    · exact h.sigComm
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · intro _; simp
    · intro w hw
      simp only [List.mem_cons] at hw
      rcases hw with rfl | hw
      · exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (hv ho)
      · exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  · exact h

theorem inv_prfEval {s : St} (d : Nat) (h : Inv s) : Inv (prfEval s d) := by
  unfold prfEval
  apply inv_leak
  · constructor
    · exact h.sigUser
    · exact h.sigComm
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · intro d' ic hm; exact List.mem_cons_of_mem _ (h.unlockPrf d' ic hm)
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => List.mem_cons_of_mem _ x) (fun _ x => x) id rfl id (Nat.le_refl _)
        (h.viaAll w hw)
  · intro ho; exact ⟨List.mem_cons_self, ho⟩

theorem inv_quorumRule {s : St} (h : Inv s) : Inv (quorumRule s) := by
  unfold quorumRule
  split
  · rename_i hc
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
    constructor
    · intro ic hi; exact Or.inr rfl
    · exact h.sigComm
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · intro _; simp
    · intro w hw
      simp only [List.mem_cons] at hw
      rcases hw with rfl | hw
      · exact hc
      · exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  · exact h

/-- Field facts of the helpers, for the cases below. -/
theorem leak_fields (s : St) (d : Nat) (v : Via) :
    (leak s d v).cfg = s.cfg ∧ (leak s d v).readers = s.readers ∧
    (leak s d v).creds = s.creds ∧ (leak s d v).unlockLog = s.unlockLog ∧
    (leak s d v).prfLog = s.prfLog ∧ (leak s d v).approved = s.approved ∧
    (leak s d v).asserts = s.asserts ∧ (leak s d v).authorized = s.authorized ∧
    (leak s d v).usedNf = s.usedNf ∧ (leak s d v).sigs = s.sigs ∧
    (leak s d v).advXf = s.advXf ∧ (leak s d v).advCred = s.advCred ∧
    (leak s d v).advGuard = s.advGuard ∧ (leak s d v).originCorrupt = s.originCorrupt ∧
    (leak s d v).rWrapEver = s.rWrapEver ∧
    (s.advRoot = true → (leak s d v).advRoot = true) := by
  unfold leak; split <;> simp

/-- A state that differs only in fields the invariant does not read, or reads
monotonically, keeps the invariant. -/
theorem inv_frame {s s' : St} (h : Inv s)
    (e1 : s'.sigs = s.sigs) (e2 : s'.unlockLog = s.unlockLog) (e3 : s'.advRoot = s.advRoot)
    (e4 : s'.authorized = s.authorized) (e5 : s'.advXf = s.advXf)
    (e6 : s'.asserts = s.asserts) (e7 : s'.usedNf = s.usedNf) (e8 : s'.prfLog = s.prfLog)
    (e9 : s'.via = s.via) (e11 : s'.advCred = s.advCred)
    (e12 : s'.cfg = s.cfg)
    (ho : s.originCorrupt = true → s'.originCorrupt = true)
    (hr : s.rWrapEver = true → s'.rWrapEver = true)
    (hg : s.advGuard.length ≤ s'.advGuard.length) : Inv s' := by
  constructor
  · rw [e1, e2, e3]; exact h.sigUser
  · rw [e1, e4, e5]; exact h.sigComm
  · rw [e4, e6]; exact h.authAssert
  · rw [e4, e7]; exact h.authUsed
  · rw [e4]; exact h.authUnique
  · rw [e2, e8]; exact h.unlockPrf
  · rw [e3, e9]; exact h.rootVia
  · rw [e9]; intro w hw
    exact viaOk_mono (fun d x => by rw [e8]; exact x) (fun d x => by rw [e11]; exact x) ho e12 hr hg (h.viaAll w hw)

theorem inv_effect {s : St} (op : Op) (h : Inv s) (hr : refusals s op = []) :
    Inv (effect s op) := by
  cases op with
  | enroll b d =>
    have h1 := inv_prfEval b h
    simp only [effect]
    exact inv_frame h1 rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | unlock d ic =>
    have h1 := inv_prfEval d h
    simp only [effect]
    constructor
    · intro i hi
      rcases h1.sigUser i hi with ⟨d', hm⟩ | hroot
      · exact Or.inl ⟨d', List.mem_cons_of_mem _ hm⟩
      · exact Or.inr hroot
    · exact h1.sigComm
    · exact h1.authAssert
    · exact h1.authUsed
    · exact h1.authUnique
    · intro d' i hm
      simp only [List.mem_cons, Prod.mk.injEq] at hm
      rcases hm with ⟨rfl, _⟩ | hm
      · have := (leak_fields { s with prfLog := d' :: s.prfLog } d' (.originLeak d')).2.2.2.2.1
        unfold prfEval; rw [this]; simp
      · exact h1.unlockPrf d' i hm
    · exact h1.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h1.viaAll w hw)
  | approve d ic nf =>
    simp only [effect]
    constructor
    · exact h.sigUser
    · exact h.sigComm
    · intro i n hm
      obtain ⟨d', hd⟩ := h.authAssert i n hm
      exact ⟨d', List.mem_cons_of_mem _ hd⟩
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | authorize d ic nf =>
    simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq] at hr
    obtain ⟨⟨ha, _⟩, hn⟩ := hr
    simp only [effect]
    constructor
    · exact h.sigUser
    · intro i hi
      rcases h.sigComm i hi with ⟨n, hm⟩ | hx
      · exact Or.inl ⟨n, List.mem_cons_of_mem _ hm⟩
      · exact Or.inr hx
    · intro i n hm
      simp only [List.mem_cons, Prod.mk.injEq] at hm
      rcases hm with ⟨rfl, rfl⟩ | hm
      · exact ⟨d, ha⟩
      · exact h.authAssert i n hm
    · intro i n hm
      simp only [List.mem_cons, Prod.mk.injEq] at hm
      rcases hm with ⟨_, rfl⟩ | hm
      · exact List.mem_cons_self
      · exact List.mem_cons_of_mem _ (h.authUsed i n hm)
    · intro i1 i2 n h1 h2
      simp only [List.mem_cons, Prod.mk.injEq] at h1 h2
      rcases h1 with ⟨rfl, rfl⟩ | h1 <;> rcases h2 with ⟨rfl, hn2⟩ | h2
      · rfl
      · exact absurd (h.authUsed _ _ h2) hn
      · exact absurd (h.authUsed _ _ h1) (hn2 ▸ hn)
      · exact h.authUnique i1 i2 n h1 h2
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | release ic nf =>
    simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq,
      Bool.or_eq_true, hasUnlock_iff] at hr
    obtain ⟨⟨_, ha⟩, hc⟩ := hr
    simp only [effect]
    constructor
    · intro i hi
      simp only [List.mem_cons] at hi
      rcases hi with rfl | hi
      · exact hc
      · exact h.sigUser i hi
    · intro i hi
      simp only [List.mem_cons] at hi
      rcases hi with rfl | hi
      · exact Or.inl ⟨nf, ha⟩
      · exact h.sigComm i hi
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | removeDevice b d =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | publishRWrap b =>
    have h1 := inv_prfEval b h
    simp only [effect]
    apply inv_quorumRule
    exact inv_frame h1 rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id (fun _ => rfl) (Nat.le_refl _)
  | recoverSubmit succ =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | recoverCancel b =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | recoverFinalise =>
    simp only [effect]
    split
    · exact h
    · rename_i succ adv _
      have hb : Inv { s with creds := [succ], readers := succ :: s.readers,
                             rWrap := false, pending := none } :=
        inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
      split
      · constructor
        · exact hb.sigUser
        · exact hb.sigComm
        · exact hb.authAssert
        · exact hb.authUsed
        · exact hb.authUnique
        · exact hb.unlockPrf
        · exact hb.rootVia
        · intro w hw
          refine viaOk_mono ?_ ?_ ?_ ?_ ?_ ?_ (hb.viaAll w hw) <;>
            first | exact fun _ x => x | exact id | rfl | exact Nat.le_refl _
                  | (intro _ x; exact List.mem_cons_of_mem _ x)
      · exact inv_leak _ _ hb (fun ho => ho)
  | advRecoverSubmit succ =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | eReprovision =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (Nat.le_refl _)
  | corruptCommittee =>
    simp only [effect]
    constructor
    · exact h.sigUser
    · intro i _; exact Or.inr rfl
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | corruptE =>
    simp only [effect]
    constructor
    · exact h.sigUser
    · intro i _; exact Or.inr rfl
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | corruptOrigin =>
    simp only [effect]
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl (fun _ => rfl) id (Nat.le_refl _)
  | corruptGuardian g =>
    simp only [effect]
    apply inv_quorumRule
    exact inv_frame h rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl id id (by simp)
  | stealDevice d unlocked =>
    simp only [effect]
    split
    · split
      · constructor
        · intro i _; exact Or.inr rfl
        · exact h.sigComm
        · exact h.authAssert
        · exact h.authUsed
        · exact h.authUnique
        · intro d' i hm; exact List.mem_cons_of_mem _ (h.unlockPrf d' i hm)
        · intro _; simp
        · intro w hw
          simp only [List.mem_cons] at hw
          rcases hw with rfl | hw
          · simp [viaOk]
          · exact viaOk_mono (fun _ x => List.mem_cons_of_mem _ x) (fun _ x => List.mem_cons_of_mem _ x) id rfl id (Nat.le_refl _)
              (h.viaAll w hw)
      · constructor
        · exact h.sigUser
        · exact h.sigComm
        · exact h.authAssert
        · exact h.authUsed
        · exact h.authUnique
        · exact h.unlockPrf
        · exact h.rootVia
        · intro w hw
          refine viaOk_mono ?_ ?_ ?_ ?_ ?_ ?_ (h.viaAll w hw) <;>
            first | exact fun _ x => x | exact id | rfl | exact Nat.le_refl _
                  | (intro _ x; exact List.mem_cons_of_mem _ x)
    · exact h
  | providerTakeover d =>
    simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq] at hr
    obtain ⟨hs, _⟩ := hr
    simp only [effect]
    split
    · constructor
      · intro i _; exact Or.inr rfl
      · exact h.sigComm
      · exact h.authAssert
      · exact h.authUsed
      · exact h.authUnique
      · exact h.unlockPrf
      · intro _; simp
      · intro w hw
        simp only [List.mem_cons] at hw
        rcases hw with rfl | hw
        · exact ⟨hs, List.mem_cons_self⟩
        · refine viaOk_mono ?_ ?_ ?_ ?_ ?_ ?_ (h.viaAll w hw) <;>
            first | exact fun _ x => x | exact id | rfl | exact Nat.le_refl _
                  | (intro _ x; exact List.mem_cons_of_mem _ x)
    · constructor
      · exact h.sigUser
      · exact h.sigComm
      · exact h.authAssert
      · exact h.authUsed
      · exact h.authUnique
      · exact h.unlockPrf
      · exact h.rootVia
      · intro w hw
        refine viaOk_mono ?_ ?_ ?_ ?_ ?_ ?_ (h.viaAll w hw) <;>
          first | exact fun _ x => x | exact id | rfl | exact Nat.le_refl _
                | (intro _ x; exact List.mem_cons_of_mem _ x)
  | advAssert d ic nf =>
    simp only [refusals, chk_nil, decide_eq_true_eq] at hr
    simp only [effect]
    constructor
    · exact h.sigUser
    · exact h.sigComm
    · intro i n hm
      obtain ⟨d', hd⟩ := h.authAssert i n hm
      exact ⟨d', List.mem_cons_of_mem _ hd⟩
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | originAssert d ic nf =>
    simp only [effect]
    constructor
    · exact h.sigUser
    · exact h.sigComm
    · intro i n hm
      obtain ⟨d', hd⟩ := h.authAssert i n hm
      exact ⟨d', List.mem_cons_of_mem _ hd⟩
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)
  | advSign ic =>
    simp only [refusals, List.append_eq_nil_iff, chk_nil, Bool.or_eq_true,
      hasUnlock_iff] at hr
    obtain ⟨hx, hc⟩ := hr
    simp only [effect]
    constructor
    · intro i hi
      simp only [List.mem_cons] at hi
      rcases hi with rfl | hi
      · exact hc
      · exact h.sigUser i hi
    · intro i hi
      simp only [List.mem_cons] at hi
      rcases hi with rfl | hi
      · exact Or.inr hx
      · exact h.sigComm i hi
    · exact h.authAssert
    · exact h.authUsed
    · exact h.authUnique
    · exact h.unlockPrf
    · exact h.rootVia
    · intro w hw
      exact viaOk_mono (fun _ x => x) (fun _ x => x) id rfl id (Nat.le_refl _) (h.viaAll w hw)

theorem inv_apply {s : St} (op : Op) (h : Inv s) : Inv (apply s op) := by
  unfold apply
  split
  · exact inv_effect op h (by assumption)
  · exact h

theorem inv_reach {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) : Inv s := by
  induction h with
  | init => exact inv_init c d0
  | step op _ ih => exact inv_apply op ih

/-! ## Second invariant: recovery bookkeeping -/

structure Inv2 (s : St) : Prop where
  wrapEver : s.rWrap = true → s.rWrapEver = true
  pendEver : s.pending.isSome = true → s.rWrapEver = true
  leakEver : ∀ d, Via.recoveryLeak d ∈ s.via → s.rWrapEver = true
  assertSrc : ∀ d ic nf, (d, ic, nf) ∈ s.asserts →
    (d, ic, nf) ∈ s.approved ∨ d ∈ s.advCred ∨ (d, ic, nf) ∈ s.hijacked
  hijackSrc : ∀ d ic nf, (d, ic, nf) ∈ s.hijacked →
    s.originCorrupt = true ∧ d ∉ s.cfg.native

theorem inv2_init (c : Cfg) (d0 : Nat) : Inv2 (init c d0) := by
  constructor <;> simp [init]

theorem inv2_apply {s : St} (op : Op) (h : Inv2 s) : Inv2 (apply s op) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  unfold apply
  split
  · rename_i hr
    cases op <;>
      simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq] at hr <;>
      constructor <;>
      simp only [effect, prfEval, leak, quorumRule] <;>
      grind
  · exact ⟨h1, h2, h3, h4, h5⟩

theorem inv2_reach {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) : Inv2 s := by
  induction h with
  | init => exact inv2_init c d0
  | step op _ ih => exact inv2_apply op ih

/-- PS-001. The configuration never changes. -/
theorem cfg_reach {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) : s.cfg = c := by
  induction h with
  | init => rfl
  | step op _ ih =>
    rw [← ih]
    unfold apply
    split
    · cases op <;> simp only [effect, prfEval, leak, quorumRule] <;> grind
    · rfl

/-! ## Property 1: nobody outside the access structure signs

The access structure of the user leaf is `d_1 OR ... OR d_m OR R`, always
ANDed with the committee. `s.via` lists every way the adversary entered the
user leaf. -/

/-- PS-058. The meaning of each entry of `via`. -/
theorem via_sound {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) :
    ∀ v, v ∈ s.via → viaOk s v := (inv_reach h).viaAll

/-- PS-058. The adversary holds the root only through an entry of `via`. -/
theorem root_needs_leaf {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (hr : s.advRoot = true) : ∃ v, v ∈ s.via ∧ viaOk s v := by
  have hi := inv_reach h
  have hne := hi.rootVia hr
  cases hv : s.via with
  | nil => exact absurd hv hne
  | cons v vs => exact ⟨v, by simp, hi.viaAll v (by rw [hv]; simp)⟩

/-- PS-058 (C3, C17). A coalition that never entered the user leaf signs only
the intents that a user-verified unlock dealt, whatever else it holds: `x_f`,
all `n` nodes, the group `E`, the origin of other accounts. -/
theorem no_signature_outside_access_structure {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (hv : s.via = []) :
    ∀ ic, ic ∈ s.sigs → ∃ d, (d, ic) ∈ s.unlockLog ∧ d ∈ s.prfLog := by
  intro ic hic
  have hi := inv_reach h
  rcases hi.sigUser ic hic with ⟨d, hd⟩ | hr
  · exact ⟨d, hd, hi.unlockPrf d ic hd⟩
  · exact absurd hv (hi.rootVia hr)

/-- PS-058. The same statement from what the adversary corrupted: an honest
origin, no credential and fewer guardians than the quorum. The committee and
`E` are unrestricted. -/
theorem fully_corrupt_committee_cannot_forge {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (ho : s.originCorrupt = false) (hc : s.advCred = [])
    (hg : s.advGuard.length < s.cfg.quorum) :
    ∀ ic, ic ∈ s.sigs → ∃ d, (d, ic) ∈ s.unlockLog ∧ d ∈ s.prfLog := by
  apply no_signature_outside_access_structure h
  have hi := inv_reach h
  cases hv : s.via with
  | nil => rfl
  | cons v vs =>
    have hok := hi.viaAll v (by rw [hv]; simp)
    cases v <;> simp only [viaOk] at hok
    · rw [ho] at hok; exact absurd hok.2 (by simp)
    · rw [ho] at hok; exact absurd hok (by simp)
    · rw [hc] at hok; exact absurd hok.2 (by simp)
    · rw [hc] at hok; exact absurd hok.2 (by simp)
    · exact absurd hok.2 (Nat.not_le_of_lt hg)

/-- PS-059 (C5, C6). Without the committee half, every signature has an
authorization in force that an assertion over the same intent carries. This
covers every user-side coalition: devices, guardians, the origin, the passkey
provider. -/
theorem no_signature_without_committee {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (hx : s.advXf = false) :
    ∀ ic, ic ∈ s.sigs → ∃ nf d, (ic, nf) ∈ s.authorized ∧ (d, ic, nf) ∈ s.asserts := by
  intro ic hic
  have hi := inv_reach h
  rcases hi.sigComm ic hic with ⟨nf, hn⟩ | hr
  · obtain ⟨d, hd⟩ := hi.authAssert ic nf hn
    exact ⟨nf, d, hn, hd⟩
  · rw [hx] at hr; exact absurd hr (by simp)

/-- PS-059. A stolen root moves nothing while the committee is honest and the
adversary holds no credential: every signature has an assertion that the user
approved for that intent. -/
theorem stolen_root_needs_user_approval {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (hx : s.advXf = false) (hc : s.advCred = [])
    (hj : s.hijacked = []) :
    ∀ ic, ic ∈ s.sigs → ∃ nf d, (d, ic, nf) ∈ s.approved := by
  intro ic hic
  obtain ⟨nf, d, _, hd⟩ := no_signature_without_committee h hx ic hic
  rcases (inv2_reach h).assertSrc d ic nf hd with ha | ha | ha
  · exact ⟨nf, d, ha⟩
  · rw [hc] at ha; exact absurd ha (by simp)
  · rw [hj] at ha; exact absurd ha (by simp)

/-- PS-059. The adversary gains the committee half only by corrupting the
committee or the group `E`. -/
theorem committee_half_source (s : St) (op : Op) :
    (apply s op).advXf = true →
      s.advXf = true ∨ op = .corruptCommittee ∨ op = .corruptE := by
  unfold apply
  split
  · cases op <;> simp only [effect, prfEval, leak, quorumRule] <;> grind
  · intro hx; exact Or.inl hx

/-! ## Property 2: user verification -/

/-- PS-060. Every signature rests on a user-verified PRF evaluation, with
three exceptions that the state names: the provider of a synced passkey, a
guardian quorum, and an honest recovery on a corrupt origin. -/
theorem signature_needs_user_verification {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (ic : Nat) (hic : ic ∈ s.sigs) :
    (∃ d, d ∈ s.prfLog ∧
      ((d, ic) ∈ s.unlockLog ∨ Via.originLeak d ∈ s.via ∨ Via.theft d ∈ s.via)) ∨
    (∃ d, Via.provider d ∈ s.via) ∨ Via.quorum ∈ s.via ∨
    (∃ d, Via.recoveryLeak d ∈ s.via) := by
  have hi := inv_reach h
  rcases hi.sigUser ic hic with ⟨d, hd⟩ | hr
  · exact Or.inl ⟨d, hi.unlockPrf d ic hd, Or.inl hd⟩
  · have hne := hi.rootVia hr
    cases hv : s.via with
    | nil => exact absurd hv hne
    | cons v vs =>
      have hm : v ∈ s.via := by rw [hv]; simp
      have hok := hi.viaAll v hm
      rw [← hv]
      cases v with
      | originLeak d => exact Or.inl ⟨d, hok.1, Or.inr (Or.inl hm)⟩
      | recoveryLeak d => exact Or.inr (Or.inr (Or.inr ⟨d, hm⟩))
      | theft d => exact Or.inl ⟨d, hok.1, Or.inr (Or.inr hm)⟩
      | provider d => exact Or.inr (Or.inl ⟨d, hm⟩)
      | quorum => exact Or.inr (Or.inr (Or.inl hm))

/-- PS-060. With device-bound readers and no recovery wrap, the statement has
no exception. -/
theorem signature_needs_user_verification_strict {c : Cfg} {d0 : Nat} {s : St}
    (h : Reach c d0 s) (hs : c.synced = []) (hw : s.rWrapEver = false)
    (ic : Nat) (hic : ic ∈ s.sigs) :
    ∃ d, d ∈ s.prfLog ∧
      ((d, ic) ∈ s.unlockLog ∨ Via.originLeak d ∈ s.via ∨ Via.theft d ∈ s.via) := by
  have hi := inv_reach h
  have h2 := inv2_reach h
  have hcfg := cfg_reach h
  rcases signature_needs_user_verification h ic hic with hgood | ⟨d, hp⟩ | hq | ⟨d, hl⟩
  · exact hgood
  · have := (hi.viaAll _ hp).1
    rw [hcfg, hs] at this; exact absurd this (by simp)
  · have := (hi.viaAll _ hq).1
    rw [hw] at this; exact absurd this (by simp)
  · have := h2.leakEver d hl
    rw [hw] at this; exact absurd this (by simp)

/-! ## Property 3: recovery -/

/-- The operations of Passport recovery and of the recovery group `E`. -/
def isRecoveryOp : Op → Bool
  | .publishRWrap _ | .recoverSubmit _ | .recoverCancel _ | .recoverFinalise
  | .eReprovision => true
  | _ => false

/-- PS-042. No recovery operation gives the adversary the committee half. -/
theorem recovery_keeps_committee_half (s : St) (op : Op) (hop : isRecoveryOp op = true) :
    (apply s op).advXf = s.advXf := by
  unfold apply
  split
  · cases op <;> simp only [isRecoveryOp] at hop <;>
      simp only [effect, prfEval, leak, quorumRule] <;> grind
  · rfl

/-- PS-036, PS-042. With an honest origin and fewer corrupt guardians than
the quorum, no recovery operation gives the adversary the root. -/
theorem recovery_gives_no_root (s : St) (op : Op) (hop : isRecoveryOp op = true)
    (ho : s.originCorrupt = false) (hg : s.advGuard.length < s.cfg.quorum) :
    (apply s op).advRoot = s.advRoot := by
  unfold apply
  split
  · cases op <;> simp only [isRecoveryOp] at hop <;>
      simp only [effect, prfEval, leak, quorumRule] <;> grind
  · rfl

/-- PS-042. The group `E` acts on the committee side only: a reprovision
changes `committee_corrupt` and `epoch` and nothing else. -/
theorem eReprovision_frame (s : St) :
    apply s .eReprovision = { s with committeeCorrupt := false, epoch := s.epoch + 1 } := by
  simp [apply, refusals, effect]

/-- PS-065. The origin hijacks an approval only while it is corrupt, and only
on a credential that is not native. -/
theorem hijack_needs_corrupt_origin {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (ho : s.originCorrupt = false) : s.hijacked = [] := by
  have h2 := inv2_reach h
  cases hh : s.hijacked with
  | nil => rfl
  | cons t ts =>
    obtain ⟨d, ic, nf⟩ := t
    have := (h2.hijackSrc d ic nf (by rw [hh]; simp)).1
    rw [ho] at this; exact absurd this (by simp)

/-- PS-003. A valid configuration has no guardian that a committee operator or
a member of `E` runs. -/
theorem valid_cfg_no_overlap (c : Cfg) (h : validCfg c = true) : c.overlap = [] := by
  unfold validCfg cfgRefusals at h
  simp only [decide_eq_true_eq, List.append_eq_nil_iff] at h
  have := h.2
  split at this
  · assumption
  · simp at this

/-! ## Property 4: an assertion authorizes only its intent -/

/-- PS-018, PS-019. An authorization in force carries an assertion over
exactly its `(ic, nf)`. -/
theorem assertion_binds_intent {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (ic nf : Nat) (ha : (ic, nf) ∈ s.authorized) : ∃ d, (d, ic, nf) ∈ s.asserts :=
  (inv_reach h).authAssert ic nf ha

/-- PS-019. Without an assertion over exactly `(d, ic, nf)`, `authorize`
changes nothing. An assertion over another intent or another `nf` does not
help. -/
theorem authorize_needs_exact_assertion (s : St) (d ic nf : Nat)
    (hn : (d, ic, nf) ∉ s.asserts) : apply s (.authorize d ic nf) = s := by
  unfold apply
  split
  · rename_i hr
    simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq] at hr
    exact absurd hr.1.1 hn
  · rfl

/-- PS-064, PS-021. One `nf` authorizes one intent. -/
theorem nf_authorizes_one_intent {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (ic1 ic2 nf : Nat) (h1 : (ic1, nf) ∈ s.authorized) (h2 : (ic2, nf) ∈ s.authorized) :
    ic1 = ic2 :=
  (inv_reach h).authUnique ic1 ic2 nf h1 h2

/-- PS-016, PS-054. While the adversary holds no credential, every
authorization in force is one the user approved, for that intent. -/
theorem authorization_is_user_approved {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (hc : s.advCred = []) (hj : s.hijacked = []) (ic nf : Nat)
    (ha : (ic, nf) ∈ s.authorized) : ∃ d, (d, ic, nf) ∈ s.approved := by
  obtain ⟨d, hd⟩ := assertion_binds_intent h ic nf ha
  rcases (inv2_reach h).assertSrc d ic nf hd with hp | hp | hp
  · exact ⟨d, hp⟩
  · rw [hc] at hp; exact absurd hp (by simp)
  · rw [hj] at hp; exact absurd hp (by simp)

/-! ## Property 6: an enrolled device is never the successor of the adversary

Decision D-1 of SHARD-SPEC.md (PS-067). The successor of a pending recovery
stays fresh until the recovery ends. A device that `ENROLL` accepted is in
`readers` from then on, so `RECOVER_FINALISE` never adds it to `advCred`. -/

/-- PS-067. `ENROLL` refuses the id of a pending successor, for both values of
`pending.adv`. -/
theorem enroll_refuses_pending_successor (s : St) (b succ : Nat) (adv : Bool)
    (hp : s.pending = some (succ, adv)) :
    Refusal.pendingSuccessor ∈ refusals s (.enroll b succ) := by
  simp [refusals, hp, notPendingSucc, chk]

/-- `readers` never loses a member (PS-006, PS-008, PS-036). -/
theorem readers_apply {s : St} (op : Op) {d : Nat} (hd : d ∈ s.readers) :
    d ∈ (apply s op).readers := by
  unfold apply
  split
  · cases op <;> simp only [effect, prfEval, leak, quorumRule] <;> grind
  · exact hd

theorem readers_runOps {s : St} (ops : List Op) {d : Nat} (hd : d ∈ s.readers) :
    d ∈ (runOps s ops).readers := by
  induction ops generalizing s with
  | nil => exact hd
  | cons op ops ih => exact ih (readers_apply op hd)

theorem reach_runOps {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) (ops : List Op) :
    Reach c d0 (runOps s ops) := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih (Reach.step op h)

theorem pendFresh_apply {s : St} (op : Op)
    (h : ∀ succ adv, s.pending = some (succ, adv) → succ ∉ s.creds ∧ succ ∉ s.readers) :
    ∀ succ adv, (apply s op).pending = some (succ, adv) →
      succ ∉ (apply s op).creds ∧ succ ∉ (apply s op).readers := by
  unfold apply
  split
  · rename_i hr
    cases op <;>
      simp only [refusals, List.append_eq_nil_iff, chk_nil, decide_eq_true_eq, fresh,
        notPendingSucc, Bool.and_eq_true, decide_not] at hr <;>
      simp only [effect, prfEval, leak, quorumRule] <;>
      grind
  · exact h

/-- PS-067, PS-033, PS-041. In every reachable state, the successor of a
pending recovery is fresh: it is in neither `creds` nor `readers`. -/
theorem pending_successor_fresh {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s) :
    ∀ succ adv, s.pending = some (succ, adv) → succ ∉ s.creds ∧ succ ∉ s.readers := by
  induction h with
  | init => intro succ adv hp; simp [init] at hp
  | step op _ ih => exact pendFresh_apply op ih

/-- PS-067, PS-038 (D-1, OD-1). Let `ENROLL(b, d)` pass in a reachable state.
After any further operations, a `RECOVER_FINALISE` does not add `d` to
`advCred`: an id that the user enrolled never becomes the credential of the
adversary through recovery. -/
theorem enrolled_never_adv_successor {c : Cfg} {d0 : Nat} {s : St} (h : Reach c d0 s)
    (b d : Nat) (hacc : refusals s (.enroll b d) = []) (ops : List Op) :
    let t := runOps (apply s (.enroll b d)) ops
    d ∈ (apply t .recoverFinalise).advCred → d ∈ t.advCred := by
  intro t hd
  have hr1 : d ∈ (apply s (.enroll b d)).readers := by
    unfold apply; simp [hacc, effect]
  have hrt : d ∈ t.readers := readers_runOps ops hr1
  have ht : Reach c d0 t := reach_runOps (Reach.step _ h) ops
  have hf := pending_successor_fresh ht
  revert hd
  unfold apply
  split
  · simp only [effect]
    split
    · exact id
    · rename_i succ adv hp
      have hne : succ ≠ d := fun e => (hf succ adv hp).2 (e ▸ hrt)
      cases adv
      · intro hd
        simp only [Bool.false_eq_true, ↓reduceIte, leak_fields] at hd
        exact hd
      · intro hd
        simp only [ite_true, List.mem_cons] at hd
        rcases hd with e | hd
        · exact absurd e.symm hne
        · exact hd
  · exact id

/-- PS-057. A refused operation leaves the state unchanged. -/
theorem apply_refused (s : St) (op : Op) (h : refusals s op ≠ []) : apply s op = s := by
  unfold apply; simp [h]

end PassportShard
