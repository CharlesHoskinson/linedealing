import SplitHandoff.Spec

/-!
# Theorems of the handoff oracle

Each theorem names its requirement IDs. The proofs use only `simp`, `omega` and
case splits over the definitions of `Spec`.
-/

namespace SplitHandoff

/-! ## Basic facts -/

theorem next_eq (s : St) (op : Op) : next s op = if refusals s op = [] then effect s op.act else s := rfl

theorem run_nil (s : St) : run s [] = s := rfl

theorem run_cons (s : St) (op : Op) (ops : List Op) : run s (op :: ops) = run (next s op) ops := rfl

theorem run_append (s : St) (a b : List Op) : run s (a ++ b) = run (run s a) b := by
  simp [run, List.foldl_append]

theorem opt_nil {c : Prop} [Decidable c] {r : Refusal} : opt c r = [] ↔ ¬ c := by
  unfold opt; split <;> simp_all

/-- The operations accepted under the actor check are the actions' own. -/
theorem refusals_nil {s : St} {op : Op} (h : refusals s op = []) :
    op.actor = op.act.actor ∧ actRefusals s op.act = [] := by
  unfold refusals at h
  split at h
  · simp at h
  · rename_i hc; exact ⟨by simpa using hc, h⟩

/-! ## HO-056, HO-057: the frame of every transition -/

theorem release_frame (s : St) :
    (release s).xf = s.xf ∧ (release s).users = s.users ∧ (release s).addrs = s.addrs := by
  unfold release; split <;> simp

theorem effect_frame (s : St) (a : Act) :
    (effect s a).xf = s.xf ∧ (effect s a).users = s.users ∧ (effect s a).addrs = s.addrs := by
  cases a with
  | midnightTick m =>
    simp only [effect]; split
    · simp
    · exact release_frame _
  | useSlot rid a i tk => simp only [effect, useEff]; split <;> simp
  | admitBoot seat w => simp only [effect]; split <;> simp
  | _ => simp [effect, activateEff, sweepEff]

/-- HO-056: every transition, and every run, keeps `X_f` of each curve, so the key
`(X_f, user shard)` of every address stays the same. -/
theorem ho056_xf_unchanged (s : St) (op : Op) :
    (next s op).xf = s.xf
      ∧ ∀ a ∈ s.addrs, ((next s op).xf.get a.curve, shardOf (next s op) a.user)
          = (s.xf.get a.curve, shardOf s a.user) := by
  have h := effect_frame s op.act
  unfold next; split
  · refine ⟨h.1, fun a _ => ?_⟩; simp [shardOf, h.1, h.2.1]
  · exact ⟨rfl, fun _ _ => rfl⟩

theorem run_xf (s : St) (ops : List Op) : (run s ops).xf = s.xf ∧ (run s ops).users = s.users := by
  induction ops generalizing s with
  | nil => exact ⟨rfl, rfl⟩
  | cons op ops ih =>
    rw [run_cons]
    have h := effect_frame s op.act
    have := ih (next s op)
    unfold next at this ⊢; split at this <;> simp_all

/-- HO-056 for runs: ten handoffs or any other run keep `X_f`. -/
theorem ho056_run_xf (s : St) (ops : List Op) : (run s ops).xf = s.xf := (run_xf s ops).1

/-- HO-057: every transition leaves the user state (shard, tweak, actor pool, sealed
contribution, slot root, asset record) and the addresses unchanged. -/
theorem ho057_user_untouched (s : St) (op : Op) :
    (next s op).users = s.users ∧ (next s op).addrs = s.addrs := by
  have h := effect_frame s op.act
  unfold next; split
  · exact ⟨h.2.1, h.2.2⟩
  · exact ⟨rfl, rfl⟩

/-! ## HO-058: no user action -/

/-- HO-058: every operation the handoff machine accepts is an operation of governance, a
committee seat, the board, the committee contract or time, and never of a user. -/
theorem ho058_no_user_action (s : St) (op : Op) (h : refusals s op = []) : op.actor ≠ .user := by
  obtain ⟨ha, hr⟩ := refusals_nil h
  rw [ha]
  cases hc : op.act <;> simp_all [Act.actor, actRefusals]

/-! ## HO-036, HO-059, HO-044: ownership and carried slot state -/

/-- HO-036, HO-043: the binding epoch owns a request below the board position of its sweep and
the successor from that position; with no sweep the binding epoch owns it. -/
theorem ho036_owner_switch (r : Req) :
    (∀ w p, r.sweep = some w → p < w → owner r p = r.bind)
      ∧ (∀ w p, r.sweep = some w → w ≤ p → owner r p = r.bind + 1)
      ∧ (r.sweep = none → ∀ p, owner r p = r.bind) := by
  refine ⟨fun w p hw hp => ?_, fun w p hw hp => ?_, fun hw p => ?_⟩
  · simp [owner, hw, hp]
  · have : ¬ p < w := by omega
    simp [owner, hw, this]
  · simp [owner, hw]

/-- HO-059: at every board position a request has exactly one owning epoch, and it is
`owner r p`. -/
theorem ho059_one_owner (r : Req) (p : Nat) : ∃ e, ownsAt r p e ∧ ∀ e', ownsAt r p e' → e' = e := by
  refine ⟨owner r p, ?_, ?_⟩
  · unfold ownsAt owner
    cases hw : r.sweep with
    | none => left; simp
    | some w =>
      by_cases hp : p < w
      · left; simp [hp]
      · right; simp [hp]; omega
  · intro e' he'
    unfold ownsAt at he'
    unfold owner
    cases hw : r.sweep with
    | none => simp_all
    | some w =>
      rcases he' with ⟨h1, h2⟩ | ⟨h1, w', h2, h3⟩
      · have := h2 w hw; simp [this, h1]
      · rw [hw] at h2; cases h2
        have : ¬ p < w := by omega
        simp [this, h1]

/-- HO-044: a target seat installs a carried slot (at the activation or at the sweep) in the
state that the board shows. -/
theorem ho044_carried_slot_board_state (s : St) (e : Nat) (ros : List Nat) (sh : Sharing) (a i : Nat)
    (h : sh.secret = .slot a i) : (install s e ros sh).st = boardSlot s (a, i) := by
  simp [install, slotState, h]

/-- HO-044 at the sweep: every slot copy the sweep installs has the board's state. -/
theorem ho044_sweep_installs_board_state (s : St) (e : Nat) :
    ∀ sh ∈ (sweepEff s e).sharings, sh ∉ s.sharings → ∀ a i, sh.secret = .slot a i →
      sh.st = boardSlot s (a, i) := by
  intro sh hsh hn a i hs
  simp only [sweepEff, List.mem_append, List.mem_map] at hsh
  rcases hsh with h | ⟨sh0, _, rfl⟩
  · exact absurd h hn
  · simp only [install] at hs ⊢
    simp [slotState, hs]

/-! ## HO-033 to HO-035: abort keeps the old committee -/

theorem close_phase_ne (t : St) (hq : t.ho.phase ≠ .QUEUED) : (closeGraces t).ho.phase = t.ho.phase := by
  simp only [closeGraces]; split
  · rename_i h; exact absurd h.1 hq
  · rfl

theorem release_ho_phase (s : St) (h : s.ho.phase ≠ .QUEUED) : release s = s := by
  unfold release; split
  · rename_i hc; exact absurd hc.1 h
  · rfl

/-- HO-033, HO-035, HO-066: when a ROTATING or ARMED handoff becomes ABORTED, the current
epoch, the epochs with their rosters and status, the sharings, the activation history (the
board's validator sets), the landed epoch and the board's slot states are as they were. -/
theorem ho035_abort_keeps_old (s : St) (op : Op)
    (hR : s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) (hA : (next s op).ho.phase = .ABORTED) :
    (next s op).cur = s.cur ∧ (next s op).epochs = s.epochs ∧ (next s op).sharings = s.sharings
      ∧ (next s op).handovers = s.handovers ∧ (next s op).landed = s.landed
      ∧ (next s op).board = s.board ∧ (next s op).pos = s.pos := by
  unfold next at hA ⊢
  split at hA
  · rename_i hacc
    obtain ⟨_, hr⟩ := refusals_nil hacc
    simp only [hacc, ↓reduceIte]
    cases hc : op.act with
    | midnightTick m =>
      rw [hc] at hA; simp only [effect] at hA ⊢
      by_cases hab : (s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) ∧ s.ho.mD < m
      · simp only [hab, and_self, ↓reduceIte]
      · exfalso
        simp only [hab, ↓reduceIte] at hA
        have hq : ({ s with mh := m } : St).ho.phase ≠ .QUEUED := by
          rcases hR with h | h <;> simp [h]
        unfold closeGraces at hA
        simp only [hq, false_and, ↓reduceIte] at hA
        rw [release_ho_phase] at hA
        · rcases hR with h | h <;> simp_all
        · simp; rcases hR with h | h <;> simp [h]
    | rotate r =>
      exfalso; rw [hc] at hr
      simp [actRefusals, rotateRefusals, opt_nil, rotationOpenP] at hr
      rcases hR with h | h <;> simp_all
    | admitBoot seat w =>
      rw [hc] at hA; simp only [effect] at hA; split at hA <;> (exfalso; rcases hR with h | h <;> simp_all)
    | useSlot rid a i tk =>
      rw [hc] at hA; simp only [effect, useEff] at hA; split at hA <;> (exfalso; rcases hR with h | h <;> simp_all)
    | _ =>
      rw [hc] at hA
      exfalso
      rcases hR with h | h <;> simp_all [effect, activateEff, sweepEff]
  · simp_all

end SplitHandoff

namespace SplitHandoff

/-! ## The invariant -/

theorem lookupE_map (f : EpochRec → EpochRec) (hf : ∀ r, (f r).id = r.id) (l : List EpochRec) (e : Nat) :
    lookupE (l.map f) e = (lookupE l e).map f := by
  induction l with
  | nil => rfl
  | cons r rs ih => simp only [List.map_cons, lookupE, hf]; split <;> simp_all

theorem lookupE_id {l : List EpochRec} {e : Nat} {r : EpochRec} (h : lookupE l e = some r) : r.id = e := by
  induction l with
  | nil => simp [lookupE] at h
  | cons x xs ih => simp only [lookupE] at h; split at h <;> simp_all

theorem lookupE_mem {l : List EpochRec} {e : Nat} {r : EpochRec} (h : lookupE l e = some r) : r ∈ l := by
  induction l with
  | nil => simp [lookupE] at h
  | cons x xs ih => simp only [lookupE] at h; split at h <;> simp_all

/-- The state invariant. `holders` is the fact that each sharing lies in one roster
(HO-055, DESIGN §8 7.4); the others pin the epochs (HO-055) and the open handoff. -/
structure Inv (s : St) : Prop where
  cur_current : statusOf s s.cur = some .current
  current_uniq : ∀ e, statusOf s e = some .current → e = s.cur
  grace_prev : ∀ e, statusOf s e = some .grace → e + 1 = s.cur
  open_src : (s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) →
    (∀ e, statusOf s e ≠ some .grace) ∧ s.ho.rot.source = s.cur
  open_tgt : (s.ho.phase = .QUEUED ∨ s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) →
    s.ho.rot.target = s.cur + 1 ∧ 1 ≤ s.ho.rot.n - s.ho.rot.f
  hist : (s.handovers.head?.map Prod.snd).getD 0 = s.cur
  batch : s.ho.lastBatch ≤ s.mh
  armed_pos : s.ho.phase = .ARMED → s.pos = s.ho.H
  holders : ∀ sh ∈ s.sharings, sh.holders = rosterOf s sh.epoch ∧ sh.epoch ≤ s.cur

theorem inv_init (p : Params) (g : Genesis) : Inv (init p g) := by
  refine ⟨by simp [statusOf, init, lookupE], ?_, ?_, ?_, ?_, rfl, Nat.le_refl _, ?_, ?_⟩
  · intro e h; simp [statusOf, init, lookupE] at h; simp [init]; omega
  · intro e h; simp [statusOf, init, lookupE] at h
  · simp [init, idleHo]
  · simp [init, idleHo]
  · simp [init, idleHo]
  · intro sh hsh
    simp only [init, genesisSharings, List.mem_append, List.mem_cons, List.mem_flatMap] at hsh
    have hr : rosterOf (init p g) 0 = g.roster := by simp [rosterOf, init, lookupE]
    rcases hsh with (rfl | rfl | h) | ⟨a, _, ha⟩
    · simp [hr]
    · simp [hr]
    · simp at h
    · split at ha
      · simp only [List.mem_map] at ha
        obtain ⟨i, _, rfl⟩ := ha
        simp [hr]
      · simp at ha

/-- HO-010 facts 2 and 4 together: no epoch is in grace and the source is the current epoch. -/
theorem pre_src {s : St} (hI : Inv s) {e : Nat} (hp : prevClosed s) (hs : sourceOk s e) :
    (∀ e', statusOf s e' ≠ some .grace) ∧ e = s.cur := by
  have ng : ∀ e', statusOf s e' ≠ some .grace := by
    intro e' h
    have h1 := hI.grace_prev e' h
    apply hp
    have : e' = s.cur - 1 := by omega
    rw [← this]; exact h
  refine ⟨ng, ?_⟩
  rcases hs with h | h
  · exact hI.current_uniq e h
  · exact absurd h (ng e)

theorem inv_frame {s t : St} (hI : Inv s) (hc : t.cur = s.cur) (he : t.epochs = s.epochs)
    (hh : t.handovers = s.handovers) (hsh : t.sharings = s.sharings)
    (hph : (t.ho.phase = .QUEUED ∨ t.ho.phase = .ROTATING ∨ t.ho.phase = .ARMED) →
      t.ho.phase = s.ho.phase ∧ t.ho.rot = s.ho.rot)
    (hb : t.ho.lastBatch ≤ t.mh) (hpos : t.ho.phase = .ARMED → t.pos = s.pos ∧ t.ho.H = s.ho.H) :
    Inv t := by
  have hst : ∀ e, statusOf t e = statusOf s e := by intro e; simp [statusOf, he]
  have hro : ∀ e, rosterOf t e = rosterOf s e := by intro e; simp [rosterOf, he]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, hb, ?_, ?_⟩
  · rw [hst, hc]; exact hI.cur_current
  · intro e h; rw [hst] at h; rw [hc]; exact hI.current_uniq e h
  · intro e h; rw [hst] at h; rw [hc]; exact hI.grace_prev e h
  · intro hp
    obtain ⟨h1, h2⟩ := hph (by rcases hp with h | h <;> simp [h])
    rw [h1] at hp
    obtain ⟨n1, n2⟩ := hI.open_src hp
    refine ⟨fun e => by rw [hst]; exact n1 e, by rw [h2, n2, hc]⟩
  · intro hp
    obtain ⟨h1, h2⟩ := hph hp
    rw [h1] at hp
    rw [h2, hc]; exact hI.open_tgt hp
  · rw [hh, hc]; exact hI.hist
  · intro hp
    obtain ⟨h1, h2⟩ := hpos hp
    have := hph (by simp [hp])
    rw [this.1] at hp
    rw [h1, h2]; exact hI.armed_pos hp
  · intro sh hm; rw [hsh] at hm; rw [hro, hc]; exact hI.holders sh hm

theorem closeRec_id (m : Nat) (r : EpochRec) : (closeRec m r).id = r.id := by
  unfold closeRec; split <;> rfl

theorem close_status (s : St) (e : Nat) :
    statusOf (closeGraces s) e = (lookupE s.epochs e).map (fun r => (closeRec s.mh r).status) := by
  simp [statusOf, closeGraces, lookupE_map _ (closeRec_id s.mh)]; rfl

theorem close_current (s : St) (e : Nat) :
    statusOf (closeGraces s) e = some .current ↔ statusOf s e = some .current := by
  rw [close_status]; simp only [statusOf]
  cases lookupE s.epochs e with
  | none => simp
  | some r => simp only [Option.map_some, Option.some.injEq]; unfold closeRec; split <;> simp_all

theorem close_grace (s : St) (e : Nat) :
    statusOf (closeGraces s) e = some .grace → statusOf s e = some .grace := by
  rw [close_status]; simp only [statusOf]
  cases lookupE s.epochs e with
  | none => simp
  | some r => simp only [Option.map_some, Option.some.injEq]; unfold closeRec; split <;> simp_all

theorem close_roster (s : St) (e : Nat) : rosterOf (closeGraces s) e = rosterOf s e := by
  simp only [rosterOf, closeGraces, lookupE_map _ (closeRec_id s.mh)]
  cases lookupE s.epochs e with
  | none => rfl
  | some r => simp only [Option.map_some]; unfold closeRec; split <;> rfl

theorem close_phase (s : St) :
    (closeGraces s).ho.phase = s.ho.phase ∨ (closeGraces s).ho.phase = .ABORTED := by
  simp only [closeGraces]; split <;> simp

theorem close_ho_rot (s : St) : (closeGraces s).ho.rot = s.ho.rot ∧ (closeGraces s).ho.H = s.ho.H
    ∧ (closeGraces s).ho.lastBatch = s.ho.lastBatch := by
  simp only [closeGraces]; split <;> simp

theorem inv_close {s : St} (hI : Inv s) : Inv (closeGraces s) := by
  have hc : (closeGraces s).cur = s.cur := rfl
  have hph : ∀ ph, ph ≠ Phase.ABORTED → (closeGraces s).ho.phase = ph → s.ho.phase = ph := by
    intro ph hne h; rcases close_phase s with h1 | h1
    · rw [← h1]; exact h
    · rw [h1] at h; exact absurd h.symm hne
  obtain ⟨hr, hH, hlb⟩ := close_ho_rot s
  refine ⟨?_, ?_, ?_, ?_, ?_, hI.hist, ?_, ?_, ?_⟩
  · rw [close_current]; exact hI.cur_current
  · intro e h; rw [close_current] at h; exact hI.current_uniq e h
  · intro e h; exact hI.grace_prev e (close_grace s e h)
  · intro hp
    have : s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED := by
      rcases hp with h | h
      · exact Or.inl (hph _ (by simp) h)
      · exact Or.inr (hph _ (by simp) h)
    obtain ⟨n1, n2⟩ := hI.open_src this
    exact ⟨fun e h => n1 e (close_grace s e h), by rw [hr, n2]; rfl⟩
  · intro hp
    have : s.ho.phase = .QUEUED ∨ s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED := by
      rcases hp with h | h | h
      · exact Or.inl (hph _ (by simp) h)
      · exact Or.inr (Or.inl (hph _ (by simp) h))
      · exact Or.inr (Or.inr (hph _ (by simp) h))
    rw [hr]; exact hI.open_tgt this
  · rw [hlb]; exact hI.batch
  · intro hp; rw [hH]; exact hI.armed_pos (hph _ (by simp) hp)
  · intro sh hm
    simp only [closeGraces, List.mem_filter] at hm
    rw [close_roster]; exact hI.holders sh hm.1

theorem inv_release {s : St} (hI : Inv s) : Inv (release s) := by
  unfold release; split
  · rename_i hq
    obtain ⟨hQ, hpre⟩ := hq
    obtain ⟨_, hp, _, hso⟩ := hpre
    obtain ⟨ng, hsrc⟩ := pre_src hI hp hso
    refine ⟨hI.cur_current, hI.current_uniq, hI.grace_prev, fun _ => ⟨ng, hsrc⟩, ?_, hI.hist, hI.batch,
      by simp, hI.holders⟩
    intro _; exact hI.open_tgt (Or.inl hQ)
  · exact hI

end SplitHandoff

namespace SplitHandoff

theorem act_status (s : St) (e : Nat) :
    statusOf (activateEff s) e = if s.ho.rot.target = e then some .current
      else if e = s.cur then (statusOf s e).map (fun _ => .grace) else statusOf s e := by
  have hf : ∀ r : EpochRec, (if r.id = s.cur then
      { r with status := .grace, graceEnd := s.mh + s.params.deltaGrace } else r).id = r.id := by
    intro r; split <;> rfl
  simp only [statusOf, activateEff, lookupE, lookupE_map _ hf]
  split
  · rfl
  · cases h : lookupE s.epochs e with
    | none => simp
    | some r =>
      have := lookupE_id h
      simp only [Option.map_some]
      split <;> simp_all

theorem act_roster (s : St) (e : Nat) :
    rosterOf (activateEff s) e = if s.ho.rot.target = e then s.ho.rot.roster else rosterOf s e := by
  have hf : ∀ r : EpochRec, (if r.id = s.cur then
      { r with status := .grace, graceEnd := s.mh + s.params.deltaGrace } else r).id = r.id := by
    intro r; split <;> rfl
  simp only [rosterOf, activateEff, lookupE, lookupE_map _ hf]
  split
  · rfl
  · cases lookupE s.epochs e with
    | none => rfl
    | some r => simp only [Option.map_some]; split <;> rfl

theorem inv_activate {s : St} (hI : Inv s) (hA : s.ho.phase = .ARMED) : Inv (activateEff s) := by
  obtain ⟨ng, hsrc⟩ := hI.open_src (Or.inr hA)
  obtain ⟨htg, _⟩ := hI.open_tgt (Or.inr (Or.inr hA))
  have hc : (activateEff s).cur = s.cur + 1 := by simp [activateEff, htg]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, hI.batch, ?_, ?_⟩
  · rw [act_status, hc, htg]; simp
  · intro e h; rw [act_status] at h; rw [hc]
    split at h
    · omega
    · split at h
      · cases hs : statusOf s e <;> simp_all
      · have := hI.current_uniq e h; omega
  · intro e h; rw [act_status] at h; rw [hc]
    split at h
    · simp at h
    · split at h
      · omega
      · exact absurd h (ng e)
  · simp [activateEff]
  · simp [activateEff]
  · simp [activateEff]
  · simp [activateEff]
  · intro sh hm
    simp only [activateEff, List.mem_append] at hm
    rw [act_roster, hc]
    rcases hm with hm | hm
    · obtain ⟨h1, h2⟩ := hI.holders sh hm
      have : ¬ s.ho.rot.target = sh.epoch := by omega
      simp only [this, ↓reduceIte]; exact ⟨h1, by omega⟩
    · simp only [carried, List.mem_map] at hm
      obtain ⟨sh0, _, rfl⟩ := hm
      simp [install, htg]

theorem sweep_hf (e : Nat) : ∀ r : EpochRec, (if r.id = e then { r with swept := true } else r).id = r.id := by
  intro r; split <;> rfl

theorem sweep_status (s : St) (e x : Nat) : statusOf (sweepEff s e) x = statusOf s x := by
  simp only [statusOf, sweepEff, lookupE_map _ (sweep_hf e)]
  cases lookupE s.epochs x with
  | none => rfl
  | some r => simp only [Option.map_some]; split <;> rfl

theorem sweep_roster (s : St) (e x : Nat) : rosterOf (sweepEff s e) x = rosterOf s x := by
  simp only [rosterOf, sweepEff, lookupE_map _ (sweep_hf e)]
  cases lookupE s.epochs x with
  | none => rfl
  | some r => simp only [Option.map_some]; split <;> rfl

theorem inv_sweep {s : St} (hI : Inv s) {e : Nat} (hg : statusOf s e = some .grace) : Inv (sweepEff s e) := by
  have he := hI.grace_prev e hg
  refine ⟨?_, ?_, ?_, ?_, ?_, hI.hist, hI.batch, hI.armed_pos, ?_⟩
  · rw [sweep_status]; exact hI.cur_current
  · intro x h; rw [sweep_status] at h; exact hI.current_uniq x h
  · intro x h; rw [sweep_status] at h; exact hI.grace_prev x h
  · intro hp; obtain ⟨n1, n2⟩ := hI.open_src hp
    exact ⟨fun x => by rw [sweep_status]; exact n1 x, n2⟩
  · exact hI.open_tgt
  · intro sh hm
    simp only [sweepEff, List.mem_append] at hm
    rw [sweep_roster]
    rcases hm with hm | hm
    · exact hI.holders sh hm
    · simp only [List.mem_map] at hm
      obtain ⟨sh0, _, rfl⟩ := hm
      exact ⟨by simp [install], by simp [install, sweepEff]; omega⟩

theorem inv_use {s : St} (hI : Inv s) (rid a i tk : Nat) : Inv (useEff s rid a i tk) := by
  unfold useEff; split
  · exact hI
  · refine ⟨hI.cur_current, hI.current_uniq, hI.grace_prev, hI.open_src, hI.open_tgt, hI.hist, hI.batch,
      hI.armed_pos, ?_⟩
    intro sh hm
    simp only [List.mem_map] at hm
    obtain ⟨sh0, h0, rfl⟩ := hm
    have := hI.holders sh0 h0
    split <;> simpa [rosterOf] using this

theorem inv_effect {s : St} (hI : Inv s) (a : Act) (h : actRefusals s a = []) : Inv (effect s a) := by
  cases a with
  | rotate r =>
    simp only [actRefusals, rotateRefusals, List.append_eq_nil_iff, opt_nil, Classical.not_not] at h
    obtain ⟨⟨⟨⟨⟨htg, hpar⟩, hso⟩, -⟩, -⟩, -⟩ := h
    have hpk := hpar.1
    unfold paramsOk at hpk
    simp only [effect]
    refine ⟨hI.cur_current, hI.current_uniq, hI.grace_prev, ?_, ?_, hI.hist, by simp, ?_, hI.holders⟩
    · intro hp
      simp only at hp ⊢
      split at hp
      · rename_i hpre; exact pre_src hI hpre.2.1 hso
      · simp at hp
    · intro _; show r.target = s.cur + 1 ∧ 1 ≤ r.n - r.f; exact ⟨htg, by omega⟩
    · intro hp; simp only at hp; split at hp <;> simp at hp
  | eks => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | carry d ok => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) (Nat.le_refl _) (fun _ => ⟨rfl, rfl⟩)
  | complaint d => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | ready seat q hs => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | arm sigs =>
    simp only [actRefusals, opt_nil, Classical.not_not] at h
    have hR : s.ho.phase = .ROTATING := h.1.1
    obtain ⟨ng, hsrc⟩ := hI.open_src (Or.inl hR)
    exact ⟨hI.cur_current, hI.current_uniq, hI.grace_prev, fun _ => ⟨ng, hsrc⟩,
      fun _ => hI.open_tgt (Or.inr (Or.inl hR)), hI.hist, hI.batch, fun _ => rfl, hI.holders⟩
  | activate gov sigs hb boots disj =>
    simp only [actRefusals, List.append_eq_nil_iff, opt_nil] at h
    obtain ⟨⟨⟨hl, -⟩, hn⟩, -⟩ := h
    have hA : s.ho.phase = .ARMED := Classical.byContradiction (fun hne => hn ⟨hl, hne⟩)
    exact inv_activate hI hA
  | midnightTick m =>
    simp only [actRefusals, opt_nil, Nat.not_lt] at h
    have h1 : Inv { s with mh := m } :=
      inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) (Nat.le_trans hI.batch h) (fun _ => ⟨rfl, rfl⟩)
    simp only [effect]
    split
    · exact inv_frame h1 rfl rfl rfl rfl (fun hp => by simp [abortHo] at hp)
        (by simp [abortHo]; exact h1.batch) (fun hp => by simp [abortHo] at hp)
    · exact inv_release (inv_close h1)
  | block =>
    simp only [actRefusals, opt_nil] at h
    exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun hp => absurd hp h)
  | restartBegin => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | restartEnd => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | admitBoot seat w =>
    simp only [effect]; split
    · exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
    · exact hI
  | order rid bind slots =>
    exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | endReq rid => exact inv_frame hI rfl rfl rfl rfl (fun _ => ⟨rfl, rfl⟩) hI.batch (fun _ => ⟨rfl, rfl⟩)
  | useSlot rid a i tk => exact inv_use hI rid a i tk
  | sweepReady e =>
    simp only [actRefusals, opt_nil, Classical.not_not] at h
    exact inv_sweep hI h.1
  | entry _ _ => exact hI
  | header _ _ => exact hI
  | envelope _ => exact hI
  | signCheckpoint _ _ => exact hI
  | submitCheckpoint _ _ => exact hI
  | cert _ => exact hI
  | userAck _ => exact hI

theorem inv_next {s : St} (hI : Inv s) (op : Op) : Inv (next s op) := by
  unfold next; split
  · rename_i h; exact inv_effect hI op.act (refusals_nil h).2
  · exact hI

theorem inv_run {s : St} (hI : Inv s) (ops : List Op) : Inv (run s ops) := by
  induction ops generalizing s with
  | nil => exact hI
  | cons op ops ih => rw [run_cons]; exact ih (inv_next hI op)

/-- A state reachable from a genesis by a run. -/
def Reach (s : St) : Prop := ∃ p g ops, s = run (init p g) ops

theorem reach_inv {s : St} (h : Reach s) : Inv s := by
  obtain ⟨p, g, ops, rfl⟩ := h; exact inv_run (inv_init p g) ops

theorem reach_run {s : St} (h : Reach s) (ops : List Op) : Reach (run s ops) := by
  obtain ⟨p, g, ops0, rfl⟩ := h
  exact ⟨p, g, ops0 ++ ops, by rw [run_append]⟩

end SplitHandoff

namespace SplitHandoff

/-! ## HO-055: two live epochs -/

/-- HO-055, HO-010: every live epoch (current or in grace) is the current epoch or the one
before it, so at most two epochs are live at every height; and while a handoff is ROTATING
or ARMED no epoch is in grace (scenario: epoch 4 current, epoch 3 in grace, no ROTATE for
epoch 5 is ROTATING). -/
theorem ho055_two_epochs (s : St) (hr : Reach s) :
    (∀ e, live s e → e = s.cur ∨ e + 1 = s.cur)
      ∧ ((s.ho.phase = .ROTATING ∨ s.ho.phase = .ARMED) → ∀ e, ¬ statusOf s e = some .grace) := by
  have hI := reach_inv hr
  refine ⟨fun e h => ?_, fun hp => (hI.open_src hp).1⟩
  rcases h with h | h
  · exact Or.inl (hI.current_uniq e h)
  · exact Or.inr (hI.grace_prev e h)

/-! ## HO-018, HO-055: the adversary's view per committee -/

/-- HO-018, HO-055 (DESIGN §8 and HANDOFF.md 7.4): under the dual threshold of each committee
(the corrupt and exposed seats `adv e` of the roster of epoch `e` number at most `t_e − 1`),
the adversary holds at most `t − 1` shares of every sharing, in each committee, because
every sharing lies inside the roster of its epoch. The hiding of each dealing (O5) is an
exception. -/
theorem ho_exposure_bound (s : St) (hr : Reach s) (adv : Nat → List Nat)
    (hdual : ∀ e, ((rosterOf s e).filter (fun x => decide (x ∈ adv e))).length ≤ tOf s e - 1) :
    ∀ sh ∈ s.sharings, (sh.holders.filter (fun x => decide (x ∈ adv sh.epoch))).length ≤ tOf s sh.epoch - 1 := by
  intro sh hm
  rw [((reach_inv hr).holders sh hm).1]
  exact hdual sh.epoch

/-! ## HO-063: signable addresses -/

theorem signable_mono {s t : St} {a : Addr} (hx : t.xf = s.xf) (hu : t.users = s.users)
    (hsh : ∀ sh ∈ s.sharings, sh.epoch = s.cur →
      ∃ sh' ∈ t.sharings, sh'.secret = sh.secret ∧ sh'.epoch = t.cur ∧ sh'.const = sh.const)
    (hb : ∀ k, boardSlot t k = .free → boardSlot s k = .free) (h : signable s a) : signable t a := by
  obtain ⟨⟨sh, hm, h1, h2, h3⟩, hs, hslots⟩ := h
  refine ⟨?_, by simp [shardOf, hu] at hs ⊢; exact hs, ?_⟩
  · obtain ⟨sh', hm', e1, e2, e3⟩ := hsh sh hm h2
    exact ⟨sh', hm', by rw [e1, h1], e2, by rw [e3, h3, hx]⟩
  · intro he i hi hf
    obtain ⟨sh, hm, h1, h2⟩ := hslots he i hi (hb _ hf)
    obtain ⟨sh', hm', e1, e2, _⟩ := hsh sh hm h2
    exact ⟨sh', hm', by rw [e1, h1], e2⟩

theorem signable_same {s t : St} {a : Addr} (hx : t.xf = s.xf) (hu : t.users = s.users) (hc : t.cur = s.cur)
    (hsub : ∀ sh ∈ s.sharings, sh.epoch = s.cur → sh ∈ t.sharings) (hb : t.board = s.board)
    (h : signable s a) : signable t a :=
  signable_mono hx hu (fun sh hm he => ⟨sh, hsub sh hm he, rfl, by rw [hc, he], rfl⟩)
    (fun k hk => by simpa [boardSlot, hb] using hk) h

theorem boardSlot_cons {s t : St} {k0 : Nat × Nat} {st : SlotSt} (hb : t.board = (k0, st) :: s.board)
    (k : Nat × Nat) : boardSlot t k = if k0 = k then st else boardSlot s k := by
  simp only [boardSlot, hb, List.find?_cons]
  by_cases h : k0 = k
  · simp [h]
  · have hb : (k0 == k) = false := by simp [h]
    simp [hb, h]

theorem signable_effect {s : St} (hI : Inv s) (a : Act) (ad : Addr) (h : actRefusals s a = [])
    (hs : signable s ad) : signable (effect s a) ad := by
  have hf := effect_frame s a
  cases a with
  | activate gov sigs hb boots disj =>
    simp only [actRefusals, List.append_eq_nil_iff, opt_nil] at h
    obtain ⟨⟨⟨hl, -⟩, hn⟩, -⟩ := h
    have hA : s.ho.phase = .ARMED := Classical.byContradiction (fun hne => hn ⟨hl, hne⟩)
    obtain ⟨_, hsrc⟩ := hI.open_src (Or.inr hA)
    show signable (activateEff s) ad
    obtain ⟨⟨sh, hm, h1, h2, h3⟩, hsd, hslots⟩ := hs
    have hcar : ∀ sh ∈ s.sharings, sh.epoch = s.cur → standing s sh = true →
        install s s.ho.rot.target s.ho.rot.roster sh ∈ (activateEff s).sharings := by
      intro sh hm he hst
      simp only [activateEff, carried, List.mem_append, List.mem_map, List.mem_filter]
      exact Or.inr ⟨sh, ⟨hm, by simp [he, hsrc, hst]⟩, rfl⟩
    refine ⟨⟨_, hcar sh hm h2 (by simp [standing, h1]), by simp [install, h1],
      by simp [install, activateEff], by simp [install, h3, activateEff]⟩, by simpa [shardOf, activateEff] using hsd, ?_⟩
    intro he i hi hfree
    obtain ⟨sh, hm, e1, e2⟩ := hslots he i hi (by simpa [boardSlot, activateEff] using hfree)
    refine ⟨_, hcar sh hm e2 ?_, by simp [install, e1], by simp [install, activateEff]⟩
    simp only [standing, e1]
    simpa [boardSlot, activateEff] using hfree
  | midnightTick m =>
    simp only [effect]
    split
    · exact signable_same (s := s) rfl rfl rfl (fun _ h _ => h) rfl hs
    · have h1 : signable (closeGraces { s with mh := m }) ad := by
        refine signable_same (s := s) (t := closeGraces { s with mh := m }) rfl rfl rfl
          (fun sh hm he => ?_) rfl hs
        simp only [closeGraces, List.mem_filter]
        refine ⟨hm, ?_⟩
        have hc := hI.cur_current
        simp only [statusOf] at hc
        simp only [closingE, he]
        cases hl : lookupE s.epochs s.cur with
        | none => simp [hl] at hc
        | some r => simp [hl] at hc; simp [hc]
      unfold release; split
      · exact signable_same (s := closeGraces { s with mh := m }) rfl rfl rfl (fun _ h _ => h) rfl h1
      · exact h1
  | useSlot rid a i tk =>
    simp only [effect, useEff]
    split
    · exact hs
    · refine signable_mono (s := s) rfl rfl (fun sh hm he => ?_) (fun k hk => ?_) hs
      · refine ⟨_, List.mem_map_of_mem hm, ?_, ?_, ?_⟩ <;> split <;> simp [he]
      · rw [boardSlot_cons (s := s) rfl] at hk
        split at hk
        · simp at hk
        · exact hk
  | sweepReady e =>
    exact signable_same (s := s) rfl rfl rfl (fun sh hm _ => by simp [effect, sweepEff, hm]) rfl hs
  | admitBoot seat w =>
    simp only [effect]; split
    · exact signable_same (s := s) rfl rfl rfl (fun _ h _ => h) rfl hs
    · exact hs
  | _ => exact signable_same (s := s) rfl rfl rfl (fun _ h _ => h) rfl hs

/-- HO-063: every operation keeps every signable address signable: the current epoch keeps a
sharing of `x_f` with constant term `X_f`, the user shard is unchanged, and every unused ECDSA
slot of the address stays held by the current epoch. At the activation the current epoch is
the target, which holds the carried sharings. -/
theorem ho063_signable_preserved (s : St) (hI : Inv s) (op : Op) (a : Addr) (h : signable s a) :
    signable (next s op) a := by
  unfold next; split
  · rename_i hr; exact signable_effect hI op.act a (refusals_nil hr).2 h
  · exact h

/-- HO-063 over a run, so over a completed handoff from its ROTATE to its activation. -/
theorem ho063_run_signable (s : St) (hI : Inv s) (ops : List Op) (a : Addr) (h : signable s a) :
    signable (run s ops) a := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => rw [run_cons]; exact ih _ (inv_next hI op) (ho063_signable_preserved s hI op a h)

end SplitHandoff

namespace SplitHandoff

theorem refusals_op (s : St) (a : Act) : refusals s a.op = actRefusals s a := by
  simp [refusals, Act.op]

theorem next_op (s : St) (a : Act) (h : actRefusals s a = []) : next s a.op = effect s a := by
  simp only [next, refusals_op, h, ↓reduceIte]; rfl

/-! ## HO-032, HO-064, HO-066, HO-067: authority -/

theorem act_validator (s : St) (p : Nat) :
    validatorAt (activateEff s) p = if s.ho.H < p then s.ho.rot.target else validatorAt s p := by
  simp only [validatorAt, activateEff, List.find?_cons]
  by_cases h : s.ho.H < p <;> simp [h]

/-- From ARMED, only the activation record reaches HANDED_OVER. -/
theorem armed_handed (s : St) (op : Op) (hA : s.ho.phase = .ARMED) (hH : (next s op).ho.phase = .HANDED_OVER) :
    refusals s op = [] ∧ next s op = activateEff s := by
  unfold next at hH ⊢
  split at hH
  · rename_i hacc
    refine ⟨hacc, ?_⟩
    simp only [hacc, ↓reduceIte]
    obtain ⟨_, hr⟩ := refusals_nil hacc
    cases hc : op.act with
    | activate => rfl
    | midnightTick m =>
      exfalso; rw [hc] at hH; simp only [effect] at hH
      split at hH
      · simp [abortHo] at hH
      · have hq : (closeGraces { s with mh := m }).ho.phase = .ARMED :=
          (close_phase_ne _ (by show s.ho.phase ≠ .QUEUED; rw [hA]; simp)).trans hA
        rw [release_ho_phase _ (by rw [hq]; simp), hq] at hH; simp at hH
    | rotate r =>
      exfalso; rw [hc] at hr
      simp [actRefusals, rotateRefusals, opt_nil, rotationOpenP, hA] at hr
    | arm sg =>
      exfalso; rw [hc] at hr
      simp [actRefusals, opt_nil, armReady, hA] at hr
    | admitBoot seat w =>
      exfalso; rw [hc] at hH; simp only [effect] at hH; split at hH <;> simp_all
    | useSlot rid a i tk =>
      exfalso; rw [hc] at hH; simp only [effect, useEff] at hH; split at hH <;> simp_all
    | _ => exfalso; rw [hc] at hH; simp_all [effect, sweepEff]
  · simp_all

/-- HO-032, HO-064, HO-066: while ARMED the board is at position `H` and makes no block; when the
activation record is final the validator epoch is unchanged at every position up to `H`, is the
target above `H`, and between the previous activation and `H` it is the source epoch. So every
position has exactly one validator epoch, with no gap and no double authority. -/
theorem ho032_authority_switch (s : St) (hr : Reach s) (op : Op) (hA : s.ho.phase = .ARMED) :
    s.pos = s.ho.H ∧ refusals s Act.block.op ≠ []
      ∧ (∀ p, (∀ x ∈ s.handovers.head?, x.1 < p) → p ≤ s.ho.H → validatorAt s p = s.ho.rot.source)
      ∧ ((next s op).ho.phase = .HANDED_OVER →
          (∀ p, p ≤ s.ho.H → validatorAt (next s op) p = validatorAt s p)
          ∧ (∀ p, s.ho.H < p → validatorAt (next s op) p = s.ho.rot.target)) := by
  have hI := reach_inv hr
  refine ⟨hI.armed_pos hA, by simp [refusals_op, actRefusals, opt, hA], ?_, ?_⟩
  · intro p hp _
    rw [(hI.open_src (Or.inr hA)).2, ← hI.hist]
    simp only [validatorAt]
    cases hh : s.handovers with
    | nil => simp
    | cons x xs =>
      rw [hh] at hp
      have : x.1 < p := hp x (by simp)
      simp [this]
  · intro hH
    rw [(armed_handed s op hA hH).2]
    refine ⟨fun p hp => ?_, fun p hp => ?_⟩
    · rw [act_validator]; simp [Nat.not_lt.mpr hp]
    · rw [act_validator]; simp [hp]

/-- HO-067: from ARMED, the transition to HANDED_OVER is the committee contract's acceptance of
the activation record, and with an honest target (a record with `t'` target signatures, a valid
heartbeat, boot tickets and disjoint operators) submitted before `m_D` it is taken with no
operation of a source seat. -/
theorem ho_no_source_after_arm (s : St) (hA : s.ho.phase = .ARMED) (hm : s.mh ≤ s.ho.mD) :
    (next s (Act.activate true s.ho.rot.t true true true).op).ho.phase = .HANDED_OVER
      ∧ (Act.activate true s.ho.rot.t true true true).actor ≠ .source
      ∧ ∀ op, (next s op).ho.phase = .HANDED_OVER → op.actor = .contract := by
  refine ⟨?_, by simp [Act.actor], fun op hH => ?_⟩
  · rw [next_op]
    · simp [effect, activateEff]
    · simp [actRefusals, opt, lateP, hA, Nat.not_lt.mpr hm]
  · have hacc := (armed_handed s op hA hH).1
    obtain ⟨ha, hr⟩ := refusals_nil hacc
    rw [ha]
    unfold next at hH; simp only [hacc, ↓reduceIte] at hH
    cases hc : op.act with
    | activate => rfl
    | midnightTick m =>
      exfalso; rw [hc] at hH; simp only [effect] at hH
      split at hH
      · simp [abortHo] at hH
      · have hq : (closeGraces { s with mh := m }).ho.phase = .ARMED :=
          (close_phase_ne _ (by show s.ho.phase ≠ .QUEUED; rw [hA]; simp)).trans hA
        rw [release_ho_phase _ (by rw [hq]; simp), hq] at hH; simp at hH
    | rotate r =>
      exfalso; rw [hc] at hr
      simp [actRefusals, rotateRefusals, opt_nil, rotationOpenP, hA] at hr
    | arm sg =>
      exfalso; rw [hc] at hr
      simp [actRefusals, opt_nil, armReady, hA] at hr
    | admitBoot seat w =>
      exfalso; rw [hc] at hH; simp only [effect] at hH; split at hH <;> simp_all
    | useSlot rid a i tk =>
      exfalso; rw [hc] at hH; simp only [effect, useEff] at hH; split at hH <;> simp_all
    | _ => exfalso; rw [hc] at hH; simp_all [effect, sweepEff]

/-! ## HO-010 to HO-012: a ROTATE starts from every reachable state -/

def maxGE : List EpochRec → Nat
  | [] => 0
  | r :: rs => max r.graceEnd (maxGE rs)

theorem le_maxGE {l : List EpochRec} {r : EpochRec} (h : r ∈ l) : r.graceEnd ≤ maxGE l := by
  induction l with
  | nil => simp at h
  | cons x xs ih =>
    simp only [List.mem_cons] at h
    simp only [maxGE]
    rcases h with rfl | h
    · omega
    · have := ih h; omega

theorem close_no_grace (s : St) (h : ∀ r ∈ s.epochs, r.graceEnd ≤ s.mh) (e : Nat) :
    statusOf (closeGraces s) e ≠ some .grace := by
  rw [close_status]
  cases hl : lookupE s.epochs e with
  | none => simp
  | some r =>
    have := h r (lookupE_mem hl)
    simp only [Option.map_some, ne_eq, Option.some.injEq]
    unfold closeRec; split
    · simp
    · rename_i hn; intro hg; exact hn ⟨hg, this⟩

/-- A QUEUED ROTATE whose source is current, with no restart open, is ROTATING after a Midnight
height at or above every grace end. -/
theorem tick_release (t : St) (m : Nat) (hm : t.mh ≤ m) (hQ : t.ho.phase = .QUEUED) (hres : t.restart = false)
    (hcur : statusOf t t.cur = some .current) (hsrc : t.ho.rot.source = t.cur)
    (hg : ∀ r ∈ t.epochs, r.graceEnd ≤ m) :
    (next t (Act.midnightTick m).op).ho.phase = .ROTATING ∧ (next t (Act.midnightTick m).op).ho.rot = t.ho.rot := by
  rw [next_op _ _ (by simp [actRefusals, opt, Nat.not_lt.mpr hm])]
  simp only [effect, hQ]
  simp only [reduceCtorEq, or_self, false_and, ↓reduceIte]
  have hclose : (closeGraces { t with mh := m }).ho = t.ho := by
    have : closingE { t with mh := m } t.ho.rot.source = false := by
      simp only [statusOf] at hcur
      simp only [closingE, hsrc]
      cases hl : lookupE t.epochs t.cur with
      | none => simp [hl] at hcur
      | some r => simp [hl] at hcur; simp [hcur]
    simp [closeGraces, this]
  have hpre : (closeGraces { t with mh := m }).ho.phase = .QUEUED
      ∧ pre (closeGraces { t with mh := m }) (closeGraces { t with mh := m }).ho.rot := by
    rw [hclose]
    refine ⟨hQ, by simp [hclose, hQ], ?_, hres, ?_⟩
    · exact close_no_grace { t with mh := m } hg _
    · left; rw [hsrc]; exact (close_current _ _).mpr hcur
  unfold release
  simp only [hpre, and_self, ↓reduceIte]
  simp [hclose]

/-- HO-010, HO-011, HO-012 (DECISIONS 79): from every reachable state, a valid ROTATE whose source
is the current epoch is ROTATING or QUEUED, never refused; a QUEUED one is ROTATING after the end
of an open restart and one Midnight height at or above every grace end, operations of a seat and
of time only. (A ROTATE whose source is in grace never meets HO-010, ledger 9.) -/
theorem ho_start_from_any (s : St) (hr : Reach s) (r : Rotate) (hv : actRefusals s (.rotate r) = [])
    (hsrc : r.source = s.cur) :
    ((next s (Act.rotate r).op).ho.phase = .ROTATING ∨ (next s (Act.rotate r).op).ho.phase = .QUEUED)
      ∧ ∃ post : List Op, (∀ op ∈ post, op.actor = .seat ∨ op.actor = .time)
        ∧ (run (next s (Act.rotate r).op) post).ho.phase = .ROTATING
        ∧ (run (next s (Act.rotate r).op) post).ho.rot = r := by
  have hI := reach_inv hr
  rw [next_op _ _ hv]
  by_cases hp : pre s r
  · have hph : (effect s (.rotate r)).ho.phase = .ROTATING := by simp [effect, hp]
    exact ⟨Or.inl hph, [], by simp, hph, by simp [run, effect]⟩
  · have hph : (effect s (.rotate r)).ho.phase = .QUEUED := by simp [effect, hp]
    refine ⟨Or.inr hph, [Act.restartEnd.op, (Act.midnightTick (max s.mh (maxGE s.epochs))).op],
      by simp [Act.op, Act.actor], ?_⟩
    let s1 := effect s (.rotate r)
    let s2 := next s1 Act.restartEnd.op
    have h2 : s2.ho = s1.ho ∧ s2.restart = false ∧ s2.epochs = s.epochs ∧ s2.cur = s.cur ∧ s2.mh = s.mh := by
      by_cases hres : s1.restart = true
      · rw [show s2 = next s1 Act.restartEnd.op from rfl, next_op _ _ (by simp [actRefusals, opt, hres])]
        simp [effect, s1]
      · have hres' : s1.restart = false := by simpa using hres
        have hn : refusals s1 Act.restartEnd.op ≠ [] := by simp [refusals_op, actRefusals, opt, hres']
        simp only [s2, next, hn, ↓reduceIte]
        exact ⟨by simp, hres', by simp [s1, effect], by simp [s1, effect], by simp [s1, effect]⟩
    have hrun : run s1 [Act.restartEnd.op, (Act.midnightTick (max s.mh (maxGE s.epochs))).op]
        = next s2 (Act.midnightTick (max s.mh (maxGE s.epochs))).op := rfl
    rw [hrun]
    obtain ⟨hho, hres, hep, hcu, hmh⟩ := h2
    have := tick_release s2 (max s.mh (maxGE s.epochs)) (by rw [hmh]; omega) (by rw [hho]; exact hph) hres
      (by simp only [statusOf, hep, hcu]; exact hI.cur_current)
      (by rw [hho, hcu]; simpa [s1, effect] using hsrc)
      (by intro x hx; rw [hep] at hx; have := le_maxGE hx; omega)
    refine ⟨this.1, ?_⟩
    rw [this.2, hho]; simp [s1, effect]

end SplitHandoff

namespace SplitHandoff

/-! ## HO-018 to HO-031, HO-064, HO-047: an honest handoff completes -/

theorem carries_run (D : List Nat) : ∀ (s : St), s.ho.phase = .ROTATING → s.ho.eks = true →
    (∀ d ∈ D, d ∈ s.ho.srcRoster) → D.Nodup → (∀ d ∈ D, d ∉ s.ho.dealt.map Prod.fst) →
    run s (D.map (fun d => (Act.carry d true).op))
      = { s with ho := { s.ho with dealt := s.ho.dealt ++ D.map (fun d => (d, s.mh)),
                                   lastBatch := if D = [] then s.ho.lastBatch else s.mh } } := by
  induction D with
  | nil => intro s _ _ _ _ _; simp [run]
  | cons d D ih =>
    intro s hR he hs hn hf
    rw [List.map_cons, run_cons, next_op]
    · simp only [List.nodup_cons] at hn
      rw [ih]
      · simp [effect]
      · exact hR
      · exact he
      · intro x hx; exact hs x (by simp [hx])
      · exact hn.2
      · intro x hx
        simp only [effect, List.map_append, List.mem_append, List.map_cons, List.map_nil, List.mem_singleton,
          not_or]
        exact ⟨hf x (by simp [hx]), fun h => hn.1 (h ▸ hx)⟩
    · simp [actRefusals, opt, hR, he, hs d (by simp), hf d (by simp)]

theorem readies_run (R : List Nat) (q : List Nat) (hs : Nat) : ∀ (s : St), s.ho.phase = .ROTATING →
    (∀ x ∈ R, x ∈ s.ho.rot.roster) → R.Nodup → (∀ x ∈ R, ∀ y ∈ s.ho.readys, y.1 ≠ x) →
    run s (R.map (fun x => (Act.ready x q hs).op))
      = { s with ho := { s.ho with readys := s.ho.readys ++ R.map (fun x => (x, q, hs)) } } := by
  induction R with
  | nil => intro s _ _ _ _; simp [run]
  | cons x R ih =>
    intro s hR hro hn hf
    rw [List.map_cons, run_cons, next_op]
    · simp only [List.nodup_cons] at hn
      rw [ih]
      · simp [effect]
      · exact hR
      · intro y hy; exact hro y (by simp [hy])
      · exact hn.2
      · intro y hy z hz
        simp only [effect, List.mem_append, List.mem_singleton] at hz
        rcases hz with hz | rfl
        · exact hf y (by simp [hy]) z hz
        · intro h; simp only at h; subst h; exact hn.1 hy
    · have : (x, q, hs) ∉ s.ho.readys := fun h => hf x (by simp) _ h rfl
      simp [actRefusals, opt, hR, hro x (by simp), this]

theorem tick_rotating (s : St) (m : Nat) (hm : s.mh ≤ m) (hR : s.ho.phase = .ROTATING) (hD : m ≤ s.ho.mD) :
    (next s (Act.midnightTick m).op).ho = s.ho ∧ (next s (Act.midnightTick m).op).mh = m
      ∧ (next s (Act.midnightTick m).op).restart = s.restart
      ∧ (next s (Act.midnightTick m).op).params = s.params ∧ (next s (Act.midnightTick m).op).pos = s.pos := by
  rw [next_op _ _ (by simp [actRefusals, opt, Nat.not_lt.mpr hm])]
  simp only [effect]
  simp only [Nat.not_lt.mpr hD, and_false, ↓reduceIte]
  have hq : (closeGraces { s with mh := m }).ho.phase ≠ .QUEUED := by
    rw [close_phase_ne _ (by show s.ho.phase ≠ .QUEUED; rw [hR]; simp)]; show s.ho.phase ≠ .QUEUED; rw [hR]; simp
  rw [release_ho_phase _ hq]
  have hc : (closeGraces { s with mh := m }).ho = s.ho := by
    simp only [closeGraces]; split
    · rename_i h; exact absurd h.1 (by show s.ho.phase ≠ .QUEUED; rw [hR]; simp)
    · rfl
  exact ⟨hc, rfl, rfl, rfl, rfl⟩

/-- HO-018, HO-019, HO-021, HO-029 to HO-031, HO-064, HO-047, HO-032: from a ROTATING handoff
with no restart open and `EKS_{e+1}` made complete, `t` honest source dealers carry (each with a
correct constant term, none disqualified), Midnight passes the last complaint window
(hypothesis `hsync`: under the complaint-window synchrony of O5 every honest complaint lands
within `Δ_cw`, and the window closes before `m_D`), `n' − f'` honest target seats post READY for
one pair `(Q, h_S)`, the board commits the arm heartbeat of `t'` partials and the activation
record with `t'` target signatures reaches the contract. The handoff is HANDED_OVER at a
Midnight height no later than `m_D`, and no operation of the run is a user's. -/
theorem ho_completes (s : St) (hr : Reach s) (hR : s.ho.phase = .ROTATING) (hrs : s.restart = false)
    (D : List Nat) (hDn : D.Nodup) (hDl : D.length = s.ho.tQ) (hDs : ∀ d ∈ D, d ∈ s.ho.srcRoster)
    (hDf : ∀ d ∈ D, d ∉ s.ho.dealt.map Prod.fst) (hDq : ∀ d ∈ D, d ∉ s.ho.disq)
    (R : List Nat) (hRn : R.Nodup) (hRl : R.length = s.ho.rot.n - s.ho.rot.f) (hRs : ∀ x ∈ R, x ∈ s.ho.rot.roster)
    (hRf : ∀ x ∈ R, ∀ y ∈ s.ho.readys, y.1 ≠ x) (hS : Nat)
    (hsync : s.mh + s.params.deltaCw + 1 ≤ s.ho.mD) :
    let pre1 := Act.eks.op :: D.map (fun d => (Act.carry d true).op)
    let q := qualified (run s pre1)
    let ops := pre1 ++ ((Act.midnightTick (s.mh + s.params.deltaCw + 1)).op :: R.map (fun x => (Act.ready x q hS).op)
      ++ [(Act.arm s.ho.rot.t).op, (Act.activate true s.ho.rot.t true true true).op])
    (∀ op ∈ ops, op.actor ≠ .user) ∧ (run s ops).ho.phase = .HANDED_OVER ∧ (run s ops).mh ≤ s.ho.mD := by
  intro pre1 q ops
  have hI := reach_inv hr
  have hneed : 1 ≤ s.ho.rot.n - s.ho.rot.f := (hI.open_tgt (Or.inr (Or.inl hR))).2
  refine ⟨?_, ?_⟩
  · intro op hop
    simp only [ops, pre1, List.mem_append, List.mem_cons, List.mem_map] at hop
    rcases hop with (rfl | ⟨d, _, rfl⟩) | (rfl | ⟨x, _, rfl⟩) | rfl | rfl | h
    all_goals first | (simp at h) | simp [Act.op, Act.actor]
  -- the eks step and the carries
  let s0 := next s Act.eks.op
  have h0 : s0 = { s with ho := { s.ho with eks := true } } := by
    simp only [s0]; rw [next_op _ _ (by simp [actRefusals, opt, hR])]; rfl
  let s1 := run s pre1
  have h1 : s1 = { s0 with ho := { s0.ho with
                    dealt := s0.ho.dealt ++ D.map (fun d => (d, s0.mh)),
                    lastBatch := if D = [] then s0.ho.lastBatch else s0.mh } } := by
    simp only [s1, pre1, run_cons]
    exact carries_run D s0 (by rw [h0]; exact hR) (by rw [h0]) (by rw [h0]; exact hDs) hDn (by rw [h0]; exact hDf)
  have hq1 : (qualified s1).length = s.ho.tQ := by
    have hfil : (D.filter (fun d => decide (d ∉ s.ho.disq))) = D := List.filter_eq_self.mpr (by simpa using hDq)
    have hm : List.map (Prod.fst ∘ fun (d : Nat) => (d, s.mh)) D = D := by
      rw [show (Prod.fst ∘ fun (d : Nat) => (d, s.mh)) = id from rfl, List.map_id]
    have hf2 : (List.filter (fun d => !decide (d ∈ s.ho.disq)) D).length = D.length := by
      rw [List.filter_eq_self.mpr (by simpa using hDq)]
    simp [qualified, h1, h0, List.filter_append, List.length_take, hm, hf2]
    omega
  have hb1 : s1.ho.lastBatch ≤ s.mh := by
    rw [h1, h0]; simp only; split
    · exact hI.batch
    · exact Nat.le_refl _
  -- the Midnight tick past the last complaint window
  let m := s.mh + s.params.deltaCw + 1
  let s2 := next s1 (Act.midnightTick m).op
  have h1R : s1.ho.phase = .ROTATING := by rw [h1, h0]; exact hR
  have h1m : s1.mh = s.mh := by rw [h1, h0]
  have h1D : s1.ho.mD = s.ho.mD := by rw [h1, h0]
  obtain ⟨h2ho, h2m, h2r, h2p, _⟩ := tick_rotating s1 m (by rw [h1m]; omega) h1R (by rw [h1D]; exact hsync)
  replace h2ho : s2.ho = s1.ho := h2ho
  replace h2m : s2.mh = m := h2m
  replace h2r : s2.restart = s1.restart := h2r
  replace h2p : s2.params = s1.params := h2p
  -- the READY posts
  let s3 := run s2 (R.map (fun x => (Act.ready x q hS).op))
  have h3 : s3 = { s2 with ho := { s2.ho with readys := s2.ho.readys ++ R.map (fun x => (x, q, hS)) } } :=
    readies_run R q hS s2 (by rw [h2ho]; exact h1R)
      (by rw [h2ho, h1, h0]; exact hRs) hRn (by rw [h2ho, h1, h0]; exact hRf)
  have hq3 : qualified s3 = q := by
    show qualified s3 = qualified s1
    simp only [qualified, h3, h2ho]
  -- the arm heartbeat
  have harm : armReady s3 := by
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [h3]; simp only; rw [h2ho]; exact h1R
    · rw [hq3]; show (qualified s1).length = s3.ho.tQ
      rw [hq1, h3]; simp only; rw [h2ho, h1, h0]
    · rw [h3]; simp only; rw [h2ho, h2p, h2m, h1]; simp only; rw [h0]; simp only
      have := hb1; rw [h1, h0] at this; simp only at this; omega
    · rw [h3]; simp only; rw [h2r, h1, h0]; exact hrs
    · cases R with
      | nil => simp at hRl; omega
      | cons x R' =>
        refine ⟨(x, q, hS), by rw [h3]; simp, by rw [hq3], ?_⟩
        simp only [need, readyCount, h3, h2ho, h1, h0, List.filter_append, List.length_append]
        have : (List.map (fun x => (x, q, hS)) (x :: R')).filter (fun y => decide (y.2 = (q, hS)))
            = List.map (fun x => (x, q, hS)) (x :: R') := List.filter_eq_self.mpr (by simp)
        rw [this, List.length_map, ← hRl]; omega
  let s4 := next s3 (Act.arm s.ho.rot.t).op
  have h3rot : s3.ho.rot = s.ho.rot := by rw [h3]; simp only; rw [h2ho, h1, h0]
  have h4 : s4 = { s3 with ho := { s3.ho with phase := .ARMED, H := s3.pos } } := by
    simp only [s4]; rw [next_op _ _ (by simp [actRefusals, opt, harm, h3rot])]; rfl
  -- the activation record
  have h3m : s3.mh = m := by rw [h3]; exact h2m
  have h3D : s3.ho.mD = s.ho.mD := by rw [h3]; simp only; rw [h2ho, h1D]
  have hacc : actRefusals s4 (Act.activate true s.ho.rot.t true true true) = [] := by
    have hl : ¬ lateP s4 := by
      intro hl; have := hl.2; rw [h4] at this; simp only at this; rw [h3D, h3m] at this; omega
    have hp4 : s4.ho.phase = .ARMED := by rw [h4]
    have hr4 : s4.ho.rot = s.ho.rot := by rw [h4]; exact h3rot
    simp [actRefusals, opt, hl, hp4, hr4]
  have hrun : run s ops = activateEff s4 := by
    simp only [ops, run_append, List.cons_append, run_cons]
    show run (next s4 (Act.activate true s.ho.rot.t true true true).op) [] = activateEff s4
    rw [next_op _ _ hacc]; rfl
  rw [hrun]
  refine ⟨by simp [activateEff], ?_⟩
  show s4.mh ≤ s.ho.mD
  rw [h4]; simp only; rw [h3m]; exact hsync

end SplitHandoff

namespace SplitHandoff

/-! ## HO-066: an armed abort leaves the source as validator -/

theorem effect_hp (s : St) (a : Act) (hA : ∀ g sg hb bt dj, a ≠ .activate g sg hb bt dj) :
    (effect s a).handovers = s.handovers ∧ s.pos ≤ (effect s a).pos := by
  cases a with
  | activate g sg hb bt dj => exact absurd rfl (hA g sg hb bt dj)
  | midnightTick m =>
    simp only [effect]; split
    · simp
    · unfold release; split <;> simp [closeGraces]
  | useSlot rid a i tk => simp only [effect, useEff]; split <;> simp
  | admitBoot seat w => simp only [effect]; split <;> simp
  | block => simp [effect]
  | _ => simp [effect, sweepEff]

/-- Every handover lies at or below the board position. -/
theorem hp_next {s : St} (hI : Inv s) (hp : ∀ x ∈ s.handovers, x.1 ≤ s.pos) (op : Op) :
    ∀ x ∈ (next s op).handovers, x.1 ≤ (next s op).pos := by
  unfold next; split
  · rename_i hacc
    obtain ⟨_, hr⟩ := refusals_nil hacc
    by_cases hact : ∃ g sg hb bt dj, op.act = .activate g sg hb bt dj
    · obtain ⟨g, sg, hb, bt, dj, hc⟩ := hact
      rw [hc] at hr ⊢
      simp only [actRefusals, List.append_eq_nil_iff, opt_nil] at hr
      obtain ⟨⟨⟨hl, -⟩, hn⟩, -⟩ := hr
      have hAr : s.ho.phase = .ARMED := Classical.byContradiction (fun hne => hn ⟨hl, hne⟩)
      have hH := hI.armed_pos hAr
      intro x hx
      simp only [effect, activateEff, List.mem_cons] at hx ⊢
      rcases hx with rfl | hx
      · exact Nat.le_of_eq hH.symm
      · exact hp x hx
    · obtain ⟨h1, h2⟩ := effect_hp s op.act (fun g sg hb bt dj h => hact ⟨g, sg, hb, bt, dj, h⟩)
      intro x hx; rw [h1] at hx; exact Nat.le_trans (hp x hx) h2
  · exact hp

theorem reach_hp {s : St} (hr : Reach s) : ∀ x ∈ s.handovers, x.1 ≤ s.pos := by
  obtain ⟨p, g, ops, rfl⟩ := hr
  suffices h : ∀ (t : St), Inv t → (∀ x ∈ t.handovers, x.1 ≤ t.pos) →
      ∀ x ∈ (run t ops).handovers, x.1 ≤ (run t ops).pos from
    h _ (inv_init p g) (by simp [init])
  induction ops with
  | nil => intro t _ h; exact h
  | cons op ops ih =>
    intro t hI h
    rw [run_cons]
    exact ih _ (inv_next hI op) (hp_next hI h op)

/-- HO-066, HO-033: when an ARMED handoff becomes ABORTED, the validator epoch is unchanged at
every board position, it is the source epoch at every position above `H` (so from `H + 1`),
and the board makes blocks again. -/
theorem ho066_armed_abort (s : St) (hr : Reach s) (op : Op) (hA : s.ho.phase = .ARMED)
    (hB : (next s op).ho.phase = .ABORTED) :
    (∀ p, validatorAt (next s op) p = validatorAt s p)
      ∧ (∀ p, s.ho.H < p → validatorAt (next s op) p = s.ho.rot.source)
      ∧ refusals (next s op) Act.block.op = [] := by
  have hI := reach_inv hr
  have hk := ho035_abort_keeps_old s op (Or.inr hA) hB
  refine ⟨fun p => by simp only [validatorAt, hk.2.2.2.1], fun p hp => ?_,
    by simp [refusals_op, actRefusals, opt, hB]⟩
  simp only [validatorAt, hk.2.2.2.1]
  rw [(hI.open_src (Or.inr hA)).2, ← hI.hist]
  have hpos := reach_hp hr
  have hH := hI.armed_pos hA
  cases hh : s.handovers with
  | nil => simp
  | cons x xs =>
    have : x.1 < p := by have := hpos x (by simp [hh]); omega
    simp [this]

end SplitHandoff
