import LineDealing.NonceReuse

/-!
# Claim 5: no one-move protocol confines a qualified coalition to one message

SCHEME 6.6 in abstract form. After the owner's single message a coalition holds a joint state
`st`. The honest continuation is a deterministic function of that state and of the chain state:
it returns the state after the step (with whatever the protocol erases removed) and a signature.
A coalition whose joint state finishes the honest protocol is free to copy `st` and run the
continuation on two chain states. Randomness of the continuation is part of `st`.
-/

namespace LineDealing.Impossibility

variable {σ Chain Msg Sig : Type*}

/-- The honest continuation of a one-move protocol: from the coalition's joint state and a chain
state to the state kept after the step and the signature produced. -/
structure Continuation (σ Chain Sig : Type*) where
  /-- One run: `(state, chain state) ↦ (state after erasure, signature)`. -/
  step : σ → Chain → σ × Sig

/-- The protocol signs `m0` under chain state `S0` and `m1` under chain state `S1` when started
from the joint state `st`. -/
def SignsBoth (P : Continuation σ Chain Sig) (valid : Msg → Sig → Prop) (st : σ) (S0 S1 : Chain)
    (m0 m1 : Msg) : Prop :=
  valid m0 (P.step st S0).2 ∧ valid m1 (P.step st S1).2

/-- The protocol confines a coalition that holds `st` to one of `m0`, `m1`: no function of the
state outputs valid signatures on both. -/
def Confines (valid : Msg → Sig → Prop) (st : σ) (m0 m1 : Msg) : Prop :=
  ∀ A : σ → Sig × Sig, ¬ (valid m0 (A st).1 ∧ valid m1 (A st).2)

/-- The coalition's strategy: run the continuation on a copy of the state for each chain state.
It never reads a state that the honest step has erased. -/
def runTwice (P : Continuation σ Chain Sig) (S0 S1 : Chain) (st : σ) : Sig × Sig :=
  ((P.step st S0).2, (P.step st S1).2)

/-- **Claim 5.** One strategy, fixed before the owner's message and independent of the messages,
outputs both signatures from every joint state from which the honest protocol signs `m0` under
`S0` and `m1` under `S1`. -/
theorem coalition_outputs_both (P : Continuation σ Chain Sig) (valid : Msg → Sig → Prop)
    (S0 S1 : Chain) :
    ∃ A : σ → Sig × Sig, ∀ (st : σ) (m0 m1 : Msg), SignsBoth P valid st S0 S1 m0 m1 →
      valid m0 (A st).1 ∧ valid m1 (A st).2 :=
  ⟨runTwice P S0 S1, fun _ _ _ h ↦ h⟩

/-- **Claim 5, impossibility form.** No continuation both signs `m0` under `S0` and `m1` under
`S1` and confines the coalition to one of the two. The messages need not differ for the proof;
the claim has content when `m0 ≠ m1`. -/
theorem not_signsBoth_and_confines (P : Continuation σ Chain Sig) (valid : Msg → Sig → Prop)
    (st : σ) (S0 S1 : Chain) (m0 m1 : Msg) :
    ¬ (SignsBoth P valid st S0 S1 m0 m1 ∧ Confines valid st m0 m1) :=
  fun ⟨hs, hc⟩ ↦ hc (runTwice P S0 S1) hs

/-- **Erasure does not bind.** The conclusion holds even when the honest step erases everything:
the state after a step is a constant `e` that carries no information. -/
theorem erasure_does_not_bind (P : Continuation σ Chain Sig) (valid : Msg → Sig → Prop) (e : σ)
    (_herase : ∀ st S, (P.step st S).1 = e) (st : σ) (S0 S1 : Chain) (m0 m1 : Msg)
    (hs : SignsBoth P valid st S0 S1 m0 m1) : ¬ Confines valid st m0 m1 :=
  fun hc ↦ hc (runTwice P S0 S1) hs

/-- A deterministic continuation gives one signature per chain state, so the only messages a
confining protocol can sign from `st` are those the owner's move already fixed: if the protocol
confines the coalition, it signs the same message, or fails, under every pair of chain states. -/
theorem confines_imp_not_signsBoth (P : Continuation σ Chain Sig) (valid : Msg → Sig → Prop)
    (st : σ) (m0 m1 : Msg) (hc : Confines valid st m0 m1) (S0 S1 : Chain) :
    ¬ SignsBoth P valid st S0 S1 m0 m1 :=
  fun hs ↦ not_signsBoth_and_confines P valid st S0 S1 m0 m1 ⟨hs, hc⟩

section OpenLine

variable {q : ℕ} [Fact q.Prime] {G : Type*} [AddCommGroup G] [Module (ZMod q) G]

/-- **The open ECDSA line is the key.** If the continuation of an open ECDSA slot returns, under
two chain states, scalars that satisfy the signature equation for one nonce point `R` and two
different sighashes, the coalition that runs it twice computes the key `x` from public values
and the two outputs. This joins claim 5 with `ecdsa_nonce_reuse`. -/
theorem open_ecdsa_coalition_gets_key {σ Chain : Type*} (P : Continuation σ Chain (ZMod q))
    {g : G} (hg : g ≠ 0) {k x r h0 h1 : ZMod q} {R X : G} (hR : R = k • g) (hX : X = x • g)
    (hr : r ≠ 0) (hh : h0 ≠ h1) (st : σ) (S0 S1 : Chain)
    (hs : SignsBoth P (fun (h s : ZMod q) ↦ s • R = h • g + r • X) st S0 S1 h0 h1) :
    let out := runTwice P S0 S1 st
    x = (out.1 * ((h0 - h1) / (out.1 - out.2)) - h0) / r := by
  obtain ⟨-, hk, hx⟩ := ecdsa_nonce_reuse hg hR hX hr hh hs.1 hs.2
  intro out
  rw [hx]
  congr 3

end OpenLine

end LineDealing.Impossibility
