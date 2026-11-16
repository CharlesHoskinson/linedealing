import LineDealing.Impossibility
import LineDealingNatural.NonceReuse

/-!
# Line dealing in Natural Lean: no one-move protocol confines a qualified coalition

Port of `formal/lean/LineDealing/Impossibility.lean` (claim 5).

`Continuation`, `SignsBoth`, `Confines` and `runTwice` are the native definitions. The natural
statements write the step of a continuation as `Continuation.step(P, st, S)` and the two
components of a pair as `Prod.fst(...)` and `Prod.snd(...)`; these are the functions behind
the native `P.step st S`, `.1` and `.2`.
-/

open LineDealing.Impossibility (Continuation SignsBoth Confines runTwice)

namespace LineDealingNatural.Impossibility

variable {σ Chain Msg Sig : Type*}

set_option autoImplicit true

Theorem "Claim 5".
  Let P : Continuation(σ)(Chain)(Sig).  Let valid : Msg → Sig → Prop.  Let S0, S1 : Chain.
  There is some A : σ → Sig × Sig such that for all st : σ and m0, m1 : Msg,
  if SignsBoth(P, valid, st, S0, S1, m0, m1) is true then
  valid(m0, Prod.fst(A(st))) is true and valid(m1, Prod.snd(A(st))) is true.
  [coalition_outputs_both]

Proof.  By [exact fun P valid S0 S1 ↦ ⟨runTwice P S0 S1, fun _ _ _ h ↦ h⟩].

example : type_of% (@coalition_outputs_both σ Chain Msg Sig) ↔
    type_of% (@LineDealing.Impossibility.coalition_outputs_both σ Chain Msg Sig) := Iff.rfl

Theorem "Claim 5, impossibility form".
  Let P : Continuation(σ)(Chain)(Sig).  Let valid : Msg → Sig → Prop.  Let st : σ.
  Let S0, S1 : Chain.  Let m0, m1 : Msg.
  If SignsBoth(P, valid, st, S0, S1, m0, m1) is true then Confines(valid, st, m0, m1) is false.
  [not_signsBoth_and_confines]

Proof.  By [exact fun P valid st S0 S1 m0 m1 hs hc ↦ hc (runTwice P S0 S1) hs].

-- The native statement is `¬ (SignsBoth ... ∧ Confines ...)`. Natural Lean cannot negate a
-- compound proposition, so the natural statement is the implication.
example : type_of% (@not_signsBoth_and_confines σ Chain Msg Sig) ↔
    type_of% (@LineDealing.Impossibility.not_signsBoth_and_confines σ Chain Msg Sig) := by
  constructor
  · exact fun h P valid st S0 S1 m0 m1 hsc ↦ h P valid st S0 S1 m0 m1 hsc.1 hsc.2
  · exact fun h P valid st S0 S1 m0 m1 hs hc ↦ h P valid st S0 S1 m0 m1 ⟨hs, hc⟩

Theorem "Erasure does not bind".
  Let P : Continuation(σ)(Chain)(Sig).  Let valid : Msg → Sig → Prop.  Let e, st : σ.
  Let S0, S1 : Chain.  Let m0, m1 : Msg.
  If SignsBoth(P, valid, st, S0, S1, m0, m1) is true and
  for all u : σ and S : Chain, Prod.fst(Continuation.step(P, u, S)) = e, then
  Confines(valid, st, m0, m1) is false.  [erasure_does_not_bind]

Proof.  Suppose that SignsBoth(P, valid, st, S0, S1, m0, m1) is true and
  for all u : σ and S : Chain, Prod.fst(Continuation.step(P, u, S)) = e.  Then
  SignsBoth(P, valid, st, S0, S1, m0, m1) is true.  Hence
  Confines(valid, st, m0, m1) is false by not_signsBoth_and_confines.

example : type_of% (@erasure_does_not_bind σ Chain Msg Sig) ↔
    type_of% (@LineDealing.Impossibility.erasure_does_not_bind σ Chain Msg Sig) := by nl_same

Theorem "A confining protocol signs one message".
  Let P : Continuation(σ)(Chain)(Sig).  Let valid : Msg → Sig → Prop.  Let st : σ.
  Let m0, m1 : Msg.  Let S0, S1 : Chain.
  If Confines(valid, st, m0, m1) is true then
  SignsBoth(P, valid, st, S0, S1, m0, m1) is false.  [confines_imp_not_signsBoth]

Proof.  Suppose that Confines(valid, st, m0, m1) is true.
  Assume that SignsBoth(P, valid, st, S0, S1, m0, m1) is true.  Then
  Confines(valid, st, m0, m1) is false by not_signsBoth_and_confines.
  This is a contradiction.  Thus SignsBoth(P, valid, st, S0, S1, m0, m1) is false.

example : type_of% (@confines_imp_not_signsBoth σ Chain Msg Sig) ↔
    type_of% (@LineDealing.Impossibility.confines_imp_not_signsBoth σ Chain Msg Sig) := by
  nl_same

/-! `open_ecdsa_coalition_gets_key` stays native: its statement passes the function literal
`fun h s ↦ s • R = h • g + r • X` as the validity predicate and names the coalition's output
with `let out := ...`. Natural Lean has neither form. -/

alias open_ecdsa_coalition_gets_key := LineDealing.Impossibility.open_ecdsa_coalition_gets_key

end LineDealingNatural.Impossibility
