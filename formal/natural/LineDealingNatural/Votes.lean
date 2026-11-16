import LineDealing.Votes
import LineDealingNatural.Quorum

/-!
# Line dealing in Natural Lean: one digest per slot

`formal/lean/LineDealing/Votes.lean` models one slot as a transition system: a structure
`State`, an inductive step relation `Step`, and `Reachable` as its reflexive transitive closure.
Every theorem there takes the instance argument `[Fintype ι]` and speaks about structure fields
(`s.prevotes i`), constructors of `Step` or a concrete state built with `Finset` literals.
Natural Lean (at the pinned revision) cannot define a structure, an inductive relation or a type
class instance argument, and it has no field access. All nine theorems stay native. This file
gives each native theorem under the natural name, so the theorem map is complete.
-/

namespace LineDealingNatural.Votes

alias locked_unique_of_prevote_once := LineDealing.Votes.locked_unique_of_prevote_once

alias Step.prevotes_mono := LineDealing.Votes.Step.prevotes_mono

alias Locked.mono := LineDealing.Votes.Locked.mono

alias Step.nodeInv := LineDealing.Votes.Step.nodeInv

alias Reachable.nodeInv := LineDealing.Votes.Reachable.nodeInv

alias honest_prevotes_once := LineDealing.Votes.honest_prevotes_once

alias locked_unique := LineDealing.Votes.locked_unique

alias one_digest_per_slot := LineDealing.Votes.one_digest_per_slot

alias two_digests_without_rule4 := LineDealing.Votes.two_digests_without_rule4

end LineDealingNatural.Votes
