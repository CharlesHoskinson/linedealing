**CHOOSE 3c.** Pin Natural Lean to `c9768172f244b36665563397d4acd170a8084816` on Lean 4.35.0 and reuse the existing local Mathlib. This avoids a new toolchain and Mathlib download while retaining the algebra and interpolation foundations used by the 48 existing proofs.

The older revision may lack useful elaboration fixes, and compatibility still needs a build check. Pin all transitive dependencies and verify representative Natural Lean proofs with Mathlib before committing to the full port. Item 2 remains needed; item 1 is deferred.

I reject 3a’s immediate upgrade cost and 3b’s substantial additional proof burden as the starting approach.

FINAL: 3c