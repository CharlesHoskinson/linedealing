# Re-vote on the algebra base (split vote)

Both reviewers: item1 = NEEDED, item2 = NEEDED.
Split: Opus chose 3b (self-contained base, no Mathlib), rejecting 3a (Mathlib v4.36.0-rc2: uncertain aarch64 cache for an rc tag, possible multi-hour 7 GB build, grammar clashes, refetch on every bump).
Codex chose 3a, rejecting 3b (re-creating finite fields, modules, polynomials, sums and interpolation greatly expands proof and review burden; Natural Lean mixes with native Lean, so keep Mathlib with thin adapters), and suggested first trying a pinned Natural Lean revision on the existing 4.35.0 with the existing Mathlib.

New option 3c from both reviews: natural_lean pinned to c9768172f244b36665563397d4acd170a8084816 (its last commit on Lean v4.35.0, 2026-10-14, 89 commits behind HEAD) in formal/natural, Lean v4.35.0 (installed), and the existing local Mathlib v4.35 by path (as formal/lean does). No toolchain install, no Mathlib download. Item 1 is then not needed unless 3c fails to build. If 3c fails, fall back to item 1 + 3b.

Vote once more on 3a, 3b and 3c (CHOOSE one, with a reason). End with: FINAL: <3a|3b|3c>
