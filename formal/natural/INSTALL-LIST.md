# Install list: Natural Lean port of the line-dealing proofs (LOOP item 7)

Owner request (2026-11-13): "write all the proofs in https://github.com/medovina/natural_lean".

Host facts: aarch64, elan 4.2.4, installed toolchain Lean 4.35.0 only. Our proofs (formal/lean, 48 theorems) use Mathlib (ZMod, Module, Polynomial, Lagrange) pinned to v4.35.0, built locally. natural_lean (public, 63 stars, pushed 2026-11-13) pins `leanprover/lean4:v4.36.0-rc2`, requires only batteries (main) and aesop (master), no Mathlib.

| # | Item | Purpose | Command | Size | Scope | Alternative already installed |
|---|---|---|---|---|---|---|
| 1 | Lean toolchain v4.36.0-rc2 via elan | natural_lean's pinned toolchain | `elan toolchain install leanprover/lean4:v4.36.0-rc2` | ~0.5-1 GB in ~/.elan | user | v4.35.0; natural_lean may not build on it (untested) |
| 2 | natural_lean as a Lake dependency (git) | the library itself | `[[require]] name="natural" git=".../natural_lean.git" rev=<pinned commit>` in formal/natural/lakefile.toml, `lake update` | small (<10 MB) + batteries and aesop sources (~50 MB) | project (.lake/packages) | none |
| 3a | EITHER Mathlib for v4.36.0-rc2 (+ `lake exe cache get`) | reuse ZMod/Module/Lagrange in the Natural Lean files | lake require mathlib at the matching tag; cache get | ~5-6 GB | user cache + project | Mathlib v4.35 (wrong toolchain) |
| 3b | OR no Mathlib: a self-contained algebra base written in the project (field and module classes, Lagrange basis over a Finset) | avoids the 5-6 GB download; keeps the port within natural_lean's own dependency set | none | 0 | project | — |

Recommendation of the lead: 1, 2 and 3b. 3b is more work but no download, and Natural Lean's grammar is aimed at first-principles developments (its examples build ℕ and ℤ from scratch).
Fallback if 1 is rejected: try natural_lean at its pinned commit on v4.35.0 first; use 1 only if that fails.
