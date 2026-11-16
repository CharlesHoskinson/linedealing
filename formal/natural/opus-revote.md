# Opus re-vote on the algebra base (3a / 3b / 3c)

Reviewer: independent Opus agent, 2026-11-13. I read REVOTE.md and codex-verdict.md and installed nothing.

## New fact that decides it

I compared the natural_lean manifest at `c9768172f244b36665563397d4acd170a8084816` with `formal/lean/lake-manifest.json`:

| package | natural_lean @ c9768172 | formal/lean (shared Mathlib v4.35) | tag |
|---|---|---|---|
| batteries | `66e469188fe07963e5cf666c7d4433f45b8131c5` | `66e469188fe07963e5cf666c7d4433f45b8131c5` | = batteries `v4.35.0` |
| aesop | `4a174c490d8707121c4a9290800489f105d85e07` | `4a174c490d8707121c4a9290800489f105d85e07` | = aesop `v4.35.0` |

The pins are identical. Under 3c, Lake has no version conflict to resolve. The toolchain is the same, and batteries and aesop are the commits the existing Mathlib was already built against. Nothing is downloaded except natural_lean's small source tree, and nothing big needs rebuilding.

## Vote

- **3c: CHOOSE.** It meets both reviewers' main objections at once. My objection to 3a was the cost and risk of a Mathlib download or build on aarch64 at an rc tag. That does not apply here, because the Mathlib v4.35 build already exists and is the exact one that `formal/lean` proves the 48 theorems against. Codex's objection to 3b was the burden of rebuilding finite fields, modules, polynomials, sums and interpolation. That is also gone, because the port reuses Mathlib, and Natural Lean supports mixing its syntax with native Lean. No toolchain is installed, so item 1 stays unused unless 3c fails.
- **3a: REJECT** for now. Use it only as a fallback (see below).
- **3b: REJECT** for now. Use it only as a fallback (see below).

The cost of 3c is that the library is 89 commits behind HEAD. 8 of those commit subjects say "fix" or "bug", so expect some elaboration bugs that upstream has already fixed. Accept that cost. It is still natural_lean, and the upstream changes every day, so any pin falls behind soon.

## Conditions on 3c

1. **Smoke test first.** Before porting the whole file, build one file that imports `Natural` and the Mathlib modules that LineDealing uses (ZMod, Module, Polynomial, Lagrange) together, and port one theorem. This checks the one real open risk: grammar or notation clashes between Natural and Mathlib.
2. **Pin everything.** Use `rev = "c9768172f244b36665563397d4acd170a8084816"` and set `formal/natural/lean-toolchain` to `leanprover/lean4:v4.35.0`. Commit the manifest, and do not run a bare `lake update`.
3. **Protect the shared Mathlib.** The path dependency points into the Moriarty worktree. Do not run `lake update`, `lake clean` or a build with another toolchain against it. If `lake build` starts to rebuild Mathlib, stop: that means the pins are not what is recorded here.
4. **Same gates as formal/lean.** Map each ported theorem by name to its formal/lean counterpart. Run `#print axioms` (only propext, Classical.choice and Quot.sound), and grep for no `sorry`.

## Fallback order if 3c fails

- **The failure is a Natural Lean bug or a missing feature that HEAD has fixed:** install item 1 (v4.36.0-rc2, project-scoped as in opus-verdict.md) and move natural_lean to a pinned HEAD SHA. Then do the smoke test from condition 1 with Mathlib at its `v4.36.0-rc2` tag (`9d581dff…`), which is 3a. Before you build, check whether `lake exe cache get` serves oleans for aarch64 at that tag. If it does not, do 3b instead of a multi-hour local Mathlib build.
- **The failure is a Natural and Mathlib grammar clash that cannot be fixed with scoped opens or thin adapters:** do 3b on the current toolchain if that toolchain works for natural_lean, otherwise on item 1. A Mathlib upgrade would not fix a clash.

FINAL: 3c
