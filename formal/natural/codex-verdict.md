Host checks found **Lean 4.33.1 and 4.35.0 installed**, contradicting the list’s “4.35.0 only” claim. The neighboring `formal/lean` project pins 4.35.0, uses an existing local Mathlib checkout, and contains 48 theorem declarations plus compiled artifacts. I did not rebuild it.

`gh api` could not connect; public web reads confirmed Natural Lean’s [toolchain pin](https://raw.githubusercontent.com/medovina/natural_lean/main/lean-toolchain) and [dependencies](https://raw.githubusercontent.com/medovina/natural_lean/main/lakefile.toml).

| Item | Decision | Reason and safer alternative |
|---|---|---|
| **1** | **NEEDED** for the current upstream pin | 4.36.0-rc2 is absent. Neither installed version establishes compatibility. **Safer alternative:** first test a pinned Natural Lean revision on existing 4.35.0 in an isolated project; install the release candidate only if required, keeping the neighboring project’s pin unchanged. |
| **2** | **NEEDED** | Using Natural Lean requires its library. **Safer alternative:** pin an exact commit and retain a reviewed Lake manifest with fixed transitive revisions; avoid floating dependency updates. |
| **3a** | **CHOOSE**, with compatibility verified first | The existing proofs rely substantially on Mathlib’s algebra and interpolation results. Reusing these preserves their mathematical foundations. **Safer alternative:** try sharing the existing 4.35.0 Mathlib checkout with a compatible Natural Lean revision. If upgrading, verify a compatible Mathlib commit exists; the proposed “matching tag” and cache availability are not established. |
| **3b** | **REJECT** | Recreating finite fields, modules, polynomials, finite sums, and interpolation greatly expands the proof and review burden. “No download” does not imply lower risk. **Safer alternative:** retain Mathlib and add thin syntax adapters. Natural Lean explicitly supports [mixing natural syntax with native Lean](https://github.com/medovina/natural_lean# getting-started); its first-principles examples do not require replacing Mathlib. |

All host checks were read-only; nothing was installed or changed.

VERDICT: item1=NEEDED, item2=NEEDED, item3a=CHOOSE, item3b=REJECT