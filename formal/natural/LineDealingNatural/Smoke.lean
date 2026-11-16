import Mathlib.LinearAlgebra.Lagrange
import Mathlib.Data.ZMod.Basic
import Natural

/-!
# Smoke test: Natural Lean together with Mathlib

The first version of this file failed with `unexpected token 'ℕ'; expected type` on

    Theorem.  For all a, b : ℕ, a + b = b + a.

Natural's `type` category accepts an identifier (`syntax ident : type`), `Prop`, an application
`T(U)`, a product and a function type. In Natural's own examples `ℕ` is an identifier that the
example declares. Mathlib declares `ℕ` as a notation, so with Mathlib imported `ℕ` is a token
and no longer an identifier. A type is therefore written by its Lean name (`Nat`, `ZMod(q)`,
`Finset(ZMod(q))`) or by its natural name ("natural number", registered for `Nat` with
`attribute [natural type "natural number"] Nat`).
-/

Theorem.  For all a, b : Nat, a + b = b + a.

Theorem.  For all natural numbers a and b, a + b = b + a.
