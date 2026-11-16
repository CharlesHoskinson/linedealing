import Mathlib
import Natural

/-!
# Prelude for the Natural Lean port of line dealing

Natural Lean (pinned at c9768172) has a small expression grammar: numerals, variables, `+`, `·`,
`^`, unary minus, one-argument calls `f(x)` and pairs. The statements of line dealing also need
subtraction, division, inverse, scalar multiplication of a point, finite sums, the size of a
finite set and calls of functions with several arguments. This file adds exactly these forms to
Natural's `expr` category. It uses the two extension points that Natural's own examples use: new
`syntax ... : expr` rules whose shape is one of Lean's notation nodes, and `natural_elab`.
Nothing here changes what a sentence means; each form is translated to the Lean notation of the
same name.

Everything in this file is native Lean.
-/

open Lean Natural

/-! ## Operators that translate to Lean's own notation node of the same name -/

syntax:65 expr:65 " - " expr:66 : expr
syntax:70 expr:70 " / " expr:71 : expr
syntax:73 expr:74 " • " expr:73 : expr
syntax expr "⁻¹" : expr

/-! ## Calls

`f(a, b, c)`, with no space before the bracket, is the application `f a b c`. Natural's
built-in `f(x)` takes one argument and decides between a call and a product by asking whether
the type of `f` is in `Mul`. That test throws for a function with implicit arguments (`lam`,
`eval`, `card`) and for a local function whose type mentions the section variable `G`. So in
this port an identifier directly followed by a bracket is always a call, and a product is
written `a · (b + c)`. -/

syntax (name := call) (priority := high) ident noWs "(" expr,+ ")" : expr

@[natural_elab call]
def call_elab : NaturalElab
  | `(expr| $f:ident( $args:expr,* )) => do
      let args ← args.getElems.mapM of_expr
      pure (← `($f $args*), #[], ← `(_))
  | _ => Lean.Elab.throwUnsupportedSyntax

/-! ## Finite sums and sizes of finite sets -/

syntax (name := big_sum) "∑ " ident " ∈ " expr ", " expr:67 : expr

@[natural_elab big_sum]
def big_sum_elab : NaturalElab
  | `(expr| ∑ $i:ident ∈ $s:expr, $e:expr) => do
      (·, #[i], ← `(_)) <$> `(∑ $i:ident ∈ $(← of_expr s), $(← of_expr e))
  | _ => Lean.Elab.throwUnsupportedSyntax

/-- `#s` is the number of elements of the finite set `s`. The node has the shape of a prefix
operator, so Natural translates it to Mathlib's notation `Finset.«term#_»`; files that use it
`open Finset`. -/
syntax "#" expr:lead : expr
attribute [natural_op "#" Finset card prefix] Finset

/-! ## The subset relation

Natural translates `A ⊆ B` to core Lean's notation node `«term_⊆_»`, which means
`HasSubset.Subset`. This Mathlib replaces that notation by its own (`subsetStx'`), which on
`Finset` means `≤`; `Finset` has no `HasSubset` instance any more. The node below has the name
Natural builds once the operator is registered for the namespace `NaturalMathlib`, and it
elaborates as Mathlib's `⊆`. The token `⊆ₙ` only gives the node a parser; it is never typed. -/

namespace NaturalMathlib

syntax:50 (name := «term_⊆_») term:51 " ⊆ₙ " term:51 : term

open Lean.Elab.Term in
@[term_elab «term_⊆_»]
def elabSubset : TermElab := fun stx expectedType? => do
  let x : Term := ⟨stx[0]⟩
  let y : Term := ⟨stx[2]⟩
  elabTerm (← `($x ⊆ $y)) expectedType?

end NaturalMathlib

attribute [natural_op "⊆" NaturalMathlib Subset infix] Finset

/-! ## The statement check

`nl_same` proves `natural statement ↔ native statement` when the two differ only in how the
hypotheses are grouped (`A ∧ B → C` against `A → B → C`), in the order of the bound variables
and in which of them are implicit. -/

/-- Splits every conjunction among the hypotheses. A natural proof assumes all hypotheses of a
theorem as one conjunction; a native tactic step that needs one of them by name starts with
`nl_hyps`. -/
macro "nl_hyps" : tactic => `(tactic| (try casesm* _ ∧ _))

/-- Closes a hypothesis goal: it is among the hypotheses, or it is a conjunction of such. -/
syntax "nl_fin" : tactic
macro_rules
  | `(tactic| nl_fin) =>
    `(tactic| first | assumption | rfl | (refine And.intro ?_ ?_ <;> nl_fin))

/-- Applies a theorem whose hypotheses are among the current hypotheses, possibly grouped
differently. Used where Natural's own `by name` (which tries `apply`, `apply_rules`, `grind`
and `aesop`) does not find the instance. -/
macro "nl_apply " t:term : tactic => `(tactic| (nl_hyps; apply $t <;> nl_fin))

/-- Closes a goal from `h` after the hypotheses were introduced. -/
macro "nl_close " h:ident : tactic => `(tactic|
  (nl_hyps
   first
   | exact $h
   | (apply $h <;> nl_fin)))

macro "nl_same" : tactic => `(tactic|
  first
  | exact Iff.rfl
  | (constructor <;> intro h <;> intros <;> nl_close h))
