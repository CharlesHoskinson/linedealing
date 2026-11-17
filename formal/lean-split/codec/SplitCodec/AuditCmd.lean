import Lean

/-!
# `#audit_ns`

Walks the environment and lists every declaration of a namespace, or of a
module whose name starts with it, that the compiled oracle runs differently
from what the kernel checks: `implemented_by`, `extern`, `csimp`, `unsafe`,
`partial`, `partial_fixpoint`, `opaque` and `axiom`. `#print axioms` cannot see
the first three. Each capability's `Audit` module pins the output at `[]` with
`#guard_msgs` (formal plugin, practices 39 and 41).
-/

open Lean Elab Command

elab "#audit_ns " ns:ident : command => do
  let env ← getEnv
  let mut bad : Array String := #[]
  for (n, ci) in env.constants.toList do
    let inModule := match env.getModuleIdxFor? n with
      | some i => ns.getId.isPrefixOf (env.header.moduleNames[i.toNat]!)
      | none => false
    if (ns.getId.isPrefixOf n || inModule) && !(n matches .str _ "_unsafe_rec") then
      if (Compiler.getImplementedBy? env n).isSome then bad := bad.push s!"implemented_by {n}"
      if isExtern env n then bad := bad.push s!"extern {n}"
      if ci.isUnsafe then bad := bad.push s!"unsafe {n}"
      if (Lean.Elab.PartialFixpoint.eqnInfoExt.find? env n).isSome then
        bad := bad.push s!"partial_fixpoint {n}"
      if ci.isPartial then bad := bad.push s!"partial {n}"
      if (Compiler.CSimp.ext.getState env).map.contains n then bad := bad.push s!"csimp {n}"
      match ci with
      | .axiomInfo _ => bad := bad.push s!"axiom {n}"
      | .opaqueInfo _ => bad := bad.push s!"opaque {n}"
      | _ => pure ()
  logInfo m!"{bad.qsort (· < ·)}"
