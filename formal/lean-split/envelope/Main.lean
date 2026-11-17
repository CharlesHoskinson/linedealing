import SplitCodec.Json
import SplitEnvelope.Spec

/-!
# Envelope oracle executable

* default: one `kink-implementation/1` request with
  `inputs = {"params", "height", "epochs", "ops"}`. The answer is
  `{"end": "final", "cells": {"state", "obs"}}`: the end state of `runOps` from
  `init` and one observation per operation. A refused operation is the
  observation `{"refused": CODES}`, leaves the state unchanged, and the run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused
  operation gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: every code comes from `Refusal.code`,
`Fault.code` and `Combine.code`, and every transition from `apply`.
-/

open Lean SplitCodec SplitEnvelope

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def suites : List (String × Suite) := [("BIP340", .BIP340), ("ED25519", .ED25519), ("ECDSA", .ECDSA)]
def rtypes : List (String × RType) :=
  [("SPEND", .SPEND), ("EXIT", .EXIT), ("SEIZURE", .SEIZURE), ("BIRTH", .BIRTH), ("REFILL", .REFILL),
   ("P0", .P0), ("CONTRIB", .CONTRIB)]

def nn (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)
def jnn : Nat × Nat → Json := jPair jNat jNat

def pubOf (j : Json) : Except String PublicPart := do
  exactKeys j "pub" ["version", "epoch", "keylist_hash", "exp", "size_class", "auth_ref", "reserved"]
  pure { version := ← gN j "version", epoch := ← gN j "epoch", keylistHash := ← gN j "keylist_hash",
         exp := ← gN j "exp", sizeClass := ← gN j "size_class", authRef := ← gN j "auth_ref",
         reserved := ← gN j "reserved" }

def envOf (j : Json) : Except String Envelope := do
  exactKeys j "envelope" ["size", "pub", "hd", "dd", "proof_ctx", "proof_valid", "type"]
  pure { size := ← gN j "size", pub := ← pubOf (← field j "pub"), hd := ← gN j "hd", dd := ← gN j "dd",
         proofCtx := ← nn "proof_ctx" (← field j "proof_ctx"), proofValid := ← gB j "proof_valid",
         rtype := ← gE j "type" rtypes }

def layoutOf (j : Json) : Except String Layout := do
  exactKeys j "layout" ["body_0", "bodies", "capsules"]
  pure { body0 := ← gN j "body_0", bodies := ← gL j "bodies" (asNat "bodies"),
         capsules := ← gL j "capsules" (asNat "capsules") }

def slotOf (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j "slot" ["g", "j", "l"]
  pure (← gN j "g", ← gN j "j", ← gN j "l")

def headerOf (j : Json) : Except String Header := do
  exactKeys j "header" ["suite", "K", "L", "tickets", "slots", "R_A", "R_ecdsa", "pairs", "layout",
    "n_capsules", "region_outside", "length_mismatch", "has_ic", "has_r_tkc", "tkc", "auth_tkc",
    "recompute_mismatch"]
  pure { suite := ← gE j "suite" suites, K := ← gN j "K", L := ← gN j "L", tickets := ← gN j "tickets",
         slots := ← gL j "slots" slotOf, rA := ← gL j "R_A" (asNat "R_A"),
         rEcdsa := ← gL j "R_ecdsa" (asNat "R_ecdsa"), pairs := ← gL j "pairs" (asNat "pairs"),
         layout := ← layoutOf (← field j "layout"), nCapsules := ← gN j "n_capsules",
         regionOutside := ← gB j "region_outside", lengthMismatch := ← gB j "length_mismatch",
         hasIc := ← gB j "has_ic", hasRtkc := ← gB j "has_r_tkc", tkc := ← gN j "tkc",
         authTkc := ← gN j "auth_tkc", recomputeMismatch := ← gB j "recompute_mismatch" }

def partialOf (j : Json) : Except String Partial := do
  exactKeys j "partial" ["sender", "proof_ok"]
  pure { sender := ← gN j "sender", proofOk := ← gB j "proof_ok" }

def opOf (j : Json) : Except String Op := do
  match ← gS j "op" with
  | "submit" => exactKeys j "op" ["op", "envelope"]; pure (.submit (← envOf (← field j "envelope")))
  | "tick" => exactKeys j "op" ["op", "height"]; pure (.tick (← gN j "height"))
  | "set_epochs" => exactKeys j "op" ["op", "epochs"]; pure (.setEpochs (← gL j "epochs" (nn "epochs")))
  | "order_check" => exactKeys j "op" ["op", "exp", "height"]; pure (.orderCheck (← gN j "exp") (← gN j "height"))
  | "header" => exactKeys j "op" ["op", "header"]; pure (.header (← headerOf (← field j "header")))
  | "combine" =>
    exactKeys j "op" ["op", "t", "dealing_ok", "partials"]
    pure (.combinePartials (← gN j "t") (← gB j "dealing_ok") (← gL j "partials" partialOf))
  | o => throw s!"unknown op {o}"

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["mode", "delta_c"]
  pure { mode := ← gE j "mode" modes, deltaC := ← gN j "delta_c" }

def paramsJson (p : Params) : Json :=
  Json.mkObj [("mode", toJson (enumName modes p.mode)), ("delta_c", jNat p.deltaC)]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("height", jNat s.height), ("epochs", jList jnn s.epochs),
    ("seen", jList jnn s.seen), ("accepted", jList jnn s.accepted)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" ["params", "height", "epochs", "seen", "accepted"]
  pure { params := ← paramsOf (← field j "params"), height := ← gN j "height",
         epochs := ← gL j "epochs" (nn "epochs"), seen := ← gL j "seen" (nn "seen"),
         accepted := ← gL j "accepted" (nn "accepted") }

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .accepted eid => Json.mkObj [("accepted", jnn eid)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .ok => Json.mkObj [("ok", true)]
  | .faults fs => Json.mkObj [("faults", toJson (fs.map Fault.code))]
  | .combined c => Json.mkObj [("combined", toJson c.code)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "height", "epochs", "ops"]
  let p ← paramsOf (← field inputs "params")
  let s0 := init p (← gN inputs "height") (← gL inputs "epochs" (nn "epochs"))
  let ops ← gL inputs "ops" opOf
  let (s, os) := runOps s0 ops
  pure (finalAnswer (Json.mkObj [("state", stJson s), ("obs", jList obsJson os)]))

def step (j : Json) : Except String Json := do
  exactKeys j "line" ["state", "op"]
  let s ← stOf (← field j "state")
  let op ← opOf (← field j "op")
  match stepRefusals s with
  | [] =>
    match apply s op with
    | (_, .refused rs) => pure (Json.mkObj [("refused", codes rs)])
    | (s', o) => pure (Json.mkObj [("state", stJson s'), ("obs", obsJson o)])
  | rs => pure (Json.mkObj [("refused", codes rs)])

def main (args : List String) : IO UInt32 := SplitCodec.main { answer, step } args
