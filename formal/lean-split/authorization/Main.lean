import SplitCodec.Json
import SplitAuthorization.Spec

/-!
# Authorization oracle executable

* default: one `kink-implementation/1` request with `inputs = {"params", "ops"}`.
  The answer is `{"end": "final", "cells": {"state", "obs"}}`: the end state of
  `runOps` from `init` and one observation per operation. A refused operation
  is the observation `{"refused": CODES}`, leaves the state unchanged, and the
  run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused
  operation gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

A nullifier is `{"fresh": n}` or `{"auth": a, "outcome": O}` for `N(nsk, a, O)`.
The codec holds no spec logic: every code comes from `Refusal.code` and every
transition from `apply`.
-/

open Lean SplitCodec SplitAuthorization

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def profiles : List (String × Profile) := [("P0", .P0), ("P1", .P1), ("P2", .P2)]
def rstates : List (String × RState) := [("UNSPENT", .UNSPENT), ("PENDING", .PENDING), ("LOCKED", .LOCKED)]
def statuses : List (String × Status) := [("SUBMITTED", .SUBMITTED), ("FINAL", .FINAL), ("REVOKED", .REVOKED)]
def settleds : List (String × Settled) :=
  [("NONE", .NONE), ("FINAL", .FINAL), ("VOID", .VOID), ("RELEASED", .RELEASED)]
def sources : List (String × Source) := [("OWNER", .OWNER), ("SEIZURE", .SEIZURE), ("RECOVERY", .RECOVERY)]
def roots : List (String × Root) := [("OWN", .OWN), ("G", .G)]

def enumJ {α : Type} [BEq α] (names : List (String × α)) (a : α) : Json := toJson (enumName names a)
def oN (j : Json) (k : String) : Except String (Option Nat) := gO j k (asNat k)
def jON : Option Nat → Json := jOpt jNat

def nfOf (j : Json) : Except String Nf := do
  match j.getObjVal? "fresh" with
  | .ok v => exactKeys j "nf" ["fresh"]; pure (.fresh (← asNat "fresh" v))
  | .error _ =>
    exactKeys j "nf" ["auth", "outcome"]
    pure (.ofSettle (← gN j "auth") (← gE j "outcome" settleds))

def nfJson : Nf → Json
  | .fresh n => Json.mkObj [("fresh", jNat n)]
  | .ofSettle a o => Json.mkObj [("auth", jNat a), ("outcome", enumJ settleds o)]

def authOf (j : Json) : Except String Auth := do
  exactKeys j "auth" ["auth", "nf", "rh", "status", "final_height", "settled", "source", "pin", "direct"]
  pure { auth := ← gN j "auth", nf := ← nfOf (← field j "nf"), rh := ← gN j "rh",
         status := ← gE j "status" statuses, finalHeight := ← oN j "final_height",
         settled := ← gE j "settled" settleds, source := ← gO j "source" (asEnum "source" sources),
         pin := ← oN j "pin", direct := ← gB j "direct" }

def authJson (b : Auth) : Json :=
  Json.mkObj [("auth", jNat b.auth), ("nf", nfJson b.nf), ("rh", jNat b.rh), ("status", enumJ statuses b.status),
    ("final_height", jON b.finalHeight), ("settled", enumJ settleds b.settled),
    ("source", jOpt (enumJ sources) b.source), ("pin", jON b.pin), ("direct", toJson b.direct)]

def recKeys : List String :=
  ["rid", "cm_addr", "profile", "board_first", "rstate", "nf", "pin", "hold_tag", "slr_own", "slr_G", "spent", "auths"]

def recOfJ (j : Json) : Except String Rec := do
  exactKeys j "record" recKeys
  pure { rid := ← gN j "rid", cmAddr := ← gN j "cm_addr", profile := ← gE j "profile" profiles,
         boardFirst := ← gB j "board_first", rstate := ← gE j "rstate" rstates, nf := ← nfOf (← field j "nf"),
         pin := ← oN j "pin", holdTag := ← gN j "hold_tag", slrOwn := ← oN j "slr_own", slrG := ← oN j "slr_G",
         spent := ← gB j "spent", auths := ← gL j "auths" authOf }

def recJson (r : Rec) : Json :=
  Json.mkObj [("rid", jNat r.rid), ("cm_addr", jNat r.cmAddr), ("profile", enumJ profiles r.profile),
    ("board_first", toJson r.boardFirst), ("rstate", enumJ rstates r.rstate), ("nf", nfJson r.nf),
    ("pin", jON r.pin), ("hold_tag", jNat r.holdTag), ("slr_own", jON r.slrOwn), ("slr_G", jON r.slrG),
    ("spent", toJson r.spent), ("auths", jList authJson r.auths)]

def charterOf (j : Json) : Except String Charter := do
  exactKeys j "charter" ["cid", "profile", "board_first"]
  pure { cid := ← gN j "cid", profile := ← gE j "profile" profiles, boardFirst := ← gB j "board_first" }

def charterJson (c : Charter) : Json :=
  Json.mkObj [("cid", jNat c.cid), ("profile", enumJ profiles c.profile), ("board_first", toJson c.boardFirst)]

def anOf (k : String) : Json → Except String (Nat × Nf) := asPair k (asNat k) nfOf
def nfaOf (k : String) : Json → Except String (Nf × Nat) := asPair k nfOf (asNat k)

def nodeOf (j : Json) : Except String Node := do
  exactKeys j "node" ["pending", "in_force", "landed"]
  pure { pending := ← gL j "pending" nfOf, inForce := ← gL j "in_force" (anOf "in_force"),
         landed := ← gL j "landed" nfOf }

def nodeJson (n : Node) : Json :=
  Json.mkObj [("pending", jList nfJson n.pending), ("in_force", jList (jPair jNat nfJson) n.inForce),
    ("landed", jList nfJson n.landed)]

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["mode", "q"]
  pure { mode := ← gE j "mode" modes, q := ← gN j "q" }

def paramsJson (p : Params) : Json := Json.mkObj [("mode", enumJ modes p.mode), ("q", jNat p.q)]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("charters", jList charterJson s.charters),
    ("records", jList recJson s.records), ("used", jList (jPair nfJson jNat) s.used),
    ("holds", jList jNat s.holds), ("recovered", toJson s.recovered), ("node", nodeJson s.node)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" ["params", "charters", "records", "used", "holds", "recovered", "node"]
  pure { params := ← paramsOf (← field j "params"), charters := ← gL j "charters" charterOf,
         records := ← gL j "records" recOfJ, used := ← gL j "used" (nfaOf "used"),
         holds := ← gL j "holds" (asNat "holds"), recovered := ← gB j "recovered",
         node := ← nodeOf (← field j "node") }

def carryOf (j : Json) : Except String Carry := do
  exactKeys j "carry" ["auth_0", "outcome", "sigs"]
  pure { auth0 := ← gN j "auth_0", outcome := ← gE j "outcome" settleds, sigs := ← gN j "sigs" }

def callOf (j : Json) : Except String Call := do
  exactKeys j "call" ["rid", "nf", "auth", "rh", "source", "slot", "inputs_ok", "pred_ok", "in_gamma",
    "blacklisted", "ticket_ok", "pin", "to_exit", "carry"]
  pure { rid := ← gN j "rid", nf := ← nfOf (← field j "nf"), auth := ← gN j "auth", rh := ← gN j "rh",
         source := ← gE j "source" sources,
         slot := ← gO j "slot" (asPair "slot" (asNat "slot") (asEnum "slot" roots)),
         inputsOk := ← gB j "inputs_ok", predOk := ← gB j "pred_ok", inGamma := ← gB j "in_gamma",
         blacklisted := ← gB j "blacklisted", ticketOk := ← gB j "ticket_ok", pin := ← gN j "pin",
         toExit := ← gB j "to_exit", carry := ← gO j "carry" carryOf }

def tupleOf (j : Json) : Except String BfTuple := do
  exactKeys j "tuple" ["auth", "nf", "rh", "root"]
  pure { auth := ← gN j "auth", nf := ← nfOf (← field j "nf"), rh := ← gN j "rh", root := ← gN j "root" }

def bfCallOf (j : Json) : Except String BfCall := do
  exactKeys j "bf_call" ["auth", "nf", "proof_ok", "root_final", "root_age", "bound", "interval", "F_M", "carry_sigs"]
  pure { auth := ← gN j "auth", nf := ← nfOf (← field j "nf"), proofOk := ← gB j "proof_ok",
         rootFinal := ← gB j "root_final", rootAge := ← gN j "root_age", bound := ← gN j "bound",
         interval := ← gN j "interval", fM := ← gN j "F_M", carrySigs := ← oN j "carry_sigs" }

def opOf (j : Json) : Except String Op := do
  match ← gS j "op" with
  | "charter" =>
    exactKeys j "op" ["op", "cid", "profile", "board_first", "stateful"]
    pure (.charter (← gN j "cid") (← gE j "profile" profiles) (← gB j "board_first") (← gB j "stateful"))
  | "record" =>
    exactKeys j "op" ["op", "rid", "cid", "cm_addr", "nf", "hold_tag", "slr_own", "slr_G"]
    pure (.record (← gN j "rid") (← gN j "cid") (← gN j "cm_addr") (← nfOf (← field j "nf")) (← gN j "hold_tag")
      (← oN j "slr_own") (← oN j "slr_G"))
  | "authorize" => exactKeys j "op" ["op", "call"]; pure (.authorize (← callOf (← field j "call")))
  | "finalize" => exactKeys j "op" ["op", "auth", "height"]; pure (.finalize (← gN j "auth") (← gN j "height"))
  | "revoke" => exactKeys j "op" ["op", "auth", "tag"]; pure (.revoke (← gN j "auth") (← gN j "tag"))
  | "settle_root" =>
    exactKeys j "op" ["op", "leaves"]
    pure (.settleRoot (← gL j "leaves" (asPair "leaves" (asNat "leaves") (asEnum "leaves" settleds))))
  | "bf_root" => exactKeys j "op" ["op", "tuples"]; pure (.bfRoot (← gL j "tuples" tupleOf))
  | "recover" => exactKeys j "op" ["op"]; pure .recover
  | "bf_call" => exactKeys j "op" ["op", "call"]; pure (.bfCall (← bfCallOf (← field j "call")))
  | "query" => exactKeys j "op" ["op", "auth", "height"]; pure (.query (← gN j "auth") (← gN j "height"))
  | "seizure" =>
    exactKeys j "op" ["op", "auth", "all_to_dreg"]; pure (.seizure (← gN j "auth") (← gB j "all_to_dreg"))
  | o => throw s!"unknown op {o}"

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .accepted => Json.mkObj [("accepted", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .ok => Json.mkObj [("ok", true)]
  | .inForce b => Json.mkObj [("in_force", toJson b)]
  | .void r => Json.mkObj [("void", toJson r)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "ops"]
  let p ← paramsOf (← field inputs "params")
  let ops ← gL inputs "ops" opOf
  let (s, os) := runOps (init p) ops
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
