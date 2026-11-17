import SplitCodec.Json
import SplitSlots.Spec

/-!
# Slot oracle executable

* default: one `kink-implementation/1` request with `inputs = {"params", "ops"}`.
  The answer is `{"end": "final", "cells": {"state", "obs"}}`: the end state of
  `runOps` from `init` and one observation per operation. A refused operation is
  the observation `{"refused": CODES}`, leaves the state unchanged, and the run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused operation
  gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: codes come from `Refusal.code` and `Verdict.code`,
every transition from `apply`.
-/

open Lean SplitCodec SplitSlots

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def suites : List (String × Suite) := [("BIP340", .BIP340), ("ED25519", .ED25519)]
def bstats : List (String × BStat) :=
  [("UNNAMED", .UNNAMED), ("NAMED", .NAMED), ("RESERVED", .RESERVED), ("CLAIMED", .CLAIMED), ("BURNED", .BURNED)]
def roots : List (String × Root) := [("OWN", .OWN), ("G", .G)]

def nn (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)
def jnn : Nat × Nat → Json := jPair jNat jNat
def jE {α : Type} [BEq α] (t : List (String × α)) (a : α) : Json := toJson (enumName t a)
def gOptN (j : Json) (k : String) : Except String (Option Nat) := gO j k (asNat k)

def ckey (j : Json) : Except String (Suite × Nat × Nat) := do
  exactKeys j "slot" ["suite", "epoch", "idx"]
  pure (← gE j "suite" suites, ← gN j "epoch", ← gN j "idx")
def jckey (k : Suite × Nat × Nat) : Json :=
  Json.mkObj [("suite", jE suites k.1), ("epoch", jNat k.2.1), ("idx", jNat k.2.2)]
def ekey (j : Json) : Except String (Nat × Nat) := do
  exactKeys j "slot" ["pool", "idx"]
  pure (← gN j "pool", ← gN j "idx")
def jekey (k : Nat × Nat) : Json := Json.mkObj [("pool", jNat k.1), ("idx", jNat k.2)]

def cslotJson (x : CSlot) : Json :=
  Json.mkObj [("suite", jE suites x.suite), ("epoch", jNat x.epoch), ("idx", jNat x.idx),
    ("bstat", jE bstats x.bstat), ("prec", jOpt jNat x.prec), ("namers", jList jnn x.namers)]
def cslotOf (j : Json) : Except String CSlot := do
  exactKeys j "cslot" ["suite", "epoch", "idx", "bstat", "prec", "namers"]
  pure { suite := ← gE j "suite" suites, epoch := ← gN j "epoch", idx := ← gN j "idx",
         bstat := ← gE j "bstat" bstats, prec := ← gOptN j "prec", namers := ← gL j "namers" (nn "namers") }

def eslotJson (x : ESlot) : Json :=
  Json.mkObj [("pool", jNat x.pool), ("idx", jNat x.idx), ("leaf_set", jNat x.leafSet), ("root", jE roots x.root),
    ("bstat", jE bstats x.bstat), ("prec", jOpt jNat x.prec), ("reserver", jOpt jNat x.reserver),
    ("namers", jList jnn x.namers)]
def eslotOf (j : Json) : Except String ESlot := do
  exactKeys j "eslot" ["pool", "idx", "leaf_set", "root", "bstat", "prec", "reserver", "namers"]
  pure { pool := ← gN j "pool", idx := ← gN j "idx", leafSet := ← gN j "leaf_set", root := ← gE j "root" roots,
         bstat := ← gE j "bstat" bstats, prec := ← gOptN j "prec", reserver := ← gOptN j "reserver",
         namers := ← gL j "namers" (nn "namers") }

def seatStJson : SeatSt → Json
  | .free => toJson "free"
  | .bound d => Json.mkObj [("bound", jNat d)]
  | .burned => toJson "burned"
def seatStOf : Json → Except String SeatSt
  | .str "free" => pure .free
  | .str "burned" => pure .burned
  | j => do exactKeys j "st" ["bound"]; pure (.bound (← gN j "bound"))

def seatJson (x : SeatSlot) : Json :=
  Json.mkObj [("key", jNat x.key), ("st", seatStJson x.st), ("current", toJson x.current),
    ("signed", jList jNat x.signed)]
def seatOf (j : Json) : Except String SeatSlot := do
  exactKeys j "seat_slot" ["key", "st", "current", "signed"]
  pure { key := ← gN j "key", st := ← seatStOf (← field j "st"), current := ← gB j "current",
         signed := ← gL j "signed" (asNat "signed") }

def forceOf (j : Json) : Except String (Nat × Root) := do
  exactKeys j "in_force" ["eid", "root"]
  pure (← gN j "eid", ← gE j "root" roots)
def jforce (x : Nat × Root) : Json := Json.mkObj [("eid", jNat x.1), ("root", jE roots x.2)]

def dealerOf (j : Json) : Except String (Nat × Bool) := do
  exactKeys j "dealer" ["dealer", "complained"]
  pure (← gN j "dealer", ← gB j "complained")

def opOf (j : Json) : Except String Op := do
  let k (ks : List String) := exactKeys j "op" ("op" :: ks)
  match ← gS j "op" with
  | "deal_c" => k ["suite", "epoch", "k"]; pure (.dealC (← gE j "suite" suites) (← gN j "epoch") (← gN j "k"))
  | "deal_e" => k ["pool", "leaf_set", "root", "k"]
                pure (.dealE (← gN j "pool") (← gN j "leaf_set") (← gE j "root" roots) (← gN j "k"))
  | "open_c" => k ["eid", "pos", "names"]; pure (.openC (← gN j "eid") (← gN j "pos") (← gL j "names" ckey))
  | "open_e" => k ["eid", "pos", "names"]; pure (.openE (← gN j "eid") (← gN j "pos") (← gL j "names" ekey))
  | "in_force" => k ["eid", "root"]; pure (.inForce (← gN j "eid") (← gE j "root" roots))
  | "lapse" => k ["eid"]; pure (.lapse (← gN j "eid"))
  | "reserve" => k ["eid"]; pure (.reserve (← gN j "eid"))
  | "claim" => k ["eid"]; pure (.claim (← gN j "eid"))
  | "end" => k ["eid"]; pure (.endReq (← gN j "eid"))
  | "burn_range" => k ["suite", "epoch", "lo", "hi"]
                    pure (.burnRange (← gE j "suite" suites) (← gN j "epoch") (← gN j "lo") (← gN j "hi"))
  | "burn_pool" => k ["pool"]; pure (.burnPool (← gN j "pool"))
  | "seat_put" => k ["key"]; pure (.seatPut (← gN j "key"))
  | "seat_bind" => k ["key", "d", "slot_acks", "sealed_acks"]
                   pure (.seatBind (← gN j "key") (← gN j "d") (← gN j "slot_acks") (← gN j "sealed_acks"))
  | "seat_release" => k ["key", "d"]; pure (.seatRelease (← gN j "key") (← gN j "d"))
  | "seat_burn" => k ["key"]; pure (.seatBurn (← gN j "key"))
  | "judge" => k ["listed", "h", "pending_min", "pending", "B", "eid", "idxs"]
               pure (.judge (← gB j "listed") (← gN j "h") (← gN j "pending_min") (← gL j "pending" (nn "pending"))
                      (← gN j "B") (← gN j "eid") (← gL j "idxs" (asNat "idxs")))
  | "batch" => k ["polys"]; pure (.batch (← gL j "polys" (asBool "polys")))
  | "qualify" => k ["t", "dealers"]; pure (.qualify (← gN j "t") (← gL j "dealers" dealerOf))
  | "anchor_gate" => k ["on", "covered", "nf", "d"]
                     pure (.anchorGate (← gB j "on") (← gL j "covered" (nn "covered")) (← gN j "nf") (← gN j "d"))
  | o => throw s!"unknown op {o}"

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["mode", "w"]
  pure { mode := ← gE j "mode" modes, w := ← gN j "w" }
def paramsJson (p : Params) : Json := Json.mkObj [("mode", jE modes p.mode), ("w", jNat p.w)]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("cslots", jList cslotJson s.cslots),
    ("eslots", jList eslotJson s.eslots), ("seat", jList seatJson s.seat), ("in_force", jList jforce s.inForce),
    ("opened", jList jNat s.opened), ("last_pos", jOpt jNat s.lastPos), ("lapsed", jList jNat s.lapsed),
    ("ended", jList jNat s.ended)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" ["params", "cslots", "eslots", "seat", "in_force", "opened", "last_pos", "lapsed", "ended"]
  pure { params := ← paramsOf (← field j "params"), cslots := ← gL j "cslots" cslotOf,
         eslots := ← gL j "eslots" eslotOf, seat := ← gL j "seat" seatOf, inForce := ← gL j "in_force" forceOf,
         opened := ← gL j "opened" (asNat "opened"), lastPos := ← gOptN j "last_pos",
         lapsed := ← gL j "lapsed" (asNat "lapsed"), ended := ← gL j "ended" (asNat "ended") }

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .ok => Json.mkObj [("ok", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .voidSlotTaken => Json.mkObj [("void", toJson "SLOT_TAKEN")]
  | .released d => Json.mkObj [("released", jNat d)]
  | .verdicts vs => Json.mkObj [("verdicts", toJson (vs.map Verdict.code))]
  | .batched fs => Json.mkObj [("complaint", jList jNat fs)]
  | .qualifiedDealers ds => Json.mkObj [("qualified", jOpt (jList jNat) ds)]
  | .gate b => Json.mkObj [("gate", toJson b)]

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
