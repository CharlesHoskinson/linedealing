import SplitCodec.Json
import SplitCheckpoint.Spec

/-!
# Checkpoint oracle executable

* default: one `kink-implementation/1` request with `inputs = {"params", "ops"}`.
  Parameters outside the domain (`paramsOk`) give `{"end": "could-not-apply",
  "reason": "outside-capability"}`. Otherwise the answer is `{"end": "final",
  "cells": {"state", "obs"}}`: the end state of `runOps` from `init` and one
  observation per operation. A refused operation is the observation
  `{"refused": CODES}`, leaves the state unchanged, and the run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused
  operation gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: every code comes from `Refusal.code`, and every
transition from `apply`.
-/

open Lean SplitCodec SplitCheckpoint

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def outcomes : List (String × Outcome) := [("FINAL", .FINAL), ("VOID", .VOID), ("RELEASED", .RELEASED)]

def nn (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)
def jnn : Nat × Nat → Json := jPair jNat jNat

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["n", "f", "mode", "B", "slot_anchor", "d_rec"]
  pure { n := ← gN j "n", f := ← gN j "f", mode := ← gE j "mode" modes, B := ← gN j "B",
         slotAnchor := ← gB j "slot_anchor", dRec := ← gN j "d_rec" }

def paramsJson (p : Params) : Json :=
  Json.mkObj [("n", jNat p.n), ("f", jNat p.f), ("mode", toJson (enumName modes p.mode)), ("B", jNat p.B),
    ("slot_anchor", toJson p.slotAnchor), ("d_rec", jNat p.dRec)]

def poolOfJ (j : Json) : Except String Pool := do
  exactKeys j "pool" ["pool", "h", "pending_min", "pending", "pending_count"]
  pure { pool := ← gN j "pool", h := ← gN j "h", pendingMin := ← gN j "pending_min",
         pending := ← gL j "pending" (asNat "pending"), pendingCount := ← gN j "pending_count" }

def poolJson (q : Pool) : Json :=
  Json.mkObj [("pool", jNat q.pool), ("h", jNat q.h), ("pending_min", jNat q.pendingMin),
    ("pending", jList jNat q.pending), ("pending_count", jNat q.pendingCount)]

def restoreOf (j : Json) : Except String Restore := do
  exactKeys j "restore" ["node_index", "boot_ctr", "cp_seq", "whole_restart"]
  pure { seat := ← gN j "node_index", bootCtr := ← gN j "boot_ctr", cpSeq := ← gN j "cp_seq", whole := ← gB j "whole_restart" }

def restoreJson (r : Restore) : Json :=
  Json.mkObj [("node_index", jNat r.seat), ("boot_ctr", jNat r.bootCtr), ("cp_seq", jNat r.cpSeq),
    ("whole_restart", toJson r.whole)]

def entryOf (j : Json) : Except String Entry := do
  match ← gS j "kind" with
  | "bind" => exactKeys j "entry" ["kind", "nf", "e"]; pure (.bind (← gN j "nf") (← gN j "e"))
  | "put" => exactKeys j "entry" ["kind", "digest"]; pure (.put (← gN j "digest"))
  | "restore" => exactKeys j "entry" ["kind", "restore"]; pure (.restore (← restoreOf (← field j "restore")))
  | "release" => exactKeys j "entry" ["kind", "eid", "g"]; pure (.release (← gN j "eid") (← gN j "g"))
  | k => throw s!"unknown entry kind {k}"

def entryJson : Entry → Json
  | .bind nf e => Json.mkObj [("kind", "bind"), ("nf", jNat nf), ("e", jNat e)]
  | .put d => Json.mkObj [("kind", "put"), ("digest", jNat d)]
  | .restore r => Json.mkObj [("kind", "restore"), ("restore", restoreJson r)]
  | .release e g => Json.mkObj [("kind", "release"), ("eid", jNat e), ("g", jNat g)]

def leafOf (k : String) : Json → Except String (Nat × Outcome) := asPair k (asNat k) (asEnum k outcomes)
def leafJson : Nat × Outcome → Json := jPair jNat (fun o => toJson (enumName outcomes o))

def seatRootOf (j : Json) : Except String (Nat × List Entry) := asPair "seat_roots" (asNat "seat") (asList "log" entryOf) j

def cpKeys : List String := ["seq", "epoch", "board_height", "board_root", "witness_root", "pools", "settle_root",
  "bf_root", "boot_counters", "restart_seq", "seat_roots", "restores"]

def cpOf (j : Json) : Except String Cp := do
  exactKeys j "checkpoint" cpKeys
  pure { seq := ← gN j "seq", epoch := ← gN j "epoch", boardHeight := ← gN j "board_height",
         boardRoot := ← gN j "board_root", witnessRoot := ← gN j "witness_root", pools := ← gL j "pools" poolOfJ,
         settle := ← gL j "settle_root" (leafOf "settle_root"), bf := ← gL j "bf_root" (nn "bf_root"),
         bootCounters := ← gL j "boot_counters" (nn "boot_counters"), restartSeq := ← gN j "restart_seq",
         seatRoots := ← gL j "seat_roots" seatRootOf, restores := ← gL j "restores" restoreOf }

def cpJson (c : Cp) : Json :=
  Json.mkObj [("seq", jNat c.seq), ("epoch", jNat c.epoch), ("board_height", jNat c.boardHeight),
    ("board_root", jNat c.boardRoot), ("witness_root", jNat c.witnessRoot), ("pools", jList poolJson c.pools),
    ("settle_root", jList leafJson c.settle), ("bf_root", jList jnn c.bf), ("boot_counters", jList jnn c.bootCounters),
    ("restart_seq", jNat c.restartSeq), ("seat_roots", jList (jPair jNat (jList entryJson)) c.seatRoots),
    ("restores", jList restoreJson c.restores)]

def aslotOf (j : Json) : Except String ASlot := do
  match j with
  | .str "free" => pure .free
  | .str "burned" => pure .burned
  | _ => exactKeys j "slot" ["bound"]; pure (.bound (← gN j "bound"))

def aslotJson : ASlot → Json
  | .free => "free"
  | .burned => "burned"
  | .bound d => Json.mkObj [("bound", jNat d)]

def acctOf (j : Json) : Except String Acct := do
  exactKeys j "account" ["id", "slots", "mark", "refill"]
  pure { id := ← gN j "id", slots := ← gL j "slots" aslotOf, mark := ← gN j "mark", refill := ← gB j "refill" }

def acctJson (a : Acct) : Json :=
  Json.mkObj [("id", jNat a.id), ("slots", jList aslotJson a.slots), ("mark", jNat a.mark), ("refill", toJson a.refill)]

def writeOf (j : Json) : Except String Write := do
  match j with
  | .str "checkpoint" => pure .checkpoint
  | .str "event" => pure .event
  | _ => exactKeys j "write" ["eks"]; pure (.eks (← gN j "eks"))

def writeJson : Write → Json
  | .checkpoint => "checkpoint"
  | .event => "event"
  | .eks e => Json.mkObj [("eks", jNat e)]

def rangeOf (k : String) (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j k ["pool", "lo", "hi"]
  pure (← gN j "pool", ← gN j "lo", ← gN j "hi")

def rangeJson (r : Nat × Nat × Nat) : Json := Json.mkObj [("pool", jNat r.1), ("lo", jNat r.2.1), ("hi", jNat r.2.2)]

def sessionOf (j : Json) : Except String (Nat × List (Nat × Nat × Nat)) :=
  asPair "sessions" (asNat "pool") (asList "burned" (rangeOf "range")) j

def stKeys : List String := ["params", "chain", "last_land_mh", "recovered", "writes", "ready", "tickets", "burn",
  "accounts", "sessions", "restart_open", "marker_prev", "marker_landed", "pending_restores", "board_restores", "cold_started", "new_pool"]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("chain", jList cpJson s.chain), ("last_land_mh", jNat s.lastLandMh),
    ("recovered", toJson s.recovered), ("writes", jList writeJson s.writes), ("ready", toJson s.ready),
    ("tickets", jList jnn s.tickets), ("burn", jList rangeJson s.burnC), ("accounts", jList acctJson s.accts),
    ("sessions", jList (jPair jNat (jList rangeJson)) s.sessions), ("restart_open", toJson s.restartOpen),
    ("marker_prev", jNat s.markerPrev), ("marker_landed", toJson s.markerLanded),
    ("pending_restores", jList restoreJson s.pendingRestores),
    ("board_restores", jList restoreJson s.board), ("cold_started", toJson s.coldStarted),
    ("new_pool", toJson s.newPool)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" stKeys
  pure { params := ← paramsOf (← field j "params"), chain := ← gL j "chain" cpOf, lastLandMh := ← gN j "last_land_mh",
         recovered := ← gB j "recovered", writes := ← gL j "writes" writeOf, ready := ← gB j "ready",
         tickets := ← gL j "tickets" (nn "tickets"), burnC := ← gL j "burn" (rangeOf "range"),
         accts := ← gL j "accounts" acctOf, sessions := ← gL j "sessions" sessionOf,
         restartOpen := ← gB j "restart_open", markerPrev := ← gN j "marker_prev",
         markerLanded := ← gB j "marker_landed", pendingRestores := ← gL j "pending_restores" restoreOf,
         board := ← gL j "board_restores" restoreOf,
         coldStarted := ← gB j "cold_started", newPool := ← gB j "new_pool" }

def covOf (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j "covered" ["account", "slot", "d"]
  pure (← gN j "account", ← gN j "slot", ← gN j "d")

def reshareOf (j : Json) : Except String (Nat × Nat × Bool × Bool) := do
  exactKeys j "slot" ["seat", "slot", "covered", "log_read"]
  pure (← gN j "seat", ← gN j "slot", ← gB j "covered", ← gB j "log_read")

def opOf (j : Json) : Except String Op := do
  let ks (l : List String) := exactKeys j "op" ("op" :: l)
  match ← gS j "op" with
  | "land" => ks ["checkpoint", "midnight_height"]; pure (.land (← cpOf (← field j "checkpoint")) (← gN j "midnight_height"))
  | "boot" => ks []; pure .boot
  | "read_ledger" =>
    ks ["ok", "tickets", "covered"]
    pure (.readLedger (← gB j "ok") (← gL j "tickets" (nn "tickets")) (← gL j "covered" covOf))
  | "open_session" => ks ["pool"]; pure (.openSession (← gN j "pool"))
  | "open_account" => ks ["account"]; pure (.openAcct (← acctOf (← field j "account")))
  | "bind_account" => ks ["account", "slot", "d"]; pure (.bindAcct (← gN j "account") (← gN j "slot") (← gN j "d"))
  | "restore_done" => ks ["restore"]; pure (.restoreDone (← restoreOf (← field j "restore")))
  | "lose_tail" => ks []; pure .loseTail
  | "recover" => ks ["midnight_height"]; pure (.recover (← gN j "midnight_height"))
  | "cold_start" => ks ["intact", "signers"]; pure (.coldStart (← gN j "intact") (← gN j "signers"))
  | "eks" => ks ["epoch", "acks", "sigs"]; pure (.eks (← gN j "epoch") (← gL j "acks" (asNat "acks")) (← gN j "sigs"))
  | "non_tee_restart" => ks []; pure .nonTeeRestart
  | "sign_bf" => ks ["leaves"]; pure (.signBf (← gL j "leaves" (nn "leaves")))
  | "sign_settle" =>
    ks ["leaves", "ended", "midnight_void"]
    pure (.signSettle (← gL j "leaves" (leafOf "leaves")) (← gL j "ended" (leafOf "ended"))
      (← gL j "midnight_void" (asNat "midnight_void")))
  | "sign_pending" => ks ["pool", "live"]; pure (.signPending (← poolOfJ (← field j "pool")) (← gL j "live" (asNat "live")))
  | "sign_seat_root" => ks ["log"]; pure (.signSeatRoot (← gL j "log" entryOf))
  | "order_request" =>
    ks ["order_height", "peer_heights", "proof"]
    pure (.orderReq (← gN j "order_height") (← gL j "peer_heights" (asNat "peer_heights")) (← gB j "proof"))
  | "covered" => ks ["height"]; pure (.covered (← gN j "height"))
  | "release_anchor" => ks ["anchor", "entry_height"]; pure (.releaseAnchor (← gB j "anchor") (← gN j "entry_height"))
  | "reshare" => ks ["slots"]; pure (.reshare (← gL j "slots" reshareOf))
  | "due" => ks ["last", "now"]; pure (.due (← gN j "last") (← gN j "now"))
  | "may_reboot" => ks []; pure .mayReboot
  | o => throw s!"unknown op {o}"

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .ok => Json.mkObj [("ok", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .bool b => Json.mkObj [("bool", toJson b)]
  | .slots xs => Json.mkObj [("slots", jList jnn xs)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "ops"]
  let p ← paramsOf (← field inputs "params")
  let ops ← gL inputs "ops" opOf
  if !paramsOk p then return refusedAnswer [Refusal.outsideCapability.code]
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
