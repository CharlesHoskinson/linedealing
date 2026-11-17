import SplitCodec.Json
import SplitHandoff.Spec

/-!
# Handoff oracle executable

* default: one `kink-implementation/1` request with
  `inputs = {"params", "genesis", "ops"}`. A genesis outside the domain gives
  `{"end": "could-not-apply", "reason": "outside-capability"}`. Otherwise the answer is
  `{"end": "final", "cells": {"state", "obs"}}`: the end state of `runOps` from `init` and
  one observation per operation. A refused operation is the observation
  `{"refused": CODES}`, leaves the state unchanged, and the run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused operation gives
  `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives `{"error": TEXT}`.

The codec holds no spec logic: every code comes from `Refusal.code` and every transition
from `apply`.
-/

open Lean SplitCodec SplitHandoff

def curves : List (String × Curve) := [("secp", .secp), ("ed", .ed)]
def statuses : List (String × EStatus) := [("current", .current), ("grace", .grace), ("closed", .closed)]
def phases : List (String × Phase) :=
  [("IDLE", .IDLE), ("QUEUED", .QUEUED), ("ROTATING", .ROTATING), ("ARMED", .ARMED),
   ("HANDED_OVER", .HANDED_OVER), ("ABORTED", .ABORTED)]
def actors : List (String × Actor) :=
  [("governance", .governance), ("source", .source), ("target", .target), ("seat", .seat),
   ("board", .board), ("contract", .contract), ("time", .time), ("user", .user)]

def nn (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)
def jnn : Nat × Nat → Json := jPair jNat jNat
def natsOf (j : Json) (k : String) : Except String (List Nat) := gL j k (asNat k)
def jNats (l : List Nat) : Json := jList jNat l

def xfOf (j : Json) : Except String XF := do
  exactKeys j "xf" ["secp", "ed"]
  pure { secp := ← gN j "secp", ed := ← gN j "ed" }
def xfJson (x : XF) : Json := Json.mkObj [("secp", jNat x.secp), ("ed", jNat x.ed)]

def userOf (j : Json) : Except String User := do
  exactKeys j "user" ["id", "shard", "tweak", "pool", "sealed", "slot_root", "asset"]
  pure { id := ← gN j "id", shard := ← gN j "shard", tweak := ← gN j "tweak", pool := ← gN j "pool",
         sealed := ← gN j "sealed", slotRoot := ← gN j "slot_root", asset := ← gN j "asset" }
def userJson (u : User) : Json :=
  Json.mkObj [("id", jNat u.id), ("shard", jNat u.shard), ("tweak", jNat u.tweak), ("pool", jNat u.pool),
    ("sealed", jNat u.sealed), ("slot_root", jNat u.slotRoot), ("asset", jNat u.asset)]

def addrOf (j : Json) : Except String Addr := do
  exactKeys j "addr" ["id", "curve", "user", "shard", "ecdsa", "slots"]
  pure { id := ← gN j "id", curve := ← gE j "curve" curves, user := ← gN j "user", shard := ← gN j "shard",
         ecdsa := ← gB j "ecdsa", slots := ← natsOf j "slots" }
def addrJson (a : Addr) : Json :=
  Json.mkObj [("id", jNat a.id), ("curve", toJson (enumName curves a.curve)), ("user", jNat a.user),
    ("shard", jNat a.shard), ("ecdsa", toJson a.ecdsa), ("slots", jNats a.slots)]

def secretOf (j : Json) : Except String SecretId := do
  match ← gS j "kind" with
  | "xf" => exactKeys j "secret" ["kind", "curve"]; pure (.xf (← gE j "curve" curves))
  | "slot" => exactKeys j "secret" ["kind", "a", "i"]; pure (.slot (← gN j "a") (← gN j "i"))
  | k => throw s!"secret: unknown kind {k}"
def secretJson : SecretId → Json
  | .xf c => Json.mkObj [("kind", "xf"), ("curve", toJson (enumName curves c))]
  | .slot a i => Json.mkObj [("kind", "slot"), ("a", jNat a), ("i", jNat i)]

def slotStOf (j : Json) : Except String SlotSt := do
  match ← gS j "kind" with
  | "free" => exactKeys j "st" ["kind"]; pure .free
  | "bound" => exactKeys j "st" ["kind", "tk"]; pure (.bound (← gN j "tk"))
  | "burned" => exactKeys j "st" ["kind"]; pure .burned
  | k => throw s!"st: unknown kind {k}"
def slotStJson : SlotSt → Json
  | .free => Json.mkObj [("kind", "free")]
  | .bound tk => Json.mkObj [("kind", "bound"), ("tk", jNat tk)]
  | .burned => Json.mkObj [("kind", "burned")]

def sharingOf (j : Json) : Except String Sharing := do
  exactKeys j "sharing" ["secret", "const", "epoch", "holders", "st"]
  pure { secret := ← secretOf (← field j "secret"), const := ← gN j "const", epoch := ← gN j "epoch",
         holders := ← natsOf j "holders", st := ← slotStOf (← field j "st") }
def sharingJson (s : Sharing) : Json :=
  Json.mkObj [("secret", secretJson s.secret), ("const", jNat s.const), ("epoch", jNat s.epoch),
    ("holders", jNats s.holders), ("st", slotStJson s.st)]

def epochOf (j : Json) : Except String EpochRec := do
  exactKeys j "epoch" ["id", "roster", "n", "f", "q", "t", "status", "grace_end", "swept"]
  pure { id := ← gN j "id", roster := ← natsOf j "roster", n := ← gN j "n", f := ← gN j "f", q := ← gN j "q",
         t := ← gN j "t", status := ← gE j "status" statuses, graceEnd := ← gN j "grace_end",
         swept := ← gB j "swept" }
def epochJson (r : EpochRec) : Json :=
  Json.mkObj [("id", jNat r.id), ("roster", jNats r.roster), ("n", jNat r.n), ("f", jNat r.f), ("q", jNat r.q),
    ("t", jNat r.t), ("status", toJson (enumName statuses r.status)), ("grace_end", jNat r.graceEnd),
    ("swept", toJson r.swept)]

def rotateOf (j : Json) : Except String Rotate := do
  exactKeys j "rotate" ["target", "source", "roster", "n", "f", "q", "t", "emergency", "sigs"]
  pure { target := ← gN j "target", source := ← gN j "source", roster := ← natsOf j "roster", n := ← gN j "n",
         f := ← gN j "f", q := ← gN j "q", t := ← gN j "t", emergency := ← gB j "emergency", sigs := ← gN j "sigs" }
def rotateJson (r : Rotate) : Json :=
  Json.mkObj [("target", jNat r.target), ("source", jNat r.source), ("roster", jNats r.roster), ("n", jNat r.n),
    ("f", jNat r.f), ("q", jNat r.q), ("t", jNat r.t), ("emergency", toJson r.emergency), ("sigs", jNat r.sigs)]

def readyOf (j : Json) : Except String (Nat × List Nat × Nat) := do
  exactKeys j "ready" ["seat", "q", "h_s"]
  pure (← gN j "seat", ← natsOf j "q", ← gN j "h_s")
def readyJson (r : Nat × List Nat × Nat) : Json :=
  Json.mkObj [("seat", jNat r.1), ("q", jNats r.2.1), ("h_s", jNat r.2.2)]

def hoOf (j : Json) : Except String Handoff := do
  exactKeys j "ho" ["phase", "rotate", "src_roster", "t_q", "m_r", "m_d", "eks", "dealt", "disq", "readys",
    "last_batch", "H"]
  pure { phase := ← gE j "phase" phases, rot := ← rotateOf (← field j "rotate"), srcRoster := ← natsOf j "src_roster",
         tQ := ← gN j "t_q", mR := ← gN j "m_r", mD := ← gN j "m_d", eks := ← gB j "eks",
         dealt := ← gL j "dealt" (nn "dealt"), disq := ← natsOf j "disq", readys := ← gL j "readys" readyOf,
         lastBatch := ← gN j "last_batch", H := ← gN j "H" }
def hoJson (h : Handoff) : Json :=
  Json.mkObj [("phase", toJson (enumName phases h.phase)), ("rotate", rotateJson h.rot),
    ("src_roster", jNats h.srcRoster), ("t_q", jNat h.tQ), ("m_r", jNat h.mR), ("m_d", jNat h.mD),
    ("eks", toJson h.eks), ("dealt", jList jnn h.dealt), ("disq", jNats h.disq), ("readys", jList readyJson h.readys),
    ("last_batch", jNat h.lastBatch), ("H", jNat h.H)]

def reqOf (j : Json) : Except String Req := do
  exactKeys j "request" ["id", "bind", "sweep", "live", "slots"]
  pure { id := ← gN j "id", bind := ← gN j "bind", sweep := ← gO j "sweep" (asNat "sweep"), live := ← gB j "live",
         slots := ← gL j "slots" (nn "slots") }
def reqJson (r : Req) : Json :=
  Json.mkObj [("id", jNat r.id), ("bind", jNat r.bind), ("sweep", jOpt jNat r.sweep), ("live", toJson r.live),
    ("slots", jList jnn r.slots)]

def boardOf (j : Json) : Except String ((Nat × Nat) × SlotSt) := do
  exactKeys j "board" ["slot", "st"]
  pure (← nn "slot" (← field j "slot"), ← slotStOf (← field j "st"))
def boardJson (b : (Nat × Nat) × SlotSt) : Json := Json.mkObj [("slot", jnn b.1), ("st", slotStJson b.2)]

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["delta_rot", "delta_grace", "delta_sweep", "delta_cw"]
  pure { deltaRot := ← gN j "delta_rot", deltaGrace := ← gN j "delta_grace", deltaSweep := ← gN j "delta_sweep",
         deltaCw := ← gN j "delta_cw" }
def paramsJson (p : Params) : Json :=
  Json.mkObj [("delta_rot", jNat p.deltaRot), ("delta_grace", jNat p.deltaGrace),
    ("delta_sweep", jNat p.deltaSweep), ("delta_cw", jNat p.deltaCw)]

def genesisOf (j : Json) : Except String Genesis := do
  exactKeys j "genesis" ["roster", "n", "f", "q", "t", "xf", "users", "addrs"]
  pure { roster := ← natsOf j "roster", n := ← gN j "n", f := ← gN j "f", q := ← gN j "q", t := ← gN j "t",
         xf := ← xfOf (← field j "xf"), users := ← gL j "users" userOf, addrs := ← gL j "addrs" addrOf }

def stKeys : List String :=
  ["params", "mh", "pos", "cur", "epochs", "sharings", "ho", "requests", "board", "xf", "users", "addrs",
   "handovers", "landed", "restart", "pending"]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("mh", jNat s.mh), ("pos", jNat s.pos), ("cur", jNat s.cur),
    ("epochs", jList epochJson s.epochs), ("sharings", jList sharingJson s.sharings), ("ho", hoJson s.ho),
    ("requests", jList reqJson s.requests), ("board", jList boardJson s.board), ("xf", xfJson s.xf),
    ("users", jList userJson s.users), ("addrs", jList addrJson s.addrs), ("handovers", jList jnn s.handovers),
    ("landed", jNat s.landed), ("restart", toJson s.restart), ("pending", jNats s.pending)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" stKeys
  pure { params := ← paramsOf (← field j "params"), mh := ← gN j "mh", pos := ← gN j "pos", cur := ← gN j "cur",
         epochs := ← gL j "epochs" epochOf, sharings := ← gL j "sharings" sharingOf, ho := ← hoOf (← field j "ho"),
         requests := ← gL j "requests" reqOf, board := ← gL j "board" boardOf, xf := ← xfOf (← field j "xf"),
         users := ← gL j "users" userOf, addrs := ← gL j "addrs" addrOf, handovers := ← gL j "handovers" (nn "handovers"),
         landed := ← gN j "landed", restart := ← gB j "restart", pending := ← natsOf j "pending" }

def actOf (j : Json) : Except String Act := do
  let ks (l : List String) : Except String Unit := exactKeys j "op" (["op", "actor"] ++ l)
  match ← gS j "op" with
  | "rotate" => ks ["rotate"]; pure (.rotate (← rotateOf (← field j "rotate")))
  | "eks" => ks []; pure .eks
  | "carry" => ks ["dealer", "ok"]; pure (.carry (← gN j "dealer") (← gB j "ok"))
  | "complaint" => ks ["dealer"]; pure (.complaint (← gN j "dealer"))
  | "ready" => ks ["seat", "q", "h_s"]; pure (.ready (← gN j "seat") (← natsOf j "q") (← gN j "h_s"))
  | "arm" => ks ["sigs"]; pure (.arm (← gN j "sigs"))
  | "activate" =>
    ks ["gov", "sigs", "heartbeat", "boots", "disjoint"]
    pure (.activate (← gB j "gov") (← gN j "sigs") (← gB j "heartbeat") (← gB j "boots") (← gB j "disjoint"))
  | "midnight_tick" => ks ["m"]; pure (.midnightTick (← gN j "m"))
  | "block" => ks []; pure .block
  | "restart_begin" => ks []; pure .restartBegin
  | "restart_end" => ks []; pure .restartEnd
  | "admit_boot" => ks ["seat", "with_rotate"]; pure (.admitBoot (← gN j "seat") (← gB j "with_rotate"))
  | "order" => ks ["rid", "bind", "slots"]; pure (.order (← gN j "rid") (← gN j "bind") (← gL j "slots" (nn "slots")))
  | "end_req" => ks ["rid"]; pure (.endReq (← gN j "rid"))
  | "use_slot" => ks ["rid", "a", "i", "tk"]; pure (.useSlot (← gN j "rid") (← gN j "a") (← gN j "i") (← gN j "tk"))
  | "sweep_ready" => ks ["e"]; pure (.sweepReady (← gN j "e"))
  | "entry" => ks ["rid", "e"]; pure (.entry (← gN j "rid") (← gN j "e"))
  | "header" => ks ["rid", "pool_epoch"]; pure (.header (← gN j "rid") (← gN j "pool_epoch"))
  | "envelope" => ks ["e"]; pure (.envelope (← gN j "e"))
  | "sign_checkpoint" => ks ["e", "board_height"]; pure (.signCheckpoint (← gN j "e") (← gN j "board_height"))
  | "submit_checkpoint" => ks ["e", "sigs"]; pure (.submitCheckpoint (← gN j "e") (← gN j "sigs"))
  | "cert" => ks ["e"]; pure (.cert (← gN j "e"))
  | "user_ack" => ks ["u"]; pure (.userAck (← gN j "u"))
  | o => throw s!"unknown op {o}"

def opOf (j : Json) : Except String Op := do
  pure { actor := ← gE j "actor" actors, act := ← actOf j }

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .ok => Json.mkObj [("ok", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "genesis", "ops"]
  let p ← paramsOf (← field inputs "params")
  let g ← genesisOf (← field inputs "genesis")
  let ops ← gL inputs "ops" opOf
  if !decide (validGenesis g) then return refusedAnswer [Refusal.outsideCapability.code]
  let (s, os) := runOps (init p g) ops
  pure (finalAnswer (Json.mkObj [("state", stJson s), ("obs", jList obsJson os)]))

def step (j : Json) : Except String Json := do
  exactKeys j "line" ["state", "op"]
  let s ← stOf (← field j "state")
  let op ← opOf (← field j "op")
  if !validState s then return Json.mkObj [("refused", codes [.outsideStateDomain])]
  match apply s op with
  | (_, .refused rs) => pure (Json.mkObj [("refused", codes rs)])
  | (s', o) => pure (Json.mkObj [("state", stJson s'), ("obs", obsJson o)])

def main (args : List String) : IO UInt32 := SplitCodec.main { answer, step } args
