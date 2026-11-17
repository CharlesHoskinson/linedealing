import SplitCodec.Json
import SplitShardHolders.Spec

/-!
# Shard-holder oracle executable

* default: one `kink-implementation/1` request with `inputs = {"params", "ops"}`.
  Parameters outside RQ-001 give `{"end": "could-not-apply", "reason":
  "outside-capability"}`. Otherwise the answer is `{"end": "final", "cells":
  {"state", "obs"}}`: the end state of `runOps` from `init` and one observation
  per operation. A refused operation is the observation `{"refused": CODES}`,
  leaves the state unchanged, and the run goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused
  operation gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: every code comes from `Refusal.code`, and every
transition from `apply`.
-/

open Lean SplitCodec SplitShardHolders

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def profiles : List (String × Profile) := [("P0", .P0), ("P1", .P1), ("P2", .P2)]

def nn (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)
def jnn : Nat × Nat → Json := jPair jNat jNat

partial def gateOf (j : Json) : Except String Gate := do
  match ← gS j "gate" with
  | "LEAF" => exactKeys j "gate" ["gate", "mid", "actor"]; pure (.leaf (← gN j "mid") (← gN j "actor"))
  | "AND" => exactKeys j "gate" ["gate", "mid", "children"]; pure (.and_ (← gN j "mid") (← gL j "children" gateOf))
  | "GROUP" =>
    exactKeys j "gate" ["gate", "mid", "k", "children"]
    pure (.group (← gN j "mid") (← gN j "k") (← gL j "children" gateOf))
  | "OR" =>
    exactKeys j "gate" ["gate", "mid", "primary", "escrow"]
    pure (.or_ (← gN j "mid") (← gateOf (← field j "primary")) (← gateOf (← field j "escrow")))
  | g => throw s!"unknown gate {g}"

partial def gateJson : Gate → Json
  | .leaf m a => Json.mkObj [("gate", "LEAF"), ("mid", jNat m), ("actor", jNat a)]
  | .and_ m cs => Json.mkObj [("gate", "AND"), ("mid", jNat m), ("children", jList gateJson cs)]
  | .group m k cs => Json.mkObj [("gate", "GROUP"), ("mid", jNat m), ("k", jNat k), ("children", jList gateJson cs)]
  | .or_ m p e => Json.mkObj [("gate", "OR"), ("mid", jNat m), ("primary", gateJson p), ("escrow", gateJson e)]

def qOf (j : Json) : Except String Q := do
  exactKeys j "weight" ["num", "den"]
  pure { num := ← gI j "num", den := ← gI j "den" }

def actorProofOf (j : Json) : Except String ActorProof := do
  exactKeys j "actor" ["slot", "x_a", "ctx", "valid", "network_created", "pop_U", "delta"]
  let ctx ← gL j "ctx" (asNat "ctx")
  match ctx with
  | [a, b, c, d, e] =>
    pure { slot := ← gN j "slot", xa := ← gN j "x_a", ctx := (a, b, c, d, e), valid := ← gB j "valid",
           netCreated := ← gB j "network_created", popU := ← gB j "pop_U", delta := ← gB j "delta" }
  | _ => throw "ctx: five numbers (X_f, X_a, slot_a, charter_id, chain_id)"

def birthOf (j : Json) : Except String BirthCheck := do
  exactKeys j "birth" ["x_f", "charter_id", "chain_id", "actors", "dealer_ok", "x_recomputed", "encoding_ok",
    "opening_ok"]
  pure { xf := ← gN j "x_f", charterId := ← gN j "charter_id", chainId := ← gN j "chain_id",
         actors := ← gL j "actors" actorProofOf, dealerOk := ← gB j "dealer_ok",
         xRecomputed := ← gB j "x_recomputed", encodingOk := ← gB j "encoding_ok", openingOk := ← gB j "opening_ok" }

def recordOf (j : Json) : Except String RecordReq := do
  exactKeys j "record" ["cm_addr", "profile", "charter", "signers", "owner_reg", "escrow_acks", "escrow_quorum",
    "guardian_acks", "q_g", "network_created"]
  pure { cm := ← gN j "cm_addr", profile := ← gE j "profile" profiles, charter := ← gN j "charter",
         signers := ← gL j "signers" (asNat "signers"), ownerReg := ← gB j "owner_reg",
         escrowAcks := ← gN j "escrow_acks", escrowQuorum := ← gN j "escrow_quorum",
         guardianAcks := ← gN j "guardian_acks", qg := ← gN j "q_g", netCreated := ← gB j "network_created" }

def ackOf (j : Json) : Except String AckCheck := do
  exactKeys j "ack" ["x_recomputed", "opening_ok", "pop_u"]
  pure { xRecomputed := ← gB j "x_recomputed", openingOk := ← gB j "opening_ok", popU := ← gB j "pop_u" }

def slotOf (j : Json) : Except String SlotRef := do
  match ← gS j "kind" with
  | "committee" => exactKeys j "slot" ["kind"]; pure .committee
  | "ecdsa" =>
    exactKeys j "slot" ["kind", "id", "leaf_set", "under_G"]
    pure (.ecdsa (← gN j "id") (← gL j "leaf_set" (asNat "leaf_set")) (← gB j "under_G"))
  | k => throw s!"unknown slot kind {k}"

def contribOf (j : Json) : Except String Contrib := do
  exactKeys j "request" ["actor", "charter", "S", "initiator", "weight", "pairs", "slot", "exp_c", "height",
    "policy_ok", "recompute_ok", "seizure_settled"]
  pure { actor := ← gN j "actor", charter := ← gN j "charter", S := ← gL j "S" (asNat "S"),
         initiator := ← gN j "initiator", weight := ← qOf (← field j "weight"),
         pairs := ← gL j "pairs" (asNat "pairs"), slot := ← slotOf (← field j "slot"), expC := ← gN j "exp_c",
         height := ← gN j "height", policyOk := ← gB j "policy_ok", recomputeOk := ← gB j "recompute_ok",
         seizureSettled := ← gB j "seizure_settled" }

def checkedSlot (j : Json) : Except String (Nat × Bool) := do
  exactKeys j "slot" ["slot", "check_ok"]
  pure (← gN j "slot", ← gB j "check_ok")

def opOf (j : Json) : Except String Op := do
  match ← gS j "op" with
  | "fix_charter" =>
    exactKeys j "op" ["op", "id", "gamma"]; pure (.fixCharter (← gN j "id") (← gateOf (← field j "gamma")))
  | "birth_check" =>
    exactKeys j "op" ["op", "node", "cm_addr", "birth"]
    pure (.birthCheck (← gN j "node") (← gN j "cm_addr") (← birthOf (← field j "birth")))
  | "submit_record" => exactKeys j "op" ["op", "record"]; pure (.submitRecord (← recordOf (← field j "record")))
  | "post_pool" =>
    exactKeys j "op" ["op", "actor", "root", "key"]
    pure (.postPool (← gN j "actor") (← gN j "root") (← gN j "key"))
  | "contribute" => exactKeys j "op" ["op", "request"]; pure (.contribute (← contribOf (← field j "request")))
  | "session" => exactKeys j "op" ["op", "slots"]; pure (.session (← gL j "slots" checkedSlot))
  | "put_shares" => exactKeys j "op" ["op", "slots"]; pure (.putShares (← gL j "slots" (asNat "slots")))
  | "holder_open" =>
    exactKeys j "op" ["op", "cm_addr", "x_match"]; pure (.holderOpen (← gN j "cm_addr") (← gB j "x_match"))
  | "ack_check" =>
    exactKeys j "op" ["op", "node", "cm_addr", "ack"]
    pure (.ackCheck (← gN j "node") (← gN j "cm_addr") (← ackOf (← field j "ack")))
  | "acknowledge" =>
    exactKeys j "op" ["op", "cm_addr", "signers"]
    pure (.acknowledge (← gN j "cm_addr") (← gL j "signers" (asNat "signers")))
  | "pay" => exactKeys j "op" ["op", "cm_addr"]; pure (.pay (← gN j "cm_addr"))
  | o => throw s!"unknown op {o}"

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["n", "f", "mode", "N_h"]
  pure { n := ← gN j "n", f := ← gN j "f", mode := ← gE j "mode" modes, nH := ← gN j "N_h" }

def paramsJson (p : Params) : Json :=
  Json.mkObj [("n", jNat p.n), ("f", jNat p.f), ("mode", toJson (enumName modes p.mode)), ("N_h", jNat p.nH)]

def recJson (r : Rec) : Json :=
  Json.mkObj [("cm_addr", jNat r.cm), ("profile", toJson (enumName profiles r.profile)), ("charter", jNat r.charter),
    ("sigs", jList jNat r.sigs), ("network_created", toJson r.netCreated), ("acked", toJson r.acked)]

def recOf (j : Json) : Except String Rec := do
  exactKeys j "record" ["cm_addr", "profile", "charter", "sigs", "network_created", "acked"]
  pure { cm := ← gN j "cm_addr", profile := ← gE j "profile" profiles, charter := ← gN j "charter",
         sigs := ← gL j "sigs" (asNat "sigs"), netCreated := ← gB j "network_created", acked := ← gB j "acked" }

def charterJson (x : Nat × Gate) : Json := Json.mkObj [("id", jNat x.1), ("gamma", gateJson x.2)]
def charterOfJ (j : Json) : Except String (Nat × Gate) := do
  exactKeys j "charter" ["id", "gamma"]
  pure (← gN j "id", ← gateOf (← field j "gamma"))

def keyJson (x : Nat × Nat × Nat) : Json := .arr #[jNat x.1, jNat x.2.1, jNat x.2.2]
def keyOf (j : Json) : Except String (Nat × Nat × Nat) := do
  match ← asList "pool_keys" (asNat "pool_keys") j with
  | [a, b, c] => pure (a, b, c)
  | _ => throw "pool_keys: three numbers"

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.params), ("charters", jList charterJson s.charters),
    ("birth_ok", jList jnn s.birthOk), ("records", jList recJson s.records), ("dealt", jList jnn s.dealt),
    ("used", jList jnn s.used), ("pool_keys", jList keyJson s.poolKeys), ("ecdsa_used", jList jnn s.ecdsaUsed),
    ("ack_ok", jList jnn s.ackOk)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" ["params", "charters", "birth_ok", "records", "dealt", "used", "pool_keys", "ecdsa_used",
    "ack_ok"]
  pure { params := ← paramsOf (← field j "params"), charters := ← gL j "charters" charterOfJ,
         birthOk := ← gL j "birth_ok" (nn "birth_ok"), records := ← gL j "records" recOf,
         dealt := ← gL j "dealt" (nn "dealt"), used := ← gL j "used" (nn "used"),
         poolKeys := ← gL j "pool_keys" keyOf, ecdsaUsed := ← gL j "ecdsa_used" (nn "ecdsa_used"),
         ackOk := ← gL j "ack_ok" (nn "ack_ok") }

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .ok => Json.mkObj [("ok", true)]
  | .birthOk => Json.mkObj [("birth_ok", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .contributed r => Json.mkObj [("contributed", Json.mkObj [("refill", toJson r)])]
  | .sessionEnd k c => Json.mkObj [("session", Json.mkObj [("kept", jList jNat k), ("complained", jList jNat c)])]
  | .puts es => Json.mkObj [("puts", jList jNat es)]
  | .ackEnvelope => Json.mkObj [("ack_envelope", true)]
  | .ackOk => Json.mkObj [("ack_ok", true)]
  | .paid => Json.mkObj [("paid", true)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "ops"]
  let p ← paramsOf (← field inputs "params")
  let ops ← gL inputs "ops" opOf
  match paramRefusals p with
  | [] =>
    let (s, os) := runOps (init p) ops
    pure (finalAnswer (Json.mkObj [("state", stJson s), ("obs", jList obsJson os)]))
  | rs => pure (refusedAnswer (rs.map Refusal.code))

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
