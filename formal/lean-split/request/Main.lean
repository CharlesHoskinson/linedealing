import SplitCodec.Json
import SplitRequest.Spec

/-!
# Request oracle executable

* default: one `kink-implementation/1` request with
  `inputs = {"params", "epochs", "ops"}`. Parameters outside RQ-001 give
  `{"end": "could-not-apply", "reason": "outside-capability"}`. Otherwise the
  answer is `{"end": "final", "cells": {"state", "obs"}}`: the end state of
  `runOps` from `init` and one observation per operation. A refused operation
  is the observation `{"refused": CODES}` and changes nothing; the run goes on.
* `--step`: JSON Lines. A line `{"state", "op"}` is a board event and gets
  `{"state", "obs"}`; a line `{"node": {"state", "eid", "view"}}` asks for the
  acts of an honest node and gets `{"acts": [...]}`. A refused event gives
  `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: codes come from `Refusal.code`, transitions
from `apply`, node acts from `nodeAct`.
-/

open Lean SplitCodec SplitRequest

def modes : List (String × Mode) := [("TEE", .TEE), ("NON_TEE", .NON_TEE)]
def phases : List (String × Phase) :=
  [("POSTED", .POSTED), ("ORDERED", .ORDERED), ("OPENED", .OPENED), ("COLLECTING", .COLLECTING),
   ("ADMITTED", .ADMITTED), ("FINAL", .FINAL), ("VOID", .VOID), ("EXPIRED", .EXPIRED)]
def outcomes : List (String × Outcome) :=
  [("NONE", .NONE), ("FINAL", .FINAL), ("VOID", .VOID), ("RELEASED", .RELEASED)]
def reasons : List (String × Reason) :=
  [("NONE", .NONE), ("SHARE_COMPLAINT", .SHARE_COMPLAINT), ("MALFORMED", .MALFORMED),
   ("AUTH_REFUSED", .AUTH_REFUSED), ("REVOKED", .REVOKED), ("RELEASE_CHECK", .RELEASE_CHECK),
   ("CONTRIBUTION", .CONTRIBUTION), ("DEALER_FAULT", .DEALER_FAULT), ("PIN_SPENT", .PIN_SPENT),
   ("SLOT_TAKEN", .SLOT_TAKEN), ("STALLED", .STALLED), ("RESTART", .RESTART),
   ("MIXED", .MIXED)]
def rtypes : List (String × RType) :=
  [("SPEND", .SPEND), ("EXIT", .EXIT), ("SEIZURE", .SEIZURE), ("BIRTH", .BIRTH), ("REFILL", .REFILL),
   ("P0", .P0), ("CONTRIB", .CONTRIB)]
def profiles : List (String × Profile) := [("P0", .P0), ("P1", .P1), ("P2", .P2)]
def auths : List (String × AuthView) :=
  [("NOT_IN_FORCE", .notInForce), ("IN_FORCE", .inForce), ("REFUSED", .refused),
   ("IN_FORCE_MISMATCH", .inForceMismatch)]
def slotViews : List (String × SlotView) :=
  [("OK", .ok), ("SLOT_TAKEN", .taken), ("ABOVE_WINDOW", .aboveWindow), ("POOL_UNLISTED", .poolUnlisted)]
def hdrViews : List (String × HdrView) :=
  [("NOT_OPEN", .notOpen), ("OK", .ok), ("MALFORMED", .malformed), ("DEALER_FAULT", .dealerFault)]

def en {α : Type} [BEq α] (t : List (String × α)) (a : α) : Json := toJson (enumName t a)
def oN : Option Nat → Json := jOpt jNat
def gON (j : Json) (k : String) : Except String (Option Nat) := gO j k (asNat k)
def lN (k : String) : Json → Except String (List Nat) := asList k (asNat k)

def paramsOf (j : Json) : Except String Params := do
  exactKeys j "params" ["n", "f", "delta_c", "delta_hold", "mode"]
  pure { n := ← gN j "n", f := ← gN j "f", deltaC := ← gN j "delta_c", deltaHold := ← gN j "delta_hold",
         mode := ← gE j "mode" modes }

def paramsJson (p : Params) : Json :=
  Json.mkObj [("n", jNat p.n), ("f", jNat p.f), ("delta_c", jNat p.deltaC), ("delta_hold", jNat p.deltaHold),
    ("mode", en modes p.mode)]

def epochOfJ (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j "epoch" ["e", "n", "f"]
  pure (← gN j "e", ← gN j "n", ← gN j "f")
def epochJ (x : Nat × Nat × Nat) : Json := Json.mkObj [("e", jNat x.1), ("n", jNat x.2.1), ("f", jNat x.2.2)]

def frameOf (j : Json) : Except String Frame := do
  exactKeys j "frame" ["position", "token_ok", "lengths_ok", "height", "cid"]
  pure { position := ← gN j "position", tokenOk := ← gB j "token_ok", lengthsOk := ← gB j "lengths_ok",
         height := ← gN j "height", cid := ← gN j "cid" }
def frameJ (f : Frame) : Json :=
  Json.mkObj [("position", jNat f.position), ("token_ok", toJson f.tokenOk), ("lengths_ok", toJson f.lengthsOk),
    ("height", jNat f.height), ("cid", jNat f.cid)]

def vote2Of (j : Json) : Except String (Nat × Nat) := do
  exactKeys j "vote" ["node", "hash"]; pure (← gN j "node", ← gN j "hash")
def vote2J (x : Nat × Nat) : Json := Json.mkObj [("node", jNat x.1), ("hash", jNat x.2)]
def vote3Of (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j "vote" ["node", "hash", "h"]; pure (← gN j "node", ← gN j "hash", ← gN j "h")
def vote3J (x : Nat × Nat × Nat) : Json := Json.mkObj [("node", jNat x.1), ("hash", jNat x.2.1), ("h", jNat x.2.2)]
def finOf (j : Json) : Except String (Nat × Nat × Nat) := do
  exactKeys j "post" ["epoch", "member", "ct"]; pure (← gN j "epoch", ← gN j "member", ← gN j "ct")
def finJ (x : Nat × Nat × Nat) : Json := Json.mkObj [("epoch", jNat x.1), ("member", jNat x.2.1), ("ct", jNat x.2.2)]
def voidOf (j : Json) : Except String (Nat × Nat × Reason) := do
  exactKeys j "post" ["epoch", "member", "reason"]; pure (← gN j "epoch", ← gN j "member", ← gE j "reason" reasons)
def voidJ (x : Nat × Nat × Reason) : Json :=
  Json.mkObj [("epoch", jNat x.1), ("member", jNat x.2.1), ("reason", en reasons x.2.2)]

/-- RQ-067: `anchor[g]` and `released[g]` for `g ∈ 1..G`. -/
def gens (g : Nat) (a1 a2 : Option Nat) : Json := jList oN ([a1, a2].take g)
def gensOf (k : String) (j : Json) : Except String (Option Nat × Option Nat) := do
  let xs ← asList k (asOpt (asNat k)) j
  match xs with
  | [] => pure (none, none)
  | [a] => pure (a, none)
  | [a, b] => pure (a, b)
  | _ => throw s!"{k}: more than G_max entries"

def reqJ (r : Req) : Json :=
  Json.mkObj [("eid", jNat r.eid), ("epoch", jNat r.epoch), ("exp", jNat r.exp), ("type", en rtypes r.rtype),
    ("profile", en profiles r.profile), ("order_pos", oN r.orderPos), ("exp_c", oN r.expC),
    ("phase", en phases r.phase), ("reason", en reasons r.reason), ("collecting", toJson r.collecting),
    ("K", jNat r.K), ("L", jNat r.L), ("G", jNat r.G), ("anchor", gens r.G r.anchor1 r.anchor2),
    ("released", gens r.G r.released1 r.released2), ("any_release", toJson r.anyRelease),
    ("restart_end", toJson r.restartEnd), ("outcome", en outcomes r.outcome),
    ("rates", jList jNat r.rates), ("positions", jList oN r.positions), ("held", jList frameJ r.held),
    ("opened_votes", jList vote2J r.openedVotes), ("admit_votes", jList vote3J r.admitVotes),
    ("early_complaint", toJson r.earlyComplaint), ("dealer_fault", toJson r.dealerFault),
    ("final_posts", jList finJ r.finalPosts), ("void_posts", jList voidJ r.voidPosts),
    ("end_height", oN r.endHeight), ("confirmed", toJson r.confirmed), ("carried", toJson r.carried)]

def reqKeys : List String :=
  ["eid", "epoch", "exp", "type", "profile", "order_pos", "exp_c", "phase", "reason", "collecting", "K", "L",
   "G", "anchor", "released", "any_release", "restart_end", "outcome", "rates", "positions", "held",
   "opened_votes", "admit_votes", "early_complaint", "dealer_fault", "final_posts", "void_posts",
   "end_height", "confirmed", "carried"]

def reqOf (j : Json) : Except String Req := do
  exactKeys j "request" reqKeys
  let (a1, a2) ← gensOf "anchor" (← field j "anchor")
  let (r1, r2) ← gensOf "released" (← field j "released")
  pure { eid := ← gN j "eid", epoch := ← gN j "epoch", exp := ← gN j "exp", rtype := ← gE j "type" rtypes,
         profile := ← gE j "profile" profiles, orderPos := ← gON j "order_pos", expC := ← gON j "exp_c",
         phase := ← gE j "phase" phases, reason := ← gE j "reason" reasons, collecting := ← gB j "collecting",
         K := ← gN j "K", L := ← gN j "L", G := ← gN j "G", anchor1 := a1, anchor2 := a2, released1 := r1,
         released2 := r2, anyRelease := ← gB j "any_release", restartEnd := ← gB j "restart_end",
         outcome := ← gE j "outcome" outcomes, rates := ← gL j "rates" (asNat "rates"),
         positions := ← gL j "positions" (asOpt (asNat "positions")), held := ← gL j "held" frameOf,
         openedVotes := ← gL j "opened_votes" vote2Of, admitVotes := ← gL j "admit_votes" vote3Of,
         earlyComplaint := ← gB j "early_complaint", dealerFault := ← gB j "dealer_fault",
         finalPosts := ← gL j "final_posts" finOf, voidPosts := ← gL j "void_posts" voidOf,
         endHeight := ← gON j "end_height", confirmed := ← gB j "confirmed", carried := ← gB j "carried" }

def medOf (j : Json) : Except String (Nat × Nat) := do
  exactKeys j "median" ["h", "m"]; pure (← gN j "h", ← gN j "m")
def medJ (x : Nat × Nat) : Json := Json.mkObj [("h", jNat x.1), ("m", jNat x.2)]

def stJson (s : St) : Json :=
  Json.mkObj [("params", paramsJson s.ctx.params), ("height", jNat s.ctx.height),
    ("cp_height", jNat s.ctx.cpHeight), ("epochs", jList epochJ s.ctx.epochs),
    ("host_med", jList medJ s.ctx.hostMed), ("requests", jList reqJ s.reqs)]

def stOf (j : Json) : Except String St := do
  exactKeys j "state" ["params", "height", "cp_height", "epochs", "host_med", "requests"]
  pure { ctx := { params := ← paramsOf (← field j "params"), height := ← gN j "height",
                  cpHeight := ← gN j "cp_height", epochs := ← gL j "epochs" epochOfJ,
                  hostMed := ← gL j "host_med" medOf },
         reqs := ← gL j "requests" reqOf }

def opOf (j : Json) : Except String Op := do
  let k (ks : List String) := exactKeys j "op" ("op" :: ks)
  match ← gS j "op" with
  | "post" => k ["eid", "epoch", "exp", "type", "profile"]
              pure (.post (← gN j "eid") (← gN j "epoch") (← gN j "exp") (← gE j "type" rtypes) (← gE j "profile" profiles))
  | "order" => k ["eid", "qc", "p"]; pure (.order (← gN j "eid") (← gB j "qc") (← gN j "p"))
  | "open" => k ["eid", "K", "L", "collecting", "positions", "rates"]
              pure (.openHdr (← gN j "eid") (← gN j "K") (← gN j "L") (← gB j "collecting") (← gN j "positions")
                (← gL j "rates" (asNat "rates")))
  | "complaint" => k ["eid"]; pure (.complaint (← gN j "eid"))
  | "frame" => k ["eid", "frame"]; pure (.frame (← gN j "eid") (← frameOf (← field j "frame")))
  | "detach" => k ["eid", "position"]; pure (.detach (← gN j "eid") (← gN j "position"))
  | "vote_opened" => k ["eid", "node", "hash"]; pure (.voteOpened (← gN j "eid") (← gN j "node") (← gN j "hash"))
  | "vote_admit" => k ["eid", "node", "hash", "h"]
                    pure (.voteAdmit (← gN j "eid") (← gN j "node") (← gN j "hash") (← gN j "h"))
  | "obs2" => k ["eid", "gen1_missed", "heights"]
              pure (.obs2 (← gN j "eid") (← gB j "gen1_missed") (← gL j "heights" (asNat "heights")))
  | "release" => k ["eid", "g", "j"]; pure (.release (← gN j "eid") (← gN j "g") (← gN j "j"))
  | "post_final" => k ["eid", "epoch", "member", "ct"]
                    pure (.postFinal (← gN j "eid") (← gN j "epoch") (← gN j "member") (← gN j "ct"))
  | "post_void" => k ["eid", "epoch", "member", "reason"]
                   pure (.postVoid (← gN j "eid") (← gN j "epoch") (← gN j "member") (← gE j "reason" reasons))
  | "tick" => k ["height"]; pure (.tick (← gN j "height"))
  | "rotate" => k ["e", "n", "f"]; pure (.rotate (← gN j "e") (← gN j "n") (← gN j "f"))
  | "land_checkpoint" => k ["height"]; pure (.landCp (← gN j "height"))
  | "restart_burn" => k ["eid"]; pure (.restartBurn (← gN j "eid"))
  | "confirm" => k ["eid"]; pure (.confirm (← gN j "eid"))
  | "carry" => k ["eid"]; pure (.carry (← gN j "eid"))
  | "host_fee" => k ["h", "m"]; pure (.hostFee (← gN j "h") (← gN j "m"))
  | o => throw s!"unknown op {o}"

def viewOf (j : Json) : Except String View := do
  exactKeys j "view" ["share_ok", "sent_header", "hdr", "auth", "revoked_at", "mid_final", "obs_mid", "hold_age",
    "slots", "admission_ok", "voted_opened", "voted_admit", "rel_check", "acks", "bound", "sent_gens",
    "contrib_fail", "sees_confirm", "posted_final", "pin_spent", "settled", "signed_leaf"]
  let (o1, o2) ← asPair "obs_mid" (asNat "obs_mid") (asNat "obs_mid") (← field j "obs_mid")
  let (k1, k2) ← asPair "acks" (asNat "acks") (asNat "acks") (← field j "acks")
  pure { shareOk := ← gB j "share_ok", sentHeader := ← gB j "sent_header", hdr := ← gE j "hdr" hdrViews,
         auth := ← gE j "auth" auths, revokedAt := ← gON j "revoked_at", midFinal := ← gN j "mid_final",
         obsMid1 := o1, obsMid2 := o2, holdAge := ← gN j "hold_age", slots := ← gE j "slots" slotViews,
         admissionOk := ← gB j "admission_ok", votedOpened := ← gB j "voted_opened",
         votedAdmit := ← gB j "voted_admit", relCheck := ← gB j "rel_check", acks1 := k1, acks2 := k2,
         bound := ← gB j "bound", sentGens := ← gL j "sent_gens" (asNat "sent_gens"),
         contribFail := ← gB j "contrib_fail", seesConfirm := ← gB j "sees_confirm",
         postedFinal := ← gB j "posted_final", pinSpent := ← gB j "pin_spent", settled := ← gB j "settled",
         signedLeaf := ← gO j "signed_leaf" (asEnum "signed_leaf" outcomes) }

def actJ : Act → Json
  | .headerPartial => Json.mkObj [("act", "header_partial")]
  | .ack => Json.mkObj [("act", "ack")]
  | .complain => Json.mkObj [("act", "complaint")]
  | .voteOpened => Json.mkObj [("act", "vote_opened")]
  | .voteAdmit => Json.mkObj [("act", "vote_admit")]
  | .postVoid r => Json.mkObj [("act", "post_void"), ("reason", en reasons r)]
  | .release g j => Json.mkObj [("act", "release"), ("g", jNat g), ("j", jNat j)]
  | .recordRelease g j => Json.mkObj [("act", "release_record"), ("g", jNat g), ("j", jNat j)]
  | .evidence => Json.mkObj [("act", "failure_evidence")]
  | .postFinal => Json.mkObj [("act", "post_final")]
  | .signLeaf o => Json.mkObj [("act", "sign_leaf"), ("outcome", en outcomes o)]
  | .erase => Json.mkObj [("act", "erase")]
  | .handoff => Json.mkObj [("act", "handoff")]
  | .refuse c => Json.mkObj [("act", "refuse"), ("code", toJson c.code)]

def codes (rs : List Refusal) : Json := toJson (rs.map Refusal.code)

def obsJson : Obs → Json
  | .ok => Json.mkObj [("ok", true)]
  | .refused rs => Json.mkObj [("refused", codes rs)]
  | .phase p => Json.mkObj [("phase", en phases p)]

def answer (inputs : Json) : Except String Json := do
  exactKeys inputs "inputs" ["params", "epochs", "ops"]
  let p ← paramsOf (← field inputs "params")
  let es ← gL inputs "epochs" epochOfJ
  let ops ← gL inputs "ops" opOf
  match paramRefusals p es with
  | [] =>
    let (s, os) := runOps (init p es) ops
    pure (finalAnswer (Json.mkObj [("state", stJson s), ("obs", jList obsJson os)]))
  | rs => pure (refusedAnswer (rs.map Refusal.code))

def step (j : Json) : Except String Json := do
  let keys := ((← j.getObj?).toArray.map (·.1)).toList
  if keys == ["node"] then
    let n ← field j "node"
    exactKeys n "node" ["state", "eid", "view"]
    let s ← stOf (← field n "state")
    let e ← gN n "eid"
    let v ← viewOf (← field n "view")
    match stepRefusals s, find s e with
    | [], some r => pure (Json.mkObj [("acts", jList actJ (nodeAct s.ctx r v))])
    | [], none => pure (Json.mkObj [("refused", codes [.unknownRequest])])
    | rs, _ => pure (Json.mkObj [("refused", codes rs)])
  else
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
