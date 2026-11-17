import SplitCodec.Json
import PassportShard.Spec

/-!
# Passport shard oracle executable

* default: one `kink-implementation/1` request with
  `inputs = {"cfg", "d0", "ops"}`. A configuration outside PS-002 or PS-003
  gives `{"end": "could-not-apply", "reason": CODES}`. Otherwise the answer is
  `{"end": "final", "cells": {"state", "obs"}}`: the end state of `runOps` from
  `init` and one observation for each operation. A refused operation is the
  observation `{"refused": CODES}`, leaves the state unchanged, and the run
  goes on.
* `--step`: JSON Lines `{"state", "op"}` to `{"state", "obs"}`; a refused
  operation gives `{"refused": CODES}`; a state outside `validState` gives
  `{"refused": ["outside-state-domain"]}`; a line that does not decode gives
  `{"error": TEXT}`.

The codec holds no spec logic: every code comes from `Refusal.code`, and every
transition from `apply`. Each list of the state is a set (SHARD-SPEC.md
section 3). The codec removes duplicates when it decodes and writes each set in
ascending order.
-/

open Lean SplitCodec PassportShard

/-! ## Sets as sorted arrays -/

def lexLe : List Nat → List Nat → Bool
  | [], _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLe as bs)

def canon {α : Type} [BEq α] (key : α → List Nat) (xs : List α) : List α :=
  (xs.eraseDups).mergeSort (fun a b => lexLe (key a) (key b))

def kN (n : Nat) : List Nat := [n]
def kP (p : Nat × Nat) : List Nat := [p.1, p.2]
def kT (p : Nat × Nat × Nat) : List Nat := [p.1, p.2.1, p.2.2]

def jSetN (xs : List Nat) : Json := jList jNat (canon kN xs)
def jSetP (xs : List (Nat × Nat)) : Json :=
  jList (fun p => Json.arr #[jNat p.1, jNat p.2]) (canon kP xs)
def jSetT (xs : List (Nat × Nat × Nat)) : Json :=
  jList (fun p => Json.arr #[jNat p.1, jNat p.2.1, jNat p.2.2]) (canon kT xs)

def asP (k : String) : Json → Except String (Nat × Nat) := asPair k (asNat k) (asNat k)

def asT (k : String) : Json → Except String (Nat × Nat × Nat)
  | .arr a =>
    if h : a.size = 3 then do pure (← asNat k a[0], ← asNat k a[1], ← asNat k a[2])
    else throw s!"{k}: not a triple"
  | v => throw s!"{k}: not a triple: {v.compress}"

def gSetN (j : Json) (k : String) : Except String (List Nat) := do
  pure (canon kN (← gL j k (asNat k)))
def gSetP (j : Json) (k : String) : Except String (List (Nat × Nat)) := do
  pure (canon kP (← gL j k (asP k)))
def gSetT (j : Json) (k : String) : Except String (List (Nat × Nat × Nat)) := do
  pure (canon kT (← gL j k (asT k)))

/-! ## Configuration and state -/

def cfgKeys : List String := ["quorum", "n_guard", "native", "synced", "overlap"]

def cfgOf (j : Json) : Except String Cfg := do
  exactKeys j "cfg" cfgKeys
  pure { quorum := ← gN j "quorum", nGuard := ← gN j "n_guard", native := ← gSetN j "native",
         synced := ← gSetN j "synced", overlap := ← gSetN j "overlap" }

def cfgJson (c : Cfg) : Json :=
  Json.mkObj [("quorum", jNat c.quorum), ("n_guard", jNat c.nGuard), ("native", jSetN c.native),
    ("synced", jSetN c.synced), ("overlap", jSetN c.overlap)]

def pendingOf (j : Json) : Except String (Nat × Bool) := do
  exactKeys j "pending" ["succ", "adv"]
  pure (← gN j "succ", ← gB j "adv")

def pendingJson (p : Nat × Bool) : Json :=
  Json.mkObj [("succ", jNat p.1), ("adv", toJson p.2)]

def stateKeys : List String :=
  ["cfg", "readers", "creds", "r_wrap", "r_wrap_ever", "pending", "unlock_log", "prf_log",
   "approved", "asserts", "hijacked", "authorized", "used_nf", "sigs", "adv_root", "adv_xf",
   "via_origin_leak", "via_recovery_leak", "via_theft", "via_provider", "via_quorum",
   "adv_cred", "adv_guard", "origin_corrupt", "committee_corrupt", "e_corrupt", "epoch"]

def viaOf (ol rl th pr : List Nat) (q : Bool) : List Via :=
  ol.map .originLeak ++ rl.map .recoveryLeak ++ th.map .theft ++ pr.map .provider ++
  (if q then [.quorum] else [])

def viaPick (f : Via → Option Nat) (vs : List Via) : List Nat := vs.filterMap f

def stateOf (j : Json) : Except String St := do
  exactKeys j "state" stateKeys
  let via := viaOf (← gSetN j "via_origin_leak") (← gSetN j "via_recovery_leak")
    (← gSetN j "via_theft") (← gSetN j "via_provider") (← gB j "via_quorum")
  pure { cfg := ← cfgOf (← field j "cfg"), readers := ← gSetN j "readers",
         creds := ← gSetN j "creds", rWrap := ← gB j "r_wrap", rWrapEver := ← gB j "r_wrap_ever",
         pending := ← gO j "pending" pendingOf, unlockLog := ← gSetP j "unlock_log",
         prfLog := ← gSetN j "prf_log", approved := ← gSetT j "approved",
         asserts := ← gSetT j "asserts", hijacked := ← gSetT j "hijacked",
         authorized := ← gSetP j "authorized",
         usedNf := ← gSetN j "used_nf", sigs := ← gSetN j "sigs", advRoot := ← gB j "adv_root",
         advXf := ← gB j "adv_xf", via := via, advCred := ← gSetN j "adv_cred",
         advGuard := ← gSetN j "adv_guard", originCorrupt := ← gB j "origin_corrupt",
         committeeCorrupt := ← gB j "committee_corrupt", eCorrupt := ← gB j "e_corrupt",
         epoch := ← gN j "epoch" }

def stateJson (s : St) : Json :=
  Json.mkObj [
    ("cfg", cfgJson s.cfg), ("readers", jSetN s.readers), ("creds", jSetN s.creds),
    ("r_wrap", toJson s.rWrap), ("r_wrap_ever", toJson s.rWrapEver),
    ("pending", jOpt pendingJson s.pending), ("unlock_log", jSetP s.unlockLog),
    ("prf_log", jSetN s.prfLog), ("approved", jSetT s.approved), ("asserts", jSetT s.asserts),
    ("hijacked", jSetT s.hijacked),
    ("authorized", jSetP s.authorized), ("used_nf", jSetN s.usedNf), ("sigs", jSetN s.sigs),
    ("adv_root", toJson s.advRoot), ("adv_xf", toJson s.advXf),
    ("via_origin_leak", jSetN (viaPick (fun | .originLeak d => some d | _ => none) s.via)),
    ("via_recovery_leak", jSetN (viaPick (fun | .recoveryLeak d => some d | _ => none) s.via)),
    ("via_theft", jSetN (viaPick (fun | .theft d => some d | _ => none) s.via)),
    ("via_provider", jSetN (viaPick (fun | .provider d => some d | _ => none) s.via)),
    ("via_quorum", toJson (s.via.contains .quorum)),
    ("adv_cred", jSetN s.advCred), ("adv_guard", jSetN s.advGuard),
    ("origin_corrupt", toJson s.originCorrupt),
    ("committee_corrupt", toJson s.committeeCorrupt), ("e_corrupt", toJson s.eCorrupt),
    ("epoch", jNat s.epoch)]

/-! ## Operations -/

def opOf (j : Json) : Except String Op := do
  let ek := exactKeys j "op"
  match ← gS j "op" with
  | "ENROLL" => ek ["op", "by", "d"]; pure (.enroll (← gN j "by") (← gN j "d"))
  | "UNLOCK" => ek ["op", "d", "ic"]; pure (.unlock (← gN j "d") (← gN j "ic"))
  | "APPROVE" =>
    ek ["op", "d", "ic", "nf"]; pure (.approve (← gN j "d") (← gN j "ic") (← gN j "nf"))
  | "AUTHORIZE" =>
    ek ["op", "d", "ic", "nf"]; pure (.authorize (← gN j "d") (← gN j "ic") (← gN j "nf"))
  | "RELEASE" => ek ["op", "ic", "nf"]; pure (.release (← gN j "ic") (← gN j "nf"))
  | "REMOVE_DEVICE" => ek ["op", "by", "d"]; pure (.removeDevice (← gN j "by") (← gN j "d"))
  | "PUBLISH_RWRAP" => ek ["op", "by"]; pure (.publishRWrap (← gN j "by"))
  | "RECOVER_SUBMIT" => ek ["op", "succ"]; pure (.recoverSubmit (← gN j "succ"))
  | "RECOVER_CANCEL" => ek ["op", "by"]; pure (.recoverCancel (← gN j "by"))
  | "RECOVER_FINALISE" => ek ["op"]; pure .recoverFinalise
  | "ADV_RECOVER_SUBMIT" => ek ["op", "succ"]; pure (.advRecoverSubmit (← gN j "succ"))
  | "E_REPROVISION" => ek ["op"]; pure .eReprovision
  | "CORRUPT_COMMITTEE" => ek ["op"]; pure .corruptCommittee
  | "CORRUPT_E" => ek ["op"]; pure .corruptE
  | "CORRUPT_ORIGIN" => ek ["op"]; pure .corruptOrigin
  | "CORRUPT_GUARDIAN" => ek ["op", "g"]; pure (.corruptGuardian (← gN j "g"))
  | "STEAL_DEVICE" =>
    ek ["op", "d", "unlocked"]; pure (.stealDevice (← gN j "d") (← gB j "unlocked"))
  | "PROVIDER_TAKEOVER" => ek ["op", "d"]; pure (.providerTakeover (← gN j "d"))
  | "ADV_ASSERT" =>
    ek ["op", "d", "ic", "nf"]; pure (.advAssert (← gN j "d") (← gN j "ic") (← gN j "nf"))
  | "ORIGIN_ASSERT" =>
    ek ["op", "d", "ic", "nf"]; pure (.originAssert (← gN j "d") (← gN j "ic") (← gN j "nf"))
  | "ADV_SIGN" => ek ["op", "ic"]; pure (.advSign (← gN j "ic"))
  | o => throw s!"unknown op {o}"

/-! ## Answers -/

def codes (rs : List Refusal) : List String :=
  ((rs.map Refusal.code).toArray.qsort (· < ·)).toList

def refusedJson (rs : List Refusal) : Json :=
  Json.mkObj [("refused", toJson (codes rs))]

def accepted : Json := Json.mkObj [("accepted", toJson true)]

def obsOf (s : St) (op : Op) : Json :=
  match refusals s op with
  | [] => accepted
  | rs => refusedJson rs

def runObs (s : St) : List Op → St × List Json
  | [] => (s, [])
  | op :: ops =>
    let (s', os) := runObs (apply s op) ops
    (s', obsOf s op :: os)

def oracle : Oracle where
  answer := fun inputs => do
    exactKeys inputs "inputs" ["cfg", "d0", "ops"]
    let c ← cfgOf (← field inputs "cfg")
    let d0 ← gN inputs "d0"
    let ops ← gL inputs "ops" opOf
    match cfgRefusals c with
    | [] =>
      let (s, obs) := runObs (init c d0) ops
      pure (finalAnswer (Json.mkObj [("state", stateJson s), ("obs", Json.arr obs.toArray)]))
    | rs => pure (refusedAnswer (codes rs))
  step := fun line => do
    exactKeys line "step" ["state", "op"]
    let s ← stateOf (← field line "state")
    let op ← opOf (← field line "op")
    if !validState s then pure (refusedJson [.outsideStateDomain])
    else match refusals s op with
      | [] => pure (Json.mkObj [("state", stateJson (apply s op)), ("obs", accepted)])
      | rs => pure (refusedJson rs)

def main (args : List String) : IO UInt32 := SplitCodec.main oracle args
