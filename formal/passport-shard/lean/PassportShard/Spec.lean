/-!
# Passport shard placement: the executable spec

Source: `research/passport-fit/SHARD-SPEC.md` (requirements PS-001 to PS-067).
This module imports no `Lean.*` module. It holds every transition and every
refusal. `Main.lean` holds only the codec.

The model is symbolic. A secret is never a number: the state records who
holds it. Each cryptographic primitive is an abstract, sound primitive, and
each one is a named hypothesis (SHARD-SPEC.md section 6). A hypothesis appears
here as the one rule that lets a party learn a secret or produce an object:

* `H-WRAP`   a wrap of the shard root opens only with its reader key
             (`prfEval`, `quorumRule`, `effect .stealDevice`).
* `H-PRF`    a reader key comes only from a PRF evaluation of its credential,
             and the authenticator performs user verification for it
             (`prfEval`, `effect .stealDevice`). The holder of a synced
             credential evaluates the PRF with no user verification
             (`effect .providerTakeover`).
* `H-PAGE`   the PRF output of a web reader reaches the wallet origin (`leak`).
* `H-SHAMIR` fewer than `quorum` guardians learn nothing about the recovery
             secret (`quorumRule`).
* `H-CONTRIB` a contribution for an intent needs the shard root
             (`refusals .release`, `refusals .advSign`: `noContribution`).
* `H-SIG`    a signature needs a contribution for its intent and the committee
             half: an honest release or the knowledge of `x_f`
             (`refusals .release`, `refusals .advSign`).
* `H-ES256`  an assertion over a challenge needs the credential and its user
             verification (`refusals .approve`, `refusals .advAssert`).
* `H-BLIND`  the authenticator does not show the intent to the user: a
             corrupt origin sets the challenge of an approval on a web
             credential (`effect .originAssert`).
* `H-BIND`   the challenge `H(charter_id, ic, nf)` is injective: an assertion
             is the triple `(d, ic, nf)` (`refusals .authorize`).
* `H-MIDNIGHT` Midnight accepts one `authorize` for each `nf`
             (`refusals .authorize`: `nfUsed`).
-/

namespace PassportShard

/-- How the adversary came to hold the shard root. -/
inductive Via where
  | originLeak (d : Nat)    -- PS-012: a web reader's unlock on a corrupt origin
  | recoveryLeak (d : Nat)  -- PS-037: an honest recovery on a corrupt origin
  | theft (d : Nat)         -- PS-062: an unlocked stolen reader
  | provider (d : Nat)      -- PS-063: the provider of a synced passkey reader
  | quorum                  -- PS-046: a corrupt guardian quorum and a recovery wrap
  deriving DecidableEq, Repr

/-- The account configuration. It never changes (PS-001). -/
structure Cfg where
  quorum : Nat         -- guardians needed to rebuild the recovery secret
  nGuard : Nat         -- guardian ids are `0 .. nGuard - 1`
  native : List Nat    -- readers held by a device enclave key (never by a web page)
  synced : List Nat    -- credentials that a passkey provider syncs
  overlap : List Nat   -- guardians that a committee operator or a member of E runs
  deriving DecidableEq, Repr

structure St where
  cfg : Cfg
  readers : List Nat                    -- devices with a wrap of the root in the inbox
  creds : List Nat                      -- credentials enrolled in the charter
  rWrap : Bool                          -- a recovery wrap of the current session exists
  rWrapEver : Bool                      -- a recovery wrap was published at some time
  pending : Option (Nat × Bool)         -- pending recovery: successor, adversarial
  unlockLog : List (Nat × Nat)          -- (d, ic): a contribution dealt for intent ic
  prfLog : List Nat                     -- user-verified PRF evaluations, by reader
  approved : List (Nat × Nat × Nat)     -- (d, ic, nf): assertions the user approved
  asserts : List (Nat × Nat × Nat)      -- (d, ic, nf): every assertion that exists
  hijacked : List (Nat × Nat × Nat)     -- (d, ic, nf): approvals whose challenge the origin set
  authorized : List (Nat × Nat)         -- (ic, nf): authorizations in force
  usedNf : List Nat
  sigs : List Nat                       -- intents with a complete signature
  advRoot : Bool                        -- the adversary holds the shard root
  advXf : Bool                          -- the adversary holds the committee half
  via : List Via
  advCred : List Nat                    -- credentials the adversary can assert with
  advGuard : List Nat                   -- corrupt guardians
  originCorrupt : Bool
  committeeCorrupt : Bool               -- the current committee is fully corrupt
  eCorrupt : Bool                       -- three members of E are corrupt
  epoch : Nat
  deriving DecidableEq, Repr

/-- The closed set of refusals. -/
inductive Refusal where
  | notEnrolled | alreadyEnrolled | noWrap | noAssertion | nfUsed
  | committeeCorrupt | notAuthorized | noContribution | selfRemoval
  | noRecoveryWrap | recoveryPending | noPending | noQuorum
  | unknownGuardian | alreadyCorrupt | notSynced | unknownDevice
  | noCredential | noCommitteeHalf | originHonest | nativeCredential
  | pendingSuccessor
  | badQuorum | guardianOverlap | outsideStateDomain
  deriving DecidableEq, Repr

def Refusal.code : Refusal → String
  | .notEnrolled => "not-enrolled"
  | .alreadyEnrolled => "already-enrolled"
  | .noWrap => "no-wrap"
  | .noAssertion => "no-assertion"
  | .nfUsed => "nf-used"
  | .committeeCorrupt => "committee-corrupt"
  | .notAuthorized => "not-authorized"
  | .noContribution => "no-contribution"
  | .selfRemoval => "self-removal"
  | .noRecoveryWrap => "no-recovery-wrap"
  | .recoveryPending => "recovery-pending"
  | .noPending => "no-pending"
  | .noQuorum => "no-quorum"
  | .unknownGuardian => "unknown-guardian"
  | .alreadyCorrupt => "already-corrupt"
  | .notSynced => "not-synced"
  | .unknownDevice => "unknown-device"
  | .noCredential => "no-credential"
  | .noCommitteeHalf => "no-committee-half"
  | .originHonest => "origin-honest"
  | .nativeCredential => "native-credential"
  | .pendingSuccessor => "pending-successor"
  | .badQuorum => "bad-quorum"
  | .guardianOverlap => "guardian-overlap"
  | .outsideStateDomain => "outside-state-domain"

inductive Op where
  | enroll (by_ d : Nat)            -- PS-006, PS-007, PS-067
  | unlock (d ic : Nat)             -- PS-010 to PS-013
  | approve (d ic nf : Nat)         -- PS-016, PS-017
  | authorize (d ic nf : Nat)       -- PS-018 to PS-021
  | release (ic nf : Nat)           -- PS-022 to PS-025
  | removeDevice (by_ d : Nat)      -- PS-008, PS-009
  | publishRWrap (by_ : Nat)        -- PS-030, PS-031
  | recoverSubmit (succ : Nat)      -- PS-032, PS-033
  | recoverCancel (by_ : Nat)       -- PS-034, PS-035
  | recoverFinalise                 -- PS-036 to PS-039
  | advRecoverSubmit (succ : Nat)   -- PS-040, PS-041
  | eReprovision                    -- PS-042
  | corruptCommittee                -- PS-043
  | corruptE                        -- PS-044
  | corruptOrigin                   -- PS-045
  | corruptGuardian (g : Nat)       -- PS-046, PS-047, PS-061
  | stealDevice (d : Nat) (unlocked : Bool)  -- PS-048 to PS-050, PS-062
  | providerTakeover (d : Nat)      -- PS-051, PS-052, PS-063
  | advAssert (d ic nf : Nat)       -- PS-053, PS-054
  | originAssert (d ic nf : Nat)    -- PS-065, PS-066
  | advSign (ic : Nat)              -- PS-055, PS-056
  deriving DecidableEq, Repr

/-! ## Configuration and the initial state -/

/-- PS-002, PS-003: the refusals of a configuration. -/
def cfgRefusals (c : Cfg) : List Refusal :=
  (if 1 ≤ c.quorum ∧ c.quorum ≤ c.nGuard then [] else [.badQuorum]) ++
  (if c.overlap = [] then [] else [.guardianOverlap])

/-- PS-002, PS-003: the domain of configurations. -/
def validCfg (c : Cfg) : Bool := decide (cfgRefusals c = [])

/-- PS-004: the account after creation on device `d0`. The creation is one
user-verified PRF evaluation on `d0`. -/
def init (c : Cfg) (d0 : Nat) : St :=
  { cfg := c, readers := [d0], creds := [d0], rWrap := false, rWrapEver := false,
    pending := none, unlockLog := [], prfLog := [d0], approved := [], asserts := [], hijacked := [],
    authorized := [], usedNf := [], sigs := [], advRoot := false, advXf := false,
    via := [], advCred := [], advGuard := [], originCorrupt := false,
    committeeCorrupt := false, eCorrupt := false, epoch := 0 }

/-- PS-005: the state domain that `--step` accepts. It is not reachability. -/
def validState (s : St) : Bool := validCfg s.cfg

/-! ## Helpers (the hypotheses) -/

/-- `H-CONTRIB`: a contribution for `ic` was dealt by a user-verified unlock. -/
def hasUnlock (s : St) (ic : Nat) : Bool := s.unlockLog.any (fun p => p.2 == ic)

/-- `H-PAGE` (PS-012, PS-037): the root reaches a corrupt origin when a reader
that is not native handles it. -/
def leak (s : St) (d : Nat) (v : Via) : St :=
  if s.originCorrupt && !decide (d ∈ s.cfg.native) then
    { s with advRoot := true, via := v :: s.via }
  else s

/-- `H-PRF`, `H-WRAP` (PS-011): one user-verified PRF evaluation on reader `d`
unwraps the root on that device. -/
def prfEval (s : St) (d : Nat) : St :=
  leak { s with prfLog := d :: s.prfLog } d (.originLeak d)

/-- `H-SHAMIR`, `H-WRAP` (PS-046): a corrupt quorum opens every recovery wrap
ever published. -/
def quorumRule (s : St) : St :=
  if s.rWrapEver && decide (s.cfg.quorum ≤ s.advGuard.length) then
    { s with advRoot := true, via := .quorum :: s.via }
  else s

def chk (c : Bool) (r : Refusal) : List Refusal := if c then [] else [r]

def fresh (s : St) (d : Nat) : Bool := decide (d ∉ s.creds) && decide (d ∉ s.readers)

/-- PS-067: `d` is not the successor of the pending recovery. -/
def notPendingSucc (s : St) (d : Nat) : Bool :=
  match s.pending with
  | some (p, _) => p != d
  | none => true

def known (s : St) (d : Nat) : Bool := decide (d ∈ s.readers) || decide (d ∈ s.creds)

/-! ## Refusals and effects -/

/-- The refusals of one operation in one state. Where several apply, all are
returned (no order is specified). -/
def refusals (s : St) : Op → List Refusal
  | .enroll b d =>            -- PS-007, PS-067
    chk (decide (b ∈ s.creds)) .notEnrolled ++ chk (decide (b ∈ s.readers)) .noWrap ++
    chk (fresh s d) .alreadyEnrolled ++ chk (notPendingSucc s d) .pendingSuccessor
  | .unlock d _ =>            -- PS-013
    chk (decide (d ∈ s.creds)) .notEnrolled ++ chk (decide (d ∈ s.readers)) .noWrap
  | .approve d _ _ =>         -- PS-017
    chk (decide (d ∈ s.creds)) .notEnrolled
  | .authorize d ic nf =>     -- PS-019, PS-020, PS-021
    chk (decide ((d, ic, nf) ∈ s.asserts)) .noAssertion ++
    chk (decide (d ∈ s.creds)) .notEnrolled ++ chk (decide (nf ∉ s.usedNf)) .nfUsed
  | .release ic nf =>         -- PS-023, PS-024, PS-025
    chk (!s.committeeCorrupt) .committeeCorrupt ++
    chk (decide ((ic, nf) ∈ s.authorized)) .notAuthorized ++
    chk (hasUnlock s ic || s.advRoot) .noContribution
  | .removeDevice b d =>      -- PS-009
    chk (decide (b ∈ s.creds)) .notEnrolled ++ chk (decide (d ∈ s.creds)) .unknownDevice ++
    chk (decide (b ≠ d)) .selfRemoval
  | .publishRWrap b =>        -- PS-031
    chk (decide (b ∈ s.creds)) .notEnrolled ++ chk (decide (b ∈ s.readers)) .noWrap
  | .recoverSubmit succ =>    -- PS-033
    chk s.rWrap .noRecoveryWrap ++ chk s.pending.isNone .recoveryPending ++
    chk (fresh s succ) .alreadyEnrolled
  | .recoverCancel b =>       -- PS-035
    chk (decide (b ∈ s.creds)) .notEnrolled ++ chk s.pending.isSome .noPending
  | .recoverFinalise =>       -- PS-039
    chk s.pending.isSome .noPending
  | .advRecoverSubmit succ => -- PS-041
    chk (decide (s.cfg.quorum ≤ s.advGuard.length)) .noQuorum ++
    chk s.rWrap .noRecoveryWrap ++ chk s.pending.isNone .recoveryPending ++
    chk (fresh s succ) .alreadyEnrolled
  | .eReprovision => []
  | .corruptCommittee => []
  | .corruptE => []
  | .corruptOrigin => []
  | .corruptGuardian g =>     -- PS-047
    chk (decide (g < s.cfg.nGuard)) .unknownGuardian ++
    chk (decide (g ∉ s.advGuard)) .alreadyCorrupt
  | .stealDevice d _ =>       -- PS-050
    chk (known s d) .unknownDevice
  | .providerTakeover d =>    -- PS-052
    chk (decide (d ∈ s.cfg.synced)) .notSynced ++ chk (known s d) .unknownDevice
  | .advAssert d _ _ =>       -- PS-054
    chk (decide (d ∈ s.advCred)) .noCredential
  | .originAssert d _ _ =>    -- PS-066
    chk s.originCorrupt .originHonest ++ chk (decide (d ∈ s.creds)) .notEnrolled ++
    chk (decide (d ∉ s.cfg.native)) .nativeCredential
  | .advSign ic =>            -- PS-056
    chk s.advXf .noCommitteeHalf ++ chk (hasUnlock s ic || s.advRoot) .noContribution

/-- The state after an accepted operation. -/
def effect (s : St) : Op → St
  | .enroll b d =>            -- PS-006, PS-012
    let s1 := prfEval s b
    { s1 with creds := d :: s1.creds, readers := d :: s1.readers }
  | .unlock d ic =>           -- PS-010, PS-011, PS-012
    let s1 := prfEval s d
    { s1 with unlockLog := (d, ic) :: s1.unlockLog }
  | .approve d ic nf =>       -- PS-016
    { s with approved := (d, ic, nf) :: s.approved, asserts := (d, ic, nf) :: s.asserts }
  | .authorize _ ic nf =>     -- PS-018
    { s with authorized := (ic, nf) :: s.authorized, usedNf := nf :: s.usedNf }
  | .release ic _ =>          -- PS-022
    { s with sigs := ic :: s.sigs }
  | .removeDevice _ d =>      -- PS-008
    { s with creds := s.creds.filter (fun x => x != d) }
  | .publishRWrap b =>        -- PS-030, PS-012, PS-046
    quorumRule { (prfEval s b) with rWrap := true, rWrapEver := true }
  | .recoverSubmit succ =>    -- PS-032
    { s with pending := some (succ, false) }
  | .recoverCancel _ =>       -- PS-034
    { s with pending := none }
  | .recoverFinalise =>       -- PS-036, PS-037, PS-038
    match s.pending with
    | none => s
    | some (succ, adv) =>
      let s1 := { s with creds := [succ], readers := succ :: s.readers,
                         rWrap := false, pending := none }
      if adv then { s1 with advCred := succ :: s1.advCred }
      else leak s1 succ (.recoveryLeak succ)
  | .advRecoverSubmit succ => -- PS-040
    { s with pending := some (succ, true) }
  | .eReprovision =>          -- PS-042
    { s with committeeCorrupt := false, epoch := s.epoch + 1 }
  | .corruptCommittee =>      -- PS-043
    { s with committeeCorrupt := true, advXf := true }
  | .corruptE =>              -- PS-044
    { s with eCorrupt := true, advXf := true }
  | .corruptOrigin =>         -- PS-045
    { s with originCorrupt := true }
  | .corruptGuardian g =>     -- PS-061, PS-046
    quorumRule { s with advGuard := g :: s.advGuard }
  | .stealDevice d unlocked =>  -- PS-048, PS-049, PS-062
    if unlocked then
      let s1 := { s with advCred := d :: s.advCred }
      if decide (d ∈ s.readers) then
        { s1 with prfLog := d :: s1.prfLog, advRoot := true, via := .theft d :: s1.via }
      else s1
    else s
  | .providerTakeover d =>    -- PS-051, PS-063
    let s1 := { s with advCred := d :: s.advCred }
    if decide (d ∈ s.readers) && !decide (d ∈ s.cfg.native) then
      { s1 with advRoot := true, via := .provider d :: s1.via }
    else s1
  | .advAssert d ic nf =>     -- PS-053
    { s with asserts := (d, ic, nf) :: s.asserts }
  | .originAssert d ic nf =>  -- PS-065
    { s with hijacked := (d, ic, nf) :: s.hijacked, asserts := (d, ic, nf) :: s.asserts }
  | .advSign ic =>            -- PS-055
    { s with sigs := ic :: s.sigs }

/-- One operation. A refused operation leaves the state unchanged (PS-057).
`cfg` never changes (PS-001). -/
def apply (s : St) (op : Op) : St :=
  if refusals s op = [] then effect s op else s

/-- A run: the end state after a list of operations. -/
def runOps (s : St) : List Op → St
  | [] => s
  | op :: ops => runOps (apply s op) ops

/-- The states that a valid account reaches. -/
inductive Reach (c : Cfg) (d0 : Nat) : St → Prop where
  | init : Reach c d0 (init c d0)
  | step {s : St} (op : Op) : Reach c d0 s → Reach c d0 (apply s op)

end PassportShard
