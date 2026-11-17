/-!
# Envelope oracle (split-envelope, EN-001 to EN-023)

The executable reference semantics of the OpenSpec capability `split-envelope`
(`openspec/changes/add-split-line-dealing/specs/split-envelope/spec.md`).

The state is one committee node's view of the board before order: the current
epochs with their key-list hashes, the board height, and the outer-dealing
digests of the envelopes it accepted. The operations are the arrival of an
envelope (the public checks EN-004 to EN-008 and the window check EN-023), a
board height, a change of the current epochs, and three checks that keep no
state: the window check again for the ordering block (EN-023), the header
checks (EN-009 to EN-013) and the PRF combination with its proof fallback
(EN-014).

Abstractions (formal plugin, practice 11):
* Hashes are collision free and are inputs. `hd` and `dd` are numbers. The
  envelope id `eid = H(hd ‖ auth_ref)` is the pair `(hd, auth_ref)`.
* The encryption proof `π` is the context it was made for (`proofCtx`) and a
  flag for the rest of its verification (`proofValid`).
* A partial's Chaum-Pedersen proof verifies exactly when the partial is the
  correct partial (soundness of the proof); a combination of `t` correct
  partials opens the AEAD tag exactly when the dealing is good (`dealingOk`).
* The layout geometry (a region that leaves the frame or overlaps the actor
  capsules, a length that disagrees with the header) is decoded outside the
  oracle and enters as two flags.
* The wallet's random bytes, its AEAD and KDF and the sealing of
  contributions (EN-015 to EN-019) are outside the state; the README lists them.
-/

namespace SplitEnvelope

/-! ## Domains -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq, BEq

/-- Signature suites: two Schnorr suites and ECDSA (EN-010, SL-001). -/
inductive Suite where
  | BIP340 | ED25519 | ECDSA
  deriving Repr, DecidableEq, BEq

def Suite.schnorr : Suite → Bool
  | .ECDSA => false
  | _ => true

/-- Request types (RQ-066); `CONTRIB` is type 0x06 (EN-018). The type lies in
`body_0` and is never read before order (EN-022). -/
inductive RType where
  | SPEND | EXIT | SEIZURE | BIRTH | REFILL | P0 | CONTRIB
  deriving Repr, DecidableEq, BEq

/-- EN-001: the one frame size of every envelope. -/
def frameSize : Nat := 16384

/-- EN-002: the public part is 96 bytes. -/
def publicSize : Nat := 96

/-- EN-002: the version byte. -/
def version1 : Nat := 1

/-- EN-002: the size class byte; the only class at launch. -/
def sizeClass0 : Nat := 0

/-- EN-020: every actor capsule is 385 bytes and holds `K_max = 8` capsule keys. -/
def capsuleSize : Nat := 385
def kMax : Nat := 8

/-- RQ-001 and RQ-067: `G_max = 2`, so `G = min(K, G_max)`. -/
def gMax : Nat := 2
def gOf (k : Nat) : Nat := min k gMax

/-- EN-002: the fields of the public part. `reserved` is the value of the 18
reserved bytes; no public check reads it (ledger 3). -/
structure PublicPart where
  version : Nat
  epoch : Nat
  keylistHash : Nat
  exp : Nat
  sizeClass : Nat
  authRef : Nat
  reserved : Nat
  deriving Repr, DecidableEq

/-- An envelope as a node receives it (EN-003, EN-004 to EN-008). `rtype` is the
request type inside `body_0`; no check before order reads it (EN-022). -/
structure Envelope where
  size : Nat
  pub : PublicPart
  hd : Nat
  dd : Nat
  proofCtx : Nat × Nat
  proofValid : Bool
  rtype : RType
  deriving Repr, DecidableEq

/-- EN-003: `eid = H(hd ‖ auth_ref)`. -/
def Envelope.eid (e : Envelope) : Nat × Nat := (e.hd, e.pub.authRef)

/-- What a node sees of an envelope before order: everything but the content of
`body_0` (EN-022, C10, C21). -/
def Envelope.publicView (e : Envelope) : Nat × PublicPart × Nat × Nat × (Nat × Nat) × Bool :=
  (e.size, e.pub, e.hd, e.dd, e.proofCtx, e.proofValid)

/-! ## State -/

/-- `mode` and the collection window `Δ_c` of RQ-001 (EN-021, EN-023). -/
structure Params where
  mode : Mode
  deltaC : Nat
  deriving Repr, DecidableEq

structure St where
  params : Params
  /-- the board height -/
  height : Nat
  /-- the current epochs, each with the hash of its `PK_i` list (EN-005) -/
  epochs : List (Nat × Nat)
  /-- `(epoch, dd)` of every accepted envelope, newest first (EN-008) -/
  seen : List (Nat × Nat)
  /-- `eid` of every accepted envelope, newest first (EN-003) -/
  accepted : List (Nat × Nat)
  deriving Repr, DecidableEq

def init (p : Params) (height : Nat) (epochs : List (Nat × Nat)) : St :=
  { params := p, height, epochs, seen := [], accepted := [] }

/-! ## Refusals

One constructor for each distinct response. The constructor order is the code
order, so a list built in constructor order is sorted. When several apply, the
spec gives no precedence, and the answer holds every code (ledger 1).

| Code | IDs |
|---|---|
| `bad_epoch` | EN-005 |
| `bad_proof` | EN-007 |
| `bad_shape` | EN-004 |
| `dd_reused` | EN-008 |
| `exp_c_not_below_exp` | EN-023 |
| `expired` | EN-006 |
| `no-rule` | an event that no requirement defines (ledger 2, 4) |
| `outside-capability` | a value outside a domain sentence (ledger 5) |
| `outside-state-domain` | a `--step` state outside `validState` |
-/

inductive Refusal where
  | badEpoch | badProof | badShape | ddReused | expCNotBelowExp | expired | noRule | outsideCapability | outsideStateDomain
  deriving Repr, DecidableEq, BEq

def Refusal.code : Refusal → String
  | .badEpoch => "bad_epoch"
  | .badProof => "bad_proof"
  | .badShape => "bad_shape"
  | .ddReused => "dd_reused"
  | .expCNotBelowExp => "exp_c_not_below_exp"
  | .expired => "expired"
  | .noRule => "no-rule"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

/-- EN-004: the frame size, `version` and `size_class`. -/
def badShape (e : Envelope) : Bool :=
  e.size != frameSize || e.pub.version != version1 || e.pub.sizeClass != sizeClass0

/-- EN-005: `epoch` is a current epoch and `keylist_hash` is the hash of its key list. -/
def badEpoch (s : St) (e : Envelope) : Bool :=
  !(s.epochs.contains (e.pub.epoch, e.pub.keylistHash))

/-- EN-006: the board height is above `exp`. -/
def expired (s : St) (e : Envelope) : Bool := decide (e.pub.exp < s.height)

/-- EN-007: `π` verifies for `eid = H(hd ‖ auth_ref)`. -/
def badProof (e : Envelope) : Bool := e.proofCtx != e.eid || !e.proofValid

/-- EN-008: an earlier accepted envelope of the same epoch has this `dd`. -/
def ddReused (s : St) (e : Envelope) : Bool := s.seen.contains (e.pub.epoch, e.dd)

/-- EN-021: `exp_c = b + Δ_c` lies below `exp`. -/
def windowInsideExpiry (b deltaC exp : Nat) : Bool := decide (b + deltaC < exp)

/-- EN-023 at acceptance: the earliest board height that can order the
envelope is the next block, `b = height + 1` (ledger 10); the node refuses the
envelope when `b + Δ_c ≥ exp`. -/
def windowBad (s : St) (e : Envelope) : Bool := !windowInsideExpiry (s.height + 1) s.params.deltaC e.pub.exp

/-- The public checks EN-004 to EN-008 and EN-023, in code order. -/
def publicRefusals (s : St) (e : Envelope) : List Refusal :=
  opt (badEpoch s e) .badEpoch ++ opt (badProof e) .badProof ++ opt (badShape e) .badShape
    ++ opt (ddReused s e) .ddReused ++ opt (windowBad s e) .expCNotBelowExp ++ opt (expired s e) .expired

/-! ## Header checks after order (EN-009 to EN-013) -/

/-- EN-009: the decoded layout block: `body_0`, 15 body regions and 8 capsule regions. -/
structure Layout where
  body0 : Nat
  bodies : List Nat
  capsules : List Nat
  deriving Repr, DecidableEq

/-- An opened header, as far as the checks of EN-009 to EN-013 read it.
`slots` lists the committee slots `ℓ(g, j)` as `(g, j, ℓ)`. -/
structure Header where
  suite : Suite
  K : Nat
  L : Nat
  tickets : Nat
  slots : List (Nat × Nat × Nat)
  rA : List Nat
  rEcdsa : List Nat
  pairs : List Nat
  layout : Layout
  nCapsules : Nat
  regionOutside : Bool
  lengthMismatch : Bool
  hasIc : Bool
  hasRtkc : Bool
  tkc : Nat
  authTkc : Nat
  recomputeMismatch : Bool
  deriving Repr, DecidableEq

/-- EN-016: the labels of the variant bodies. Schnorr: `(v, g)` for each variant
`v ≤ K` and generation `g ≤ min(v, G)`; ECDSA: one body `(v, 0)` per variant. -/
def bodyLabels (suite : Suite) (k : Nat) : List (Nat × Nat) :=
  if suite.schnorr then
    (List.range k).flatMap (fun i => (List.range (min (i + 1) (gOf k))).map (fun g => (i + 1, g + 1)))
  else (List.range k).map (fun i => (i + 1, 0))

/-- EN-010: `N_h = L·Σ_{v=1..K} min(v, G)` tickets on Schnorr suites, `K·L` on ECDSA. -/
def ticketCount (suite : Suite) (k l : Nat) : Nat :=
  if suite.schnorr then l * ((List.range k).map (fun i => min (i + 1) (gOf k))).sum else k * l

/-- EN-010: the grid `(g, j)` for `g ≤ G` and `j ≤ L`. -/
def slotGrid (k l : Nat) : List (Nat × Nat) :=
  (List.range (gOf k)).flatMap (fun g => (List.range l).map (fun j => (g + 1, j + 1)))

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

/-- Which requirement a malformed header fails. -/
inductive Fault where
  | en009 | en010 | en011 | en012 | en013
  deriving Repr, DecidableEq, BEq

def Fault.code : Fault → String
  | .en009 => "EN-009"
  | .en010 => "EN-010"
  | .en011 => "EN-011"
  | .en012 => "EN-012"
  | .en013 => "EN-013"

/-- EN-009: a nonzero unused entry, a region that leaves the frame or overlaps
the actor capsules, or a length that disagrees with the header. The used body
regions are the variant bodies of EN-016; the used capsule regions are the
first `nCapsules`. -/
def layoutBad (h : Header) : Bool :=
  let nb := (bodyLabels h.suite h.K).length
  (h.layout.bodies.drop nb).any (· != 0) || (h.layout.capsules.drop h.nCapsules).any (· != 0)
    || h.regionOutside || h.lengthMismatch

/-- EN-010: the ticket count, and on Schnorr suites one committee slot for every
`g ≤ G` and `j ≤ L` (exactly `G·L` slots). -/
def countBad (h : Header) : Bool :=
  h.tickets != ticketCount h.suite h.K h.L
    || (h.suite.schnorr &&
        (h.slots.length != (gOf h.K) * h.L
          || !((slotGrid h.K h.L).all (fun c => h.slots.any (fun x => (x.1, x.2.1) == c)))))

/-- EN-011: a repeated `R_A`, ECDSA `R_ℓ` or committee slot, or in TEE mode a
repeated actor pool pair. -/
def distinctBad (m : Mode) (h : Header) : Bool :=
  !nodupB h.rA || !nodupB h.rEcdsa || !nodupB (h.slots.map (·.2.2)) || (m == .TEE && !nodupB h.pairs)

/-- EN-012: `ic` and `r_tkc` present. The check is structural only (DECISIONS 68): the match of
`tkc` with the one that `auth` commits is the admission check of RQ-025, so `tkc` and
`authTkc` take no part in the opening checks. -/
def commitBad (h : Header) : Bool := !h.hasIc || !h.hasRtkc

/-- EN-013: in TEE mode, a recomputed sighash, `pm` or `c̃` differs from a ticket's own fields. -/
def recomputeBad (m : Mode) (h : Header) : Bool := m == .TEE && h.recomputeMismatch

/-- The requirements a header fails; the header is malformed exactly when the
list is not empty (EN-009 to EN-013; the request ends VOID by RQ-014). -/
def headerFaults (m : Mode) (h : Header) : List Fault :=
  (if layoutBad h then [.en009] else []) ++ (if countBad h then [.en010] else [])
    ++ (if distinctBad m h then [.en011] else []) ++ (if commitBad h then [.en012] else [])
    ++ (if recomputeBad m h then [.en013] else [])

/-- The domain of a header: `K ∈ 1..8` and `L ∈ 1..2` (RQ-067), a layout of
15 body and 8 capsule regions and at most 8 capsules (EN-009). A header outside
it is refused (ledger 5). -/
def headerInDomain (h : Header) : Bool :=
  decide (1 ≤ h.K) && decide (h.K ≤ kMax) && decide (1 ≤ h.L) && decide (h.L ≤ 2)
    && h.layout.bodies.length == 15 && h.layout.capsules.length == 8 && decide (h.nCapsules ≤ 8)

/-! ## PRF combination with the proof fallback (EN-014, RQ-015) -/

/-- A PRF partial of one label: its sender and whether its Chaum-Pedersen proof
verifies against the outer commitments. -/
structure Partial where
  sender : Nat
  proofOk : Bool
  deriving Repr, DecidableEq

inductive Combine where
  /-- the tag opens -/
  | opened
  /-- fewer than `t` partials (or proved partials) are at hand -/
  | needMore
  /-- `t` proved partials still fail the tag: RQ-015, VOID with reason DEALER_FAULT -/
  | dealerFault
  deriving Repr, DecidableEq, BEq

def Combine.code : Combine → String
  | .opened => "opened"
  | .needMore => "need_more"
  | .dealerFault => "dealer_fault"

/-- `t` partials open the tag exactly when the dealing is good and every one of them is correct. -/
def tagOpens (dealingOk : Bool) (ps : List Partial) : Bool := dealingOk && ps.all (·.proofOk)

/-- EN-014: combine the first `t` partials; if the tag fails, drop each partial
whose proof fails and combine the first `t` proved partials again. -/
def combine (t : Nat) (dealingOk : Bool) (ps : List Partial) : Combine :=
  if ps.length < t then .needMore
  else if tagOpens dealingOk (ps.take t) then .opened
  else
    let proved := ps.filter (·.proofOk)
    if proved.length < t then .needMore
    else if tagOpens dealingOk (proved.take t) then .opened
    else .dealerFault

/-! ## Wallet rules with a checkable form -/

/-- EN-018: the layout of a contribution frame has zero body and capsule lengths. -/
def contribLayout (body0 : Nat) : Layout :=
  { body0, bodies := List.replicate 15 0, capsules := List.replicate 8 0 }

/-! ## Operations -/

inductive Op where
  /-- an envelope reaches the node: the public checks EN-004 to EN-008 -/
  | submit (e : Envelope)
  /-- the board reaches height `h` -/
  | tick (h : Nat)
  /-- the current epochs and their key-list hashes (EN-005) -/
  | setEpochs (es : List (Nat × Nat))
  /-- EN-023 again for the ordering block: the envelope with `exp` would be
  ordered at board height `b` -/
  | orderCheck (exp b : Nat)
  /-- an opened header: the checks EN-009 to EN-013 -/
  | header (h : Header)
  /-- `t` and the partials of one label, in arrival order (EN-014) -/
  | combinePartials (t : Nat) (dealingOk : Bool) (ps : List Partial)
  deriving Repr, DecidableEq

inductive Obs where
  | accepted (eid : Nat × Nat)
  | refused (codes : List Refusal)
  | ok
  | faults (fs : List Fault)
  | combined (c : Combine)
  deriving Repr, DecidableEq

/-- The refusals of one operation. -/
def opRefusals (s : St) : Op → List Refusal
  | .submit e => publicRefusals s e
  -- the board height never goes down; the spec has no event for it (ledger 4)
  | .tick h => opt (decide (h < s.height)) .noRule
  | .setEpochs es => opt (!nodupB (es.map (·.1))) .outsideCapability
  -- EN-023: `b + Δ_c ≥ exp` is refused
  | .orderCheck x b => opt (!windowInsideExpiry b s.params.deltaC x) .expCNotBelowExp
  | .header h => opt (!headerInDomain h) .outsideCapability
  | .combinePartials t _ ps => opt (t == 0 || !nodupB (ps.map (·.sender))) .outsideCapability

/-- One operation that no refusal stops. -/
def exec (s : St) : Op → St × Obs
  -- EN-004 to EN-008 pass: the node accepts the envelope (RQ-003 adds the request)
  | .submit e => ({ s with seen := (e.pub.epoch, e.dd) :: s.seen, accepted := e.eid :: s.accepted },
                  .accepted e.eid)
  | .tick h => ({ s with height := h }, .ok)
  | .setEpochs es => ({ s with epochs := es }, .ok)
  -- EN-023: the window lies inside the expiry; the check keeps no state
  | .orderCheck _ _ => (s, .ok)
  -- EN-009 to EN-013: the header checks keep no state
  | .header h => (s, .faults (headerFaults s.params.mode h))
  -- EN-014: the combination keeps no state
  | .combinePartials t d ps => (s, .combined (combine t d ps))

/-- One operation: a refused operation leaves the state unchanged. -/
def apply (s : St) (op : Op) : St × Obs :=
  match opRefusals s op with
  | [] => exec s op
  | rs => (s, .refused rs)

/-- The end state and the observation of each operation. -/
def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s1, o) := apply s op
    let (s2, os) := runOps s1 ops
    (s2, o :: os)

def run (s : St) (ops : List Op) : St := (runOps s ops).1

/-- The state domain of `--step`: the accepted digests are distinct (EN-008) and
the epochs are distinct. It is not a reachability check. -/
def validState (s : St) : Bool := nodupB s.seen && nodupB (s.epochs.map (·.1))

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

/-! ## Theorems -/

theorem nodupB_cons {α : Type} [BEq α] (x : α) (xs : List α) :
    nodupB (x :: xs) = (!xs.contains x && nodupB xs) := rfl

/-- A refused operation leaves the state unchanged. -/
theorem apply_refused (s : St) (op : Op) (h : opRefusals s op ≠ []) : (apply s op).1 = s := by
  unfold apply; split
  · contradiction
  · rfl

/-- EN-004 to EN-008, EN-023 and C9: an accepted envelope passed every public
check, the window check among them. -/
theorem accepted_passed (s : St) (e : Envelope) (eid : Nat × Nat)
    (h : (apply s (.submit e)).2 = .accepted eid) :
    badShape e = false ∧ badEpoch s e = false ∧ expired s e = false ∧ badProof e = false
      ∧ ddReused s e = false ∧ windowBad s e = false := by
  unfold apply at h
  simp only [opRefusals] at h
  split at h
  · rename_i hr
    simp [publicRefusals, opt] at hr
    exact ⟨hr.2.2.1, hr.1, hr.2.2.2.2.2, hr.2.1, hr.2.2.2.1, hr.2.2.2.2.1⟩
  · simp at h

/-- EN-023, RQ-006: every envelope the node accepts gives `exp_c < exp` when
the next block orders it. -/
theorem en023_accepted_window (s : St) (e : Envelope) (eid : Nat × Nat)
    (h : (apply s (.submit e)).2 = .accepted eid) : s.height + 1 + s.params.deltaC < e.pub.exp := by
  have := (accepted_passed s e eid h).2.2.2.2.2
  simpa [windowBad, windowInsideExpiry] using this

/-- Every step keeps the accepted `(epoch, dd)` pairs distinct. -/
theorem apply_seen_nodup (s : St) (op : Op) (h : nodupB s.seen = true) :
    nodupB (apply s op).1.seen = true := by
  unfold apply
  split
  · rename_i hr
    cases op with
    | submit e =>
      simp only [exec, nodupB_cons]
      simp [opRefusals, publicRefusals, opt, ddReused] at hr
      simp [hr.2.2.2.1, h]
    | tick _ => exact h
    | setEpochs _ => exact h
    | orderCheck _ _ => exact h
    | header _ => exact h
    | combinePartials _ _ _ => exact h
  · exact h

theorem runOps_seen_nodup (s : St) (ops : List Op) (h : nodupB s.seen = true) :
    nodupB (runOps s ops).1.seen = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_seen_nodup s op h)

/-- C9 (EN-008): in every run from `init`, no two accepted envelopes of one epoch
share an outer dealing, so no release on one opens a label of another. -/
theorem C9_run_dd_unique (p : Params) (height : Nat) (epochs : List (Nat × Nat)) (ops : List Op) :
    nodupB (run (init p height epochs) ops).seen = true :=
  runOps_seen_nodup _ ops rfl

/-- C10 and C21 (EN-002, EN-018, EN-022): the answer of the public checks is a
function of the public view alone, so it is the same for every request type and
every content of `body_0`, the contribution frame included. -/
theorem C10_public_checks_blind (s : St) (e e' : Envelope) (h : e.publicView = e'.publicView) :
    publicRefusals s e = publicRefusals s e' := by
  obtain ⟨s1, p1, hd1, dd1, c1, v1, r1⟩ := e
  obtain ⟨s2, p2, hd2, dd2, c2, v2, r2⟩ := e'
  simp [Envelope.publicView] at h
  obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
  rfl

/-- C10 and C21 for whole runs: two operation lists that differ only in the
request types of their envelopes give the same states and observations. -/
def blindOp : Op → Op
  | .submit e => .submit { e with rtype := .SPEND }
  | op => op

theorem apply_blind (s : St) (op : Op) : apply s (blindOp op) = apply s op := by
  cases op with
  | submit e =>
    have hv : ({ e with rtype := .SPEND } : Envelope).publicView = e.publicView := rfl
    simp only [blindOp, apply, opRefusals]
    rw [C10_public_checks_blind s _ e hv]
    rfl
  | _ => rfl

theorem C21_run_blind (s : St) (ops : List Op) : runOps s (ops.map blindOp) = runOps s ops := by
  induction ops generalizing s with
  | nil => rfl
  | cons op ops ih => simp only [List.map, runOps, apply_blind, ih]

/-- EN-007 (DECISIONS 49): a party that rewrites `auth_ref` of a posted envelope
has no proof for the new `eid`. -/
theorem en007_rewrite_refused (s : St) (e : Envelope) (a : Nat) (ha : a ≠ e.pub.authRef)
    (hp : e.proofCtx = e.eid) :
    Refusal.badProof ∈ publicRefusals s { e with pub := { e.pub with authRef := a } } := by
  have : badProof { e with pub := { e.pub with authRef := a } } = true := by
    simp [badProof, Envelope.eid, hp] at *
    exact Or.inl (fun h => ha h.symm)
  simp [publicRefusals, opt, this]

/-- EN-017: for every `K ≤ 8` and every suite the variant bodies have distinct
labels, so each body key encrypts one body. -/
theorem en017_labels_distinct : ∀ k, k < 9 →
    nodupB (bodyLabels .BIP340 k) = true ∧ nodupB (bodyLabels .ED25519 k) = true
      ∧ nodupB (bodyLabels .ECDSA k) = true := by decide

/-- EN-014 and RQ-015: the combination ends in `dealerFault` only for a bad
dealing, and opens for a good dealing with `t` proved partials at hand. -/
theorem en014_fault_needs_bad_dealing (t : Nat) (d : Bool) (ps : List Partial)
    (h : combine t d ps = .dealerFault) : d = false := by
  unfold combine at h
  cases d with
  | false => rfl
  | true =>
    simp only [tagOpens, Bool.true_and] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · rename_i _ _ hl
          simp at h
          obtain ⟨x, hx, hf⟩ := h
          have := (List.mem_filter.mp (List.mem_of_mem_take hx)).2
          simp [hf] at this

theorem en014_opens_good_dealing (t : Nat) (ps : List Partial)
    (h : t ≤ (ps.filter (·.proofOk)).length) : combine t true ps = .opened := by
  unfold combine
  have hl : ¬ ps.length < t := by
    have := List.length_filter_le (·.proofOk) ps; omega
  simp only [hl, ite_false, tagOpens, Bool.true_and]
  split
  · rfl
  · have hn : ¬ (ps.filter (·.proofOk)).length < t := by omega
    simp only [hn, ite_false]
    have : ((ps.filter (·.proofOk)).take t).all (·.proofOk) = true := by
      simp only [List.all_eq_true]
      intro x hx
      have := List.mem_of_mem_take hx
      simpa using (List.mem_filter.mp this).2
    simp [this]

/-- The refusal list is empty exactly when `validState` holds. -/
theorem stepRefusals_nil_iff (s : St) : stepRefusals s = [] ↔ validState s = true := by
  unfold stepRefusals opt; cases validState s <;> simp

end SplitEnvelope
