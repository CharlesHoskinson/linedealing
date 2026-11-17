/-!
# Shard-holder oracle (split-shard-holders, SH-001 to SH-038)

The executable reference semantics of the OpenSpec capability
`split-shard-holders`
(`openspec/changes/add-split-line-dealing/specs/split-shard-holders/spec.md`).

The state is the shard-holder side of one committee and its actors: the
charters fixed at birth (their access structures `Γ`), the BIRTH_OK signatures
the committee nodes gave, the address records that FenrirAssets admitted, the
actors' nonce pools (dealt and used pairs, used pool keys) and the ECDSA slots
each actor contributed on, the ACK_OK signatures of the committee nodes and the
`acked` flag of each record (SH-030 to SH-037, DECISIONS 67).

Abstractions (formal plugin, practice 11):
* Points, hashes and signatures are numbers and enter as inputs. A proof of
  possession is the context it was made for and a validity flag (SH-007); a
  network-created shard carries two flags for `pop_U` and the proof of `δ`
  (SH-008). Dealer proofs, the recomputed `X_γ` and `X`, the address encoding
  and the opening of `cm_addr` are flags of the birth check (SH-009).
* A BIRTH_OK signature verifies exactly when the node gave it in this run
  (`birthOk`); a P0 owner registration and the escrow and guardian ACK counts
  are inputs of the record (SH-011, SH-012).
* The actor's own policy and its recomputation of the request (SH-021, SH-023)
  are inputs. A request names the actor's pairs by their index in its pool.
* The holder wallet's derivation check `x_u·G = X_u` (SH-030, SH-036) and the
  checks of an ACK envelope (SH-031) are flags. An ACK_OK signature verifies
  exactly when the node gave it in this run (`ackOk`). The holder wallet and the
  payer wallet are operations whose answer is the wallet's decision.
* Sessions, puts, nonces, the tweak and the signature scheme (SH-005, SH-006,
  SH-016, SH-017, SH-024, SH-025, SH-027 to SH-029) are outside the state
  except for the counts the requirements state; the README lists them.
-/

namespace SplitShardHolders

/-! ## Domains -/

inductive Mode where
  | TEE | NON_TEE
  deriving Repr, DecidableEq, BEq

inductive Profile where
  | P0 | P1 | P2
  deriving Repr, DecidableEq, BEq

/-- SH-001: a monotone access structure. Every gate carries `mid`, its member id
within a group parent (SH-002); the top gate `Fenrir AND Γ` is implicit. -/
inductive Gate where
  | leaf (mid actor : Nat)
  | and_ (mid : Nat) (cs : List Gate)
  | group (mid k : Nat) (cs : List Gate)
  /-- `p` is the primary child, `e` the escrow child -/
  | or_ (mid : Nat) (p e : Gate)

mutual
/-- A structural `Repr` (the deriving handler gives an opaque one for the nested list). -/
def Gate.reprG : Gate → Std.Format
  | .leaf m a => s!"leaf {m} {a}"
  | .and_ m cs => "and_ " ++ repr m ++ " " ++ Gate.reprL cs
  | .group m k cs => "group " ++ repr m ++ " " ++ repr k ++ " " ++ Gate.reprL cs
  | .or_ m p e => "or_ " ++ repr m ++ " (" ++ Gate.reprG p ++ ") (" ++ Gate.reprG e ++ ")"
def Gate.reprL : List Gate → Std.Format
  | [] => "[]"
  | g :: gs => "(" ++ Gate.reprG g ++ ") :: " ++ Gate.reprL gs
end

instance : Repr Gate := ⟨fun g _ => Gate.reprG g⟩

mutual
/-- Equality of gates, by structure (the deriving handler does not cover the nested
list). -/
def Gate.decEq : (a b : Gate) → Decidable (a = b)
  | .leaf m a, .leaf m' a' =>
    if h : m = m' ∧ a = a' then isTrue (by obtain ⟨rfl, rfl⟩ := h; rfl)
    else isFalse (fun e => by cases e; exact h ⟨rfl, rfl⟩)
  | .and_ m cs, .and_ m' cs' =>
    match Nat.decEq m m', Gate.decEqL cs cs' with
    | isTrue h1, isTrue h2 => isTrue (by subst h1; subst h2; rfl)
    | isFalse h, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, isFalse h => isFalse (fun e => by cases e; exact h rfl)
  | .group m k cs, .group m' k' cs' =>
    match Nat.decEq m m', Nat.decEq k k', Gate.decEqL cs cs' with
    | isTrue h1, isTrue h2, isTrue h3 => isTrue (by subst h1; subst h2; subst h3; rfl)
    | isFalse h, _, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, isFalse h, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, _, isFalse h => isFalse (fun e => by cases e; exact h rfl)
  | .or_ m p e, .or_ m' p' e' =>
    match Nat.decEq m m', Gate.decEq p p', Gate.decEq e e' with
    | isTrue h1, isTrue h2, isTrue h3 => isTrue (by subst h1; subst h2; subst h3; rfl)
    | isFalse h, _, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, isFalse h, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, _, isFalse h => isFalse (fun e => by cases e; exact h rfl)
  | .leaf .., .and_ .. => isFalse (fun h => Gate.noConfusion h)
  | .leaf .., .group .. => isFalse (fun h => Gate.noConfusion h)
  | .leaf .., .or_ .. => isFalse (fun h => Gate.noConfusion h)
  | .and_ .., .leaf .. => isFalse (fun h => Gate.noConfusion h)
  | .and_ .., .group .. => isFalse (fun h => Gate.noConfusion h)
  | .and_ .., .or_ .. => isFalse (fun h => Gate.noConfusion h)
  | .group .., .leaf .. => isFalse (fun h => Gate.noConfusion h)
  | .group .., .and_ .. => isFalse (fun h => Gate.noConfusion h)
  | .group .., .or_ .. => isFalse (fun h => Gate.noConfusion h)
  | .or_ .., .leaf .. => isFalse (fun h => Gate.noConfusion h)
  | .or_ .., .and_ .. => isFalse (fun h => Gate.noConfusion h)
  | .or_ .., .group .. => isFalse (fun h => Gate.noConfusion h)
def Gate.decEqL : (a b : List Gate) → Decidable (a = b)
  | [], [] => isTrue rfl
  | [], _ :: _ => isFalse (fun h => by cases h)
  | _ :: _, [] => isFalse (fun h => by cases h)
  | x :: xs, y :: ys =>
    match Gate.decEq x y, Gate.decEqL xs ys with
    | isTrue h1, isTrue h2 => isTrue (by subst h1; subst h2; rfl)
    | isFalse h, _ => isFalse (fun e => by cases e; exact h rfl)
    | _, isFalse h => isFalse (fun e => by cases e; exact h rfl)
end

instance : DecidableEq Gate := Gate.decEq

def Gate.mid : Gate → Nat
  | .leaf m _ => m
  | .and_ m _ => m
  | .group m _ _ => m
  | .or_ m _ _ => m

def nodupB {α : Type} [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && nodupB xs

/-! ## The access structure -/

mutual
/-- The actors of the leaves, in order. -/
def leaves : Gate → List Nat
  | .leaf _ a => [a]
  | .and_ _ cs => leavesL cs
  | .group _ _ cs => leavesL cs
  | .or_ _ p e => leaves p ++ leaves e
def leavesL : List Gate → List Nat
  | [] => []
  | g :: gs => leaves g ++ leavesL gs
end

mutual
/-- SH-001 and SH-002: every AND and group has a child, a group has
`1 ≤ k ≤ m`, and every child of a group has a nonzero member id, distinct
within the group. -/
def shapeOk : Gate → Bool
  | .leaf _ _ => true
  | .and_ _ cs => !cs.isEmpty && shapeOkL cs
  | .group _ k cs => decide (1 ≤ k) && decide (k ≤ cs.length) && shapeOkL cs
  | .or_ _ p e => shapeOk p && shapeOk e
def shapeOkL : List Gate → Bool
  | [] => true
  | g :: gs => shapeOk g && shapeOkL gs
end

mutual
/-- SH-002: member ids of each group nonzero and distinct. -/
def midsOk : Gate → Bool
  | .leaf _ _ => true
  | .and_ _ cs => midsOkL cs
  | .group _ _ cs => (cs.map Gate.mid).all (· != 0) && nodupB (cs.map Gate.mid) && midsOkL cs
  | .or_ _ p e => midsOk p && midsOk e
def midsOkL : List Gate → Bool
  | [] => true
  | g :: gs => midsOk g && midsOkL gs
end

/-- SH-001: the gate structure. -/
def structureOk (g : Gate) : Bool := shapeOk g

/-- SH-002: distinct nonzero member ids in every group, and no leaf twice. -/
def leavesOk (g : Gate) : Bool := midsOk g && nodupB (leaves g)

def validCharter (g : Gate) : Bool := structureOk g && leavesOk g

mutual
/-- Some leaf of the gate is an actor of `S`. -/
def uses (S : List Nat) : Gate → Bool
  | .leaf _ a => S.contains a
  | .and_ _ cs => usesL S cs
  | .group _ _ cs => usesL S cs
  | .or_ _ p e => uses S p || uses S e
def usesL (S : List Nat) : List Gate → Bool
  | [] => false
  | g :: gs => uses S g || usesL S gs
end

mutual
/-- `S` satisfies the monotone structure. -/
def sat (S : List Nat) : Gate → Bool
  | .leaf _ a => S.contains a
  | .and_ _ cs => satAll S cs
  | .group _ k cs => decide (k ≤ satCount S cs)
  | .or_ _ p e => sat S p || sat S e
def satAll (S : List Nat) : List Gate → Bool
  | [] => true
  | g :: gs => sat S g && satAll S gs
def satCount (S : List Nat) : List Gate → Nat
  | [] => 0
  | g :: gs => (if sat S g then 1 else 0) + satCount S gs
end

mutual
/-- SH-003 on one gate: an AND needs every child, a group it uses exactly `k`
used children, an OR exactly one used child; every used child is admitted. -/
def adm (S : List Nat) : Gate → Bool
  | .leaf _ a => S.contains a
  | .and_ _ cs => admAll S cs
  | .group _ k cs => usedCount S cs == k && admUsed S cs
  | .or_ _ p e => (uses S p != uses S e) && (if uses S p then adm S p else adm S e)
def admAll (S : List Nat) : List Gate → Bool
  | [] => true
  | g :: gs => adm S g && admAll S gs
def admUsed (S : List Nat) : List Gate → Bool
  | [] => true
  | g :: gs => (!uses S g || adm S g) && admUsed S gs
def usedCount (S : List Nat) : List Gate → Nat
  | [] => 0
  | g :: gs => (if uses S g then 1 else 0) + usedCount S gs
end

/-- SH-003: the signing set names the initiator, only actors of `Γ`, each once,
and is admitted on `Γ`. -/
def admitted (g : Gate) (S : List Nat) (initiator : Nat) : Bool :=
  S.contains initiator && nodupB S && S.all (leaves g).contains && adm S g

/-! ## Weights (SH-004)

Exact rationals as `num / den` with `den ≠ 0`, compared by cross multiplication. -/

structure Q where
  num : Int
  den : Int
  deriving Repr, DecidableEq

def Q.one : Q := ⟨1, 1⟩
def Q.mul (a b : Q) : Q := ⟨a.num * b.num, a.den * b.den⟩
def Q.eqv (a b : Q) : Bool := a.num * b.den == b.num * a.den && a.den != 0 && b.den != 0

/-- The Lagrange coefficient at zero of member `x` in the member set `xs`:
`Π_{y ∈ xs, y ≠ x} y / (y − x)`. -/
def lagrange0 (x : Nat) (xs : List Nat) : Q :=
  (xs.filter (· != x)).foldl (fun acc (y : Nat) => acc.mul ⟨(y : Int), (y : Int) - (x : Int)⟩) Q.one

mutual
/-- SH-004: the weight of actor `a` from the signing set alone: the product of the
Lagrange coefficients at zero of the used children sets of the groups along its
path, 1 for an AND or OR child. `none` when `a` has no leaf. -/
def weight (S : List Nat) (a : Nat) : Gate → Option Q
  | .leaf _ b => if a == b then some Q.one else none
  | .and_ _ cs => weightL S a cs
  | .group _ _ cs =>
    let xs := (cs.filter (uses S)).map Gate.mid
    (weightG S a cs).map (fun (x, w) => (lagrange0 x xs).mul w)
  | .or_ _ p e => match weight S a p with
    | some w => some w
    | none => weight S a e
def weightL (S : List Nat) (a : Nat) : List Gate → Option Q
  | [] => none
  | g :: gs => match weight S a g with
    | some w => some w
    | none => weightL S a gs
/-- the member id of the child that holds `a`, with the weight below it -/
def weightG (S : List Nat) (a : Nat) : List Gate → Option (Nat × Q)
  | [] => none
  | g :: gs => match weight S a g with
    | some w => some (g.mid, w)
    | none => weightG S a gs
end

/-! ## The commitment list (SH-038)

The actors that `CL` names. Its pool pairs, slot and points are hash inputs
outside the state. -/

/-- SH-038: the actors that the commitment list names for the signing set `S`:
the initiator's leaf id first, then the leaf id of every other named actor. -/
def clActors (S : List Nat) (initiator : Nat) : Nat × List Nat :=
  (initiator, S.filter (· != initiator))

mutual
/-- Actor `a` holds a leaf under the primary child of an OR gate (SH-019). -/
def inPrimary (a : Nat) : Gate → Bool
  | .leaf _ _ => false
  | .and_ _ cs => inPrimaryL a cs
  | .group _ _ cs => inPrimaryL a cs
  | .or_ _ p e => (leaves p).contains a || inPrimary a p || inPrimary a e
def inPrimaryL (a : Nat) : List Gate → Bool
  | [] => false
  | g :: gs => inPrimary a g || inPrimaryL a gs
end

mutual
/-- Actor `a` holds a leaf under the escrow child of an OR gate: a guardian (SH-026). -/
def inEscrow (a : Nat) : Gate → Bool
  | .leaf _ _ => false
  | .and_ _ cs => inEscrowL a cs
  | .group _ _ cs => inEscrowL a cs
  | .or_ _ p e => (leaves e).contains a || inEscrow a p || inEscrow a e
def inEscrowL (a : Nat) : List Gate → Bool
  | [] => false
  | g :: gs => inEscrow a g || inEscrowL a gs
end

mutual
/-- `Γ` has an OR gate (SH-012). -/
def hasOr : Gate → Bool
  | .leaf _ _ => false
  | .and_ _ cs => hasOrL cs
  | .group _ _ cs => hasOrL cs
  | .or_ _ _ _ => true
def hasOrL : List Gate → Bool
  | [] => false
  | g :: gs => hasOr g || hasOrL gs
end

/-! ## Constants and counts -/

/-- SH-013: pairs per pool and pool keys per pool-key root. -/
def nPool : Nat := 64
def nPk : Nat := 1024

/-- `G_max = 2` (RQ-001); `G = min(K, G_max)`. -/
def gOf (k : Nat) : Nat := min k 2

/-- SH-014 (DECISIONS 36): one pair per half, `N_h = L·Σ_{v=1..K} min(v, G)` on
Schnorr suites, `K·L` on ECDSA. -/
def halves (ecdsa : Bool) (k l : Nat) : Nat :=
  if ecdsa then k * l else l * ((List.range k).map (fun i => min (i + 1) (gOf k))).sum

/-- SH-020: `G_g = 2·K·L_max` guardian slots of a P2 ECDSA address. -/
def guardianSlots (k lMax : Nat) : Nat := 2 * k * lMax

/-- SH-016: the slots a session keeps, and the slots a node complains about: a
slot whose public check fails at the node is dropped. -/
def sessionKeep (slots : List (Nat × Bool)) : List Nat := (slots.filter (·.2)).map (·.1)
def sessionComplain (slots : List (Nat × Bool)) : List Nat := (slots.filter (!·.2)).map (·.1)

/-- SH-017: in TEE mode, one `slot_put` and one put entry per slot share. -/
def putEntries (m : Mode) (slots : List Nat) : List Nat := if m == .TEE then slots else []

/-! ## Inputs of the operations -/

/-- The proof of possession of one actor at birth (SH-007, SH-008). `ctx` is the
statement the proof was made for: `(X_f, X_a, slot_a, charter_id, chain_id)`. -/
structure ActorProof where
  slot : Nat
  xa : Nat
  ctx : Nat × Nat × Nat × Nat × Nat
  valid : Bool
  netCreated : Bool
  popU : Bool
  delta : Bool
  deriving Repr, DecidableEq

/-- The checks of SH-009 at one node. -/
structure BirthCheck where
  xf : Nat
  charterId : Nat
  chainId : Nat
  actors : List ActorProof
  dealerOk : Bool
  xRecomputed : Bool
  encodingOk : Bool
  openingOk : Bool
  deriving Repr, DecidableEq

/-- SH-007: `pop_a` verifies for its own statement. SH-008: a network-created shard
carries `pop_U` and the proof of `δ`. -/
def proofOk (b : BirthCheck) (a : ActorProof) : Bool :=
  a.valid && a.ctx == (b.xf, a.xa, a.slot, b.charterId, b.chainId) && (!a.netCreated || (a.popU && a.delta))

/-- SH-009: every check passes. -/
def birthPasses (b : BirthCheck) : Bool :=
  b.actors.all (proofOk b) && b.dealerOk && b.xRecomputed && b.encodingOk && b.openingOk

/-- An address record that arrives at FenrirAssets (SH-011, SH-012). `signers` are
the nodes whose BIRTH_OK on `cm` the birth certificate carries. -/
structure RecordReq where
  cm : Nat
  profile : Profile
  charter : Nat
  signers : List Nat
  ownerReg : Bool
  escrowAcks : Nat
  escrowQuorum : Nat
  guardianAcks : Nat
  qg : Nat
  /-- the address has a network-created shard (SH-008; DECISIONS 67, ledger 14) -/
  netCreated : Bool
  deriving Repr, DecidableEq

/-- The checks of SH-031 at one node on one ACK envelope (DECISIONS 67): the birth
data recompute `X`, the opening of `cm_addr` passes, and `pop_u` verifies under
`X_u`. -/
structure AckCheck where
  xRecomputed : Bool
  openingOk : Bool
  popU : Bool
  deriving Repr, DecidableEq

/-- SH-031: every check passes. -/
def ackPasses (a : AckCheck) : Bool := a.xRecomputed && a.openingOk && a.popU

/-- The slot a request names for the actor's half. -/
inductive SlotRef where
  | committee
  /-- an ECDSA slot: its id, the leaf set `T_ℓ` recorded with it, and whether it
  lies under `slr_G` (reserved for the escrow branch) -/
  | ecdsa (id : Nat) (leafSet : List Nat) (underG : Bool)
  deriving Repr, DecidableEq

/-- A request as one actor sees it before it contributes. -/
structure Contrib where
  actor : Nat
  charter : Nat
  S : List Nat
  initiator : Nat
  weight : Q
  pairs : List Nat
  slot : SlotRef
  expC : Nat
  height : Nat
  policyOk : Bool
  recomputeOk : Bool
  /-- a seizure order settled on Midnight whose outputs all pay `D_reg` (SH-026) -/
  seizureSettled : Bool
  deriving Repr, DecidableEq

/-! ## State -/

structure Params where
  n : Nat
  f : Nat
  mode : Mode
  /-- the halves of the largest request the actor serves (SH-014) -/
  nH : Nat
  deriving Repr, DecidableEq

/-- RQ-001: `q = ⌈(n + f + 1)/2⌉`. -/
def Params.q (p : Params) : Nat := (p.n + p.f + 2) / 2

/-- RQ-001: `f ≥ 1` and `n ≥ 3f + 1`. -/
def paramsOk (p : Params) : Bool := decide (1 ≤ p.f) && decide (3 * p.f + 1 ≤ p.n)

structure Rec where
  cm : Nat
  profile : Profile
  charter : Nat
  /-- the distinct nodes of the certificate whose BIRTH_OK verified -/
  sigs : List Nat
  /-- the address has a network-created shard -/
  netCreated : Bool
  /-- SH-034, SH-037: set only by a landed `acknowledge` call (DECISIONS 67) -/
  acked : Bool
  deriving Repr, DecidableEq

structure St where
  params : Params
  charters : List (Nat × Gate)
  /-- `(node, cm_addr)` of every BIRTH_OK a node gave -/
  birthOk : List (Nat × Nat)
  records : List Rec
  /-- `(actor, pair index)` of every pair the actor posted -/
  dealt : List (Nat × Nat)
  /-- `(actor, pair index)` of every pair the actor answered -/
  used : List (Nat × Nat)
  /-- `(actor, root, key index)` of every pool key the actor signed a pool with -/
  poolKeys : List (Nat × Nat × Nat)
  /-- `(actor, ECDSA slot)` the actor contributed on (SH-018) -/
  ecdsaUsed : List (Nat × Nat)
  /-- `(node, cm_addr)` of every ACK_OK a node gave (SH-031) -/
  ackOk : List (Nat × Nat)
  deriving Repr, DecidableEq

def init (p : Params) : St :=
  { params := p, charters := [], birthOk := [], records := [], dealt := [], used := [], poolKeys := [],
    ecdsaUsed := [], ackOk := [] }

def findRec (s : St) (cm : Nat) : Option Rec := s.records.find? (·.cm == cm)

def charterOf (s : St) (c : Nat) : Option Gate := (s.charters.find? (·.1 == c)).map (·.2)

def unusedOf (s : St) (a : Nat) : List Nat :=
  (s.dealt.filter (fun x => x.1 == a && !s.used.contains x)).map (·.2)

/-- SH-014: the actor holds fewer than `N_h` unused pairs. -/
def needsRefill (s : St) (a : Nat) : Bool := decide ((unusedOf s a).length < s.params.nH)

/-! ## Refusals

The constructor order is the code order. Requirements that state a response
("the charter is not valid", "the actor does not contribute") without a code
answer with the requirement ID (ledger 1). When several apply the answer holds
all of them, sorted (ledger 2).

| Code | IDs |
|---|---|
| `SH-001`, `SH-002` | the charter is not valid |
| `SH-013` | the pool key is not fresh |
| `SH-015`, `SH-018`, `SH-019`, `SH-021`, `SH-026` | the actor does not contribute |
| `SH-035` | the payer wallet sends no payment |
| `SH-036` | the holder wallet sends no ACK envelope |
| `ack_refused` | SH-032 |
| `bad_request` | SH-022 |
| `birth_refused` | SH-010 |
| `no-rule` | an event no requirement defines (ledger 3) |
| `no_ack_certificate` | SH-033 |
| `no_birth_certificate` | SH-011 |
| `no_escrow_certificate` | SH-012 |
| `outside-capability` | a value outside a domain sentence (ledger 4) |
| `outside-state-domain` | a `--step` state outside `validState` |
| `policy_refused` | SH-023 |
-/

inductive Refusal where
  | sh001 | sh002 | sh013 | sh015 | sh018 | sh019 | sh021 | sh026 | sh035 | sh036
  | ackRefused | badRequest | birthRefused | noRule | noAckCertificate | noBirthCertificate | noEscrowCertificate
  | outsideCapability | outsideStateDomain | policyRefused
  deriving Repr, DecidableEq, BEq

def Refusal.code : Refusal → String
  | .sh001 => "SH-001"
  | .sh002 => "SH-002"
  | .sh013 => "SH-013"
  | .sh015 => "SH-015"
  | .sh018 => "SH-018"
  | .sh019 => "SH-019"
  | .sh021 => "SH-021"
  | .sh026 => "SH-026"
  | .sh035 => "SH-035"
  | .sh036 => "SH-036"
  | .ackRefused => "ack_refused"
  | .badRequest => "bad_request"
  | .birthRefused => "birth_refused"
  | .noRule => "no-rule"
  | .noAckCertificate => "no_ack_certificate"
  | .noBirthCertificate => "no_birth_certificate"
  | .noEscrowCertificate => "no_escrow_certificate"
  | .outsideCapability => "outside-capability"
  | .outsideStateDomain => "outside-state-domain"
  | .policyRefused => "policy_refused"

def opt (b : Bool) (r : Refusal) : List Refusal := if b then [r] else []

/-- SH-011: the distinct certificate signers whose BIRTH_OK on `cm` verifies. -/
def validSigners (s : St) (r : RecordReq) : List Nat :=
  r.signers.filter (fun n => s.birthOk.contains (n, r.cm))

/-- SH-011: a P1 or P2 record without `q` BIRTH_OK, a P0 record without the owner's registration. -/
def noBirthCert (s : St) (r : RecordReq) : Bool :=
  if r.profile == .P0 then !r.ownerReg else decide ((validSigners s r).length < s.params.q)

/-- SH-033: the distinct certificate signers whose ACK_OK on `cm` verifies. -/
def validAckers (s : St) (cm : Nat) (signers : List Nat) : List Nat :=
  signers.filter (fun n => s.ackOk.contains (n, cm))

/-- SH-033: an `acknowledge` call without `q` ACK_OK signatures for the record. -/
def noAckCert (s : St) (cm : Nat) (signers : List Nat) : Bool :=
  decide ((validAckers s cm signers).length < s.params.q)

/-- SH-035: the record has a network-created shard and `acked = false`. -/
def payBlocked (r : Rec) : Bool := r.netCreated && !r.acked

/-- SH-037: the record of `cm` with `acked = true`. -/
def setAcked (cm : Nat) (r : Rec) : Rec := if r.cm == cm then { r with acked := true } else r

/-- SH-012: an OR gate without an escrow quorum, a P2 record without `q_g` guardian ACKs. -/
def noEscrowCert (g : Gate) (r : RecordReq) : Bool :=
  (hasOr g && decide (r.escrowAcks < r.escrowQuorum)) || (r.profile == .P2 && decide (r.guardianAcks < r.qg))

/-- SH-022: the signing set is not in `Γ`, the claimed weight does not follow from
it, or a named pair is not an unused pair of the actor's pool, one per half. -/
def badRequest (s : St) (g : Gate) (c : Contrib) : Bool :=
  !admitted g c.S c.initiator
    || (match weight c.S c.actor g with
        | some w => !w.eqv c.weight
        | none => true)
    || !nodupB c.pairs
    || !c.pairs.all (fun i => s.dealt.contains (c.actor, i) && !s.used.contains (c.actor, i))

/-- SH-018: an ECDSA slot whose leaf set is not the signing set, or one the actor
already contributed on. -/
def leafSetBad (s : St) (c : Contrib) : Bool :=
  match c.slot with
  | .committee => false
  | .ecdsa id ls _ =>
    !(nodupB ls && ls.length == c.S.length && ls.all c.S.contains) || s.ecdsaUsed.contains (c.actor, id)

/-- SH-019: the primary holder of an OR gate on a slot under `slr_G`. -/
def escrowSlotBad (g : Gate) (c : Contrib) : Bool :=
  match c.slot with
  | .ecdsa _ _ true => inPrimary c.actor g
  | _ => false

/-- SH-026: a guardian half outside a settled seizure order that pays `D_reg`. -/
def guardianBad (g : Gate) (c : Contrib) : Bool := inEscrow c.actor g && !c.seizureSettled

/-- Every refusal of a contribution, in code order. -/
def contribRefusals (s : St) (c : Contrib) : List Refusal :=
  match charterOf s c.charter with
  | none => [.noRule]
  | some g =>
    opt (decide (c.expC < c.height)) .sh015 ++ opt (leafSetBad s c) .sh018 ++ opt (escrowSlotBad g c) .sh019
      ++ opt (!c.recomputeOk) .sh021 ++ opt (guardianBad g c) .sh026 ++ opt (badRequest s g c) .badRequest
      ++ opt (!c.policyOk) .policyRefused

/-! ## Operations -/

inductive Op where
  /-- SH-001, SH-002: a charter fixes `Γ` at birth -/
  | fixCharter (id : Nat) (g : Gate)
  /-- SH-009, SH-010: node `node` checks the BIRTH request for `cm_addr` -/
  | birthCheck (node cm : Nat) (b : BirthCheck)
  /-- SH-011, SH-012: an address record arrives at FenrirAssets -/
  | submitRecord (r : RecordReq)
  /-- SH-013: the actor posts one pool signed by key `idx` of its pool-key root `root` -/
  | postPool (actor root idx : Nat)
  /-- SH-014, SH-015, SH-018, SH-019, SH-021 to SH-023, SH-026: the actor contributes -/
  | contribute (c : Contrib)
  /-- SH-016: an ECDSA slot session ends; each slot with its public check at the node -/
  | session (slots : List (Nat × Bool))
  /-- SH-017: the committee shares of the slots of an ended session -/
  | putShares (slots : List Nat)
  /-- SH-030, SH-036: the holder wallet first opens the record of `cm_addr`;
  `xMatch` is `x_u·G = X_u` for the `x_u` it derives from the `E_c` of the record -/
  | holderOpen (cm : Nat) (xMatch : Bool)
  /-- SH-031, SH-032: node `node` checks the ACK envelope for `cm_addr` -/
  | ackCheck (node cm : Nat) (a : AckCheck)
  /-- SH-033, SH-037: an `acknowledge` call with the nodes whose ACK_OK its certificate carries -/
  | acknowledge (cm : Nat) (signers : List Nat)
  /-- SH-035: the payer wallet reads the record of `cm_addr` and would pay to the address -/
  | pay (cm : Nat)
  deriving Repr, DecidableEq

inductive Obs where
  | ok
  /-- SH-009: the node signs BIRTH_OK and sends it to the coordinator -/
  | birthOk
  | refused (codes : List Refusal)
  /-- the actor contributed; `refill` is SH-014 after the step -/
  | contributed (refill : Bool)
  /-- SH-016: slots kept and slots complained about -/
  | sessionEnd (kept complained : List Nat)
  /-- SH-017: the put entries appended -/
  | puts (entries : List Nat)
  /-- SH-030: the holder wallet sends the ACK envelope -/
  | ackEnvelope
  /-- SH-031: the node signs ACK_OK and sends it to the holder wallet -/
  | ackOk
  /-- SH-035: the payer wallet sends the payment -/
  | paid
  deriving Repr, DecidableEq

def opRefusals (s : St) : Op → List Refusal
  | .fixCharter id g =>
    opt (!structureOk g) .sh001 ++ opt (!leavesOk g) .sh002 ++ opt ((charterOf s id).isSome) .noRule
  | .birthCheck node _ b => opt (!birthPasses b) .birthRefused ++ opt (decide (s.params.n ≤ node)) .outsideCapability
  | .submitRecord r =>
    match charterOf s r.charter with
    | none => [.noRule]
    | some g =>
      opt (noBirthCert s r) .noBirthCertificate ++ opt (noEscrowCert g r) .noEscrowCertificate
        ++ opt (s.records.any (·.cm == r.cm)) .noRule ++ opt (!nodupB r.signers) .outsideCapability
  | .postPool a root idx =>
    opt (s.poolKeys.contains (a, root, idx)) .sh013 ++ opt (decide (nPk ≤ idx)) .outsideCapability
  | .contribute c => contribRefusals s c
  | .session slots => opt (!nodupB (slots.map (·.1))) .outsideCapability
  | .putShares slots => opt (!nodupB slots) .outsideCapability
  -- SH-030, SH-036: the holder wallet sends the ACK envelope only when `x_u·G = X_u`
  | .holderOpen cm xMatch =>
    match findRec s cm with
    | none => [.noRule]
    | some r => opt (!xMatch) .sh036 ++ opt (!r.netCreated) .noRule
  -- SH-032: a failed check of SH-031
  | .ackCheck node _ a => opt (!ackPasses a) .ackRefused ++ opt (decide (s.params.n ≤ node)) .outsideCapability
  -- SH-033: no certificate of `q` ACK_OK signatures
  | .acknowledge cm signers =>
    match findRec s cm with
    | none => [.noRule]
    | some _ => opt (noAckCert s cm signers) .noAckCertificate ++ opt (!nodupB signers) .outsideCapability
  -- SH-035: no payment while `acked = false`
  | .pay cm =>
    match findRec s cm with
    | none => [.noRule]
    | some r => opt (payBlocked r) .sh035

def exec (s : St) : Op → St × Obs
  -- SH-001, SH-002: a valid charter is fixed
  | .fixCharter id g => ({ s with charters := (id, g) :: s.charters }, .ok)
  -- SH-009: the node signs BIRTH_OK(eid, cm_addr)
  | .birthCheck node cm _ =>
    ({ s with birthOk := if s.birthOk.contains (node, cm) then s.birthOk else (node, cm) :: s.birthOk }, .birthOk)
  -- SH-011, SH-012: the record is admitted with its verified signers; SH-034: with
  -- `acked = false`
  | .submitRecord r =>
    ({ s with records := { cm := r.cm, profile := r.profile, charter := r.charter, sigs := validSigners s r,
                           netCreated := r.netCreated, acked := false } :: s.records },
     .ok)
  -- SH-013: a pool of `N_pool` fresh pairs, numbered after the actor's dealt pairs
  | .postPool a root idx =>
    let base := (s.dealt.filter (·.1 == a)).length
    ({ s with dealt := s.dealt ++ (List.range nPool).map (fun i => (a, base + i)),
              poolKeys := (a, root, idx) :: s.poolKeys }, .ok)
  -- SH-015: the actor marks each named pair used in the step that computes the
  -- contribution; SH-018: and the ECDSA slot answered
  | .contribute c =>
    let s1 := { s with used := c.pairs.map (fun i => (c.actor, i)) ++ s.used,
                       ecdsaUsed := match c.slot with
                         | .ecdsa id _ _ => (c.actor, id) :: s.ecdsaUsed
                         | .committee => s.ecdsaUsed }
    (s1, .contributed (needsRefill s1 c.actor))
  -- SH-016: keep the slots whose check passes, complain about the others
  | .session slots => (s, .sessionEnd (sessionKeep slots) (sessionComplain slots))
  -- SH-017: one put entry per slot in TEE mode
  | .putShares slots => (s, .puts (putEntries s.params.mode slots))
  -- SH-030: the holder wallet sends the ACK envelope
  | .holderOpen _ _ => (s, .ackEnvelope)
  -- SH-031: the node signs ACK_OK(eid, cm_addr)
  | .ackCheck node cm _ =>
    ({ s with ackOk := if s.ackOk.contains (node, cm) then s.ackOk else (node, cm) :: s.ackOk }, .ackOk)
  -- SH-037: the call lands and sets `acked = true` on the record
  | .acknowledge cm _ => ({ s with records := s.records.map (setAcked cm) }, .ok)
  -- SH-035: the payer wallet pays to an acknowledged address
  | .pay _ => (s, .paid)

def apply (s : St) (op : Op) : St × Obs :=
  match opRefusals s op with
  | [] => exec s op
  | rs => (s, .refused rs)

def runOps : St → List Op → St × List Obs
  | s, [] => (s, [])
  | s, op :: ops =>
    let (s1, o) := apply s op
    let (s2, os) := runOps s1 ops
    (s2, o :: os)

def run (s : St) (ops : List Op) : St := (runOps s ops).1

/-- The parameters a run starts from (RQ-001 domain). -/
def paramRefusals (p : Params) : List Refusal := opt (!paramsOk p) .outsideCapability

/-- The state domain of `--step` (not reachability): parameters in the domain,
dealt pairs distinct, used pairs distinct and dealt, charters valid. -/
def validState (s : St) : Bool :=
  paramsOk s.params && nodupB s.dealt && nodupB s.used && s.used.all s.dealt.contains
    && s.charters.all (fun x => validCharter x.2)

def stepRefusals (s : St) : List Refusal := opt (!validState s) .outsideStateDomain

/-! ## Theorems -/

theorem apply_refused (s : St) (op : Op) (h : opRefusals s op ≠ []) : (apply s op).1 = s := by
  unfold apply; split
  · contradiction
  · rfl

/-! ### C17: admitted signing sets satisfy `Γ` (SH-002, SH-003) -/

mutual
theorem adm_sat (S : List Nat) : (g : Gate) → adm S g = true → sat S g = true
  | .leaf _ a, h => by simpa [adm, sat] using h
  | .and_ _ cs, h => by
    simp only [adm, sat] at *
    exact admAll_satAll S cs h
  | .group _ k cs, h => by
    simp only [adm, sat, Bool.and_eq_true, beq_iff_eq] at *
    have := admUsed_count S cs h.2
    simp; omega
  | .or_ _ p e, h => by
    simp only [adm, sat, Bool.and_eq_true, Bool.or_eq_true] at *
    cases hp : uses S p
    · rw [hp] at h; simp at h; exact Or.inr (adm_sat S e h.2)
    · rw [hp] at h; simp at h; exact Or.inl (adm_sat S p h.2)
theorem admAll_satAll (S : List Nat) : (cs : List Gate) → admAll S cs = true → satAll S cs = true
  | [], _ => rfl
  | g :: gs, h => by
    simp only [admAll, satAll, Bool.and_eq_true] at *
    exact ⟨adm_sat S g h.1, admAll_satAll S gs h.2⟩
theorem admUsed_count (S : List Nat) : (cs : List Gate) → admUsed S cs = true → usedCount S cs ≤ satCount S cs
  | [], _ => Nat.le_refl _
  | g :: gs, h => by
    simp only [admUsed, usedCount, satCount, Bool.and_eq_true] at *
    have ih := admUsed_count S gs h.2
    cases hu : uses S g
    · simp; split <;> omega
    · rw [hu] at h
      have hs : sat S g = true := adm_sat S g (by simpa using h.1)
      simp [hs]; omega
end

/-- C17 (structural part, SH-003): an admitted signing set satisfies `Γ`. -/
theorem C17_admitted_satisfies (g : Gate) (S : List Nat) (i : Nat) (h : admitted g S i = true) :
    sat S g = true := by
  simp only [admitted, Bool.and_eq_true] at h
  exact adm_sat S g h.2

/-- Every step keeps every fixed charter valid. -/
theorem apply_charters_valid (s : St) (op : Op) (h : s.charters.all (fun x => validCharter x.2) = true) :
    (apply s op).1.charters.all (fun x => validCharter x.2) = true := by
  unfold apply
  split
  · rename_i hr
    cases op with
    | fixCharter id g =>
      simp [opRefusals, opt] at hr
      simp only [exec, List.all_cons, validCharter, hr.1, hr.2.1, Bool.true_and]
      exact h
    | birthCheck _ _ _ => exact h
    | submitRecord _ => exact h
    | postPool _ _ _ => exact h
    | contribute _ => exact h
    | session _ => exact h
    | putShares _ => exact h
    | holderOpen _ _ => exact h
    | ackCheck _ _ _ => exact h
    | acknowledge _ _ => exact h
    | pay _ => exact h
  · exact h

theorem runOps_charters_valid (s : St) (ops : List Op) (h : s.charters.all (fun x => validCharter x.2) = true) :
    (runOps s ops).1.charters.all (fun x => validCharter x.2) = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_charters_valid s op h)

/-- C17 (SH-002): in every run from `init`, every fixed charter has nonzero distinct
member ids in each group and no leaf twice. -/
theorem C17_run_charters_valid (p : Params) (ops : List Op) :
    (run (init p) ops).charters.all (fun x => validCharter x.2) = true :=
  runOps_charters_valid _ ops rfl

/-- C17 (SH-003, SH-022): an actor contributes only to a signing set that is
admitted on a fixed charter, and that set satisfies its `Γ`. -/
theorem C17_contribution_admitted (s : St) (c : Contrib) (r : Bool)
    (h : (apply s (.contribute c)).2 = .contributed r) :
    ∃ g, charterOf s c.charter = some g ∧ admitted g c.S c.initiator = true ∧ sat c.S g = true := by
  unfold apply at h
  split at h
  · rename_i hr
    simp only [opRefusals, contribRefusals] at hr
    split at hr
    · simp at hr
    · rename_i g hg
      simp [opt] at hr
      have ha : admitted g c.S c.initiator = true := by
        have := hr.2.2.2.2.2.1
        simp only [badRequest, Bool.or_eq_false_iff] at this
        simpa using this.1.1.1
      exact ⟨g, hg, ha, C17_admitted_satisfies g c.S c.initiator ha⟩
  · simp at h

/-! ### SH-015: one answer per pool pair -/

theorem nodupB_cons {α : Type} [BEq α] (x : α) (xs : List α) :
    nodupB (x :: xs) = (!xs.contains x && nodupB xs) := rfl

theorem nodupB_map_append (a : Nat) (ps : List Nat) (u : List (Nat × Nat))
    (h1 : nodupB ps = true) (h2 : nodupB u = true) (h3 : ps.all (fun i => !u.contains (a, i)) = true) :
    nodupB (ps.map (fun i => (a, i)) ++ u) = true := by
  induction ps with
  | nil => simpa using h2
  | cons p ps ih =>
    simp only [nodupB_cons, Bool.and_eq_true, Bool.not_eq_true', List.all_cons] at h1 h3
    simp only [List.map_cons, List.cons_append, nodupB_cons, Bool.and_eq_true, Bool.not_eq_true']
    refine ⟨?_, ih h1.2 h3.2⟩
    rw [Bool.eq_false_iff]; intro hc
    have hp : p ∉ ps := by simpa using h1.1
    have hu : (a, p) ∉ u := by simpa using h3.1
    simp at hc
    rcases hc with hc | hc <;> simp_all

theorem apply_used_nodup (s : St) (op : Op) (h : nodupB s.used = true) :
    nodupB (apply s op).1.used = true := by
  unfold apply
  split
  · rename_i hr
    cases op with
    | contribute c =>
      simp only [opRefusals, contribRefusals] at hr
      split at hr
      · simp at hr
      · rename_i g _
        simp [opt] at hr
        have hb := hr.2.2.2.2.2.1
        simp only [badRequest, Bool.or_eq_false_iff, Bool.not_eq_false'] at hb
        simp only [exec]
        apply nodupB_map_append _ _ _ hb.1.2 h
        have := hb.2
        simp only [List.all_eq_true, Bool.and_eq_true, Bool.not_eq_true'] at this ⊢
        intro x hx; simpa using (this x hx).2
    | fixCharter _ _ => exact h
    | birthCheck _ _ _ => exact h
    | submitRecord _ => exact h
    | postPool _ _ _ => exact h
    | session _ => exact h
    | putShares _ => exact h
    | holderOpen _ _ => exact h
    | ackCheck _ _ _ => exact h
    | acknowledge _ _ => exact h
    | pay _ => exact h
  · exact h

theorem runOps_used_nodup (s : St) (ops : List Op) (h : nodupB s.used = true) :
    nodupB (runOps s ops).1.used = true := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_used_nodup s op h)

/-- SH-015: in every run from `init`, no actor answers one pool pair twice. -/
theorem sh015_run_one_answer_per_pair (p : Params) (ops : List Op) :
    nodupB (run (init p) ops).used = true :=
  runOps_used_nodup _ ops rfl

/-! ### C1, C2: certified records (SH-009, SH-011) -/

theorem apply_params (s : St) (op : Op) : (apply s op).1.params = s.params := by
  unfold apply; split
  · cases op <;> rfl
  · rfl

theorem apply_birthOk_mono (s : St) (op : Op) (x : Nat × Nat) (h : x ∈ s.birthOk) :
    x ∈ (apply s op).1.birthOk := by
  unfold apply; split
  · cases op with
    | birthCheck node cm _ =>
      simp only [exec]; split
      · exact h
      · exact List.mem_cons_of_mem _ h
    | _ => exact h
  · exact h

/-- C2 (structural part, SH-009): a BIRTH_OK enters the state only through a birth
check of that node and that `cm_addr` in which every SH-009 check passed. -/
theorem C2_birthOk_from_check (s : St) (op : Op) (x : Nat × Nat) (h : x ∈ (apply s op).1.birthOk)
    (hn : x ∉ s.birthOk) : ∃ b, op = .birthCheck x.1 x.2 b ∧ birthPasses b = true := by
  unfold apply at h; split at h
  · rename_i hr
    cases op with
    | birthCheck node cm b =>
      simp only [exec] at h
      split at h
      · exact absurd h hn
      · simp only [List.mem_cons] at h
        rcases h with rfl | h
        · simp [opRefusals, opt] at hr
          exact ⟨b, rfl, hr.1⟩
        · exact absurd h hn
    | fixCharter _ _ => exact absurd h hn
    | submitRecord _ => exact absurd h hn
    | postPool _ _ _ => exact absurd h hn
    | contribute _ => exact absurd h hn
    | session _ => exact absurd h hn
    | putShares _ => exact absurd h hn
    | holderOpen _ _ => exact absurd h hn
    | ackCheck _ _ _ => exact absurd h hn
    | acknowledge _ _ => exact absurd h hn
    | pay _ => exact absurd h hn
  · exact absurd h hn

/-- Every admitted P1 or P2 record holds `q` distinct certificate signers, each with
a BIRTH_OK on its `cm_addr` in the state. -/
def RecInv (s : St) : Prop :=
  ∀ r ∈ s.records, r.profile ≠ .P0 →
    s.params.q ≤ r.sigs.length ∧ nodupB r.sigs = true ∧ ∀ n ∈ r.sigs, (n, r.cm) ∈ s.birthOk

theorem nodupB_filter {α : Type} [BEq α] (p : α → Bool) (l : List α) (h : nodupB l = true) :
    nodupB (l.filter p) = true := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [nodupB_cons, Bool.and_eq_true, Bool.not_eq_true'] at h
    by_cases hp : p x
    · simp only [List.filter_cons, hp, ite_true, nodupB_cons, ih h.2, Bool.and_true]
      cases hc : (xs.filter p).contains x
      · rfl
      · exfalso
        have : xs.contains x = true := by
          simp only [List.contains_eq_any_beq, List.any_eq_true] at hc ⊢
          obtain ⟨y, hy, hb⟩ := hc
          exact ⟨y, (List.mem_filter.mp hy).1, hb⟩
        rw [h.1] at this; exact Bool.false_ne_true this
    · simp only [List.filter_cons, hp]; exact ih h.2

theorem apply_recInv (s : St) (op : Op) (h : RecInv s) : RecInv (apply s op).1 := by
  intro r hr hp
  rw [apply_params]
  have mono := apply_birthOk_mono s op
  unfold apply at hr ⊢
  split at hr
  · rename_i hrf
    cases op with
    | submitRecord rr =>
      simp only [exec, List.mem_cons] at hr ⊢
      rcases hr with rfl | hr
      · simp only [opRefusals] at hrf
        split at hrf
        · simp at hrf
        · simp [opt] at hrf
          have hnb := hrf.1
          simp only [noBirthCert] at hnb
          have hp' : (rr.profile == .P0) = false := by
            cases hq : rr.profile <;> first | rfl | simp_all
          rw [hp'] at hnb
          simp at hnb
          refine ⟨by simpa [validSigners] using hnb, nodupB_filter _ _ (by simpa using hrf.2.2.2), ?_⟩
          intro n hn
          have := (List.mem_filter.mp hn).2
          simpa using this
      · exact h r hr hp
    | birthCheck node cm b =>
      simp only [exec] at hr ⊢
      obtain ⟨h1, h2, h3⟩ := h r hr hp
      refine ⟨h1, h2, fun n hn => ?_⟩
      split
      · exact h3 n hn
      · exact List.mem_cons_of_mem _ (h3 n hn)
    | fixCharter _ _ => exact h r hr hp
    | postPool _ _ _ => exact h r hr hp
    | contribute _ => exact h r hr hp
    | session _ => exact h r hr hp
    | putShares _ => exact h r hr hp
    | holderOpen _ _ => exact h r hr hp
    | ackCheck _ _ _ => exact h r hr hp
    | pay _ => exact h r hr hp
    | acknowledge cm sg =>
      simp only [exec, List.mem_map] at hr
      obtain ⟨r0, hr0, rfl⟩ := hr
      have hp0 : r0.profile ≠ .P0 := by unfold setAcked at hp; split at hp <;> exact hp
      obtain ⟨h1, h2, h3⟩ := h r0 hr0 hp0
      unfold setAcked; split <;> exact ⟨h1, h2, h3⟩
  · exact h r hr hp

theorem runOps_recInv (s : St) (ops : List Op) (h : RecInv s) : RecInv (runOps s ops).1 := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_recInv s op h)

theorem runOps_birthOk_mono (s : St) (ops : List Op) (x : Nat × Nat) (h : x ∈ s.birthOk) :
    x ∈ (runOps s ops).1.birthOk := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_birthOk_mono s op x h)

/-- C1 and C2 (structural part, SH-011): in every run from `init`, every admitted P1
or P2 address record carries `q` distinct nodes whose BIRTH_OK on its `cm_addr`
the run holds; by `C2_birthOk_from_check` each of them came from a birth check
that passed every SH-009 check. -/
theorem C1_run_records_certified (p : Params) (ops : List Op) :
    RecInv (run (init p) ops) :=
  runOps_recInv _ ops (by intro r hr; simp [init] at hr)

/-! ### Acknowledgement of a network-created shard (DECISIONS 67)

The holder's `acknowledge` call carries `q` ACK_OK signatures, each given by a
node in an ACK check that passed; only that call sets `acked`; a payer wallet
pays only to an address whose network-created shard is acknowledged. -/

theorem apply_ackOk_mono (s : St) (op : Op) (x : Nat × Nat) (h : x ∈ s.ackOk) :
    x ∈ (apply s op).1.ackOk := by
  unfold apply; split
  · cases op with
    | ackCheck node cm _ =>
      simp only [exec]; split
      · exact h
      · exact List.mem_cons_of_mem _ h
    | _ => exact h
  · exact h

-- SH-031: an ACK_OK enters the state only through an ACK check of that node and
-- that `cm_addr` in which every check passed (DECISIONS 67)
theorem sh031_ackOk_from_check (s : St) (op : Op) (x : Nat × Nat) (h : x ∈ (apply s op).1.ackOk)
    (hn : x ∉ s.ackOk) : ∃ a, op = .ackCheck x.1 x.2 a ∧ ackPasses a = true := by
  unfold apply at h; split at h
  · rename_i hr
    cases op with
    | ackCheck node cm a =>
      simp only [exec] at h
      split at h
      · exact absurd h hn
      · simp only [List.mem_cons] at h
        rcases h with rfl | h
        · simp [opRefusals, opt] at hr
          exact ⟨a, rfl, hr.1⟩
        · exact absurd h hn
    | fixCharter _ _ => exact absurd h hn
    | birthCheck _ _ _ => exact absurd h hn
    | submitRecord _ => exact absurd h hn
    | postPool _ _ _ => exact absurd h hn
    | contribute _ => exact absurd h hn
    | session _ => exact absurd h hn
    | putShares _ => exact absurd h hn
    | holderOpen _ _ => exact absurd h hn
    | acknowledge _ _ => exact absurd h hn
    | pay _ => exact absurd h hn
  · exact absurd h hn

/-- Every acknowledged record has `q` distinct nodes whose ACK_OK on its `cm_addr`
the state holds (SH-033, SH-037). -/
def AckInv (s : St) : Prop :=
  ∀ r ∈ s.records, r.acked = true →
    ∃ sg : List Nat, nodupB sg = true ∧ s.params.q ≤ sg.length ∧ ∀ n ∈ sg, (n, r.cm) ∈ s.ackOk

theorem apply_ackInv (s : St) (op : Op) (h : AckInv s) : AckInv (apply s op).1 := by
  intro r hr ha
  rw [apply_params]
  have mono := apply_ackOk_mono s op
  suffices H : ∃ sg : List Nat, nodupB sg = true ∧ s.params.q ≤ sg.length ∧ ∀ n ∈ sg, (n, r.cm) ∈ s.ackOk by
    obtain ⟨sg, h1, h2, h3⟩ := H
    exact ⟨sg, h1, h2, fun n hn => mono _ (h3 n hn)⟩
  unfold apply at hr
  split at hr
  · rename_i hrf
    cases op with
    | submitRecord rr =>
      simp only [exec, List.mem_cons] at hr
      rcases hr with rfl | hr
      · simp at ha
      · exact h r hr ha
    | acknowledge cm sg =>
      simp only [exec, List.mem_map] at hr
      obtain ⟨r0, hr0, rfl⟩ := hr
      unfold setAcked at ha ⊢
      split
      · rename_i hc
        have hcm : r0.cm = cm := by simpa using hc
        simp only [opRefusals] at hrf
        split at hrf
        · simp at hrf
        · simp [opt] at hrf
          refine ⟨validAckers s cm sg, nodupB_filter _ _ (by simpa using hrf.2), ?_, ?_⟩
          · have := hrf.1
            simp only [noAckCert, decide_eq_false_iff_not, Nat.not_lt] at this
            exact this
          · intro n hn
            have hm := (List.mem_filter.mp hn).2
            rw [hcm]
            simpa using hm
      · rename_i hc
        simp only [hc] at ha
        exact h r0 hr0 ha
    | fixCharter _ _ => exact h r hr ha
    | birthCheck _ _ _ => exact h r hr ha
    | postPool _ _ _ => exact h r hr ha
    | contribute _ => exact h r hr ha
    | session _ => exact h r hr ha
    | putShares _ => exact h r hr ha
    | holderOpen _ _ => exact h r hr ha
    | ackCheck _ _ _ => exact h r hr ha
    | pay _ => exact h r hr ha
  · exact h r hr ha

theorem runOps_ackInv (s : St) (ops : List Op) (h : AckInv s) : AckInv (runOps s ops).1 := by
  induction ops generalizing s with
  | nil => exact h
  | cons op ops ih => exact ih _ (apply_ackInv s op h)

-- SH-033, SH-037: in every run from `init`, every record with `acked = true` carries
-- `q` distinct nodes whose ACK_OK on its `cm_addr` the run holds; by
-- `sh031_ackOk_from_check` each came from an ACK check that passed (DECISIONS 67)
theorem sh037_run_acked_certified (p : Params) (ops : List Op) :
    AckInv (run (init p) ops) :=
  runOps_ackInv _ ops (by intro r hr; simp [init] at hr)

-- SH-034: a record registers with `acked = false` (DECISIONS 67)
theorem sh034_registered_unacked (s : St) (rr : RecordReq) (h : (apply s (.submitRecord rr)).2 = .ok) :
    ∃ r, findRec (apply s (.submitRecord rr)).1 rr.cm = some r ∧ r.acked = false := by
  unfold apply at h ⊢
  split at h
  · exact ⟨{ cm := rr.cm, profile := rr.profile, charter := rr.charter, sigs := validSigners s rr,
              netCreated := rr.netCreated, acked := false }, by simp [exec, findRec], rfl⟩
  · simp at h

-- SH-035: the payer wallet pays only to an address whose record exists and, when
-- the address has a network-created shard, has `acked = true` (DECISIONS 67)
theorem sh035_paid_only_acked (s : St) (cm : Nat) (h : (apply s (.pay cm)).2 = .paid) :
    ∃ r, findRec s cm = some r ∧ (r.netCreated = true → r.acked = true) := by
  unfold apply at h
  split at h
  · rename_i hr
    simp only [opRefusals] at hr
    split at hr
    · simp at hr
    · rename_i r hr0
      refine ⟨r, hr0, fun hn => ?_⟩
      simpa [opt, payBlocked, hn] using hr
  · simp at h

/-! ### SH-038: one commitment list fixes every weight -/

mutual
theorem uses_congr (S T : List Nat) (h : ∀ x, S.contains x = T.contains x) :
    (g : Gate) → uses S g = uses T g
  | .leaf _ a => by simp only [uses]; exact h a
  | .and_ _ cs => by simp only [uses]; exact usesL_congr S T h cs
  | .group _ _ cs => by simp only [uses]; exact usesL_congr S T h cs
  | .or_ _ p e => by simp only [uses]; rw [uses_congr S T h p, uses_congr S T h e]
theorem usesL_congr (S T : List Nat) (h : ∀ x, S.contains x = T.contains x) :
    (cs : List Gate) → usesL S cs = usesL T cs
  | [] => rfl
  | g :: gs => by simp only [usesL]; rw [uses_congr S T h g, usesL_congr S T h gs]
end

mutual
/-- SH-004: the weight reads the signing set only through its members. -/
theorem weight_congr (S T : List Nat) (h : ∀ x, S.contains x = T.contains x) (a : Nat) :
    (g : Gate) → weight S a g = weight T a g
  | .leaf _ _ => by simp only [weight]
  | .and_ _ cs => by simp only [weight]; exact weightL_congr S T h a cs
  | .group _ _ cs => by
    have hu : uses S = uses T := funext (uses_congr S T h)
    simp only [weight, hu, weightG_congr S T h a cs]
  | .or_ _ p e => by simp only [weight]; rw [weight_congr S T h a p, weight_congr S T h a e]
theorem weightL_congr (S T : List Nat) (h : ∀ x, S.contains x = T.contains x) (a : Nat) :
    (cs : List Gate) → weightL S a cs = weightL T a cs
  | [] => rfl
  | g :: gs => by simp only [weightL]; rw [weight_congr S T h a g, weightL_congr S T h a gs]
theorem weightG_congr (S T : List Nat) (h : ∀ x, S.contains x = T.contains x) (a : Nat) :
    (cs : List Gate) → weightG S a cs = weightG T a cs
  | [] => rfl
  | g :: gs => by simp only [weightG]; rw [weight_congr S T h a g, weightG_congr S T h a gs]
end

/-- SH-038: two requests with one commitment list have the same members in their
signing sets, when each signing set holds its initiator (SH-003). -/
theorem sh038_cl_fixes_members (S T : List Nat) (i j : Nat) (hi : S.contains i = true)
    (hj : T.contains j = true) (h : clActors S i = clActors T j) (x : Nat) :
    S.contains x = T.contains x := by
  simp only [clActors, Prod.mk.injEq] at h
  obtain ⟨hij, hf⟩ := h
  subst hij
  by_cases hx : x = i
  · subst hx; rw [hi, hj]
  · have key : ∀ L : List Nat, L.contains x = (L.filter (· != i)).contains x := by
      intro L
      rw [Bool.eq_iff_iff]
      simp [List.mem_filter, hx]
    rw [key S, key T, hf]

/-- SH-038: one commitment list fixes the weight of every actor. No two requests
with one `CL` give an actor two weights, so no binding factor serves two weights. -/
theorem sh038_cl_fixes_weight (g : Gate) (S T : List Nat) (i j a : Nat) (hi : S.contains i = true)
    (hj : T.contains j = true) (h : clActors S i = clActors T j) :
    weight S a g = weight T a g :=
  weight_congr S T (sh038_cl_fixes_members S T i j hi hj h) a g

end SplitShardHolders
