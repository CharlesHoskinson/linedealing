## ADDED Requirements

### Requirement: HO-001 Handoff phases

**HO-001** The handoff state machine SHALL keep `phase` in `{IDLE, QUEUED, ROTATING, ARMED, HANDED_OVER, ABORTED}` for each target epoch and `CLOSED` for each epoch whose grace has ended.

No charter, profile, suite or mode can block a handoff or opt out of it (DECISIONS 79). Every clock counts Midnight blocks (DECISIONS 81). DESIGN §8, `HANDOFF.md`.

#### Scenario: New target

- **WHEN** epoch 4 is current and no ROTATE names epoch 5
- **THEN** epoch 5 has `phase = IDLE`

### Requirement: HO-002 ROTATE fields

**HO-002** When a ROTATE is ordered, the handoff state machine SHALL record its target epoch, its roster with one operator key per seat, its parameters `(n', f', q', t')`, its source epoch and its emergency flag.

#### Scenario: Scheduled rotation

- **WHEN** a ROTATE for epoch 5 with nine seats, `f' = 2`, source epoch 4 and no emergency flag is ordered
- **THEN** the handoff state machine records those fields for epoch 5

### Requirement: HO-003 Governance signatures

**HO-003** If a ROTATE carries fewer than `q` valid signatures of the governance key set of the latest landed checkpoint, then the handoff state machine SHALL refuse the ROTATE with the code `rotate_unauthorized`.

The governance key set is the set of operator keys of the current roster. It rotates with the roster at each activation record (HO-047).

#### Scenario: Five signatures

- **WHEN** a ROTATE carries five valid operator signatures at `q = 6`
- **THEN** the ROTATE is refused with `rotate_unauthorized`

### Requirement: HO-004 Target parameters

**HO-004** If a ROTATE has `n' < 3f' + 1`, `f' < 1`, `q' ≠ ⌈(n' + f' + 1)/2⌉` or `t' ≠ n' − f'`, then the handoff state machine SHALL refuse the ROTATE with the code `bad_params`.

#### Scenario: Wrong threshold

- **WHEN** a ROTATE names `n' = 9`, `f' = 2` and `t' = 6`
- **THEN** the ROTATE is refused with `bad_params`

### Requirement: HO-005 Seats per scheduled rotation

**HO-005** If a ROTATE without the emergency flag replaces more than `⌊f/2⌋` seats of the source roster, then the handoff state machine SHALL refuse the ROTATE with the code `too_many_seats`.

A joining seat that fails counts against `f'`, and a departing seat that fails counts against `f`. `⌊f/2⌋` keeps `⌈f/2⌉` of each budget for other faults (DECISIONS 81).

#### Scenario: Two seats at launch

- **WHEN** a scheduled ROTATE replaces two seats at `f = 2`
- **THEN** the ROTATE is refused with `too_many_seats`

### Requirement: HO-006 Seats per emergency rotation

**HO-006** If a ROTATE with the emergency flag replaces more than `f` seats of the source roster, then the handoff state machine SHALL refuse the ROTATE with the code `too_many_seats`.

#### Scenario: Emergency within budget

- **WHEN** an emergency ROTATE replaces two seats at `f = 2`
- **THEN** the ROTATE is not refused for its seat count

### Requirement: HO-007 Target epoch

**HO-007** If a ROTATE names a target epoch other than the current epoch plus one, then the handoff state machine SHALL refuse the ROTATE with the code `bad_epoch`.

#### Scenario: Skipped epoch

- **WHEN** epoch 4 is current and a ROTATE names epoch 6
- **THEN** the ROTATE is refused with `bad_epoch`

### Requirement: HO-008 Source epoch

**HO-008** If the source epoch of a ROTATE is neither the current epoch nor an epoch in grace, then the handoff state machine SHALL refuse the ROTATE with the code `bad_source`.

A source in grace lets the holders of epoch `e` replace a committee of epoch `e + 1` that cannot sign (DECISIONS 84).

#### Scenario: Closed source

- **WHEN** a ROTATE names source epoch 3 after epoch 3 is CLOSED
- **THEN** the ROTATE is refused with `bad_source`

### Requirement: HO-009 Second rotation

**HO-009** If a ROTATE is ordered while a ROTATE is QUEUED or ROTATING, then the handoff state machine SHALL refuse the new ROTATE with the code `rotation_open`.

#### Scenario: Two ROTATE posts

- **WHEN** a ROTATE for epoch 5 is ROTATING and a second ROTATE for epoch 5 is ordered
- **THEN** the second ROTATE is refused with `rotation_open`

### Requirement: HO-010 Preconditions

**HO-010** The handoff state machine SHALL define the preconditions of a ROTATE as the conjunction of four facts: no rotation is ROTATING, the epoch before the current epoch is CLOSED, no whole-committee restart is open, and the source epoch is current or in grace.

The second condition keeps at most two epochs live (HO-055).

#### Scenario: Grace not ended

- **WHEN** epoch 3 is still in grace after the activation of epoch 4
- **THEN** the preconditions of a ROTATE for epoch 5 are not met

### Requirement: HO-011 Queue

**HO-011** When a valid ROTATE is ordered while its preconditions are not met, the handoff state machine SHALL set `phase = QUEUED` for its target epoch.

A ROTATE that arrives early is queued, not refused, so a handoff can be started from every reachable state (DECISIONS 79).

#### Scenario: Early ROTATE

- **WHEN** a valid ROTATE for epoch 5 is ordered while epoch 3 is in grace
- **THEN** epoch 5 has `phase = QUEUED`

### Requirement: HO-012 Start

**HO-012** When a valid ROTATE is ordered with its preconditions met, or the preconditions of a QUEUED ROTATE become met, the handoff state machine SHALL set `phase = ROTATING`, `m_R` to the latest final Midnight height that the board block names and `m_D = m_R + Δ_rot`.

`Δ_rot` is 5 days of Midnight blocks at launch (DECISIONS 81). Nodes read Midnight heights at the finality depth `F_M`.

#### Scenario: Queue released

- **WHEN** epoch 3 closes and the board block that releases a QUEUED ROTATE for epoch 5 names Midnight height 9,000
- **THEN** epoch 5 has `phase = ROTATING` and `m_R = 9,000`

### Requirement: HO-013 Joining boot

**HO-013** When an `admitBoot` names a seat of the roster of a ROTATING ROTATE and carries that ROTATE, the Node Registry SHALL record the seat as pending.

#### Scenario: New operator

- **WHEN** the operator of joining seat 10 submits `admitBoot` with the ROTATE for epoch 5
- **THEN** seat 10 is pending in the Node Registry

### Requirement: HO-014 Unknown seat

**HO-014** If an `admitBoot` names a seat that is in no current roster and in no roster of a ROTATING ROTATE, then the Node Registry SHALL refuse the boot with the code `seat_unknown`.

#### Scenario: Self-appointed operator

- **WHEN** an operator submits `admitBoot` for a seat that no ROTATE names
- **THEN** the boot is refused with `seat_unknown`

### Requirement: HO-015 Epoch keys of the target

**HO-015** When every seat of the target roster has `w'` acks on the board for its `NodeKeys`, the handoff state machine SHALL record `EKS_{e+1}` as complete.

`w' = n' − 1 − f'`. `EKS_{e+1}` reaches Midnight only inside the activation record (HO-047).

#### Scenario: Keys complete

- **WHEN** the ninth seat of epoch 5 gets its sixth ack
- **THEN** `EKS_5` is complete on the board

### Requirement: HO-016 Seal group of the target

**HO-016** Where `mode = TEE`, the committee node of the target roster SHALL install its share of the seal-group secret `σ_{e+1}` from a DKG among the target roster before it posts READY.

#### Scenario: Seal group

- **WHEN** seat 10 of epoch 5 posts READY in TEE mode
- **THEN** seat 10 holds its share of `σ_5`

### Requirement: HO-017 Silence before activation

**HO-017** While the handoff of its epoch is not HANDED_OVER, the committee node of a target seat SHALL send no partial, cast no board vote and sign no checkpoint for the target epoch other than the activation record.

An envelope that binds epoch `e + 1` waits for the activation.

#### Scenario: Early envelope

- **WHEN** an envelope that binds epoch 5 is ordered before the activation of epoch 5
- **THEN** no seat of epoch 5 sends a header partial for it before that activation

### Requirement: HO-018 Standing carry

**HO-018** When `EKS_{e+1}` is complete, the committee node of each seat of the source epoch SHALL deal a carry of its share of `x_f` per curve and of its share pair of every ECDSA committee slot that no request has used.

A carry is the reshare of DESIGN §8.1: a polynomial of degree `t' − 1` per share, Feldman commitments whose constant term is implied by the old commitments (base `G` for `x_f`, base `R_ℓ` for a slot) and one ciphertext per target seat.

#### Scenario: Inventory carried

- **WHEN** `EKS_5` is complete and an address holds 16 unused ECDSA slots
- **THEN** each seat of epoch 4 deals a carry of its share pair of each of the 16 slots

### Requirement: HO-019 Constant term

**HO-019** If the implied constant term of a carry dealing by seat `i` differs from `Eval` of the old commitments at `i`, then the handoff state machine SHALL refuse the dealing with the code `carry_mismatch`.

#### Scenario: Wrong constant term

- **WHEN** seat 3 deals a carry of `x_f` whose constant term is not `X_{f,3}`
- **THEN** the dealing is refused with `carry_mismatch`

### Requirement: HO-020 Complaint

**HO-020** If a valid complaint against a carry dealing is ordered within `Δ_cw` Midnight blocks after the dealing's batch, then the handoff state machine SHALL disqualify the dealer for every dealing of the rotation.

The window assumes that every honest target seat's complaint is ordered within it. That is the synchrony hypothesis of O5.

#### Scenario: Bad share

- **WHEN** seat 10 posts a valid complaint against seat 3 inside `Δ_cw`
- **THEN** seat 3 is disqualified for every dealing of the rotation

### Requirement: HO-021 Qualified set

**HO-021** The handoff state machine SHALL take as the qualified set `Q` the first `t` source dealers in board order with no valid complaint.

#### Scenario: One dealer disqualified

- **WHEN** seat 3 is disqualified and seats 1, 2 and 4 to 9 deal
- **THEN** `Q` is seats 1, 2 and 4 to 8

### Requirement: HO-022 No burn on a failed dealing

**HO-022** If a carry dealing of an ECDSA slot fails, then the handoff state machine SHALL leave the slot's state unchanged.

The failed dealer is disqualified (HO-020). The other dealers carry the slot.

#### Scenario: Slot kept

- **WHEN** the carry of slot 7 of an address by seat 3 draws a valid complaint
- **THEN** slot 7 stays `free`

### Requirement: HO-023 Carry rate

**HO-023** While a handoff is ROTATING, the committee node SHALL keep its carry dealings to at most the share `β` of the board bytes of each block.

`β` is 10 % at launch (DECISIONS 81).

#### Scenario: Busy block

- **WHEN** a block carries 1 MB of envelopes
- **THEN** it carries at most 100 kB of carry dealings at `β = 10 %`

### Requirement: HO-024 Copy burned on use

**HO-024** When the board shows a request of the source epoch use a carried ECDSA slot, the committee node of each target seat SHALL burn its copy of that slot.

#### Scenario: Spend during CARRY

- **WHEN** a request of epoch 4 reserves slot 7 after slot 7 was carried to epoch 5
- **THEN** every seat of epoch 5 burns its copy of slot 7

### Requirement: HO-025 Release on the board during a handoff

**HO-025** While a handoff is ROTATING or HANDED_OVER, the committee node of the source epoch SHALL send no partial before its RELEASE entry for that generation is committed on the board.

In TEE mode this adds one board commit to each release from ROTATE to CLOSE. In non-TEE mode it is the rule of DECISIONS 59.

#### Scenario: TEE release during a rotation

- **WHEN** a TEE seat of epoch 4 releases generation 1 while the handoff to epoch 5 is ROTATING
- **THEN** its RELEASE entry is committed before its partial leaves

### Requirement: HO-026 Witness releases in the carry

**HO-026** When the committee node of a source seat deals a carry, the committee node SHALL list in it the release entries of its witness log for every request that is live at the dealing.

#### Scenario: Early TEE release

- **WHEN** seat 2 holds a witnessed release of request 41 from before the ROTATE
- **THEN** seat 2 lists that release entry in its carry

### Requirement: HO-027 Release evidence

**HO-027** When a committed RELEASE entry or a listed release entry of a carry shows a release of a request, the request state machine SHALL set `any_release = true` for that request.

A request with `any_release = true` never settles VOID with a fresh nullifier (DESIGN §5.6, RQ-076).

#### Scenario: Listed release

- **WHEN** a carry lists a release entry of request 41
- **THEN** request 41 has `any_release = true`

### Requirement: HO-028 ECDSA sessions at the snapshot

**HO-028** While a handoff is ROTATING and the board is above its snapshot height `h_S`, the committee node SHALL start no ECDSA birth or refill session for the source epoch.

The session waits for the activation and runs with the target epoch. Its session parties are online for the session in any case.

#### Scenario: Late refill

- **WHEN** a refill session is requested above `h_S`
- **THEN** it starts after the activation with the target epoch

### Requirement: HO-029 READY

**HO-029** When a target seat holds valid shares under `Q` of `x_f` per curve and of every ECDSA slot of the inventory at `h_S`, and holds `k_nf`, the committee node SHALL post `READY(e + 1, H(Q), h_S)`.

In TEE mode READY also needs HO-016 and sealed sessions of the target epoch. The last carry before READY is the source epoch's last step that the activation needs.

#### Scenario: Seat ready

- **WHEN** seat 10 holds valid shares of both `x_f` and of every slot of the inventory at `h_S`, and holds `k_nf`
- **THEN** seat 10 posts READY

### Requirement: HO-030 READY counting

**HO-030** The handoff state machine SHALL count READY posts for each pair `(H(Q), h_S)` and never add posts of two pairs.

#### Scenario: Split READY

- **WHEN** four seats post READY for one `Q` and three for another at `n' = 9`
- **THEN** neither pair has a count above four

### Requirement: HO-031 Arm heartbeat

**HO-031** While the last complaint window of a ROTATING handoff is closed and no whole-committee restart is open, when the `n' − f'`-th READY post for one pair `(H(Q), h_S)` commits, the committee node of each target seat SHALL contribute its partial to the arm heartbeat.

The heartbeat is a threshold signature under `X_f` per curve by `t'` target seats over `("fenrir/arm", e + 1, H(Q), h_S)`. It is never a signature under an address key (DECISIONS 84).

#### Scenario: Seven READY

- **WHEN** the seventh READY for one pair commits at `n' = 9`, `f' = 2`
- **THEN** each target seat contributes its partial to the arm heartbeat

### Requirement: HO-032 Validator set

**HO-032** When the activation record of the target epoch is final on Midnight, the board SHALL take the target roster as its validator set from height `H + 1`.

Epoch `e` members cast no block vote above `H` (HO-064). The board makes no block between `H` and the activation.

#### Scenario: First new block

- **WHEN** the activation record of epoch 5 with `H = 12,000` is final on Midnight
- **THEN** block 12,001 needs a quorum certificate of epoch 5

### Requirement: HO-033 Deadline

**HO-033** If Midnight passes `m_D` while a handoff is ROTATING or ARMED and no activation record of it has landed, then the handoff state machine SHALL set `phase = ABORTED`.

#### Scenario: Slow carry

- **WHEN** Midnight height `m_D` is final with five READY posts at `n' = 9`
- **THEN** the handoff has `phase = ABORTED`

### Requirement: HO-034 Abort erase

**HO-034** When a handoff becomes ABORTED, the committee node of each target seat SHALL erase every share it received, its target epoch keys and its target nonce pools.

A joining seat then retires. Nothing of the aborted rotation reaches Midnight except the joining seats' boots.

#### Scenario: Erase after abort

- **WHEN** the handoff to epoch 5 aborts
- **THEN** seat 10 holds no share and no key of epoch 5

### Requirement: HO-035 Abort keeps the source

**HO-035** When a handoff becomes ABORTED, the handoff state machine SHALL keep the current epoch, its roster, its sharings, its pools and its authorities as they were.

An abort in ARMED resumes the source epoch at `H + 1` (HO-066).

#### Scenario: Old committee intact

- **WHEN** the handoff to epoch 5 aborts
- **THEN** epoch 4 is current with every sharing it held

### Requirement: HO-036 Owning epoch

**HO-036** The request state machine SHALL take as the owning epoch of a request its binding epoch until the board position of its sweep and the successor of its binding epoch after that position.

The binding epoch is the envelope's `epoch` field with its `keylist_hash`. The owning epoch opens, admits and releases. FINAL and VOID posts follow RQ-042, which counts every epoch that serves the request (DECISIONS 56, DECISIONS 80).

#### Scenario: Request across the activation

- **WHEN** a request that binds epoch 4 is admitted after the activation of epoch 5 and before the sweep
- **THEN** epoch 4 owns it

### Requirement: HO-037 Epoch posts

**HO-037** When a member of an epoch that is not the board's validator set posts its OPENED, ADMIT with OBS, RELEASE or FINAL entries for a request that its epoch owns, the request state machine SHALL count the epoch post at its board position against that epoch's own thresholds as it counts votes.

#### Scenario: Old ADMIT after the activation

- **WHEN** six members of epoch 4 post ADMIT for a request that binds epoch 4 after the activation of epoch 5
- **THEN** the request has `phase = ADMITTED`

### Requirement: HO-038 Entry from an epoch that does not own

**HO-038** If an OPENED, ADMIT or RELEASE entry for a request comes from a member of an epoch that does not own the request at the entry's board position, then the request state machine SHALL refuse the entry with the code `not_owner`.

#### Scenario: New epoch admits early

- **WHEN** a member of epoch 5 posts ADMIT for a request that epoch 4 owns
- **THEN** the entry is refused with `not_owner`

### Requirement: HO-039 Pool of the binding epoch

**HO-039** If a header names a committee slot of a pool of another epoch than the request's binding epoch, then the committee node SHALL vote for no slot reservation of the header and record the code `pool_epoch_mismatch`.

#### Scenario: Mixed pools

- **WHEN** a request that binds epoch 4 names a slot of the BIP340 pool of epoch 5
- **THEN** no honest node votes for the header and the code is `pool_epoch_mismatch`

### Requirement: HO-040 Epoch open to new envelopes

**HO-040** The committee node SHALL treat an epoch as current for the public check of EN-005 from the activation that opens it until the sweep of its grace.

#### Scenario: Lagging wallet

- **WHEN** an envelope that binds epoch 4 arrives one hour after the activation of epoch 5
- **THEN** the public check of EN-005 accepts its epoch

### Requirement: HO-041 Closed epoch

**HO-041** If an envelope binds an epoch whose sweep has passed, then the committee node SHALL refuse to accept it with the code `epoch_closed`.

The envelope never reaches the board, so it reserves and burns nothing.

#### Scenario: Envelope after the sweep

- **WHEN** an envelope that binds epoch 4 arrives after the sweep of epoch 4
- **THEN** it is refused with `epoch_closed`

### Requirement: HO-042 Sweep

**HO-042** When Midnight reaches `m_W = grace_end(e) − Δ_sweep`, the committee node of each seat of epoch `e` SHALL deal a carry of the live material of every request that binds epoch `e` and has not ended.

The live material is `κ_0`, each `κ_c`, each P0 line and each unreleased named slot. The activation never depends on the sweep.

#### Scenario: Open collection at the sweep

- **WHEN** a collecting request that binds epoch 4 is live at `m_W`
- **THEN** each seat of epoch 4 carries its share of the request's `κ_0` and of each slot it names

### Requirement: HO-043 Sweep switch

**HO-043** When `n' − f'` target seats post READY for the sweep batch, the request state machine SHALL set the board position of the sweep of every request in the batch to that position.

#### Scenario: Sweep ready

- **WHEN** the seventh READY for the sweep batch of epoch 4 commits
- **THEN** epoch 5 owns every request of the batch from that position

### Requirement: HO-044 Carried slot state

**HO-044** When a target seat installs a carried committee slot, the committee node SHALL give the slot the state that the board shows: `free`, `bound` to the anchored ticket, or `burned`.

A carried slot keeps its pool label `slots-s-e`, its index, its points and its nullifier under `k_nf`, so `ρ`, `R` and every challenge stay the same.

#### Scenario: Anchored before the sweep

- **WHEN** the anchor of generation 2 fixed the ticket of slot 30 before the sweep
- **THEN** the target seat installs slot 30 as `bound` to that ticket

### Requirement: HO-045 Grace end

**HO-045** When the grace of epoch `e` ends, the committee node of each seat of epoch `e` SHALL erase every share and every epoch key it holds for epoch `e`.

The grace ends `Δ_grace` Midnight blocks after the activation record of epoch `e + 1`, 2 days at launch. Continuing seats keep their epoch `e + 1` shares. In TEE mode the seat calls `session_destroy` and `close_epoch` (DESIGN §7.8). Departing seats then retire.

#### Scenario: Departing seat at grace end

- **WHEN** the grace of epoch 4 ends
- **THEN** seat 3 of epoch 4 holds no share of `x_f`, no slot share and no key of epoch 4

### Requirement: HO-046 No source checkpoint above H

**HO-046** If a checkpoint of the source epoch has a board height above `H`, then the committee node of the source epoch SHALL refuse to sign it with the code `epoch_superseded`.

#### Scenario: Old signer after arming

- **WHEN** a checkpoint of epoch 4 with board height `H + 50` is proposed
- **THEN** no seat of epoch 4 signs it

### Requirement: HO-047 Activation record

**HO-047** When a handoff is ARMED, the committee node of each target seat SHALL sign the activation record: the checkpoint fields at board height `H`, `EKS_{e+1}`, the target roster with each operator key, the departing seats, the ROTATE with its governance signatures and the arm heartbeat.

It carries `t'` target signatures and none of the source epoch (DECISIONS 83).

#### Scenario: Activation write

- **WHEN** the handoff to epoch 5 is ARMED at height 12,000
- **THEN** one Midnight record with board height 12,000 carries `EKS_5`, the roster of epoch 5, the ROTATE, the heartbeat and seven signatures of epoch 5

### Requirement: HO-048 Activation check

**HO-048** If an activation record lacks valid ROTATE signatures of the governance key set, `t'` valid signatures of the target epoch, a valid arm heartbeat under `X_f` or a boot ticket for a joining seat, then the committee contract SHALL refuse it with the code `bad_activation`.

The contract verifies the edwards25519 heartbeat. The secp256k1 heartbeat needs secp256k1 verification in Compact (O43), and until then the nodes check it before they sign the record.

#### Scenario: Six new signers

- **WHEN** an activation record carries six signatures of epoch 5 at `t' = 7`
- **THEN** it is refused with `bad_activation`

### Requirement: HO-049 Operator disjointness

**HO-049** If an activation record names an operator key that is a member of the recovery group `E` or of any guardian set, then the committee contract SHALL refuse it with the code `operator_not_disjoint`.

#### Scenario: Guardian as operator

- **WHEN** the roster of epoch 5 names an operator key of a guardian of a P2 charter
- **THEN** the activation record is refused with `operator_not_disjoint`

### Requirement: HO-050 Signer switch

**HO-050** When an activation record lands, the committee contract SHALL accept a later checkpoint only with `t'` valid signatures of `EKS_{e+1}`.

#### Scenario: First checkpoint of the new epoch

- **WHEN** the activation record of epoch 5 has landed
- **THEN** the next checkpoint needs seven signatures of `EKS_5`

### Requirement: HO-051 Superseded epoch

**HO-051** If a checkpoint signed by an epoch is submitted after the activation record of its successor has landed, then the committee contract SHALL refuse it with the code `epoch_superseded`.

#### Scenario: Late old checkpoint

- **WHEN** a checkpoint signed by seven members of epoch 4 arrives after the activation record of epoch 5
- **THEN** it is refused with `epoch_superseded`

### Requirement: HO-052 Epoch-scoped certificates

**HO-052** The committee contract SHALL check each committee certificate that it receives (birth certificate, acknowledgement certificate, slot-root certificate, carried VOID leaf) against the epoch key set of the epoch that the certificate names.

`authorize` checks no committee signature (DECISIONS 83). AU-021 and AU-022 read `EKS_e` as the key set of the leaf's epoch.

#### Scenario: Leaf of the old epoch

- **WHEN** a reissue in grace carries a VOID leaf signed by six members of epoch 4
- **THEN** the contract checks the signatures against `EKS_4`

### Requirement: HO-053 Certificate of a closed epoch

**HO-053** If a committee certificate names an epoch whose grace has ended, then the committee contract SHALL refuse it with the code `epoch_closed`.

A record that Midnight already holds stays valid. A reissue after the grace end uses the root path, because a checkpoint covers every leaf within one interval.

#### Scenario: Very late reissue

- **WHEN** a reissue carries a VOID leaf of epoch 4 after the grace of epoch 4 ended
- **THEN** the carry is refused with `epoch_closed`

### Requirement: HO-054 Continuity across an activation

**HO-054** The committee contract SHALL treat a joining seat as continuous from the activation record that names it, and apply the boot-counter rule of CP-009 across the activation record to the continuing seats only.

At most `f` seats change, so at least `n − f ≥ w + 1` seats stay continuous, and an activation is not a whole-committee restart (DECISIONS 85).

#### Scenario: One seat swapped

- **WHEN** the activation record of epoch 5 replaces seat 3 by seat 10 and the eight other seats keep their boot counters
- **THEN** CP-009 does not refuse the record

### Requirement: HO-055 Two live epochs

**HO-055** The handoff state machine SHALL keep at most two epochs that are current or in grace at every board height.

#### Scenario: Grace and current

- **WHEN** epoch 4 is current and epoch 3 is in grace
- **THEN** no ROTATE for epoch 5 is ROTATING

### Requirement: HO-056 X_f unchanged

**HO-056** The handoff state machine SHALL keep the public committee key `X_f` of each curve unchanged in every transition.

Every address `X = X_f + tw·G + Σ_a X_a` therefore survives every handoff.

#### Scenario: After ten handoffs

- **WHEN** ten handoffs have completed since genesis
- **THEN** `X_f` of secp256k1 and of edwards25519 equal their genesis values

### Requirement: HO-057 User state untouched

**HO-057** The handoff state machine SHALL leave every user shard, tweak, actor nonce pool, sealed contribution, slot root and asset record unchanged in every handoff transition.

Owner ruling 2026-11-16: the user's shard stays unchanged.

#### Scenario: Shard after a handoff

- **WHEN** the handoff to epoch 5 completes
- **THEN** every user shard equals its value before the ROTATE

### Requirement: HO-058 No user action

**HO-058** The handoff state machine SHALL take every handoff transition on an operation of governance, of a committee seat, of the board or of board time, and on no operation of a user or an actor.

Owner rule: the owner is online only to initiate a spend and to broadcast it.

#### Scenario: Request live across a handoff

- **WHEN** a request that binds epoch 4 is live from before the ROTATE until after the sweep
- **THEN** it reaches its end with no post by its owner after its envelope

### Requirement: HO-059 One owning epoch

**HO-059** The request state machine SHALL give each live request exactly one owning epoch at every board position from its ordering to its end.

#### Scenario: Position of the sweep

- **WHEN** the sweep of request 41 is at position 20,000
- **THEN** epoch 4 owns request 41 below 20,000 and epoch 5 owns it from 20,000

### Requirement: HO-060 Slot-nullifier key

**HO-060** The committee node SHALL keep the slot-nullifier key `k_nf` unchanged across every handoff.

#### Scenario: Seat log after a handoff

- **WHEN** a carried ECDSA slot binds after the activation of epoch 5
- **THEN** its binding entry has the nullifier it had under epoch 4

### Requirement: HO-061 Slot-nullifier key in non-TEE mode

**HO-061** Where `mode = NON_TEE`, the committee node of a target seat SHALL take as `k_nf` the value that `f + 1` source dealers send alike.

#### Scenario: One dealer lies

- **WHEN** eight source dealers send one value of `k_nf` and one sends another
- **THEN** the target seat takes the value of the eight

### Requirement: HO-062 Recovery backup kept

**HO-062** The recovery group SHALL keep its backup of `x_f`, of ECDSA slot shares and of `k_nf` unchanged across a committee handoff.

The backup holds constant terms that a handoff does not change. `E` refreshes its sharing only when its own membership changes (DECISIONS 82).

#### Scenario: No backup step

- **WHEN** the handoff to epoch 5 completes
- **THEN** no member of `E` received a dealing in it

### Requirement: HO-063 Signable after a handoff

**HO-063** The handoff state machine SHALL keep every address that is signable before a completed handoff signable after it.

An address is signable when the current epoch holds a sharing of `x_f` of its curve with constant term `X_f`, its user shard is unchanged, and, on ECDSA, every unused slot of the address is held by the current epoch.

#### Scenario: ECDSA address

- **WHEN** an ECDSA address has 16 unused slots before the handoff to epoch 5
- **THEN** epoch 5 holds the shares of all 16 after the handoff

### Requirement: HO-064 ARMED

**HO-064** When a board block commits the arm heartbeat of a ROTATING handoff with a quorum certificate of the source epoch, the handoff state machine SHALL set `phase = ARMED` with `H` the height of that block.

From `H` on, source-epoch members cast no block vote. They still post epoch posts for the requests that their epoch owns (HO-037).

#### Scenario: Heartbeat committed

- **WHEN** block 12,000 commits the arm heartbeat of epoch 5
- **THEN** the handoff to epoch 5 has `phase = ARMED` and `H = 12,000`

### Requirement: HO-065 Late activation

**HO-065** If an activation record reaches the committee contract after Midnight height `m_D` of its ROTATE, then the committee contract SHALL refuse it with the code `activation_late`.

Midnight decides between activation and abort, so both committees read one outcome.

#### Scenario: Record one block late

- **WHEN** the activation record of epoch 5 arrives at Midnight height `m_D + 1`
- **THEN** it is refused with `activation_late`

### Requirement: HO-066 Resume after an armed abort

**HO-066** When a handoff that was ARMED becomes ABORTED, the board SHALL take the source roster as its validator set from height `H + 1`.

#### Scenario: Activation never landed

- **WHEN** Midnight height `m_D` of the handoff to epoch 5 is final with no activation record and the handoff was ARMED at 12,000
- **THEN** block 12,001 needs a quorum certificate of epoch 4

### Requirement: HO-067 No source step after arming

**HO-067** While a handoff is ARMED, the handoff state machine SHALL take the transition to HANDED_OVER on operations of target seats, of the committee contract and of Midnight time only.

The armed committee holds its own sharing of `x_f` and of every ECDSA slot of the inventory, and the heartbeat proves it. The activation is the operation that an armed reserve committee would also use (`HANDOFF.md` §12).

#### Scenario: Source silent after arming

- **WHEN** every source seat stops after block `H` and the target seats submit the activation record before `m_D`
- **THEN** the handoff reaches `phase = HANDED_OVER`

### Requirement: HO-068 Checkpoint signers

**HO-068** If a checkpoint carries fewer than `t` valid signatures of the epoch key set of its epoch, then the committee contract SHALL refuse it with the code `too_few_signers`.

`t` seats can sign under `X_f`, and `q < t` seats cannot (`q = 6`, `t = 7` at launch). A checkpoint that `q` seats could land would keep the committee's Midnight record alive while it cannot sign (DECISIONS 86). CP-003 counts `t` signatures.

#### Scenario: Six signers at launch

- **WHEN** a checkpoint of epoch 4 carries six valid signatures at `t = 7`
- **THEN** it is refused with `too_few_signers`
