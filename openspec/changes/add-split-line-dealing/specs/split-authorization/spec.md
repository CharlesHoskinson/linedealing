## ADDED Requirements

### Requirement: AU-001 Asset record fields

**AU-001** The FenrirAssets contract SHALL keep for each asset record the fields `cm_addr`, `profile`, `board_first`, `rstate`, `nf`, `pin`, `hold_tag`, `slr_own` and `slr_G`.

`profile ∈ {P0, P1, P2}`. `rstate ∈ {UNSPENT, PENDING, LOCKED}`; LOCKED follows a RELEASED settlement and binds `pin`, the pinned input or nonce. `slr_own` and `slr_G` exist on ECDSA records, `slr_G` in P2 only.

#### Scenario: New P1 record

- **WHEN** a P1 record with a birth certificate lands
- **THEN** it has `rstate = UNSPENT` and a fresh `nf`

### Requirement: AU-002 Authorization fields

**AU-002** The FenrirAssets contract SHALL keep for each authorization the fields `auth`, `nf`, `rh`, `status`, `final_height` and `settled`.

`status ∈ {SUBMITTED, FINAL, REVOKED}`. `final_height` is the Midnight height at which the transaction became final, or `none`. `settled ∈ {NONE, FINAL, VOID, RELEASED}`.

#### Scenario: Submitted authorization

- **WHEN** an `authorize` call is included and not yet final
- **THEN** the authorization has `status = SUBMITTED` and `final_height = none`

### Requirement: AU-003 Authorization digest

**AU-003** The initiator wallet SHALL compute `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)` and publish with `authorize` only `auth`, `nf`, `rh` and the proof.

`ic` is a hiding commitment to the intent, `tkc` a hiding commitment to the ticket list padded to 32 entries, `rh` the hold handle (AU-016). One circuit serves every suite, profile and variant count (DESIGN §5.3).

#### Scenario: Public inputs

- **WHEN** a wallet submits `authorize`
- **THEN** Midnight sees `auth`, `nf`, `rh` and a proof, and no suite, profile or variant count

### Requirement: AU-004 Accept an authorization

**AU-004** When an `authorize` call names a record with `board_first = false` and its current unused `nf`, and its proof verifies the statement of AU-005, the FenrirAssets contract SHALL set `rstate = PENDING` and add the authorization with `status = SUBMITTED`.

#### Scenario: Valid authorization

- **WHEN** a valid `authorize` names the current `nf` of an unspent record
- **THEN** the record has `rstate = PENDING`

### Requirement: AU-005 Statement

**AU-005** The FenrirAssets contract SHALL accept an `authorize` proof only for the statement of DESIGN §5.3 items 1 to 4, and in NON_TEE mode also item 5.

Item 1: record and fresh `nf`, or LOCKED with its `pin`, or a successor whose settlement counts (AU-020, AU-021). Item 2: inputs and fee ceiling. Item 3: one source with its checks (AU-006, AU-007). Item 4: `tkc` and ECDSA slot roots. Item 5: the ticket proof.

#### Scenario: ECDSA slot of another record

- **WHEN** an owner proves an intent on record A and names a slot under `slr_own` of record B
- **THEN** the proof does not verify

### Requirement: AU-006 Sources per profile

**AU-006** The FenrirAssets contract SHALL admit the owner or initiator source for P0, P1 and P2, the seizure-order source for P2 only and the recovery-exit source for P1 and P2 only, and open ECDSA slots under `slr_own` for the owner and recovery sources and under `slr_G` for the seizure source.

For P1 and P2 the owner source also proves `S ∈ Γ` and the initiator in `S` (DECISIONS 19, 20, 22).

#### Scenario: Seizure on a P1 record

- **WHEN** a seizure order names a P1 record
- **THEN** no source admits it and the proof does not verify

### Requirement: AU-007 Checks per source

**AU-007** The FenrirAssets contract SHALL apply the checks of the DESIGN §5.3 check table: owner-chosen predicates and approver checks to the owner or initiator source of the P1 and P2 charters that chose them, the registry blacklist to that source in P2, the hold accumulator to the owner and recovery sources in P2, and no check to a P1 recovery exit.

The P1 recovery exit is unconditional.

#### Scenario: Held P2 record

- **WHEN** the tag of a P2 record is in the hold set and its owner proves a spend
- **THEN** the proof does not verify

### Requirement: AU-008 Nullifier already used

**AU-008** If an `authorize` call names an `nf` that an earlier `authorize` already used, then the FenrirAssets contract SHALL refuse the call with the code `nf_used`.

That is the single-spend rule for one record state (claim C11).

#### Scenario: Second authorization

- **WHEN** a second `authorize` names the same `nf`
- **THEN** the call is refused and the record is unchanged

### Requirement: AU-009 Locked record

**AU-009** If an `authorize` call for a record with `rstate = LOCKED` proves an intent that does not spend the record's `pin`, then the FenrirAssets contract SHALL refuse the call with the code `pin_mismatch`.

A later authorization for a RELEASED request spends the same pinned input or nonce, so at most one transaction confirms (DECISIONS 47).

#### Scenario: Re-post with another nonce

- **WHEN** a locked Ethereum record proves an intent with nonce `n + 1` for `pin = n`
- **THEN** the call is refused

### Requirement: AU-010 In force, Midnight-first

**AU-010** The committee node SHALL treat a Midnight-first authorization as in force from the Midnight block at which its `authorize` transaction is final, and never at inclusion without finality.

A signature released to a host chain cannot be recalled (DESIGN §5.11).

#### Scenario: Included, not final

- **WHEN** the `authorize` of a request is in a Midnight block that is not final
- **THEN** the authorization is not in force

### Requirement: AU-011 Board-first eligibility

**AU-011** If a charter sets `board_first` with profile P2, or with a predicate that reads Midnight state that other requests change, then the Charters contract SHALL refuse the charter with the code `board_first_forbidden`.

Eligible: P0, and P1 with fixed destination allow-lists, time locks and approver signatures checked in the proof (DECISIONS 29, DESIGN §5.3). A cumulative limit or a veto is stateful.

#### Scenario: Cumulative limit

- **WHEN** a P1 charter with a daily limit sets `board_first`
- **THEN** the charter is refused

### Requirement: AU-012 Direct call on a board-first record

**AU-012** If an `authorize` call names a record of a charter with `board_first = true`, then the FenrirAssets contract SHALL refuse the call with the code `board_first_record`.

Such a record changes only through the `bf_root` of a landed checkpoint, so a direct call cannot race the board (DECISIONS 52).

#### Scenario: Direct call

- **WHEN** a wallet submits `authorize` for a board-first record on Midnight
- **THEN** the call is refused

### Requirement: AU-013 Board-first call check

**AU-013** When an initiator posts a board-first `authorize` call to the board, the committee node SHALL verify its proof, that its state root is a finalized Midnight root not older than the charter bound minus one checkpoint interval and `F_M`, that no leaf of a landed `bf_root` holds its `nf`, and for a reissue the `q` signatures on the carried VOID leaf.

In TEE mode the enclave runs the verifier.

#### Scenario: Stale root

- **WHEN** a board-first call names a root older than the bound minus 60 s and `F_M`
- **THEN** the node does not accept the call

### Requirement: AU-014 Board-first pending set

**AU-014** When the board orders a board-first call whose checks of AU-013 pass at the node and whose `nf` the pending set does not hold, the committee node SHALL add `nf` to its pending set.

A copied `nf` under an invalid proof blocks nothing. The pending set holds the calls ordered after the latest landed checkpoint, lives on the board and is part of the rotation handover.

#### Scenario: First verified call

- **WHEN** the board orders the first verified call for `nf`
- **THEN** the node's pending set holds `nf`

### Requirement: AU-015 Second board-first call

**AU-015** If the board orders a verified board-first call whose `nf` the pending set already holds, then the committee node SHALL refuse the call with the code `nf_pending`.

#### Scenario: Duplicate call

- **WHEN** a second verified call with the same `nf` is ordered
- **THEN** the call is refused and the first call stays in force

### Requirement: AU-016 In force, board-first

**AU-016** The committee node SHALL treat a board-first authorization as in force once it has verified the call (AU-013) and the board has ordered it as the first call for its `nf`.

The request waits for no Midnight finality. Board-first is O29 (claims C6, C11).

#### Scenario: Board-first P0 spend

- **WHEN** the board orders the verified call of a P0 request
- **THEN** the authorization is in force for the node

### Requirement: AU-017 Hold handle

**AU-017** The initiator wallet SHALL compute `rh` as a fresh key-private ElGamal encryption of the record's hold tag to the charter's hold key `PK_H`.

A P0 or P1 charter has a hold key derived by hash to the curve from the charter id, whose discrete log nobody knows, so its handles have the same shape and nobody opens them (DESIGN §5.5).

#### Scenario: P1 handle

- **WHEN** a P1 wallet computes `rh`
- **THEN** `rh` has the same form as a P2 handle

### Requirement: AU-018 Revoke

**AU-018** Where a record has `profile = P2`, when its hold authority posts `revoke(auth)` with `SetHold(tag)` for an authorization with `status` SUBMITTED or FINAL and `settled = NONE`, the FenrirAssets contract SHALL set `status = REVOKED` and add `tag` to the hold accumulator.

Later authorizations for that record fail AU-007 for the owner and recovery sources.

#### Scenario: Freeze a pending spend

- **WHEN** the hold authority revokes a pending P2 authorization
- **THEN** the authorization has `status = REVOKED` and the record's tag is held

### Requirement: AU-019 Revoke without a hold authority

**AU-019** If a `revoke` names an authorization of a P0 or P1 record, or an authorization whose `settled ≠ NONE`, then the FenrirAssets contract SHALL refuse the call with the code `not_revocable`.

A VOID tombstone with reason REVOKED needs `f + 1` REVOKED posts, one of them honest (RQ-045), so a P0 or P1 request never shows it; MIXED is not REVOKED (RQ-071, DECISIONS 61).

#### Scenario: Revoke on P1

- **WHEN** a party posts `revoke` for a P1 authorization
- **THEN** the call is refused

### Requirement: AU-020 Settlement by root

**AU-020** When a checkpoint lands whose `settle_root` covers the leaf `(auth, outcome)` of an authorization with `settled = NONE`, the FenrirAssets contract SHALL set `settled = outcome` for that authorization.

The next `authorize` on the successor shows inside its proof that the leaf lies under a landed root (AU-005 item 1, O37). This is the path of every FINAL and RELEASED settlement.

#### Scenario: FINAL by root

- **WHEN** a checkpoint lands with a `settle_root` over `(auth, FINAL)`
- **THEN** the authorization has `settled = FINAL`

### Requirement: AU-021 Carried VOID settlement

**AU-021** When a reissue's `authorize` carries the leaf `(auth_0, VOID)` of its stalled request with `q` signatures that verify against the epoch key set `EKS_e`, the FenrirAssets contract SHALL set `settled = VOID` for `auth_0`.

One Midnight transaction, the wallet's, settles the stalled request and authorizes the reissue (DECISIONS 52, D2 option (c)). A stalled request has reason STALLED, never MIXED (DECISIONS 61) or with a RELEASE (DECISIONS 64).

#### Scenario: Reissue after STALLED

- **WHEN** a reissue carries the signed VOID leaf of its stalled request
- **THEN** the stalled authorization has `settled = VOID` and the reissue is accepted

### Requirement: AU-022 Carried leaf refused

**AU-022** If a carried settlement leaf has an outcome other than VOID, or fewer than `q` of its signatures verify against `EKS_e`, then the FenrirAssets contract SHALL refuse the call with the code `bad_carry`.

FINAL and RELEASED count only by the root path (DECISIONS 52).

#### Scenario: Carried FINAL

- **WHEN** an `authorize` carries a leaf with outcome FINAL
- **THEN** the call is refused

### Requirement: AU-023 Successor of a settlement

**AU-023** When an authorization gets `settled ≠ NONE`, the FenrirAssets contract SHALL make its successor the change record for FINAL, the same record under the nullifier `nf' = N(nsk, auth, VOID)` with `rstate = UNSPENT` for VOID of an authorization accepted on an UNSPENT record (AU-029 for a LOCKED one), and the same record with `rstate = LOCKED` to the pinned input or nonce for RELEASED.

`nsk` is the record's nullifier secret; the successor has one nullifier on both paths (DESIGN §5.6).

#### Scenario: VOID successor

- **WHEN** an authorization accepted on an UNSPENT record settles VOID
- **THEN** the record is UNSPENT under `N(nsk, auth, VOID)`

### Requirement: AU-029 VOID successor of a LOCKED record

**AU-029** When an authorization accepted on a record with `rstate = LOCKED` settles VOID, the FenrirAssets contract SHALL keep its successor LOCKED to the same `pin`.

This holds for a root settlement (AU-020) and a carried one (AU-021). The RELEASED transaction of the earlier request may still confirm, and a later authorization spends only the pinned input (DECISIONS 47, 60). Claim C11.

#### Scenario: VOID on a LOCKED record

- **WHEN** an authorization of a record LOCKED to pin `p` settles VOID
- **THEN** the record is LOCKED to `p` under `N(nsk, auth, VOID)`

### Requirement: AU-024 One spend per record state

**AU-024** The FenrirAssets contract SHALL keep at most one FINAL settlement for the successors of one record state.

Claim C11. Midnight-first: nullifier uniqueness (AU-008), one outcome per `auth` (RQ-054) and the pinned input. Board-first: O29.

#### Scenario: Two settlements on one state

- **WHEN** two requests try to settle FINAL from one record state
- **THEN** the second needs a second `authorize` on the same `nf` and is refused

### Requirement: AU-025 Released never unspent

**AU-025** The FenrirAssets contract SHALL never return a record whose authorization settled RELEASED, or a later successor of that record other than the change record of a FINAL settlement, to `rstate = UNSPENT` with a fresh nullifier.

Quint invariant `C11_ReleasedNeverUnspent` of item 26 (DECISIONS 47, 53). The successors of a VOID settlement keep the lock (AU-023, DECISIONS 60).

#### Scenario: Expired after a release

- **WHEN** a request expires after a release and settles RELEASED
- **THEN** the record is LOCKED to its pin

#### Scenario: Re-post that ends VOID

- **WHEN** the re-post of a RELEASED request authorizes on the pin and then settles VOID
- **THEN** the record stays LOCKED to the same pin and the next authorization spends that pin

### Requirement: AU-026 Board-first record change

**AU-026** When a checkpoint lands with a `bf_root` over the tuples `(auth, nf, rh, root)` of the board-first calls of its interval, the FenrirAssets contract SHALL move each named board-first record to PENDING under its `auth`.

The contract holds roots and not nullifiers, so duplicate `nf` values are refused at the node (AU-013), in board order (AU-015) and by the checkpoint signers (CP-012).

#### Scenario: Batch of board-first calls

- **WHEN** a checkpoint lands with a `bf_root` over 500 calls
- **THEN** each named record is PENDING and Midnight took one transaction

### Requirement: AU-027 Recovery exit

**AU-027** If the recovery-exit source is used for a record before a recovery transition is recorded on Midnight, or with a destination other than `D_exit`, then the FenrirAssets contract SHALL refuse the call with the code `no_recovery`.

After `recover(committee_id)` the successor committee's charter mode is exit only: spends to `D_exit` by an admitted signing set, and seizure in P2 (DESIGN §5.8).

#### Scenario: Exit before Δ_rec

- **WHEN** an owner uses the recovery source while checkpoints still land
- **THEN** the call is refused

### Requirement: AU-028 Seizure destination

**AU-028** If a request whose authorization uses the seizure-order source has an output that does not pay `D_reg`, then the committee node SHALL post VOID for the request with reason AUTH_REFUSED.

Admission checks that every output pays `D_reg` (DESIGN §5.8 step 4).

#### Scenario: Seizure to another address

- **WHEN** a seizure header has an output to an address other than `D_reg`
- **THEN** every honest node posts VOID
