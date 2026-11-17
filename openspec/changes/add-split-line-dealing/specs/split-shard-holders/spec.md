## ADDED Requirements

### Requirement: SH-001 Access structure

**SH-001** The charter SHALL fix at birth a monotone access structure `Γ` over the actors, built from AND gates, `k_γ`-of-`m_γ` group gates and OR gates, under a top gate `Fenrir AND Γ`.

AND shares additively, a group by Shamir at degree `k_γ − 1`, OR by escrow of the primary's secret to the other child (DECISIONS 21, 22).

#### Scenario: Regulated custody

- **WHEN** a charter sets `user AND (custodian OR G)` with `G` 3-of-5
- **THEN** the signing sets are `{user, custodian}` and `user` with any three guardians

### Requirement: SH-002 Leaves

**SH-002** The charter SHALL give every member of a group a nonzero member id that is distinct within its group and hold no leaf twice in `Γ`.

The secrecy of C17 needs both (DESIGN §2.4, Lean finding of item 8).

#### Scenario: Repeated leaf

- **WHEN** a charter lists the same issuer leaf under two gates
- **THEN** the charter is not valid

### Requirement: SH-003 Signing set

**SH-003** The initiator wallet SHALL name a signing set that has the initiator as a member, exactly `k_γ` members of each group gate it uses and exactly one child of each OR gate it uses.

#### Scenario: Treasury

- **WHEN** an officer of a 2-of-3 treasury initiates
- **THEN** the signing set names that officer and one other officer

### Requirement: SH-004 Weights

**SH-004** The actor SHALL compute its weight `λ_a` as the product of the Lagrange coefficients at zero of the children sets along its path from the root, with weight 1 for an AND or OR child, from the signing set alone.

Every actor and every TEE node computes the weights from the header (DESIGN §2.4 rule 3).

#### Scenario: Nested group

- **WHEN** a member of a nested 2-of-3 group under a 2-of-3 group signs
- **THEN** its weight is the product of two Lagrange coefficients

### Requirement: SH-005 Fresh shard per address

**SH-005** The actor SHALL use a fresh uniformly random shard for every address and every change address it serves.

Shard points then do not link addresses (DESIGN §2.4 rule 1).

#### Scenario: Two addresses

- **WHEN** one issuer serves two addresses
- **THEN** its two shard points are independent

### Requirement: SH-006 Tweak

**SH-006** The birth coordinator SHALL set `tw = Hq_tw(X_f ‖ X_{a_1} ‖ … ‖ X_{a_r} ‖ charter_id ‖ seed)` with the top-level shard points in charter slot order and send `seed` to every actor sealed to its request key.

`tw` is shown at birth as a scalar, never as a point, because a point lets an actor set it after choosing its own point (DESIGN §3.1 step 3).

#### Scenario: Address key

- **WHEN** the coordinator fixes `tw`
- **THEN** every actor recomputes `X = X_f + tw·G + Σ_a X_a`

### Requirement: SH-007 Proof of possession

**SH-007** The actor SHALL attach to its top-level shard point `pop_a = Schnorr_{x_a}(Hq_pop(SL1/pop ‖ X_f ‖ X_a ‖ slot_a ‖ charter_id ‖ chain_id))`.

A group shard is proved by its dealers' proofs of their constant terms (DESIGN §3.1 step 1).

#### Scenario: Proof bound to its slot

- **WHEN** a proof made for slot 1 is copied to slot 2
- **THEN** it does not verify

### Requirement: SH-008 Network-created shard

**SH-008** The creator SHALL prove a network-created user shard by the holder's registration proof `pop_U` and a Schnorr proof of `δ = Hq_st(e_c·U)` with `X_u − U = δ·G` bound to the birth context.

In NON_TEE mode the node sees `U`, so the network-created addresses of one holder link at birth (DECISIONS 46 item (9)). The proofs do not bind the `E_c` of the record. SH-030 to SH-037 bind it (DECISIONS 67).

#### Scenario: Offline holder

- **WHEN** a payer creates an address for an offline holder
- **THEN** the birth request carries `pop_U` and the proof of `δ`

### Requirement: SH-009 Birth check

**SH-009** When a BIRTH request opens and every proof of possession, every dealer proof, the recomputed `X_γ` and `X`, the chain's address encoding and the opening of `cm_addr = Commit(X ‖ chain_id ‖ root ‖ charter_id ‖ profile ‖ H(Γ); r)` pass, the committee node SHALL sign `BIRTH_OK(eid, cm_addr)` and send it to the coordinator over the node channel.

BIRTH_OK never goes to the board, so a board observer cannot link the envelope to the Midnight record (DECISIONS 50 item (8)).

#### Scenario: Valid birth

- **WHEN** a two-actor birth passes every check
- **THEN** each honest node sends BIRTH_OK to the coordinator

### Requirement: SH-010 Failed birth check

**SH-010** If a check of SH-009 fails, then the committee node SHALL refuse to sign BIRTH_OK with the code `birth_refused`.

#### Scenario: Rogue key

- **WHEN** the last actor publishes a point without a valid proof of possession
- **THEN** no honest node signs BIRTH_OK

### Requirement: SH-011 Birth certificate

**SH-011** If a P1 or P2 address record arrives without a birth certificate of `q` BIRTH_OK signatures, or a P0 record without a registration signed by the owner's existing key, then the FenrirAssets contract SHALL refuse the record with the code `no_birth_certificate`.

C1 and C2 hold for `|C| < q`. In NON_TEE mode without `slot_anchor`, C2 holds for `|C| ≤ f` (DECISIONS 66). C1 covers a network-created shard once acknowledged (DECISIONS 67).

#### Scenario: Five signatures

- **WHEN** a P1 record carries five BIRTH_OK signatures at `q = 6`
- **THEN** the record is refused

### Requirement: SH-012 Escrow certificate

**SH-012** If a record whose `Γ` has an OR gate arrives without an escrow certificate of a quorum of the escrow holders, or a P2 record without `q_g` guardian ACKs, then the FenrirAssets contract SHALL refuse the record with the code `no_escrow_certificate`.

#### Scenario: P2 without guardians

- **WHEN** a P2 record carries three guardian ACKs at `q_g = 4`
- **THEN** the record is refused

### Requirement: SH-013 Actor nonce pool

**SH-013** The actor SHALL post each nonce pool of `N_pool` pairs `(D_{a,ν}, E_{a,ν})` as one `POOL` record signed by a fresh pool key that lies under one of its pool-key roots of `N_pk` keys.

`N_pool = 64`, `N_pk = 1,024`. One pool-key root is one Midnight write per batch (DECISIONS 52 D9).

#### Scenario: New pool

- **WHEN** an actor posts a pool
- **THEN** the board shows a pool under a pseudonym and Midnight shows no pool key

### Requirement: SH-014 Pool refill

**SH-014** If the actor's pool holds fewer than `N_h` unused pairs, then the actor SHALL post a new pool before it contributes again.

One request consumes one pair per half: 30 at `K = 8`, `L = 2` (DECISIONS 36).

#### Scenario: Low pool

- **WHEN** 25 unused pairs remain and `N_h = 30`
- **THEN** the actor posts a new pool

### Requirement: SH-015 One answer per pair

**SH-015** The actor SHALL answer at most once per pool pair, mark the pair used and erase `(d_{a,ν}, e_{a,ν})` in the step that computes the contribution, and answer no request after its `exp_c`.

A pair that a request named and the actor never answered stays unused (DESIGN §3.10).

#### Scenario: Second request on one pair

- **WHEN** a second request names a pair that the actor already answered
- **THEN** the actor does not answer

### Requirement: SH-016 ECDSA slot session

**SH-016** When an address birth or a REFILL request starts an ECDSA slot session, the committee node SHALL run the session of DESIGN §3.6 with every session party online and drop each slot whose public check fails at a node that posts a complaint.

The functionalities `F_presig` and `F_mul` at `t = n − f` are open items O1, O2 and O19. The session runs in the clear on the board (O35).

#### Scenario: Bad correction

- **WHEN** a party sends node 3 a correction that fails the public check of step 6
- **THEN** node 3 posts a complaint and the slot is dropped

### Requirement: SH-017 ECDSA shares into the account pool

**SH-017** Where `mode = TEE`, when an ECDSA slot session ends, the committee node SHALL put its committee shares of each slot into the account pool of the address with `slot_put`, which appends a put entry to its seat log.

A put counts once a landed checkpoint root covers it, and a share goes into a slot once (DECISIONS 51 item 6, Sessions SS-128 to SS-131).

#### Scenario: Birth on Ethereum

- **WHEN** a birth session prepares 32 slots
- **THEN** the node puts 32 shares and appends 32 put entries

### Requirement: SH-018 One leaf set per ECDSA slot

**SH-018** The actor SHALL contribute on an ECDSA slot `ℓ` only to a request whose signing set has the leaf set `T_ℓ` recorded with the slot, and at most once.

Two subsets of one group on one slot give the group's shard; recovering `x` also needs the halves of every other actor on the slot (DECISIONS 43, 54 item 3). The members enforce the rule, so it holds against all `n` nodes.

#### Scenario: Other subset

- **WHEN** a request with subset `{A, C}` names a slot bound to `{A, B}`
- **THEN** member A does not contribute

### Requirement: SH-019 Escrow-branch slots

**SH-019** The actor SHALL never contribute as the primary holder of an OR gate on a slot reserved for the escrow branch.

#### Scenario: User on a guardian slot

- **WHEN** a user request names a slot under `slr_G`
- **THEN** the user's wallet does not contribute on it

### Requirement: SH-020 Guardian slots

**SH-020** The birth coordinator SHALL reserve `G_g = 2·K·L_max` ECDSA slots of a P2 ECDSA address for the guardians, bound to two guardian leaf sets of `K·L_max` slots each.

`G_g = 12` on P2WPKH (DECISIONS 48).

#### Scenario: P2WPKH guardian slots

- **WHEN** a P2 P2WPKH address is born
- **THEN** 12 slots are reserved for two guardian subsets

### Requirement: SH-021 Actor recomputes the request

**SH-021** The actor SHALL recompute every sighash, `X`, `Q`, `g_P`, `g_Q`, `pm`, `CL`, `ρ_a`, `R_A`, `ρ`, `R`, `σ`, `c` and its own weight from the request and the public pool and slot points before it contributes, and take none of them from the initiator.

#### Scenario: Wrong R_A

- **WHEN** a ticket's `R_A` differs from the sum that the actor computes
- **THEN** the actor does not contribute

### Requirement: SH-022 Actor checks the signing set

**SH-022** If the signing set of a request is not in `Γ`, the actor's weight does not follow from it, or a pair named for the actor is not an unused pair of its own pool with a different pair for every half, then the actor SHALL refuse to contribute with the code `bad_request`.

#### Scenario: One pair for two halves

- **WHEN** a request names pair 7 of an actor for two halves
- **THEN** the actor refuses

### Requirement: SH-038 Initiator leaf in the commitment list

**SH-038** The actor SHALL compute `CL` with the initiator's leaf id as its first element.

`CL` then names every actor of the signing set, so one `CL` fixes every weight, and no binding factor `ρ_a` serves two weights. The initiator wallet and the combiner compute the same list (DESIGN §4.2 item 3, DECISIONS 72).

#### Scenario: Two initiators in a 2-of-3 group

- **WHEN** two requests name one pool pair of member 1 of a 2-of-3 group, one with member 2 as the initiator and one with member 3
- **THEN** the two lists differ, and member 1 computes two binding factors

### Requirement: SH-023 Actor policy

**SH-023** If the actor's own policy rejects a request, then the actor SHALL refuse to contribute with the code `policy_refused`.

DESIGN §4.2 actor rule 3 says the actor "may refuse" a request. The condition on the actor's own policy keeps that meaning; models take the policy as a free input. The refusal leaves no state on the board. The code `policy_refused` is a lead decision.

#### Scenario: Amount above the actor's limit

- **WHEN** an issuer's policy caps a transfer below the requested amount
- **THEN** the issuer may refuse and the request stalls or is reissued

### Requirement: SH-024 Initiator nonce

**SH-024** The initiator wallet SHALL draw a fresh nonce `k_0` for every half from the OS generator, hedged with a hash of `(x_0, tw, ℓ, m)`, and draw no pair from its own pool for its own contribution.

#### Scenario: Thirty halves

- **WHEN** an initiator signs a request with 30 halves
- **THEN** it uses 30 distinct nonces `k_0`

### Requirement: SH-025 Tweak term once

**SH-025** The initiator wallet SHALL place the tweak term `c̃·tw + c·g_Q·t_tap` in its own contribution only.

A formula without `c·g_Q·t_tap` signs for `P` and not `Q`; a second copy fails verification (DESIGN §4.2).

#### Scenario: Taproot spend

- **WHEN** a two-actor P2TR request is combined
- **THEN** the signature verifies under `x(Q)`

### Requirement: SH-026 Guardian halves

**SH-026** The actor SHALL produce a guardian half only for a seizure order settled on Midnight whose outputs all pay `D_reg`.

#### Scenario: Unsettled order

- **WHEN** a guardian is named in a seizure request whose order is not settled
- **THEN** the guardian does not contribute

### Requirement: SH-027 Unadmitted coalitions cannot sign

**SH-027** The split-line signature scheme SHALL give every set of committee nodes, up to all `n`, together with any actor coalition outside `Γ`, no valid signature on a message for which the honest actors of no admitted signing set dealt contributions.

Claim C17 (with C3 for the single-user form and C4). Schnorr: sketched for an honest initiator, open for pool actors (O20). ECDSA: conditional on O1, O2, O19.

#### Scenario: All nodes corrupt

- **WHEN** all nine nodes and the issuer collude against an honest user of `user AND issuer`
- **THEN** they sign nothing outside the variants that the user dealt

### Requirement: SH-028 No spend without the committee

**SH-028** The split-line signature scheme SHALL give every actor of `A` together with `t − 1` committee nodes no valid signature.

Claim C5. In NON_TEE mode the slot rules need `|C| ≤ f` or `slot_anchor`. Schnorr open (O6); ECDSA conditional on O1, O2, O19, O32.

#### Scenario: Actors and six nodes

- **WHEN** every actor colludes with six nodes at `t = 7`
- **THEN** they produce no signature

### Requirement: SH-029 Confinement of a contribution

**SH-029** The split-line signature scheme SHALL let an honest actor's contribution complete only the half `(v, g, j)` for which the actor computed it.

Claim C18. Secrecy before release needs an honest initiator (DECISIONS 40). C19 (no concurrent-session forgery) is open item O20.

#### Scenario: Contribution reused

- **WHEN** a party takes an actor's scalar for variant 2 and tries it on variant 3
- **THEN** the signature fails

### Requirement: SH-030 Holder derivation check

**SH-030** When the holder wallet first opens the asset record of an address with a network-created shard and the scalar `x_u = u + Hq_st(u·E_c)` from the `E_c` of the record has `x_u·G = X_u`, the holder wallet SHALL send the ACK envelope.

The ACK envelope is request type 0x07 in the frame of DESIGN §4.6. It carries the birth data of SH-009 for the address and `pop_u = Schnorr_{x_u}(Hq_pop(SL1/pop ‖ X_f ‖ X_u ‖ slot_u ‖ charter_id ‖ chain_id))` (DECISIONS 67).

#### Scenario: Wrong E_c in the record

- **WHEN** the holder of a correctly built record comes online
- **THEN** its wallet sends the ACK envelope with `pop_u`

### Requirement: SH-036 Holder refuses a wrong E_c

**SH-036** If the scalar that the holder wallet derives from the `E_c` of the record has `x_u·G ≠ X_u`, then the holder wallet SHALL send no ACK envelope.

The address then never becomes fundable for a payer (SH-035, DECISIONS 67).

#### Scenario: Wrong E_c in the record

- **WHEN** the creator put a point other than the `E_c` behind `δ` in the record
- **THEN** the holder wallet sends no ACK envelope

### Requirement: SH-031 Acknowledgement check

**SH-031** When an ACK envelope opens and its birth data recompute `X` and the opening of `cm_addr` as in SH-009 and its `pop_u` verifies under `X_u`, the committee node SHALL sign `ACK_OK(eid, cm_addr)` and send it to the holder wallet over the node channel.

ACK_OK never goes to the board, as BIRTH_OK does not (DECISIONS 67).

#### Scenario: Holder online

- **WHEN** the holder of a network-created shard sends a valid ACK envelope
- **THEN** each honest node sends ACK_OK to the holder wallet

### Requirement: SH-032 Failed acknowledgement check

**SH-032** If a check of SH-031 fails, then the committee node SHALL refuse to sign ACK_OK with the code `ack_refused`.

#### Scenario: Creator posts the acknowledgement

- **WHEN** the creator sends an ACK envelope without a valid `pop_u`
- **THEN** no honest node signs ACK_OK

### Requirement: SH-033 Acknowledgement certificate

**SH-033** If an `acknowledge` call lacks an acknowledgement certificate of `q` ACK_OK signatures for the record, then the FenrirAssets contract SHALL refuse the call with the code `no_ack_certificate`.

The holder's call shows the certificate inside its proof, as `authorize` does for the record (DECISIONS 67).

#### Scenario: Five signatures

- **WHEN** an `acknowledge` call carries five ACK_OK signatures at `q = 6`
- **THEN** the call is refused

### Requirement: SH-034 Unacknowledged record

**SH-034** The FenrirAssets contract SHALL register the record of an address with a network-created shard with `acked = false`.

Claim C1 for a network-created shard holds for an acknowledged record (DECISIONS 67).

#### Scenario: New record

- **WHEN** a payer registers the record of an address for an offline holder
- **THEN** the record has `acked = false`

### Requirement: SH-037 Acknowledged record

**SH-037** When an `acknowledge` call with an acknowledgement certificate of `q` ACK_OK signatures for the record lands, the FenrirAssets contract SHALL set `acked = true` on the record.

No other call sets the flag (DECISIONS 67).

#### Scenario: Holder acknowledges

- **WHEN** the holder's `acknowledge` call with six ACK_OK signatures at `q = 6` lands
- **THEN** the record has `acked = true`

### Requirement: SH-035 Payer waits for the acknowledgement

**SH-035** While the asset record of an address with a network-created shard has `acked = false`, the payer wallet SHALL send no payment to that address.

Midnight cannot stop a host-chain payment, so the rule binds the payer's wallet. A creator that funds the address earlier carries that risk itself (DECISIONS 67).

#### Scenario: Payment before the acknowledgement

- **WHEN** a payer wallet reads a record with `acked = false`
- **THEN** it does not pay to the address
