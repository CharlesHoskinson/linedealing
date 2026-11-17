## ADDED Requirements

### Requirement: SL-001 Committee pools

**SL-001** The slot ledger SHALL keep one committee pool for each Schnorr suite `s ∈ {BIP340, ED25519}` and epoch `e`, with slot indices `ℓ = 1, 2, …` in dealing order.

One shared index space would let the floor of one suite pass over the unreserved slots of the other (DECISIONS 51 item 2). Up to four pools exist while two epochs overlap (DESIGN §11.6).

#### Scenario: Two suites

- **WHEN** epoch 3 deals BIP340 and Ed25519 slots
- **THEN** pools `(BIP340, 3)` and `(ED25519, 3)` each start at index 1

### Requirement: SL-002 Committee slot fields

**SL-002** The slot ledger SHALL keep for each committee slot `(s, e, ℓ)` the fields `bstat`, `prec` and `namers`.

`bstat ∈ {UNNAMED, NAMED, RESERVED, CLAIMED, BURNED}`. `prec` is `none` or the `eid` with precedence. `namers` is the set of `eid`s whose opened headers list the slot, with their board positions.

#### Scenario: Dealt slot

- **WHEN** a slot is dealt and no header names it
- **THEN** it has `bstat = UNNAMED`, `prec = none` and no namers

### Requirement: SL-003 ECDSA slot fields

**SL-003** The slot ledger SHALL keep for each ECDSA slot `(pool, ℓ)` the fields `leaf_set`, `root`, `bstat`, `prec`, `reserver` and `namers`.

`pool` is the account pool of one address, named by a random 16-byte id (DESIGN §7.4). `leaf_set` is `H(T_ℓ)` (SH-018). `root ∈ {OWN, G}` says whether the slot lies under `slr_own` or under `slr_G` (DECISIONS 48). `bstat` has the domain of SL-002. `reserver` is `none` or the `eid` that reserved the slot.

#### Scenario: Guardian slot

- **WHEN** a P2 birth session reserves slot 30 for the guardians
- **THEN** slot 30 has `root = G` and a guardian leaf set

### Requirement: SL-004 Committee precedence

**SL-004** When the header of a request opens and names a committee slot with `prec = none` and `bstat = UNNAMED`, the slot ledger SHALL set `prec` to the namer of that slot with the lowest board position and `bstat = NAMED`.

Precedence follows board order, not the order of opening or of authorization (DECISIONS 44). A node judges a header after every earlier-ordered live envelope has opened or ended (Q-003, provisional).

#### Scenario: Copied header

- **WHEN** request B, ordered after request A, names a slot of A and B's authorization comes into force first
- **THEN** A keeps precedence on the slot

### Requirement: SL-005 Lapse

**SL-005** While the board height is at least `b + Δ_c` and the authorization of a request ordered at board height `b` was not in force at `b + Δ_c`, the slot ledger SHALL hold the precedence of that request lapsed on every slot where it holds `prec`, also on a slot taken after `b + Δ_c`.

A header that opens late under Q-003 takes a lapsed precedence, and SL-010 burns the slot at once (SL-017). Claim C13, DECISIONS 63.

#### Scenario: Authorization never finalizes

- **WHEN** a request was ordered at height 100 and its authorization is not in force at height 701
- **THEN** its precedence lapses at launch

#### Scenario: Header that opens after the lapse height

- **WHEN** a request ordered at height 100 with no authorization in force waits for an earlier header and opens at height 750
- **THEN** the precedence it takes is lapsed and its committee slots burn

### Requirement: SL-006 ECDSA precedence

**SL-006** When the authorization of a request comes into force, the slot ledger SHALL set `prec` of each ECDSA slot that the request names, that lies under the root its authorization source opens, and that has `prec = none` and `bstat ≠ BURNED`, to the earliest such request in board order with an authorization in force.

The owner and recovery sources open `slr_own`, the seizure source `slr_G` (AU-006). DECISIONS 54 item 4, option (b).

#### Scenario: Unauthorized namer first

- **WHEN** envelope E names slot 7 of an account and has no authorization, and a later owner request names slot 7 and comes into force
- **THEN** the owner request gets precedence on slot 7

### Requirement: SL-007 Unauthorized namer of an ECDSA slot

**SL-007** If a request that names an ECDSA slot has no authorization in force, then the slot ledger SHALL leave `prec`, `bstat` and `reserver` of that slot unchanged.

Such a request takes no precedence, voids no other request on the slot, and its end burns nothing (DECISIONS 54).

#### Scenario: Spam envelope ends

- **WHEN** an envelope with no authorization names guardian slot 30 and expires
- **THEN** slot 30 keeps its state

### Requirement: SL-008 Reserve

**SL-008** While a request holds `prec` on a slot and its authorization is in force, when `q` votes with one header hash commit for that request, the slot ledger SHALL set `bstat = RESERVED` on that slot and, for an ECDSA slot, `reserver` to that request.

The votes are the OPENED votes of a collecting request and the ADMIT votes of every other request (DESIGN §4.1).

#### Scenario: Reservation by ADMIT

- **WHEN** six ADMIT votes commit for the request with precedence on slot 12
- **THEN** slot 12 has `bstat = RESERVED`

### Requirement: SL-009 Claim

**SL-009** When a request reaches ADMITTED (RQ-026), the slot ledger SHALL set `bstat = CLAIMED` on every slot that the request reserved.

#### Scenario: Admission claims

- **WHEN** a collecting request reaches ADMITTED
- **THEN** its reserved slots have `bstat = CLAIMED`

### Requirement: SL-010 Burn of a committee slot

**SL-010** When the request that holds `prec` on a committee slot reaches FINAL, VOID or EXPIRED, or its precedence lapses, the slot ledger SHALL set `bstat = BURNED` on that slot, used or not.

A committee slot whose id a header showed is never dealt to another request (DECISIONS 44, 54 item 1).

#### Scenario: Never-authorized envelope

- **WHEN** an envelope that names four committee slots lapses
- **THEN** the four slots have `bstat = BURNED`

### Requirement: SL-011 Burn of an ECDSA slot

**SL-011** When the request in `reserver` of an ECDSA slot reaches FINAL, VOID or EXPIRED, the slot ledger SHALL set `bstat = BURNED` on that slot.

An ECDSA slot that no request reserved holds no partial and needs no burn (DECISIONS 54).

#### Scenario: Unselected variant

- **WHEN** an ECDSA request with `K = 3` reaches FINAL with variant 1 selected
- **THEN** every ECDSA slot it reserved, the slots of variants 2 and 3 included, has `bstat = BURNED`

### Requirement: SL-012 Window

**SL-012** The committee node SHALL treat a committee index `ℓ` of a pool as in the window of checkpoint `cp` exactly for `cp.h < ℓ ≤ cp.h + B`, or for `cp.pending_min ≤ ℓ ≤ cp.h` with `ℓ` held for the same request in the pending list that opens `cp.pending_root`.

`cp` is the latest landed checkpoint at the time of the vote. `B` is set by measurement, at least the largest number of committee slot reservations between two checkpoints, and at least 1 (DESIGN §2.3).

#### Scenario: Index in the window

- **WHEN** `cp.h = 100`, `B = 200` and a header names index 150
- **THEN** index 150 is in the window

### Requirement: SL-013 Index below the window

**SL-013** If a header names a committee index below `cp.pending_min`, or an index in `[cp.pending_min, cp.h]` that the pending list does not hold for its own request, then the committee node SHALL post VOID for the request with reason SLOT_TAKEN.

That index was reserved by an earlier request, skipped or burned (DESIGN §4.1).

#### Scenario: Skipped index

- **WHEN** `cp.h = 100`, `cp.pending_min = 90` and a new header names index 95 that no pending request holds
- **THEN** every honest node posts VOID with reason SLOT_TAKEN

### Requirement: SL-014 Index above the window

**SL-014** If a header names a committee index above `cp.h + B`, then the committee node SHALL refuse to vote OPENED or ADMIT for the request with the code `above_window`.

The request keeps its phase until a checkpoint brings the index into the window.

#### Scenario: Index too high

- **WHEN** `cp.h = 100`, `B = 200` and a header names index 301
- **THEN** the node casts no vote and the request keeps its phase

### Requirement: SL-015 Pool not yet listed

**SL-015** If a header names a slot of a pool that no landed checkpoint lists, then the committee node SHALL refuse to vote OPENED or ADMIT for the request with the code `pool_unlisted`.

#### Scenario: New epoch pool

- **WHEN** a header names a slot of the pool of epoch 4 before any checkpoint lists that pool
- **THEN** the node casts no vote

### Requirement: SL-016 Slot under another precedence

**SL-016** While the authorization of an opened request is in force, if its header names a committee slot whose `prec` is another request, or an ECDSA slot whose `prec` is another request with an authorization in force, then the committee node SHALL post VOID for the request with reason SLOT_TAKEN.

Precedence is an admission check (DESIGN §4.7 item 5). A request whose authorization never comes into force gets no SLOT_TAKEN post: its precedence lapses by SL-005 (DECISIONS 68).

#### Scenario: Later namer

- **WHEN** request B names a committee slot with `prec = A` and the authorization of B is in force
- **THEN** every honest node posts VOID for B with reason SLOT_TAKEN

#### Scenario: Namer not yet authorized

- **WHEN** the header of request B opens while its authorization is not yet final
- **THEN** no honest node posts SLOT_TAKEN for B until the authorization is in force

### Requirement: SL-017 Precedence forward only

**SL-017** The slot ledger SHALL change `bstat` only along UNNAMED → NAMED → RESERVED → CLAIMED and from any value to BURNED, never out of BURNED, and never give `prec` of a committee slot to a second request.

#### Scenario: Burned slot named again

- **WHEN** a header names a burned slot
- **THEN** the slot stays BURNED and gets no `prec`

### Requirement: SL-018 Seat slot states

**SL-018** Where `mode = TEE`, the committee node SHALL keep each slot share of its seat in state `free`, `bound(H(tk))` or `burned`, moving only from `free` to `bound` or `burned` and from `bound` to `burned`.

The states live in the seat's pool session `slots-s-e` or in the account pool of the address (Sessions SS-050 to SS-062, DECISIONS 51 item 3).

#### Scenario: Bound slot

- **WHEN** a slot is `bound(d)`
- **THEN** no operation makes it `free` again

### Requirement: SL-030 Slot burn at the end

**SL-030** Where `mode = TEE`, when a request that holds a slot share of the seat reaches FINAL, VOID or EXPIRED, the committee node SHALL call `slot_burn` on that slot.

Peers then refuse the session key of every older version (DESIGN §4.5 item 5, §7.8).

#### Scenario: Request ends

- **WHEN** a request with a `bound` slot reaches FINAL
- **THEN** the node calls `slot_burn` and the slot is `burned` in a new session version

### Requirement: SL-019 Batched bind before a partial

**SL-019** Where `mode = TEE`, the committee node SHALL send no signature partial on a slot before one batched `slot_bind` of every slot that the anchors of one board height fix in the pool session has `w` acks for its `slot` entries and a current sealed version that records `bound(H(tk))` for that slot.

`slot_release_ok` is true only after that version is current (DESIGN §7.7, Sessions SS-140, SS-141, O36).

#### Scenario: Bind round incomplete

- **WHEN** the `slot` entries have `w` acks and the sealed version has five acks at `w = 6`
- **THEN** the node sends no partial on those slots

### Requirement: SL-020 Restored bound slot

**SL-020** If a restored slot is `bound(d)` and a release names a ticket with digest `d' ≠ d`, then the committee node SHALL refuse the release on that slot with the code `slot_bound`.

After a restore the node releases on a `bound` slot again only for the same ticket, which repeats the same partial (DESIGN §4.5 item 6).

#### Scenario: Restored slot, other ticket

- **WHEN** a restored slot is bound to `d` and a request asks for a partial on ticket `d'`
- **THEN** the node releases nothing on that slot

### Requirement: SL-021 One ticket per slot at a node

**SL-021** The committee node SHALL compute partials on one slot for at most one ticket.

#### Scenario: Two candidates

- **WHEN** eight tickets of one request name slot `ℓ(1, 1)`
- **THEN** the node signs only the ticket of the variant that the generation 1 anchor selects

### Requirement: SL-022 Indices never dealt twice

**SL-022** The slot ledger SHALL deal no share to a slot index that a dealing already gave shares or that a header named.

A burned slot holds no share and keeps its index (DESIGN §4.1).

#### Scenario: Refill after a burn

- **WHEN** the pool falls below its low-water mark after index 500 burned
- **THEN** the next dealing starts above the highest dealt index

### Requirement: SL-023 Batched slot dealing

**SL-023** When a dealer message with `B_slot` slot dealings arrives, the committee node SHALL check its `2·B_slot` shares with one random linear combination whose 128-bit coefficients it draws after it holds the message.

`B_slot` is set by measurement (DESIGN §2.3, §5.10 rule 6).

#### Scenario: Honest batch

- **WHEN** a node receives a batch of 16 slot dealings with good shares
- **THEN** one equation accepts all 32 shares

### Requirement: SL-024 Failed batch check

**SL-024** If the batch equation of a dealer message fails, then the committee node SHALL check each polynomial of the message alone and post the public complaint that names each failing dealing.

#### Scenario: One bad polynomial

- **WHEN** polynomial 5 of a batch is bad
- **THEN** the node posts a complaint that names polynomial 5

### Requirement: SL-025 Qualified slot dealers

**SL-025** The slot ledger SHALL make each committee slot the sum of the polynomials of the first `t` dealers of that slot in board order without a valid complaint.

At least one of them is honest, so no coalition of `t − 1` nodes knows `d_ℓ` or `e_ℓ` (DESIGN §4.1).

#### Scenario: One complained dealer

- **WHEN** dealer 2 of slot 9 has a valid complaint
- **THEN** slot 9 sums the first seven dealers other than dealer 2

### Requirement: SL-026 Slot anchor

**SL-026** Where `slot_anchor` is on, the committee node SHALL release on a slot only after a landed checkpoint root covers its seat-log entry `nf → H(tk)` and no covered entry of any seat binds that slot nullifier `nf` to another ticket.

`nf = HMAC-SHA256(k_nf, VT1/slot-nf ‖ committee ‖ purpose ‖ ℓ)`, so the seat log shows no slot id (Sessions SS-070). It adds no Midnight transaction (DECISIONS 42, open item O32). `slot_anchor` is off at launch.

#### Scenario: Forked board with anchors

- **WHEN** two board histories show two tickets for one slot and a covered entry binds the first
- **THEN** no honest node releases the second ticket

### Requirement: SL-027 One nonce use

**SL-027** The slot ledger SHALL let no committee slot and no ECDSA slot collect honest partials for two tickets.

Claim C12. Adversary: TEE, all operators with enclaves intact within the rollback bound `c ≤ n − 1 − 2f` of DESIGN §7.7, and any number of rolled-back disks across a whole-committee restart; NON_TEE, `|C| ≤ f`, or `|C| < t` with `slot_anchor` (DECISIONS 42, 51). Proof obligations O27, O32.

#### Scenario: Restart from old disks

- **WHEN** every disk rolls back to a state before a slot was bound and the committee restarts
- **THEN** the restart burn of CP-020 leaves no honest node able to sign the slot for a second ticket

### Requirement: SL-028 ECDSA burns need a reservation

**SL-028** The slot ledger SHALL set `bstat = BURNED` on an ECDSA slot outside a whole-committee restart burn only at the end of the request in its `reserver`.

DECISIONS 54, Quint invariant `C13_EcdsaBurnOnlyIfReserved` of item 26.

#### Scenario: Copy of a header

- **WHEN** a copied header names an ECDSA slot and has no authorization in force
- **THEN** the slot does not burn when the copy ends

### Requirement: SL-029 One slot per generation and input

**SL-029** The committee node SHALL treat a Schnorr committee slot as serving exactly one `(generation, input)` of one request and an ECDSA slot as serving exactly one `(variant, input)` of one leaf set.

Up to `K` tickets name one Schnorr slot; the committee releases one partial on it (DECISIONS 27). ECDSA keeps `K·L` slots (DESIGN §4.4).

#### Scenario: ECDSA variants

- **WHEN** a P2WPKH request with `K = 3`, `L = 2` opens
- **THEN** it names six ECDSA slots, one per variant and input
