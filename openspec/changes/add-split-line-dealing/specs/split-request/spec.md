## ADDED Requirements

### Requirement: RQ-001 Committee parameters

**RQ-001** The request state machine SHALL use the committee parameters `n`, `f`, `q = ⌈(n + f + 1)/2⌉`, `t = n − f`, `w = n − 1 − f`, `G_max = 2`, `Δ_c` and `mode`.

Domains: `n ≥ 3f + 1` and `f ≥ 1`. Launch values `n = 9`, `f = 2`, `q = 6`, `t = 7`, `w = 6`; later `n = 17`, `f = 5`, `q = 12`, `t = 12`, `w = 11`. `Δ_c` is a count of board blocks, 600 at launch. `mode ∈ {TEE, NON_TEE}`. The same parameters serve split-slots, split-authorization and split-checkpoint (DESIGN §2.3).

#### Scenario: Launch committee

- **WHEN** the committee registers `n = 9` and `f = 2`
- **THEN** the request state machine uses `q = 6`, `t = 7` and `w = 6`

### Requirement: RQ-002 Request fields

**RQ-002** The request state machine SHALL keep for each request the fields `eid`, `epoch`, `exp`, `type`, `profile`, `order_pos`, `exp_c`, `phase`, `reason`, `collecting`, `K`, `L`, `G`, `anchor`, `released`, `any_release`, `restart_end` and `outcome`.

The domains are RQ-064 to RQ-067. `order_pos` and `exp_c` are `none` until ordering.

#### Scenario: Fields of a new request

- **WHEN** a request is added
- **THEN** it has `phase = POSTED`, `reason = NONE`, `any_release = false`, `restart_end = false` and `outcome = NONE`

### Requirement: RQ-064 Phase domain

**RQ-064** The request state machine SHALL keep `phase` in `{POSTED, ORDERED, OPENED, COLLECTING, ADMITTED, FINAL, VOID, EXPIRED}` and `outcome` in `{NONE, FINAL, VOID, RELEASED}`.

DESIGN §5.1 names ANCHORED(g), which is `phase = ADMITTED` with `anchor[g] ≠ none`, and RELEASED(g, j), which is `released[g] = j`. The settlement RELEASED of §5.1 is `outcome = RELEASED`.

#### Scenario: Anchored request

- **WHEN** an admitted request gets `anchor[1] = 2`
- **THEN** its phase stays ADMITTED

### Requirement: RQ-065 Reason domain

**RQ-065** The request state machine SHALL keep `reason` in `{NONE, SHARE_COMPLAINT, MALFORMED, AUTH_REFUSED, REVOKED, RELEASE_CHECK, CONTRIBUTION, DEALER_FAULT, PIN_SPENT, SLOT_TAKEN, STALLED, RESTART, MIXED}`.

MALFORMED, DEALER_FAULT, PIN_SPENT and RESTART name VOID cases that DESIGN states without a code (Q-001). MIXED is the reason of a VOID tombstone whose posts name no common reason (RQ-045, DECISIONS 61).

#### Scenario: Reason of a live request

- **WHEN** a request has `phase = ADMITTED`
- **THEN** `reason = NONE`

### Requirement: RQ-066 Type and profile domains

**RQ-066** The request state machine SHALL keep `type` in `{SPEND, EXIT, SEIZURE, BIRTH, REFILL, P0, CONTRIB}` and `profile` in `{P0, P1, P2}`.

#### Scenario: Seizure request

- **WHEN** a guardian posts a seizure envelope for a P2 record
- **THEN** the request has `type = SEIZURE` and `profile = P2`

### Requirement: RQ-067 Grid domains

**RQ-067** The request state machine SHALL keep `K ∈ 1..8`, `L ∈ 1..2`, `G = min(K, G_max)` and, for each generation `g ∈ 1..G`, `anchor[g]` and `released[g]` in `{none} ∪ 1..K`.

`K_max = 8` (DECISIONS 57). `L ≤ 2` is the launch bound (DESIGN §2.3).

#### Scenario: Ethereum grid

- **WHEN** an Ethereum request opens with `K = 1`, `L = 1`
- **THEN** `G = 1`

### Requirement: RQ-003 Post

**RQ-003** When an envelope passes the public checks of EN-004 to EN-008 and EN-023, the request state machine SHALL add a request for its `eid` with `phase = POSTED`.

#### Scenario: Accepted envelope

- **WHEN** a node accepts an envelope after the public checks
- **THEN** the request has `phase = POSTED`

### Requirement: RQ-004 Unknown request

**RQ-004** If an event names an `eid` that the request state machine does not hold, then the request state machine SHALL refuse the event with the code `unknown_request`.

#### Scenario: Vote for an unknown eid

- **WHEN** an ADMIT vote names an `eid` with no request
- **THEN** the state is unchanged and the code is `unknown_request`

### Requirement: RQ-005 Terminal request

**RQ-005** If an event other than a settlement signature or the restart re-end of RQ-068 names a request with `phase` FINAL, VOID or EXPIRED, then the request state machine SHALL refuse the event with the code `terminal`.

The phases FINAL, VOID and EXPIRED are terminal. Settlement signatures (RQ-053) follow the end of a request.

#### Scenario: Vote after FINAL

- **WHEN** an ADMIT vote arrives for a request with `phase = FINAL`
- **THEN** the state is unchanged and the code is `terminal`

### Requirement: RQ-006 Order

**RQ-006** When the board commits the envelope of a request with `phase = POSTED` in a block that has a quorum certificate at board position `p` and board height `b`, the request state machine SHALL set `phase = ORDERED`, `order_pos = p` and `exp_c = b + Δ_c`.

#### Scenario: Ordering block

- **WHEN** the block at height 100 with a QC orders the envelope at launch
- **THEN** the request has `phase = ORDERED` and `exp_c = 700`

#### Scenario: Window past the expiry

- **WHEN** an envelope with `exp = 650` would be ordered at board height 100 with `Δ_c = 600`
- **THEN** EN-023 refuses it and no request is ordered

### Requirement: RQ-007 Block without a quorum certificate

**RQ-007** If a block that names the envelope of a request has no quorum certificate, then the request state machine SHALL refuse the order event with the code `no_qc`.

#### Scenario: Proposal without QC

- **WHEN** a proposal that holds the envelope gets no QC
- **THEN** the request keeps `phase = POSTED`

### Requirement: RQ-008 Nothing leaves before order

**RQ-008** The committee node SHALL send no header partial, no variant partial and no signature partial for a request whose `phase` is POSTED.

Claim C8 (sealed until order). The rule holds on every path (DESIGN §5.11).

#### Scenario: Envelope in the mempool

- **WHEN** a node holds a posted envelope that no QC has ordered
- **THEN** the node sends no partial for it

### Requirement: RQ-009 Share check and header partial

**RQ-009** When the quorum certificate that orders a request commits and the node's share of `κ_0` verifies against the outer commitments, the committee node SHALL send its header partial `Y_{i,hdr}` to every other node and list ACK for the request in its next board vote.

The node does not wait for other ACKs (DESIGN §5.2 step 2).

#### Scenario: Good share

- **WHEN** the ordering QC commits and node 3 holds a good share
- **THEN** node 3 sends its header partial and lists ACK in its next vote

### Requirement: RQ-010 Bad share

**RQ-010** If the node's share of `κ_0` fails the check against the outer commitments, then the committee node SHALL post the public share complaint with the decrypted share and a DLEQ proof of correct decryption and send no header partial for the request.

#### Scenario: Bad share

- **WHEN** node 4 decrypts a share that does not match the commitments
- **THEN** node 4 posts a complaint and sends no header partial

### Requirement: RQ-011 Complaint before admission

**RQ-011** When a verified share complaint against a request is ordered before the first ADMIT vote of that request, the committee node SHALL post VOID for the request with reason SHARE_COMPLAINT.

#### Scenario: Early complaint

- **WHEN** a verified complaint is ordered while no ADMIT vote of the request is on the board
- **THEN** every honest node posts VOID with reason SHARE_COMPLAINT

### Requirement: RQ-012 Complaint after admission

**RQ-012** When a verified share complaint against a request is ordered after the first ADMIT vote of that request, the request state machine SHALL record the dealer's fault and leave `phase` and `reason` unchanged.

DECISIONS 47: partials may already have left, so the complaint voids nothing.

#### Scenario: Late complaint

- **WHEN** a verified complaint is ordered after the first ADMIT vote
- **THEN** the request keeps its phase and the dealer's fault is recorded

### Requirement: RQ-013 Open

**RQ-013** When `t` header partials of a request with `phase = ORDERED` combine to a key that decrypts `body_0` and the header checks of EN-009 to EN-012 pass, the request state machine SHALL set `phase = OPENED`, `K`, `L` and `G` from the header, and `collecting` to `true` exactly for a header that names an actor whose contribution is not embedded.

A request whose contributions are all embedded, and the single-user form, have `collecting = false` and follow the two-commit path (DECISIONS 35).

#### Scenario: Single-user request

- **WHEN** the header of a single-user P2TR request with `K = 8`, `L = 2` opens
- **THEN** the request has `phase = OPENED`, `G = 2` and `collecting = false`

### Requirement: RQ-014 Malformed header

**RQ-014** If a header check of EN-009 to EN-012 fails after `body_0` decrypts, then the committee node SHALL post VOID for the request with reason MALFORMED.

DESIGN §5.4 says that a node posts VOID "with the reason" and names no code for a malformed header; MALFORMED is provisional (Q-001).

#### Scenario: Wrong ticket count

- **WHEN** an opened header holds 29 tickets for `K = 8`, `L = 2`, `G = 2`
- **THEN** every honest node posts VOID with reason MALFORMED

### Requirement: RQ-015 Dealer fault on a key

**RQ-015** If `t` proved PRF partials for a label of a request still fail the AEAD tag, then the committee node SHALL post VOID for the request with reason DEALER_FAULT.

The proof fallback is EN-014.

#### Scenario: Bad dealing found by the fallback

- **WHEN** seven partials with valid DLEQ proofs fail the header tag
- **THEN** every honest node posts VOID with reason DEALER_FAULT

### Requirement: RQ-016 OPENED vote

**RQ-016** While a request has `phase = OPENED` and `collecting = true`, its authorization is in force (AU-010) and every committee slot that its header names meets the window rule of SL-012, the committee node SHALL vote OPENED with `H(header)` once.

#### Scenario: Collecting request in force

- **WHEN** the authorization of a collecting request finalizes and its slots lie in the window
- **THEN** each honest node votes OPENED with the header hash

### Requirement: RQ-017 Collecting

**RQ-017** When `q` OPENED votes with one header hash for a request with `phase = OPENED` and `collecting = true` are committed, the request state machine SHALL set `phase = COLLECTING`.

The same votes reserve the slots of the request (SL-007).

#### Scenario: Quorum of OPENED votes

- **WHEN** the sixth OPENED vote with one header hash commits at `n = 9`
- **THEN** the request has `phase = COLLECTING`

### Requirement: RQ-018 Attach a contribution frame

**RQ-018** When a contribution frame ordered at a board height at most `exp_c` names the `hd` of a request with `phase = COLLECTING`, a position of its actor slot table that holds no contribution, a token that opens `H(τ_a)` of that position and one sealed contribution of the right length for every variant body, the request state machine SHALL attach the frame to that position.

#### Scenario: First frame for a position

- **WHEN** the first well-formed frame for position 2 is ordered before `exp_c`
- **THEN** position 2 holds that contribution

### Requirement: RQ-019 Second frame for a position

**RQ-019** If a contribution frame names a position of an actor slot table that already holds a contribution, then the request state machine SHALL refuse the frame with the code `position_filled`.

#### Scenario: Duplicate frame

- **WHEN** a second frame for position 2 is ordered
- **THEN** position 2 keeps the first contribution and the code is `position_filled`

### Requirement: RQ-020 Late contribution frame

**RQ-020** If a contribution frame is ordered at a board height above `exp_c` of its target request, then the request state machine SHALL refuse the frame with the code `late_contribution`.

A late contribution is never opened, because no honest node releases a variant partial for a VOID request (DESIGN §5.9).

#### Scenario: Frame after the window

- **WHEN** a frame is ordered at height `exp_c + 1`
- **THEN** the frame is not attached and the code is `late_contribution`

### Requirement: RQ-021 Frame before the target opens

**RQ-021** While the target request of a contribution frame has `phase` POSTED or ORDERED, when the frame is ordered, the request state machine SHALL hold the frame and apply RQ-018 to it at the event that sets the target to COLLECTING.

#### Scenario: Frame ordered first

- **WHEN** a frame is ordered before its target request opens
- **THEN** the frame is held and attaches when the target reaches COLLECTING

### Requirement: RQ-075 Frame for an opened target

**RQ-075** If a contribution frame is ordered while its target request has `phase` OPENED or ADMITTED, then the request state machine SHALL refuse the frame with the code `late_contribution`.

RQ-021 holds a frame only while the target has `phase` POSTED or ORDERED, and RQ-018 attaches a frame only while the target has `phase` COLLECTING. RQ-020 refuses a frame ordered above `exp_c` in every phase, ORDERED included. RQ-005 refuses a frame for a terminal target (DECISIONS 70).

#### Scenario: Frame while the target is OPENED

- **WHEN** a frame is ordered at a height at most `exp_c` while its target request has `phase = OPENED`
- **THEN** the frame is neither held nor attached and the code is `late_contribution`

### Requirement: RQ-022 Detach a complained frame

**RQ-022** When a verified share complaint against an attached contribution frame is ordered, the request state machine SHALL detach the frame and leave its position empty.

DECISIONS 50 item (6).

#### Scenario: Complaint on a frame

- **WHEN** a verified complaint against the frame of position 1 is ordered
- **THEN** position 1 holds no contribution

### Requirement: RQ-023 ADMIT vote

**RQ-023** While a request has `phase = OPENED` with `collecting = false`, or `phase = COLLECTING` with every position of its actor slot table filled, and the admission checks of DESIGN §5.4 hold, the committee node SHALL vote ADMIT once with `H(header)` and `OBS(eid, 1, 1, h)` at its finalized host height `h` and its finalized Midnight height.

Checks: EN-009 to EN-013; AU-005, AU-010, AU-018; SL-004, SL-006, SL-012; in TEE mode every ECDSA slot belongs to `X`.

#### Scenario: Two-commit path

- **WHEN** the header of a single-user request is open and its authorization is in force
- **THEN** each honest node votes ADMIT once with its OBS report

#### Scenario: Authorization not yet in force

- **WHEN** the header is open and its authorization is not yet final
- **THEN** no honest node votes ADMIT, and none runs the admission checks of RQ-025 and SL-016

### Requirement: RQ-024 Authorization not in force

**RQ-024** If the authorization of a request is not in force, then the committee node SHALL refuse to vote OPENED or ADMIT for the request with the code `not_in_force`.

The request stays in its phase. Precedence lapses at `order_pos` height plus `Δ_c` (SL-005).

#### Scenario: Midnight not final

- **WHEN** the header is open and the `authorize` transaction is included but not final
- **THEN** the node casts no ADMIT vote

### Requirement: RQ-025 Authorization refused

**RQ-025** If Midnight refused the `authorize` call of `auth_ref`, or the authorization of `auth_ref` is in force and its record does not open to the `hd` and the `tkc` of the header, then the committee node SHALL post VOID for the request with reason AUTH_REFUSED.

The match is an admission check. A header can open before its authorization is final, and no node posts AUTH_REFUSED for an authorization that is not yet in force (DESIGN §4.7 item 5, DECISIONS 68).

#### Scenario: Wrong ticket commitment

- **WHEN** `auth` on Midnight commits to another `tkc`
- **THEN** every honest node posts VOID with reason AUTH_REFUSED

#### Scenario: Authorization not yet final

- **WHEN** the header opens while its authorization is not yet final
- **THEN** no honest node posts AUTH_REFUSED

### Requirement: RQ-026 Admitted

**RQ-026** When the first `q` ADMIT votes in board order with one header hash for a request with `phase` OPENED or COLLECTING are committed, the request state machine SHALL set `phase = ADMITTED`.

The same votes claim the slots of the request (SL-008). An OBS report on an ADMIT vote counts only once the request reaches ADMITTED (DESIGN §13, SCHEME §3.6 change).

#### Scenario: Quorum of ADMIT votes

- **WHEN** the sixth ADMIT vote with one header hash commits at `n = 9`
- **THEN** the request has `phase = ADMITTED`

### Requirement: RQ-027 Generation 1 anchor

**RQ-027** When a request reaches ADMITTED, the request state machine SHALL set `anchor[1]` to the variant that the header's selection rule gives at the anchor height of the OBS reports of the first `q` ADMIT votes.

The anchor height is entry `f + 1` of those `q` heights sorted highest first (SCHEME §3.6). The rule is "first variant whose fee rate meets the anchored median, else the highest" (DESIGN §4.6).

#### Scenario: Anchor from ADMIT votes

- **WHEN** a request reaches ADMITTED
- **THEN** `anchor[1]` is set and every honest node selects the same variant

### Requirement: RQ-028 Generation 2 anchor

**RQ-028** While a request has `phase = ADMITTED`, `G = 2` and `anchor[2] = none`, when the variant of generation 1 has not confirmed by its deadline and the board commits an OBS set for generation 2 whose anchor selects a variant `j > anchor[1]`, the request state machine SHALL set `anchor[2] = j`.

#### Scenario: Fee bump

- **WHEN** variant 3 of generation 1 has not confirmed by its deadline and the generation 2 anchor selects variant 5
- **THEN** `anchor[2] = 5`

### Requirement: RQ-029 Selection domain

**RQ-029** The request state machine SHALL keep `g ≤ min(anchor[g], G_max)` for every generation with `anchor[g] ≠ none` and `anchor[1] < anchor[2]` for every request with `anchor[2] ≠ none`.

A request runs at most `G = min(K, G_max)` generations. A further fee bump is a new request (DECISIONS 27).

#### Scenario: Variant 1 in generation 2

- **WHEN** an OBS set for generation 2 would select variant 1
- **THEN** `anchor[2]` stays `none`

### Requirement: RQ-030 Release

**RQ-030** While a request has `phase = ADMITTED`, its authorization is in force and not revoked, `anchor[g] = j` and the release checks of generation `g` hold (RQ-031 to RQ-033, RQ-035 in TEE mode and RQ-069 in NON_TEE mode), the committee node SHALL send once its PRF partial for the variant body `(j, g)` and its signature partial for each slot `ℓ(g, ·)` to the combiners of RQ-036.

#### Scenario: Release of generation 1

- **WHEN** an admitted request has `anchor[1] = 3` and every check of generation 1 passes
- **THEN** each honest node sends the partials for body `(3, 1)` and slots `ℓ(1, ·)`

### Requirement: RQ-069 Release record before send in non-TEE mode

**RQ-069** Where `mode = NON_TEE`, the committee node SHALL post RELEASE for generation `g` with variant `j` in its board vote and send no partial of generation `g` before that RELEASE has committed for the request in `phase = ADMITTED`.

A partial can combine off the board. The committed RELEASE sets `any_release` (RQ-037), so the request settles RELEASED (RQ-051, DECISIONS 59). RQ-005 refuses a RELEASE on a terminal request. TEE mode: RQ-035. Claim C11.

#### Scenario: Partial before the record

- **WHEN** a non-TEE node passes every release check of generation 1 and its RELEASE vote has not committed
- **THEN** the node sends no partial of generation 1

#### Scenario: Record on an expired request

- **WHEN** a non-TEE node's RELEASE for generation 1 reaches the board after the request expired
- **THEN** the RELEASE is refused with the code `terminal` and the node sends no partial

### Requirement: RQ-031 Release check

**RQ-031** If the `x(R)` that a node computes from `R_A`, the slot points and `ρ` differs from the `x(R)` of a ticket of the selected variant, or on ECDSA the `r` of the slot record differs, then the committee node SHALL release nothing for the generation and post VOID with reason RELEASE_CHECK.

The node never takes `R` or `σ` from the initiator (DESIGN §4.2, §4.7 item 7).

#### Scenario: Wrong x(R)

- **WHEN** a ticket of the selected variant carries an `x(R)` that the node does not compute
- **THEN** every honest node posts VOID with reason RELEASE_CHECK

### Requirement: RQ-032 Revocation height before release

**RQ-032** The committee node SHALL check that the authorization is not revoked at a finalized Midnight height at least as new as every Midnight height reported in the OBS set of generation `g` before it sends a partial for generation `g`.

A P0 or P1 charter has no hold authority, so the check passes by construction (DESIGN §5.5).

#### Scenario: Revocation after the OBS set

- **WHEN** a revocation finalizes at a Midnight height below the newest OBS report of generation 1
- **THEN** the node finds the revocation before it releases generation 1

### Requirement: RQ-033 Hold wait in P2

**RQ-033** Where a request has `profile = P2`, the committee node SHALL send no partial of generation 1 until the authorization has been final on Midnight for `Δ_hold` Midnight blocks.

`Δ_hold = 2` at launch (DESIGN §2.3).

#### Scenario: P2 release

- **WHEN** a P2 authorization became final one Midnight block ago
- **THEN** the node releases nothing for generation 1

### Requirement: RQ-034 Revoked authorization

**RQ-034** When the authorization of a request with `any_release = false` is revoked, the committee node SHALL post VOID for the request with reason REVOKED.

A revocation after a release stops every later generation through RQ-030 and voids nothing (DESIGN §5.5).

#### Scenario: Revocation before release

- **WHEN** the hold authority revokes an admitted P2 authorization before any release
- **THEN** every honest node posts VOID with reason REVOKED

### Requirement: RQ-035 Witness before release in TEE mode

**RQ-035** Where `mode = TEE`, the committee node SHALL send no partial of generation `g` before `w` peers have acked its entry `release(node, eid, g) → (j_g, H(tk_1 ‖ … ‖ tk_L))` and `slot_bind` has made each slot `ℓ(g, ·)` `bound` to its ticket digest in a current session version.

The `release` entries go in one batched message per peer and board height after the anchor; the slot bind is the batch of SL-019 and Sessions SS-140, SS-141 (DECISIONS 38, 51 item 3).

#### Scenario: Missing ack

- **WHEN** only five peers acked the release entry at `n = 9`
- **THEN** the node sends no partial

### Requirement: RQ-036 Combiners

**RQ-036** The committee node SHALL send its release partials to the `f + 1` nodes that `H(eid ‖ g)` chooses in NON_TEE mode and to every node in TEE mode.

#### Scenario: Non-TEE combiners

- **WHEN** a non-TEE node releases generation 1 at `n = 9`
- **THEN** it sends its partials to the three combiners chosen by `H(eid ‖ 1)`

### Requirement: RQ-037 Release recorded

**RQ-037** When a RELEASE of generation `g` with variant `j` commits in a board vote, or a peer acks a witnessed `release` entry for it, the request state machine SHALL set `released[g] = j` and `any_release = true`.

#### Scenario: Witnessed release

- **WHEN** a release entry of generation 1 with variant 3 has `w` acks
- **THEN** `released[1] = 3` and `any_release = true`

### Requirement: RQ-038 Failed contribution

**RQ-038** If a combined signature fails and the combiner finds a contribution that fails its equation, or `y_{v,g}·G ≠ P_{v,g}` for the released body, then the committee node SHALL post VOID for the request with reason CONTRIBUTION.

A key mismatch names the initiator (DESIGN §6.4 item 10). The slots of the request burn (SL-009) and the initiator reissues (RQ-051).

#### Scenario: Bad actor scalar

- **WHEN** the combined signature fails and actor 2's scalar fails its equation
- **THEN** every honest node posts VOID with reason CONTRIBUTION

### Requirement: RQ-039 Failure evidence in non-TEE mode

**RQ-039** Where `mode = NON_TEE`, when an honest combiner finds a failing contribution, the committee node SHALL send `Z_{j_g,g}`, the `t` proved partials and the failing equation to every node.

Each node then verifies the failure and posts VOID, so `f + 1` VOID posts form when the other combiners stay silent (DECISIONS 50 item (1)).

#### Scenario: Silent combiners

- **WHEN** one honest combiner finds a failing scalar and two corrupt combiners stay silent
- **THEN** every honest node receives the evidence and posts VOID

### Requirement: RQ-040 FINAL vote

**RQ-040** When the node's own chain view shows a variant transaction of a request at the confirmation depth of its chain, the committee node SHALL post FINAL for the request with `Enc_{k_fin}(txid)`.

DECISIONS 55: the poster validates its own evidence, and the board counts posts at their positions.

#### Scenario: Confirmation seen

- **WHEN** node 2 sees the variant transaction at confirmation depth
- **THEN** node 2 posts FINAL with one ciphertext of `txid`

### Requirement: RQ-041 Foreign spend in TEE mode

**RQ-041** Where `mode = TEE`, when the node sees before a release that the pinned input or nonce of a request was spent by a transaction that is not one of its variants, the committee node SHALL post VOID for the request with reason PIN_SPENT.

A non-TEE committee does not read the host chain for a foreign spend before release, and such a request ends EXPIRED (DESIGN §5.6). The reason code is provisional (Q-001).

#### Scenario: Pin spent elsewhere

- **WHEN** a TEE node sees the pinned input spent by a foreign transaction
- **THEN** it posts VOID with reason PIN_SPENT

### Requirement: RQ-042 Counting epochs

**RQ-042** The request state machine SHALL count the FINAL and VOID posts of the members of each serving epoch at their board positions against that epoch's own threshold and never add posts of two epochs.

An epoch serves a request when it is the binding epoch, or a successor epoch from the board position of the ROTATE that registers it until its post keys expire with the grace period (DECISIONS 56).

#### Scenario: Posts across a rotation

- **WHEN** two old-committee members and one new-committee member post VOID at `f = f' = 2`
- **THEN** no VOID tombstone forms

### Requirement: RQ-043 Post of an unregistered epoch

**RQ-043** If a FINAL or VOID post names an epoch that is not registered at its board position, then the request state machine SHALL refuse the post with the code `unknown_epoch`.

#### Scenario: Post before ROTATE

- **WHEN** a member of epoch 5 posts FINAL before the ROTATE that registers epoch 5
- **THEN** the post does not count and the code is `unknown_epoch`

### Requirement: RQ-044 FINAL tombstone

**RQ-044** When the post that completes `q` FINAL votes with one `Enc_{k_fin}(txid)` for one serving epoch commits at a position before any VOID tombstone of the request, the request state machine SHALL set `phase = FINAL`.

FINAL before VOID is decided by board position (DECISIONS 55).

#### Scenario: Six FINAL votes

- **WHEN** the sixth FINAL vote with one ciphertext commits at `n = 9`
- **THEN** the request has `phase = FINAL`

### Requirement: RQ-045 VOID tombstone

**RQ-045** When the post that completes `f + 1` VOID posts of distinct members of one serving epoch commits at a position before any FINAL tombstone of the request, the request state machine SHALL set `phase = VOID` and `reason` to the reason that at least `f + 1` of the counted reason posts carry.

Reason posts: the counted posts, less STALLED posts after a RELEASE (RQ-074). A named reason has an honest post (DECISIONS 61, Q-002 resolved). RQ-072: no common reason. Claims C13, C20.

#### Scenario: Three VOID posts

- **WHEN** three members of the binding epoch post VOID with reason SLOT_TAKEN at `f = 2`
- **THEN** the request has `phase = VOID` and `reason = SLOT_TAKEN`

### Requirement: RQ-072 Tombstone without a common reason

**RQ-072** If no reason is carried by `f + 1` of the reason posts of a VOID tombstone (RQ-045), then the request state machine SHALL set `reason = MIXED`.

The tombstone forms at exactly `f + 1` counted posts, so posts with two reasons give MIXED (DECISIONS 61). After a RELEASE a tombstone with a STALLED post gives MIXED (DECISIONS 64).

#### Scenario: Posts with two reasons

- **WHEN** at `f = 1` an honest member posts VOID with reason MALFORMED and a corrupt member completes the count with reason REVOKED
- **THEN** the request has `phase = VOID` and `reason = MIXED`

### Requirement: RQ-073 No STALLED reason after a RELEASE

**RQ-073** The request state machine SHALL never set `reason = STALLED` for a request with `any_release = true`.

Admission after `exp_c` stays allowed; a RELEASE that committed (RQ-037) takes STALLED out of the tombstone reason (RQ-045, RQ-074, RQ-072), so the stalled gate of AU-021 sees STALLED only on a request that released nothing. Claim C20 (DECISIONS 64).

#### Scenario: ADMIT after an honest STALLED post

- **WHEN** at `f = 1` an honest member posts STALLED at `exp_c`, the `q` ADMIT votes commit, a RELEASE commits and a corrupt member posts STALLED
- **THEN** the request has `phase = VOID`, `reason = MIXED` and `outcome = RELEASED`

### Requirement: RQ-074 STALLED posts after a RELEASE

**RQ-074** If a request has `any_release = true`, then the request state machine SHALL count no STALLED post of the request as a reason post of its VOID tombstone.

The STALLED post still counts toward the `f + 1` posts that form the tombstone (RQ-045), so the outcome stays RELEASED (RQ-051). Claim C20 (DECISIONS 64).

#### Scenario: STALLED post before the RELEASE

- **WHEN** an honest STALLED post commits, then a RELEASE, then a corrupt STALLED post completes the tombstone at `f = 1`
- **THEN** no post is a STALLED reason post and the request has `reason = MIXED`

### Requirement: RQ-071 Reading MIXED

**RQ-071** The request state machine SHALL read a VOID tombstone with reason MIXED as none of STALLED, SLOT_TAKEN and REVOKED.

The rules that read a tombstone reason are the SLOT_TAKEN half of RQ-063, the stalled gate of the carried VOID settlement (AU-021, RQ-060) and the revocation cause of RQ-034 and AU-019. A MIXED request settles by the outcome rules (RQ-050, RQ-051) and its leaf counts by root (AU-020). Claims C13 and C20 (DECISIONS 61).

#### Scenario: MIXED tombstone and a reissue

- **WHEN** a request ends VOID with reason MIXED
- **THEN** no reissue carries its VOID leaf as the leaf of a stalled request

### Requirement: RQ-046 Expiry

**RQ-046** When the board height passes `exp` of a request whose `phase` is not FINAL or VOID, the request state machine SHALL set `phase = EXPIRED`.

#### Scenario: Expired request

- **WHEN** the board passes `exp` and no tombstone has formed
- **THEN** the request has `phase = EXPIRED`

### Requirement: RQ-047 Stall

**RQ-047** While a request has `collecting = true`, when the board reaches height `exp_c` and no `q` ADMIT votes for the request are committed, the committee node SHALL post VOID for the request with reason STALLED.

Every honest node posts it, whatever its own view of the actor slot table (DECISIONS 50 item (6)). The `q` ADMIT votes may still commit after it; the post then counts toward the tombstone but not toward reason STALLED (RQ-074, RQ-073, DECISIONS 64).

#### Scenario: Silent actor

- **WHEN** the board reaches `exp_c` with position 2 empty
- **THEN** every honest node posts VOID with reason STALLED

### Requirement: RQ-048 Restart end

**RQ-048** When a whole-committee restart burns a slot that a live request holds (CP-020, CP-021), the committee node SHALL set `restart_end = true` for the request and post VOID for it with reason RESTART.

DESIGN §7.11 ends these requests VOID and names no reason code; RESTART is provisional (Q-001). A request that ended after the latest landed checkpoint is not live, and RQ-068 ends it again.

#### Scenario: Pending request at a restart

- **WHEN** a restart burns index 40 that a pending request holds
- **THEN** the node posts VOID with reason RESTART for that request

### Requirement: RQ-068 Restart re-end

**RQ-068** When a whole-committee restart burns a slot of a request that ended after the latest landed checkpoint, the request state machine SHALL end the request again with `restart_end = true`, keep its `phase` and `reason` and set `outcome` to FINAL for a request whose variant transaction the host chain shows at confirmation depth and to RELEASED for every other such request.

Burns: CP-020, CP-021. Rule of RQ-052 (DECISIONS 53, 58, DESIGN §7.11), leaf by RQ-054; claim C11.

#### Scenario: Ended request at a restart

- **WHEN** a request ended VOID with reason STALLED after the latest landed checkpoint, its pinned input is unspent, and a restart burns index 41 that it holds
- **THEN** `restart_end = true`, `phase = VOID`, and `outcome = RELEASED`

#### Scenario: Confirmed variant at a restart

- **WHEN** a request ended after the latest landed checkpoint, the host chain shows one of its variant transactions at confirmation depth, and a restart burns a slot that it holds
- **THEN** `outcome = FINAL`

### Requirement: RQ-076 Release record across a restart

**RQ-076** When a whole-committee restart loses the board entries after the latest landed checkpoint, the request state machine SHALL keep `any_release` and every `released[g]` of each request as they were before the restart.

Only RQ-037 sets them and no rule clears them, so a released request settles RELEASED or FINAL (RQ-051, RQ-052). Claim C11 (DECISIONS 70).

#### Scenario: RELEASE in the lost board tail

- **WHEN** the RELEASE of generation 1 of a request committed after the latest landed checkpoint and a whole-committee restart loses those board entries
- **THEN** the request keeps `any_release = true` and `released[1]`, and its outcome is RELEASED or FINAL

### Requirement: RQ-049 Outcome of FINAL

**RQ-049** When a request reaches `phase = FINAL`, the request state machine SHALL set `outcome = FINAL`.

#### Scenario: Confirmed spend

- **WHEN** the FINAL tombstone forms
- **THEN** `outcome = FINAL`

### Requirement: RQ-050 Outcome of an end without a release

**RQ-050** When a request with `any_release = false` and `restart_end = false` reaches `phase` VOID or EXPIRED, the request state machine SHALL set `outcome = VOID`.

With RQ-035 and RQ-069 no honest partial leaves a node before `any_release = true`, so an end with `any_release = false` released nothing (DECISIONS 59).

#### Scenario: Stalled request

- **WHEN** a request that released nothing ends VOID with reason STALLED
- **THEN** `outcome = VOID`

### Requirement: RQ-051 Outcome of an end after a release

**RQ-051** When a request with `any_release = true` and `restart_end = false` reaches `phase` VOID or EXPIRED, the request state machine SHALL set `outcome = RELEASED`.

DECISIONS 47: the signed transaction may still confirm, so the record never returns to unspent. DECISIONS 59: a committed RELEASE counts even when no combined signature is seen, because the partial may have combined off the board.

#### Scenario: Expired after a release

- **WHEN** a request that released generation 1 expires
- **THEN** `outcome = RELEASED`

#### Scenario: Non-TEE expiry after a recorded send

- **WHEN** a non-TEE request whose RELEASE for generation 1 committed expires and no FINAL tombstone formed
- **THEN** `outcome = RELEASED` and the record settles LOCKED to its pin

### Requirement: RQ-052 Outcome of a restart end

**RQ-052** When a request with `restart_end = true` reaches `phase` VOID or EXPIRED, the request state machine SHALL set `outcome = FINAL` for a request whose variant transaction the host chain shows at confirmation depth and `outcome = RELEASED` for every other such request.

DECISIONS 53: release evidence can lie in the lost board tail, so an unspent pin does not show that no partial left. CP-030 and CP-033 use the same rule.

#### Scenario: Restart end with an unspent pin

- **WHEN** a request ended by a restart has an unspent pinned input
- **THEN** `outcome = RELEASED`

### Requirement: RQ-053 Settlement leaf

**RQ-053** When a request gets an `outcome` other than NONE, the committee node SHALL sign the settlement leaf `(auth, outcome)` with `post_i` on the board.

The committee submits no Midnight transaction per request; the next checkpoint carries `settle_root` (CP-013, DECISIONS 52).

#### Scenario: Leaf after VOID

- **WHEN** a request gets `outcome = VOID`
- **THEN** each honest node signs `(auth, VOID)` on the board

### Requirement: RQ-054 One outcome per authorization

**RQ-054** The committee node SHALL sign at most one settlement outcome for one `auth` among the leaves that Midnight holds and replace a leaf that Midnight does not hold only by the restart leaf of RQ-068.

Midnight holds a leaf under a landed `settle_root` or carried by a reissue. For `|C| ≤ f` no `auth` settles with two outcomes: two quorums share `2q − n ≥ f + 1` nodes. A larger coalition can sign two, and the pinned input lets one spend confirm (C11, DECISIONS 58, DECISIONS 65).

#### Scenario: Second outcome

- **WHEN** a node signed `(auth, VOID)` and a replay shows the same `auth`
- **THEN** the node signs no other outcome for that `auth`

### Requirement: RQ-055 Erase at the end

**RQ-055** When a request reaches FINAL, VOID or EXPIRED, the committee node SHALL erase the slot shares, its share of `κ_0`, every PRF point and key, every `κ_c` share, the opened scalars, the header and the capsules of the request and keep only the board record and `Enc_{k_fin}(txid)`.

In TEE mode the slot shares are erased by `slot_burn` (SL-018).

#### Scenario: Erasure after FINAL

- **WHEN** a request reaches FINAL
- **THEN** the node holds no secret of that request

### Requirement: RQ-056 Phases move forward

**RQ-056** The request state machine SHALL change `phase` only along POSTED → ORDERED → OPENED → (COLLECTING →) ADMITTED and from any non-terminal phase to FINAL, VOID or EXPIRED, and never out of a terminal phase.

#### Scenario: No return

- **WHEN** a request has `phase = VOID`
- **THEN** no event changes its phase

### Requirement: RQ-057 No release before admission

**RQ-057** The committee node SHALL send no variant partial and no signature partial for a request that has not reached ADMITTED.

Claims C6 and C20: release needs ADMITTED, which needs every contribution and an authorization in force (DESIGN §5.9).

#### Scenario: Stalled request releases nothing

- **WHEN** a collecting request ends VOID with reason STALLED
- **THEN** no node released a partial for it

### Requirement: RQ-058 One variant per generation

**RQ-058** The committee node SHALL release partials for at most one variant per generation of a request and for no label other than `(anchor[g], g)`.

Claim C9 (unselected variants stay sealed). Honest nodes agree on `anchor[g]` because they read one board, which holds for `|C| ≤ f` in non-TEE mode (DECISIONS 42).

#### Scenario: Other variant

- **WHEN** generation 1 released variant 3
- **THEN** no honest node sends a partial for body `(4, 1)`

### Requirement: RQ-059 No new generation after revocation

**RQ-059** The committee node SHALL send no partial of a generation `g` of a request whose authorization was revoked at a finalized Midnight height at or below the height that RQ-032 reads for `g`.

Claim C7 (hold enforcement). In NON_TEE mode the claim is honest-threshold: `t` corrupt nodes can release already-dealt variants (DECISIONS 8).

#### Scenario: Revocation between generations

- **WHEN** generation 1 released and the hold authority then revokes the authorization
- **THEN** no honest node releases generation 2

### Requirement: RQ-060 Reissue

**RQ-060** When the initiator reissues a VOID request, the request state machine SHALL treat the reissue as a new request with its own `eid`, authorization, committee slots, actor pool pairs and nonces `k_0`, and never as a generation of the old request.

The reissue's `authorize` carries the VOID leaf of the stalled request (AU-021).

#### Scenario: Reissue after STALLED

- **WHEN** the initiator posts a reissue with signing set `S_2`
- **THEN** the reissue is a new request with `phase = POSTED`

### Requirement: RQ-061 Settled authorization replayed

**RQ-061** If a request names an `auth` that Midnight shows as settled, then the committee node SHALL refuse to vote for the request with the code `settled`.

A node that replays the board after a restart meets such requests (DESIGN §5.6 availability).

#### Scenario: Replay after restart

- **WHEN** a node replays a request whose `auth` Midnight records as settled VOID
- **THEN** the node casts no vote for it

### Requirement: RQ-062 Request types without signing

**RQ-062** When a request of `type` BIRTH, REFILL or CONTRIB reaches OPENED, the request state machine SHALL hand it to the birth check (SH-009), the ECDSA slot session (SH-016) or the frame attachment (RQ-018) and keep no signing state for it.

A P0 request runs line dealing after OPENED (SCHEME §3.6 to §3.10).

#### Scenario: Birth request

- **WHEN** a BIRTH envelope opens
- **THEN** the birth check runs and no slot or release state is kept

### Requirement: RQ-063 Liveness

**RQ-063** While `|C| ≤ f` and the network is partially synchronous, the request state machine SHALL bring every valid request whose authorization comes into force to FINAL, EXPIRED or VOID, and VOID only after an honest SLOT_TAKEN post for a slot that an earlier live request named or that lies at or below the floor `h` and is not pending.

Reason SLOT_TAKEN or MIXED (RQ-072, DECISIONS 61). Claim C13; open items O28 and O38. A temporal property over fair runs.

#### Scenario: Honest run

- **WHEN** an authorized single-user request runs with `f` silent nodes
- **THEN** it reaches FINAL or EXPIRED
