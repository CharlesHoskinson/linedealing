## ADDED Requirements

### Requirement: EN-001 One frame size

**EN-001** The initiator wallet SHALL build every envelope of every request type as one frame of 16,384 bytes, padded with random bytes under the AEAD.

The frame size is the only public size class at launch. A second class waits for O7 (DESIGN §4.6, §5.11).

#### Scenario: Small request

- **WHEN** an Ethereum request uses 3 KB
- **THEN** the envelope is 16,384 bytes

### Requirement: EN-002 Public part

**EN-002** The initiator wallet SHALL put into the 96-byte public part only `version = 0x01`, `epoch`, `keylist_hash`, `exp`, `size_class = 0x00`, `auth_ref` and 18 reserved bytes.

The public part names no chain, suite or variant count, so ordering is blind to the request type (claims C10, C21).

#### Scenario: Public part of a seizure

- **WHEN** a guardian builds a seizure envelope
- **THEN** its public part has the form of an owner's envelope

### Requirement: EN-003 Envelope id

**EN-003** The initiator wallet SHALL compute `hd` over the whole frame except `π` and `auth_ref`, `eid = H(hd ‖ auth_ref)`, and the encryption proof `π` with `eid` as its context.

`hd = H(pub* ‖ commitments ‖ ciphertexts ‖ E ‖ lay ‖ body_0 ‖ var… ‖ cap… ‖ tail)` with `pub*` the public part with `auth_ref` zero. The wallet computes `hd`, then `auth`, then `π` (DECISIONS 49).

#### Scenario: Order of computation

- **WHEN** a wallet builds a spend
- **THEN** `auth` commits to `hd` and `π` binds `eid`

### Requirement: EN-004 Frame shape check

**EN-004** If an envelope's size is not 16,384 bytes, or its `version` or `size_class` is unknown, then the committee node SHALL refuse to accept it with the code `bad_shape`.

A refused envelope is not ordered.

#### Scenario: Short frame

- **WHEN** a node receives a frame of 16,000 bytes
- **THEN** the node does not accept it

### Requirement: EN-005 Epoch check

**EN-005** If an envelope's `epoch` is not a current epoch or its `keylist_hash` is not the hash of that epoch's `PK_i` list, then the committee node SHALL refuse to accept it with the code `bad_epoch`.

#### Scenario: Old key list

- **WHEN** an envelope names the key list of a closed epoch
- **THEN** the node does not accept it

### Requirement: EN-006 Expiry check

**EN-006** If the board height is above an envelope's `exp`, then the committee node SHALL refuse to accept it with the code `expired`.

#### Scenario: Late post

- **WHEN** an envelope with `exp = 900` reaches a node at board height 901
- **THEN** the node does not accept it

### Requirement: EN-007 Proof check

**EN-007** If an envelope's encryption proof `π` does not verify for `eid = H(hd ‖ auth_ref)`, then the committee node SHALL refuse to accept it with the code `bad_proof`.

A party that rewrites `auth_ref` in a posted envelope has no proof for the new `eid` (DECISIONS 49).

#### Scenario: Rewritten auth_ref

- **WHEN** a party copies an envelope and changes `auth_ref`
- **THEN** the copy fails the proof check

### Requirement: EN-008 One outer dealing per epoch

**EN-008** If an envelope has the outer-dealing digest `dd` of an earlier envelope of the same epoch, then the committee node SHALL refuse to accept it with the code `dd_reused`.

Both would share every PRF key, so a release on one opens the same label on the other (claim C9, DECISIONS 45).

#### Scenario: Copied dealing

- **WHEN** an envelope reuses the outer dealing of an ordered envelope under other bodies
- **THEN** the node does not accept it

### Requirement: EN-023 Collection window inside the expiry check

**EN-023** If the board height `b` at which an envelope would be ordered gives `b + Δ_c ≥ exp`, then the committee node SHALL refuse to accept the envelope with the code `exp_c_not_below_exp`.

Checked at acceptance and again for the ordering block, so every ordered request has `exp_c < exp` (RQ-006) and STALLED (RQ-047) fires before the expiry of RQ-046. EN-021 stays the wallet's duty (DECISIONS 62).

#### Scenario: Window past the expiry

- **WHEN** a node would order an envelope with `exp = 650` at board height 100 with `Δ_c = 600`
- **THEN** the node does not accept it and the code is `exp_c_not_below_exp`

### Requirement: EN-009 Layout block

**EN-009** If a decoded layout block has a nonzero unused entry, a region that leaves the frame or overlaps the actor capsules, or a length that disagrees with the header, then the committee node SHALL treat the header as malformed.

`lay = AEAD(k_lay, layout)` holds 24 big-endian 2-byte lengths: `body_0`, 15 body regions and 8 capsule regions (DECISIONS 57). A malformed header ends VOID by RQ-014.

#### Scenario: Overlapping region

- **WHEN** the layout gives capsule 8 a region that runs into the actor capsules
- **THEN** the header is malformed

### Requirement: EN-010 Ticket and slot count

**EN-010** If an opened header does not hold `N_h = L·Σ_{v=1..K} min(v, G)` tickets on Schnorr suites or `K·L` tickets on ECDSA, or does not name one committee slot `ℓ(g, j)` for every `g ≤ G` and `j ≤ L` on Schnorr suites, then the committee node SHALL treat the header as malformed.

A Schnorr header names exactly `G·L` committee slots, 4 at `K = 8`, `L = 2` (DECISIONS 27, 44).

#### Scenario: P2TR grid

- **WHEN** a P2TR header with `K = 8`, `L = 2` holds 30 tickets and 4 committee slots
- **THEN** the count check passes

### Requirement: EN-011 Distinct points

**EN-011** If an opened header repeats an `R_A`, an ECDSA `R_ℓ` or a committee slot `ℓ(g, j)`, or in TEE mode names one actor pool pair twice, then the committee node SHALL treat the header as malformed.

DESIGN §4.5 item 2.

#### Scenario: Repeated slot

- **WHEN** a header names one committee slot for generations 1 and 2
- **THEN** the header is malformed

### Requirement: EN-012 Header commitments

**EN-012** If an opened header lacks `ic` or `r_tkc`, then the committee node SHALL treat the header as malformed.

Every node recomputes `tkc` and checks `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)` against the record of `auth_ref` (DECISIONS 49). That match is an admission check: it runs once the authorization is in force, and a mismatch gives AUTH_REFUSED (RQ-025, DECISIONS 68).

#### Scenario: Missing r_tkc

- **WHEN** an opened header holds no `r_tkc`
- **THEN** the header is malformed

### Requirement: EN-013 Sighash recomputation in TEE mode

**EN-013** Where `mode = TEE`, if a sighash, `pm` or challenge `c̃` that the enclave recomputes from the intent in the header differs from a ticket's own fields, then the committee node SHALL treat the header as malformed.

TEE v1: the header carries the intent, `X`, the leaf root, `r_ic` and the salt seeds (DESIGN §4.6, §4.7 item 4).

#### Scenario: Ticket for another message

- **WHEN** a ticket's `c̃` does not match the recomputed challenge of its variant
- **THEN** the enclave refuses the header

### Requirement: EN-014 Proof fallback for PRF partials

**EN-014** If `t` combined PRF partials fail an AEAD tag, then the committee node SHALL ask the senders for their Chaum-Pedersen proofs, drop each partial whose proof fails against the outer commitments and combine again.

The proof challenge hashes `SL1/dleq`, `dd`, the label, `i`, the whole statement including `Y_{i,lab}`, and both commitments (DECISIONS 46 item (1)). If `t` proved partials still fail, RQ-015 applies.

#### Scenario: One bad partial

- **WHEN** node 5 sends a false header partial and the tag fails
- **THEN** the node drops node 5's partial and opens the header with seven proved partials

### Requirement: EN-015 Random auth_ref

**EN-015** The initiator wallet SHALL put 32 random bytes into `auth_ref` of every envelope without an authorization, the contribution frame included.

BIRTH, slot refill, CONTRIB and P0 envelopes carry no authorization. A zero `auth_ref` would mark the frame as a contribution (DECISIONS 54 item 2).

#### Scenario: Contribution frame

- **WHEN** an actor builds a contribution frame
- **THEN** its `auth_ref` is 32 random bytes

### Requirement: EN-016 Keys by threshold PRF

**EN-016** The initiator wallet SHALL derive every key of an envelope from `Z_lab = κ_0·H_c(dd ‖ lab)`: `k_hdr = KDF(Z_hdr)`, `k_lay = KDF(Z_hdr ‖ "layout")`, `k_fin = KDF(Z_hdr ‖ "final")`, and for variant `v` in generation `g` the body key `KDF(Z_{v,g} ‖ "body")`, `y_{v,g} = Hq(Z_{v,g} ‖ "ctb")` and `P_{v,g} = y_{v,g}·G`.

The envelope deals `κ_0` and nothing else; an ECDSA request has one body per variant with label `(v, 0)` (DECISIONS 28). Nobody reconstructs `κ_0`.

#### Scenario: One dealing

- **WHEN** an envelope with 15 variant bodies is built
- **THEN** it carries one outer dealing and no inner dealing

### Requirement: EN-017 One message per AEAD key

**EN-017** The initiator wallet SHALL encrypt one message under each AEAD key of an envelope and of its FINAL votes, with the zero nonce.

#### Scenario: FINAL ciphertext

- **WHEN** six nodes vote FINAL
- **THEN** their votes carry one ciphertext under `k_fin`

### Requirement: EN-018 Contribution frame

**EN-018** The actor SHALL build a contribution frame as an envelope of request type CONTRIB (0x06) with its own outer dealing of a fresh `κ_c`, a layout block with zero body and capsule lengths, and a header that holds the target `hd`, its position, `τ_a` and one sealed contribution for every variant body.

The frame keeps the public shape of every other frame (DECISIONS 34, claim C21).

#### Scenario: Frame shape

- **WHEN** an actor posts a contribution frame
- **THEN** it passes the same public checks as a spend envelope

### Requirement: EN-019 Sealed contribution

**EN-019** The actor SHALL seal its scalars for variant body `(v, g)` as `(E = e·G, AEAD(KDF(e·P_{v,g} ‖ E ‖ dd ‖ position ‖ v ‖ g), s_{a,v,g,1} ‖ … ‖ s_{a,v,g,L}))` with a fresh ephemeral scalar `e`.

The context is `dd`, not `hd` (DECISIONS 45). The committee opens it with `y_{v,g}·E` once it has derived `y_{v,g}`, for a released variant only.

#### Scenario: Embedded contribution

- **WHEN** an actor contributes before the post
- **THEN** its sealed contribution uses the `dd` that the initiator gave it

### Requirement: EN-020 Actor capsule size

**EN-020** The initiator wallet SHALL make every actor capsule 385 bytes, holding `k_hdr`, `k_lay`, the position, `τ_a` and `K_max = 8` capsule keys with the unused keys zero.

A capsule size that depends on `K` would show `K` to every reader of the frame (DECISIONS 57).

#### Scenario: Ethereum request with one other actor

- **WHEN** a request with `K = 1` names one other actor
- **THEN** that actor's capsule is 385 bytes

### Requirement: EN-021 Collection window inside the expiry

**EN-021** The initiator wallet SHALL choose `Δ_c` so that `exp_c` lies below `exp`.

The committee also refuses an envelope that breaks this (EN-023, DECISIONS 62).

#### Scenario: Window choice

- **WHEN** a wallet posts a collecting request with `exp = ordering height + 1000`
- **THEN** it uses `Δ_c < 1000`

### Requirement: EN-022 Public shape is one

**EN-022** The committee node SHALL see the same public shape and public checks for every request type before ordering.

Claims C10 and C21. Nothing inside `body_0` is checked before ordering (DESIGN §4.7).

#### Scenario: Birth and spend

- **WHEN** a node receives a BIRTH envelope and a spend envelope
- **THEN** it cannot tell them apart before ordering
