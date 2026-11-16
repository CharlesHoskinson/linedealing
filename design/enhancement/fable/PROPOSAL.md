# Split-line dealing: co-custody and operator blindness for line dealing

Lane: fable. Date: 2026-11-14. Inputs read: `design/SCHEME.md` (§1–§10), `requirements/catalogue/FACTS.md`, `design/enhancement/VERITEE-MODEL.md`, and the Veritee sources named in the brief (`README.md`, `docs/attested-channel-implementation-plan.md`, `docs/tls-channel-binding.md` §7, `server/akx/src`, `server/azure_attestation_server/src/enclave_key.rs`, `state.rs`, `veritee-os/measured_setup/main.py`). Warden, the Veritee spec and the Midnight contracts were not available; every assumption about them is marked **[assumed]**.

Status of the statements below: the protocol is specified; nothing is implemented or measured; every cost is derived with the SCHEME §7 planning figure of 50 µs per scalar multiplication. Section 6 marks each claim as *reduces to an existing theorem*, *sketched* or *open*.

## 1. Summary

**The enhancement.** In line dealing the owner holds both coefficients of the signature line and deals them. Split-line dealing cuts the line in two halves at address birth. For Schnorr and Ed25519 the line `s(c) = k + c·x` is the sum of a user half `s_u(c) = k_u + c·x_u` and a committee half `s_f(c) = k_f + c·x_f`, with `X = X_u + X_f`. For ECDSA the line `s(h) = h·w + r·μ` is the sum of `(w_u, μ_u)` and `(w_f, μ_f)`, produced once per address by a birth protocol. The address key `x` is never held by anyone. The committee half is created by a DKG and never leaves Shamir form. The user half never reaches the committee as a line: the user's one message deals **sealed half-points**, the user half already evaluated at the sighash of each transaction of a conflicting fee grid. A finished signature is `user half-point + committee half-point`, an ordinary single-key BIP340, Ed25519 or ECDSA signature.

**The one idea.** A half-point is useless alone and linear to complete. Because the final signature is a sum of two points on two half-lines, three things follow at once.

1. *Co-custody without interaction.* The user computes its half offline from public committee nonces. The committee adds its half with one linear partial per node, as in SCHEME §3.8. No multiplication, no Paillier and no class group runs at signing time.
2. *The sealed guarantee survives for the user's half.* A committee that is corrupt in full holds `x_f` and the dealt half-points. It completes the variants the user sealed and nothing else, because every other message needs another point of the user's half-line, and the user never dealt the line (Claim S2).
3. *Blind co-signing.* The committee half of a Schnorr signature needs the challenge `c` and a nonce binder. The committee half of an ECDSA signature needs the sighash `h`. A node signs a **ticket** of a few scalars and one fresh point with its share of the root key `x_f`; every address-specific term sits in the user's half. On the Schnorr suites a node never sees the address, the owner, the intent or the covenant. On Ethereum it never sees the owner, the intent or the covenant, and it does know which account a slot belongs to. Midnight proves in zero knowledge that the ticket's scalar is the sighash challenge of a transaction the charter admits. The committee checks a commitment and a ledger entry.

**How R1 is read.** R1 means: *no valid spend exists unless one authorization source that the asset's charter admits contributes its own key element and the admission is recorded on Midnight; the committee holds no element of any source.* The three sources of R4 are three element holders. (a) The holder's wallet holds `x_u`. (b) The charter's guardian set (issuer, regulator, court trustee; a threshold among parties who are not committee operators) holds a line-dealt escrow of `x_u`, made at birth and publicly checked. (c) The exit record is a sealed committee half-signature on one timelocked sweep to the owner's standing exit address. All nine nodes together hold none of these. A seizure moves funds without the owner and never without the guardians.

**Two modes, one protocol.** The cryptographic protocol is the same in both modes. The request travels as an opaque **envelope** whose keys are line-dealt to the committee with threshold `t = n − f` (7 of 9), so it opens only when `t` nodes release shares, and they release only after a quorum certificate fixes its order.

- **Non-TEE mode** is that protocol and nothing else. Midnight verifies a proof that every ticket is well formed (a small-field STARK over the sighash computation, wrapped once in BLS12-381). A node operator sees blinded scalars after ordering and the host transaction at release.
- **TEE mode** runs the same node inside a Veritee confidential VM. Every node key lives in the enclave and is attested, so a single operator sees ciphertext only. At launch (v1) the enclave recomputes the sighash from the opened intent and the Midnight proof covers the charter predicate alone; the ticket proof of the non-TEE mode plugs into the same check later (v2) with no change of message format, state machine or key model.

The TEE is therefore an addition to a threshold-cryptographic base. A broken TEE at fewer than `t` nodes costs those operators' blindness on requests already ordered. It costs no signature, no early decryption and no key.

**What it does not do.** A holder who colludes with `t` nodes holds the whole key, so covenant enforcement (R4) is a threshold guarantee; no native single-key output avoids this. An exit certificate, once matured, lets the holder sweep to the exit record without the network, so a legal hold binds only until the certificate's horizon and binds a coin older than `Δ_exit` not at all, unless the guardians seize first; a charter that needs strict holds turns certificates off and gives up the exit path. Ethereum needs an interactive birth session per account and a refill when its slots run out; the two sub-protocols of that session are specified by their interface and their instantiation is open (§10). Host-chain graph analysis of a coin's own history is outside the protocol.

## 2. Key and address model

### 2.1 Who holds what

| Element | Holder | Form | Lifetime |
|---|---|---|---|
| Committee root key `x_f`, `X_f = x_f·G` (one per suite curve) | committee | Shamir, `t = n − f`, Feldman commitments on the board | permanent; reshared at every rotation, constant term fixed |
| Address tweak `δ` | public | `δ = Hq_addr(X_f ‖ U_a ‖ cov_id ‖ idx)` | per address |
| User element `x_u` | the holder's wallet | one scalar per address | per address |
| Address key `x` | nobody | Schnorr suites `x = x_u + x_f + δ`; ECDSA `x = x_u·(x_f + δ)` | per address |
| Escrow of the user half | guardian set of the charter (`t_g` of `n_g`, disjoint from committee operators) | SCHEME open mode with the guardians as committee: `Share_{t_g}(x_u)` and `G_g` nonce pairs (Schnorr suites), or the half-lines `(w_u, μ_u)` of `G_g` reserved slots (ECDSA) | per address, covenanted assets only |
| Committee nonce slots `(d, e)`, `D = d·G`, `E = e·G` | committee | Shamir, `t`, each the sum of `t` dealers' polynomials; RAM only | per epoch, single use; shared by all addresses |
| ECDSA split lines `(w_u, μ_u)` / `(w_f, μ_f)` per slot | user / committee | scalars / Shamir `t` | per EOA slot, single use |
| Exit certificate | user | finished timelocked signature (Bitcoin) or time-locked committee partials (Ethereum, Solana) | until `Δ_exit` after issue |
| Node keys `PK_i` (share encryption), post key, channel key | node `i` (in TEE mode: the enclave) | per epoch and boot | epoch |

No row gives the committee a value the user holds, and no row gives any single party `x`.

### 2.2 Committee root key

The committee runs one DKG per suite curve at genesis. Each node deals one random polynomial of degree `t − 1` with the dealing, ACK and complaint machinery of SCHEME §3.4 (labels `SL1/dkg-*`); the qualified set is the first `t` dealers in board order with no valid complaint; `x_f` is the sum of their constant terms. Each dealer attaches a proof of knowledge of its constant term. `X_f` and the share commitments `X_{f,i}` are public.

### 2.3 Birth of an address

An address belongs to a **receive key** `U = u·G` that the holder registers once on Midnight in shielded form **[assumed: a Compact contract `FenrirAssets` with a shielded Merkle tree of asset records]**. Two birth paths exist.

- *Wallet-supplied element.* The wallet picks `x_u`, sends `X_u` and a proof of possession. `U_a = X_u`.
- *Network-created address.* A payer, an issuer or the committee creates an address for a holder who is offline. The creator picks `e`, posts `E_a = e·G` encrypted to the holder on Midnight, and sets `U_a = U + Hq_st(e·U)·G`. Only the holder computes `x_u = u + Hq_st(u·E_a)`. `E_a` is "the element the user needs to start spends" of R3: the committee and the creator know `U_a` and never `x_u`. A change address is born the same way inside the spend that creates it, from a fresh `e` in the user's message.

Then, for the Schnorr suites, `X = U_a + X_f + δ·G`. The tweak depends on `U_a`, so a chosen `U_a` cannot cancel `X_f`. No DKG runs per address, and no node stores anything per address: a node always signs with its root share `x_{f,i}`, and the wallet adds `c·(δ + τ)` to its own half-point (`τ` is the taproot tweak, zero elsewhere). BIP340 parity: when `X` or `Q` has odd y the whole key is negated; the wallet negates its own terms and folds the sign `g ∈ {1, −1}` of the committee term into the ticket by sending `g·c` as the challenge, so a node needs no parity information.

A holder registers one receive key per charter, so that an escrow of `u` under one charter exposes nothing about addresses under another.

| Chain | What the chain sees |
|---|---|
| Bitcoin | P2TR only. Output key `Q = X + Hq_TapTweak(X)·G`, the BIP341 key-path-only form; the wallet adds the tweak term to its own half-point. No script path exists. A spend is one BIP340 signature. Network-created Bitcoin addresses are never P2WPKH; P2WPKH stays available for imported keys under unchanged line dealing. |
| Solana | An ordinary account whose key is `X` on edwards25519 (prime-order subgroup). A spend is one Ed25519 signature. The pin is a durable nonce account whose authority is `X`. |
| Ethereum | An EOA with `address = Keccak(X)[12..32]`, `X = x_u·(X_f + δ·G)`. A spend is one type-2 transaction with one ECDSA signature. No contract account. |

**Ethereum birth session.** ECDSA is not linear in the nonce, so the split is made in advance. One interactive session per EOA (three rounds, user online; the brief allows setup interaction at address creation) produces `N` slots (launch `N = 32`). Per slot:

1. The committee holds a threshold-ECDSA presignature for the key `x_f + δ`: a point `R_f = k_f·G` and Shamir shares of `φ = k_f⁻¹` and `ψ = k_f⁻¹(x_f + δ)`, with Feldman commitments in base `R_f` whose constant terms are `G` and `X_f + δ·G`. This is functionality `F_presig`. Its instantiation is open: the quadruple protocol of ePrint 2022/506 (read in full by this project, `design/notes-2022-506.md`) realizes it at `t = f + 1` only, which would lower the Ethereum key threshold to 3 of 9; a dishonest-majority protocol is needed for `t = n − f`, and none has been read in full (§10).
2. The user picks `k_u`, sets `a = k_u⁻¹`, `b = a·x_u`, `R = k_u·R_f`. The slot's line is `w = a·φ`, `μ = b·ψ`.
3. The user and each node `i` run two two-party multiplications, functionality `F_mul` (inputs one scalar each, outputs an additive sharing of the product; instantiation open, §10): `a·φ_i = c_i + d_i` and `b·ψ_i = c'_i + d'_i`. The user picks polynomials `P, P'` of degree `t − 1` with `P(0) = w_u`, `P'(0) = μ_u`, and sends node `i` the corrections `d_i − P(i)` and `d'_i − P'(i)`. Node `i` now holds `w_{f,i} = a·φ_i − P(i)` and `μ_{f,i} = b·ψ_i − P'(i)`.
4. Public check, no proof system: `a·φ_i·R = φ_i·R_f`, so `w_{f,i}·R = Eval(Φ, i) − Eval(Com_R(P), i)` where `Φ` is the committee's commitment to `φ` in base `R_f`. The implied constant terms satisfy `W_u + W_f = G` and `M_u + M_f = X` in base `R`. For `μ` the user publishes `x_u·Ψ_k` for each coefficient commitment with one batched DLEQ against `(X_f + δ·G, X)`. A node whose share fails posts a complaint and the slot is dropped.

After the session the user holds `(w_u, μ_u)` per slot and the committee holds Shamir shares of `(w_f, μ_f)`. Signing is linear: `s = (w_u·h + μ_u·r) + (w_f·h + μ_f·r)`. A refill is another session; when the slots run out and the user cannot come online, the account still exits through its certificate.

### 2.4 Guardian escrow (source b)

A charter that admits seizure names a guardian set `Γ` with keys registered on Midnight. At birth the holder (or, for a network-created address, the holder once per receive key, with standing consent recorded on Midnight) posts an **escrow dealing**. It is SCHEME open mode unchanged, with `Γ` as the committee and the user half as the dealt key:

- Schnorr suites: `Share_{t_g}(x_u)` with implied constant term `U_a` (for the stealth path the holder deals `u` once and the tweak `Hq_st(e·U)` is disclosed to the guardians), plus `G_g` two-nonce pairs.
- ECDSA: the half-lines `(w_u, μ_u)` of `G_g` reserved slots of the birth session, with commitments in base `R_ℓ` and implied constant terms `W_u`, `M_u`. The escrow of `x_u` alone would be useless on Ethereum, because the user's ECDSA half is the per-slot line, not the key.

The guardians ACK on the board. The asset record on Midnight is valid only with an escrow ACK quorum of `Γ`. A non-covenanted asset has no escrow and cannot be seized by anyone. Launch `G_g = 4`.

Guardians are online parties. For a seizure they prove the legal order or the default terms in the Midnight authorization, each posts one linear partial of the user half-point for each ticket (SCHEME §3.8 with the guardians' own lock certificate), and their combiner deals the resulting half-points in an ordinary envelope. They never hold `x_f`, and `t_g − 1` of them learn nothing about the user half.

### 2.5 Exit and recovery (source c, R5)

The **exit record** is the owner's standing sweep address, committed in the asset record. Changing it is a Midnight transaction with a charter delay and the approvers' veto.

- *Bitcoin.* An exit certificate is an ordinary spend request whose single variant sweeps the pinned outpoint to the exit record with `nLockTime = issue height + Δ_exit`. The committee co-signs it at once and the capsule (§3) is addressed to the user, who keeps the finished signature. For a self-funded deposit the user obtains the certificate before broadcasting the funding transaction, because the outpoint is known from the unsigned funding transaction.
- *Ethereum and Solana.* These chains have no transaction-level timelock, so the time lock must sit on the committee's half. The design point is: each node encrypts its exit partial to a public time-release service for the time `issue + Δ_exit`, the user stores the `n` ciphertexts, and after that time any `t` open. The candidate service is tlock on the League of Entropy beacon; it is **open** until the paper is read in full (§10), and until then Ethereum and Solana have no exit path. A new certificate is issued after every spend, because the account nonce or the durable nonce changes.

While the committee lives, the holder renews the certificate whenever it is online; each certificate matures at its own horizon. If Fenrir disappears, the holder waits for the last horizon and sweeps to the exit record. Nothing else is recoverable without the committee, and that is the intended reading of R2.

**Position on legal holds.** A live hold makes every authorization of sources (a) and (c) fail on Midnight, so the committee signs nothing for the holder and issues no certificate. A certificate already issued still matures, and a matured certificate never expires: no host chain revokes a signed transaction except by spending its input. Three consequences are stated plainly.

1. A hold binds a coin until its outstanding certificate matures, and a coin whose certificate has matured is not bound at all. The holder can sweep it to the exit record without the network.
2. The sweep pays the exit record and nothing else, and the exit record changes only with a charter delay and the approvers' consent. A matured certificate is therefore source (c) exercised in advance, not a bypass of the charter's destinations.
3. A hold that must bind is executed by the guardians as a seizure into a hold address (source b), at once when the certificate has matured and otherwise before its horizon. A charter that cannot accept this race sets `exit = off`: no certificate is issued, holds bind without limit, and R5's exit path does not exist for that asset.

The charter sets `Δ_exit`; the launch value is 26 weeks.

### 2.6 Rotation

`ROTATE(e → e+1)` reshares `x_f` (and the unspent ECDSA slot shares) to the new committee with the transfer step of SCHEME §5 run at epoch level, not per request, with one change. SCHEME allows resharing at `t = f + 1` only, because a new node that received a bad sub-share and was slow to complain is then not needed. At `t' = n' − f'` every honest new node is needed, so the handover adds a complaint window of fixed board length after the last dealing: a dealer with a valid complaint leaves the candidate set, and `HANDOVER` is declared only when `n' − f'` new nodes post READY for the same set. The old committee keeps signing until then, and a handover that does not complete leaves the old committee in place. Constant terms do not change, so no address changes and no coin moves. This step has no proof (Claim S9). Nonce slots are discarded and regenerated. Envelopes in flight carry `on_rotation ∈ {finish, void}` as in profile T2.

## 3. Spend flow

### 3.1 Objects

- **Slot.** A committee nonce pair `(D_ℓ, E_ℓ)` with Shamir shares `(d_{ℓ,i}, e_{ℓ,i})`, each the sum of the polynomials of `t` dealers, so that one honest dealer hides it from any coalition below `t`. Slots form one public pool for all addresses. A wallet picks unused slot ids at random from the pool, and `authorize` publishes them as **slot claims**; Midnight rejects a claimed id. A slot id is a counter and says nothing about the address.
- **Ticket.** What a node signs. Schnorr suites: `tk = (ℓ, R_u, pm, c)`, where `R_u` is the user's fresh nonce point and `pm = H_pm(Q ‖ m ‖ salt)` hides the address key and the sighash. ECDSA: `tk = (ℓ, h)`. Plus selection data: `fee_rate`, `not_before`. Tickets live in the header and are seen by nodes only, never on the board.
- **Envelope.** `Env = pub ‖ deal ‖ ct ‖ body_0 ‖ body_1..K ‖ π`.
  - `pub`: version, suite class, epoch, `keylist_hash`, expiry, a size class (envelopes are padded to one of four sizes) and `auth_ref`, the Midnight authorization commitment. Nothing else is in clear.
  - `deal`, `ct`, `π`: a line dealing in the sense of SCHEME §3.2 of `K + 1` scalars with threshold `t = n − f`: the **header point** `κ_0` (random) and the **sealed half-points** `s_{u,1..K}`. Commitments include the constant terms explicitly, because a blind node cannot recompute them. `π` is the ephemeral-key proof and an authorship proof of knowledge of `κ_0`.
  - `body_0 = AEAD(KDF(κ_0), header)`: the tickets, and in TEE v1 also the opened intent.
  - `body_j = AEAD(KDF(s_{u,j}), capsule_j)`: the transaction bytes of variant `j`, its nonce point `R_j`, and the destination of the result (broadcast, or return to the user for an exit certificate). The half-signature is the key of its own capsule.
- **Authorization** on Midnight **[assumed interface]**: `authorize` is a Compact circuit of `FenrirAssets`. Private inputs: the asset record and its Merkle path, the intent, the source tag, the witnesses the charter asks for (intent signatures of every principal for source a; the order or default proof and guardian signatures for source b; the exit record opening for source c), approver signatures, non-membership in the hold and blacklist accumulators. Public outputs: `auth = H(ic ‖ hd ‖ tkc)`, the slot claims, and a nullifier over (asset, pin). `ic` commits to the intent and the address, `hd` is the dealing digest, `tkc` commits to the ticket list. The source tag is private, so the three sources are indistinguishable on Midnight and on the board.

### 3.2 The owner's one move

Inputs the wallet reads beforehand, all public: the epoch key list, the slot pool with its claims, `X_f`.

For each variant `j = 1..K` of `Variant(intent, j)` (SCHEME §4, unchanged):

- *Schnorr suites.* Pick `k_u`, `R_u = k_u·G` and a salt. `pm = H_pm(Q ‖ m_j ‖ salt)`, `ρ = Hq_bind(ℓ_j ‖ R_u ‖ pm)`, `R = R_u + D_ℓ + ρ·E_ℓ` (with the sign `σ` of SCHEME §3.8 for BIP340 parity), `c = suite challenge(R, Q, m_j)`, `s_{u,j} = σ·k_u + c·(x_u + δ + τ)` (signs for parity as in §2.3). The ticket is `(ℓ_j, R_u, pm, g·c)`. `ρ` is a hash of values that fix `R`, `Q` and `m`, hence `c`; this is the binding that defeats a ROS or Wagner search across open slots, and it needs no curve arithmetic inside any proof: the node recomputes `R` from the ticket, and the proof takes `R` as an input.
- *ECDSA.* `h = m_j`, `r = x(R_ℓ)`, `s_{u,j} = w_u·h + μ_u·r` on slot `ℓ_j`. The ticket is `(ℓ_j, h)`.

The wallet deals `κ_0, s_{u,1..K}`, encrypts the bodies, builds the Midnight `authorize` transaction and posts both. Then it is offline. The move is one message to the board and one transaction to Midnight, prepared together; if a slot claim collides with another wallet's claim made in the same interval, the Midnight transaction fails and no state changes; the wallet draws from a pool of thousands, so this is rare.

### 3.3 Committee steps

```
(unseen) -> ORDERED -> OPENED -> ARMED -> per generation: ANCHORED -> RELEASED(j) -> FINAL
                                       -> VOID / EXPIRED            (tombstones as in SCHEME §3.5)
```

1. **Order.** The board orders `Env` by its digest. Nodes run the public checks of SCHEME §3.4 that need no content (encoding, points, `π`, epoch), the private share check, and post `ACK` or a complaint. `q` ACKs and the quorum certificate make the envelope ORDERED.
2. **Open.** Only now does each node send its share of `κ_0` to the other nodes over node-to-node channels (not on the board). `t` shares open the header. The envelope is OPENED when `q` nodes post `OPENED(eid, H(header))`.
3. **Admit.** Each node checks that `auth` is in Midnight's finalized state and that the header opens `tkc`, that each Schnorr ticket's `R` equals `R_u + D_ℓ + ρ·E_ℓ` for the `ρ` it recomputes (and, in TEE v1, that the tickets equal the sighash challenges it recomputes from the opened intent, and that `ic` opens to that intent). It checks that every slot of the tickets is among the slot claims of this `auth` and is unused in its ledger. Failure by `f + 1` nodes voids the envelope. Success by `q` arms it.
4. **Anchor and select.** As SCHEME §3.6–3.7 with the eligibility that the mode can see (§3.5 below): `j_g = Select(...)` on the disclosed fee rates.
5. **Release.** Each node writes `(ℓ_j → tk_j)` to its durable slot ledger, then computes its committee partial and sends it, with its share of `s_{u,j}`, to the combiner set over node-to-node channels:
   - Schnorr: `s_{f,i} = σ·(d_i + ρ·e_i) + c̃·x_{f,i}` with `c̃ = g·c` from the ticket; check by others `s_{f,i}·G = σ·(D_i + ρ·E_i) + c̃·X_{f,i}`. The partial contains no address-specific value.
   - ECDSA: `s_{f,i} = h·w_{f,i} + r·μ_{f,i}`; check by others in base `R_ℓ` as in SCHEME §3.8.
   It then erases the nonce shares. The board gets `RELEASED(eid, g, j, H(partial))` from each node, which fixes the evidence for slashing without publishing the partial.
6. **Combine.** Any node with `t` shares of both halves interpolates `s_{u,j}` and `s_f`, opens `capsule_j` with `KDF(s_{u,j})`, forms `s = s_{u,j} + s_f`, verifies the signature against the transaction in the capsule, and broadcasts or returns it. `f + 1` `FINAL` posts set the tombstone.

There is no lock round: a sealed ticket fixes the message before any share exists, so one digest per slot holds by the ledger rule alone, as in sealed mode today.

### 3.4 Covenants, approvers, seizure, freeze, hold

| Action | Who authorizes | What Midnight proves | What the committee does |
|---|---|---|---|
| Payment (a) | every principal of the charter, by intent signatures; approvers by signature or veto | effect admitted, recipients are Fenrir-born addresses carrying `cov_id` or allowed exits, no hold, no blacklist hit | co-signs the tickets |
| Seizure, reversal of stolen funds (b) | `t_g` guardians, who supply the user half from the escrow | a legal order or the default terms named in the charter | the same; the envelope is indistinguishable from (a) |
| Exit (c) | the holder | the variant pays the standing exit record, no hold | co-signs; certificate returns to the holder |
| Freeze, blacklist | the authority named in the charter | sets the hold or blacklist accumulator | nothing; `authorize` fails, so no envelope arms |
| Veto | named approver | `authorize` requires the approver's signature, or the absence of a veto entry | nothing |

The holder cannot bypass a covenant, and neither can a thief of the wallet: `x_u` alone signs nothing, and the committee half needs an armed envelope. The covenant follows the asset because a payment under (a) is admitted only to an address born under the same `cov_id`, on the same chain or through a bridge leg whose far address is Fenrir-born.

### 3.5 Line dealing's variants in the new design

- **Sealed variants** are the default and are unchanged in meaning: a fee grid of conflicting transactions on one pin, selection by the committee, replacement by a higher variant.
- **Open user leg** (the user deals its half-*line*) exists as a charter option `open_ok`. It restores committee-side construction, and it gives `t` nodes the whole key of that address. An asset with `open_ok` meets R1 at the threshold only; no covenanted launch asset sets it.
- **One-move channel.** Its states are sealed half-points on a common pin; the channel logic does not change.
- **Imported keys.** An existing address whose owner holds `x` uses line dealing as specified today, inside the same envelope for blindness. It does not meet R2 and is not offered for covenanted assets.

## 4. Blindness

### 4.1 What the board carries

The board orders and stores: envelope ciphertexts in four padded size classes; `pub` (suite class, epoch, expiry, `auth_ref`); node posts `ACK`, `OPENED`, `OBS`, `RELEASED`, `FINAL`, each naming an envelope id and a hash; slot batches; rotation records. Every post is signed by a registered post key, so equivocation, a false ACK and a partial that does not match its `RELEASED` hash are provable to anyone, and slashing needs no plaintext: a node's partial is checked against public share commitments (`X_{f,i}`, `D_i`, `E_i`, the dealing's Feldman commitments) by whoever holds the opened header, and that party publishes the one failing ticket as evidence.

The board never carries an address, a public key of an address, an amount, a recipient, a sighash, a nonce point that appears on a host chain, a partial signature, or a link to a Midnight asset record. `auth_ref` is a hash output of a shielded Midnight transaction.

### 4.2 Decryption after ordering (B3)

The header key is the line-dealt point `κ_0` with threshold `t = n − f`. An honest node releases its share of `κ_0` only after the quorum certificate for the envelope's position exists in its own view of the board, and it sends the share to nodes, not to the board. Fewer than `t` nodes hold fewer than `t` shares of a degree-`t − 1` polynomial and the hashed-ElGamal ciphertexts of the others (ICDH, SCHEME Theorem C), so they learn nothing about `κ_0` before ordering. At launch `f = 2 < t = 7`; at `n = 17`, `f = 5 < t = 12`. This is dealer-based threshold encryption: it needs no committee encryption key, no pairing and no DKG, and the complaint rule of line dealing makes a malformed envelope void in public.

The capsule of variant `j` opens only with `s_{u,j}`, which nodes release at step 5 for the selected variant alone. Unselected variants stay sealed below `t` as in SCHEME Claim 3.

### 4.3 What each party sees, per step

| Step | Observer of board and Midnight | Operator, TEE mode | Operator, non-TEE mode (its own node's view) |
|---|---|---|---|
| Midnight `authorize` | a shielded transaction, a commitment, a nullifier | same | same |
| Envelope posted | size class, suite class, epoch, expiry | same, plus arrival time and network peer | same |
| Order, ACK | which nodes ACKed | same | one share of each dealt scalar; nothing readable |
| Open | that the envelope opened | traffic volume between enclaves | the header: slot ids, `R_u`, `pm`, `c` or `h`, fee rates, `not_before` |
| Admit, anchor | OBS heights | egress destination names (chain and Midnight endpoints) | as above; in v2 nothing more |
| Release | that variant `j` of some envelope was released | traffic | its own partial; if it is in the combiner set, the capsule: the host transaction and `R` |
| Host inclusion | the host transaction, public | same | same, and the link from envelope to host transaction |

In non-TEE mode an operator therefore never sees the owner's identity, the receive key, the intent beyond the released transaction, the unselected variants, the covenant terms, the authorization source or the approvers. On the Schnorr suites it also sees no address before release, because the ticket and the partial are address-free. On Ethereum the slot id names a birth session, and the nodes checked that session against the account key, so an operator knows which account an opened envelope spends. It sees the released host transaction shortly before the chain does (B6 allows this) and can link it to an opaque envelope. In TEE mode it sees none of this.

### 4.4 Nothing to select by (B2)

Before ordering every envelope is a padded ciphertext with a suite class and an expiry. The posting fee is paid inside the shielded Midnight transaction, so no payer shows. After ordering a node can refuse to release, and `f` refusals do not stop the `n − f ≥ t` honest nodes. A node that withholds after ACK is identified by its missing `RELEASED` post.

### 4.5 Unlinkability (B5)

- *Address to owner.* A network-created address is `U + Hq_st(e·U)·G + X_f + δ·G`; without `u` or `e` it is unlinkable to `U` and to every other address of the same holder. The asset record on Midnight is shielded.
- *Egress to deposit, inside Fenrir.* The envelope names no input (on Ethereum the opened header names the account to nodes, not to observers). Midnight's nullifier is derived from the asset secret and the pin and is unlinkable to the note that recorded the deposit.
- *Customer or institution.* Payment, seizure and exit use one envelope format, one ticket format and one `authorize` circuit with a private source tag. A guardian-made envelope and a wallet-made envelope are the same bytes in distribution.
- *Limit.* The host chain shows which coin a transaction spends. A Bitcoin spend is linked to the transaction that funded that outpoint by the chain itself. The protocol adds no link and removes none; breaking that link needs a pooled egress service, which this proposal does not specify.

### 4.6 Blindness and enforcement together

The party that evaluates a covenant predicate is the prover of `authorize` (the wallet, or the guardians), and the party that checks it is Midnight. The committee checks set membership of `auth` and the opening of `tkc`. The link from "the charter admits this effect" to "this scalar is what the node signs" is closed in one of two ways with the same interface `ticket_ok(header, auth)`:

- **v1, TEE mode.** The header carries the opened intent, the address key and each `R`. The enclave recomputes `Variant`, the sighash, `pm` and `c`, and checks that `ic` in `auth` opens to this intent. `authorize` is then a small Compact circuit over the charter predicate.
- **v2, both modes.** `authorize` also proves, for each variant: `m_j = sighash(Variant(intent, j))`, `pm_j = H_pm(Q ‖ m_j ‖ salt_j)`, `c̃_j = g·suite challenge(R_j, Q, m_j)` for a private sign `g` (ECDSA: `h_j = m_j`), with `(ℓ_j, R_j, pm_j, c̃_j)` committed in `tkc`. The statement is hashing only: SHA-256 for Bitcoin, Keccak-256 and RLP for Ethereum, SHA-512 for Solana; there is no curve arithmetic in it. The wallet proves it as a small-field STARK and wraps it once in BLS12-381 for Midnight. One Taproot variant costs about twelve SHA-256 compressions; a grid of eight stays far below `2^21` rows before the wrap (estimate, not measured).

A node in v2 never needs the intent. A deployment runs v1, then v1 and v2 together, then v2 alone, by a header version flag.

## 5. Veritee integration (TEE mode)

### 5.1 Components used as they are

| Veritee component | Use |
|---|---|
| SEV-SNP confidential VM, dm-verity root, UKI measured in PCR4 | isolation of the node's memory from the operator; code identity of the OS |
| App disk measured into PCR15 (`measured_setup/main.py`) | code identity of the Fenrir node image |
| Raw SEV-SNP evidence path (`raw-report` build, `report_data = SHA256(JSON{nonce, payload})`) | binds node keys to the VM (§5.2); the MAA path is not used, so Microsoft Azure Attestation leaves the trust base |
| `akx` crate: transcript hash, HPKE session, AES-GCM record layer | node-to-node channels, linked as a library into the node (§5.2) |
| Measured egress proxy with an allowlist | confines the node to peers, Midnight endpoints and host-chain endpoints |
| Warden registration on Midnight | publishes each node's measurements and keys; the wallet and the peers read the key list from Midnight |
| `internal` TLS mode (CA generated in the VM, committed to PCR15) | the only TLS mode allowed |

### 5.2 What Veritee lacks and what this design adds

1. **A static, attested, application-held encryption key.** Veritee's only attested long-lived key is the Ed25519 `pk_e` of the host attestation server; recipient keys are interactive and die after 300 s; plaintext reaches the app over loopback. The owner's move is offline, so this cannot carry it. *Addition:* the node process generates inside the VM, at each boot, its share-encryption keys `PK_i` (one per suite curve), its post key and a static X25519 channel key. It obtains raw SNP evidence over a new local-only route (a Unix socket of the attestation server, not reachable through Caddy) with `nonce = "fenrir-node-key-v1"` and `payload = H(board_id ‖ epoch ‖ node_id ‖ boot_seq ‖ keys ‖ latest finalized Midnight block hash)`. The Midnight block hash makes the evidence fresh without a challenger. The owner encrypts shares to `PK_i` exactly as SCHEME §3.2 does; the key simply lives in an enclave now.
2. **Closing the attestation oracle.** Today any caller of `GET /tee_attestation` gets evidence over a payload of its choice, including the constant akx nonce. *Addition:* the public route rejects every nonce with the prefixes `fenrir-` and `temenos-akx-`; **[assumed]** Warden accepts a node-key record only with the reserved nonce and records `(node_id, boot_seq, key hash, PCR4, PCR15, TCB, vmid)` on Midnight.
3. **Mutual node-to-node channels that end in the node.** akx authenticates the server only and terminates in the host process. *Addition:* both ends sign the akx transcript with their registered post keys, and the HPKE recipient key is held by the node process.
4. **Attestation-gated key provisioning across reboots and redeploys.** Veritee has none; Key Vault releases to a managed identity, not to a measurement, and a redeploy starts with an empty disk. *Addition:* **share repair.** A node that boots registers fresh keys, then asks its peers for its share of `x_f` (and of unspent ECDSA slot shares). A peer answers only a requester whose current registration on Midnight carries an approved measurement and the highest `boot_seq` for that `node_id`; `t` peers each send a degree-`t − 1` sub-sharing evaluated at the requester's index, masked so that the requester learns its own share and nothing else. Reboot, redeploy and image upgrade are one path. Azure Key Vault holds no Fenrir secret.
5. **Sealed storage, for disaster recovery only.** If more than `n − t = 2` nodes lose memory at once, repair is impossible. *Addition:* each node keeps one sealed copy of its `x_f` share: the persist partition becomes LUKS2 with dm-integrity, its key sealed to the vTPM under a policy on PCR4 and a new PCR14 that `measured_setup` extends with the app root hash alone (PCR15 changes at every boot in `internal` TLS mode and cannot carry a sealing policy). After unsealing, the node extends PCR14 with a terminator so nothing started later can unseal.
6. **Rollback and clone protection.** Veritee has no monotonic counter; an operator can restore or fork the persist disk. The design removes what a rollback could revive.
   - Nonce shares, envelope shares, header keys and half-point shares live in locked RAM only. A reboot or a restored disk has none of them, so a rolled-back node cannot sign a slot twice.
   - The sealed `x_f` share does not change inside an epoch, so an old copy equals the current one; a copy from an earlier epoch is useless after `t` honest nodes erased that epoch.
   - Freshness of everything else comes from the board: a booted node replays to the highest committed position among `q` peers before it posts (SCHEME §3.9 rule 4), and peers repair only slots their own ledgers show unconsumed.
   - A clone has the same measurement. Only the registration with the highest `boot_seq` is live, the peers hold channels to one key per `node_id`, and a second live key for one `node_id` is slashing evidence against the operator.
7. **Erasure.** Veritee has no `zeroize`. *Addition:* every secret type zeroizes on drop, memory is `mlock`ed, swap and core dumps are off in the measured image, and erasure points are those of SCHEME §3.10.
8. **Measured image hygiene.** The packaged MPC node uses the `unrestricted` egress profile and no `proxy_allowed_paths`; the release sets a measured allowlist. Debug images, `azure_vault` TLS and the PCR15-failure override are rejected by measurement. PCR0–3 and the SNP fields are pinned from an independent rebuild, not hydrated from the operator's first deployment; `require_reproduced_os` is on **[assumed: Warden can enforce both]**.
9. **Side-channel floor.** Envelopes are padded to size classes, nodes answer on board ticks, not on arrival, and scalar code is constant-time.

### 5.3 What an operator who controls the Azure host can still do

- Stop, delay, restart or delete its node, and cut or shape its network. This is the `f` budget of liveness.
- See ciphertext sizes, timing, peer addresses and egress destination names; correlate an envelope's arrival with a later host transaction by timing, within the batching window.
- Snapshot, restore or clone the VM and its disks. It obtains a sealed share ciphertext and no usable state; a clone is detected as in 5.2 item 6.
- Deploy another image. Its measurement differs; peers and Warden reject it.
- Mount attacks on SEV-SNP itself or exploit the Azure paravisor, which is in the trust base. Success puts that one node in the non-TEE mode's position: it reads headers after ordering and its own shares. It does not obtain a signature, an early decryption or `x_f` below `t` nodes.
- Refuse to register. The node is then out of the committee.

It cannot read enclave memory, cannot obtain a node key, cannot make the node sign outside an armed envelope, and cannot learn which request it is delaying.

## 6. Security claims

Notation: `C` the set of corrupt nodes, `b ≤ |C|` the Byzantine ones. In TEE mode a node is corrupt when its enclave is broken *and* its operator is malicious; an operator with an intact enclave is a network adversary. Static corruption, as in SCHEME.

**S1. Address binding.** *Both modes, any corruption.* An accepted birth yields a key `X` such that every released sum of a valid user half-point and a valid committee half-point verifies under `X`. Proof: direct calculation, as SCHEME Claim 1; for ECDSA the constant terms satisfy `W_u + W_f = G` and `M_u + M_f = X` in base `R`. Status: direct.

**S2. Sealed user half, all nodes corrupt (R1).** *Both modes; `|C| = n`; TEE broken; guardians honest.* The adversary holds `x_f`, every nonce, every header and every half-point of every envelope of an address. It outputs no signature under `X` on a message outside the sealed variants. Schnorr suites: reduction to unforgeability of the suite scheme under the key `X_u` in the random oracle model. The reduction gets `X_u`, picks `x_f` itself, and answers each sealed variant with a signing query that returns `(R_u, s_u)` for a challenge it programs at `(R_u + R_f, Q, m)`; `R_u` is fresh, so the point is unqueried except with negligible probability. A forgery `(R', s')` on a new message gives `s' − c'·(x_f + δ + τ)`, a forgery under `X_u`. ECDSA: one point per slot on a half-line with two unknown coefficients; reduction to ECDSA with single-use presignatures (ePrint 2021/1330 Theorem 3) with the committee's view simulated from `(w_f, μ_f)` chosen by the reduction. Status: Schnorr sketched and close to SCHEME Theorem D; ECDSA open until the birth protocol's leakage is bounded.

**S3. No spend without a source element (R1, R2).** *Both modes; `|C| = n`.* Without `x_u` (the holder), `t_g` guardian shares, or a matured exit certificate, no signature under `X` exists. Follows from S2 with zero sealed variants and from the hiding of the escrow dealing below `t_g` (SCHEME Theorem C applied to the guardian keys). Status: follows.

**S4. No spend without the committee (R2).** *Both modes; `|C| < t`, `b ≤ f`; holder and guardians corrupt.* The adversary holds `x_u` and at most `t − 1` shares of `x_f`. It obtains a signature only on a ticket that `q` nodes armed, apart from matured exit certificates. Every slot sums `t` dealers, so at least one dealer is outside `C` and the slot's nonces are hidden from `C`. Schnorr: the committee half is a two-nonce threshold Schnorr signer whose binder `ρ` hashes values that determine `(R, Q, m)`; this is the single-signer game of SCHEME Theorem B with the key `x_f + δ + τ` and the adversary supplying an additive nonce and key share; AOMDL, random oracle model. ECDSA: SCHEME Theorem A on the committee half-line, with the user half known to the adversary. Status: sketched; the additive adversarial share needs a written proof (it is the MuSig2 setting with one honest signer).

**S5. Covenant enforcement (R4).** *Both modes; `|C| < t`, `b ≤ f`; holder corrupt; Midnight sound.* Every signature released under `X` is on a message whose effect `authorize` admitted. v1: `q − f` honest enclaves recomputed the challenge from an intent that opens `ic`. v2: soundness of the wrapped proof gives `c = suite challenge(R, Q, m)` for an admitted `m`, and collision resistance of the challenge hash excludes a second message for the same `c`; a Wagner search over many tickets is excluded because each `ρ` is fixed by a hash of values that determine its `c`. *Fails* when `|C| ≥ t` with a corrupt holder: they hold `x`. In TEE mode v1 it fails when `t` enclaves are broken; in v2 it fails only when `t` nodes are corrupt, with or without TEE. Status: sketched.

**S6. Sealed before ordering (B3).** *Both modes; `|C| < t`.* Before an honest node sees the quorum certificate the adversary learns nothing about the header beyond `pub`. ICDH and the random oracle model, SCHEME Theorem C and D. In TEE mode the bound is on broken enclaves, not on operators. Status: reduces to existing theorems.

**S7. Operator blindness (B1, B2).** *TEE mode, enclave intact:* an operator's view is simulatable from sizes, timing and public board posts; assumption: SEV-SNP confidentiality, the measured image, IND-CCA of HPKE. *Non-TEE mode:* an operator's view is `pub`, its shares, opened headers and released capsules; it is independent of the owner, the receive key, the intent of unreleased variants, the charter and the source, given the zero-knowledge property of `authorize` and the hiding of `pm`. Status: by inspection of the view; no simulation proof written.

**S8. One spend, liveness, replay.** As SCHEME Claims 6 and 7 with the sealed rules; the Midnight nullifier adds a second replay barrier. `n − f ≥ t` and `n − f ≥ q` give liveness.

**S9. Rotation keeps the key (rotation must not move coins).** *Both modes; at most `f` Byzantine in the old and `f'` in the new committee; consistent board.* After `HANDOVER` the new committee holds a degree-`t' − 1` sharing of the same `x_f`, and no coalition below `t` old and below `t'` new nodes learns it. Status: **open**. SCHEME has no theorem for `reshare` even at `t = f + 1`, and this design extends it to `t = n − f`; the complaint window gives liveness on a synchronous-enough board and nothing more is proved.

**When the TEE is broken in TEE mode.** At fewer than `t` nodes: those operators read headers after ordering and capsules they combine, and learn their own shares; S2–S6 and S8 hold unchanged, S7 falls to the non-TEE statement for those nodes. At `t` or more nodes, with operators colluding: early decryption (B3 lost), `x_f` exposed, v1 covenant checks void (S5 lost); S2 and S3 still hold, so no coin moves without the holder, the guardians or a matured certificate.

## 7. Requirement table

| Req | TEE mode | Non-TEE mode | Why |
|---|---|---|---|
| R1 | MET | MET | Under the stated reading: all nodes corrupt complete only sealed variants of a source that contributed its element (S2, S3). An asset with `open_ok` is PARTIAL (threshold only). |
| R2 | PARTIAL | PARTIAL | `x` is a sum or product of `x_u` and `x_f`; neither side signs alone and nobody holds `x` (S3, S4). Not full: a matured exit certificate lets the holder sweep to the exit record with no further network step. With `exit = off` R2 is MET and R5 is not. |
| R3 | MET (Bitcoin, Solana), PARTIAL (Ethereum) | same | Committee DKG plus public tweak; user element by receive-key derivation or wallet key; fresh per address. Ethereum needs an interactive birth session whose two sub-protocols are not yet instantiated at `t = n − f`. |
| R4 | PARTIAL | PARTIAL | No bypass by holder or thief, freeze, blacklist, veto, seizure and reversal hold below `t` corrupt nodes (S5). A hold binds only until the coin's certificate matures, and not at all afterwards, unless guardians seize first; a holder with `t` nodes bypasses. Rotation of `x_f` at `t = n − f` is unproved (S9). |
| R5 | MET (Bitcoin), NOT MET (Ethereum, Solana) | same | Two keys, guardians as the third. Bitcoin exit is a timelocked native transaction signed in advance. Ethereum and Solana have no transaction timelock; the time-release candidate is not yet read and is open. A charter with `exit = off` has no exit on any chain. |
| B1 | MET | PARTIAL | TEE: operator sees ciphertext. Non-TEE: operator sees address-free tickets after ordering and the released host transaction; never owner, intent, charter or source. On Ethereum it also knows the account from the slot. |
| B2 | MET | MET | Before ordering an envelope shows a size class, a suite class and an expiry. |
| B3 | MET | MET | Header key is line-dealt at `t = n − f`; shares move only after the quorum certificate (S6). |
| B4 | MET | MET | TEE v1 runs the cryptographic base inside enclaves; the ticket proof replaces enclave recomputation behind one interface. |
| B5 | PARTIAL | PARTIAL | No protocol-level link, one format for all sources, unlinkable addresses. The host chain's own coin graph stays visible. Non-TEE operators link an envelope to its host transaction at release, and on Ethereum to the account at opening. |
| B6 | MET | MET | Only the combiner set sees the transaction before broadcast. |

## 8. Costs

All figures are derived, `n = 9`, `t = 7`, `q = 6`, one input, `K = 8`; 50 µs per scalar multiplication.

| Item | Figure |
|---|---|
| Owner messages per spend | 1 envelope + 1 Midnight transaction, prepared offline together |
| Owner rounds at birth | Schnorr suites: 0 (wallet key) or 1 received note. Ethereum: 3 rounds, once per `N = 32` slots |
| Board rounds per spend | ACK, OPENED, OBS, RELEASED: 4, against 3 for sealed mode today. Plus Midnight finality of `authorize` before step 3 |
| Envelope size | dealing of 9 scalars: `9 × (33·7 + 32·9) = 4,671` B; `π` 196 B; header about 1.2 KB; 8 capsules about 300 B each; padded to the 8 KB class. SCHEME sealed `K = 8`: 4,872 B |
| Committee nonce slots | 8 per request; each slot is 2 polynomials from `t = 7` dealers: `7 × 2 × 486 = 6.8` KB of board data and about `7 × 2 × 7 = 98` multiplications per node. Per request: 54 KB and about 39 ms per node, produced off the request path. This is the largest recurring cost; `K = 3` cuts it to 20 KB and 15 ms |
| Node CPU per request | Step A as sealed `K = 8` plus one point: about 90 multiplications; ticket checks 3 per variant (24); partial checks `3t = 21`; post signatures about 30. Total about 165 multiplications, 8 ms, against 6 to 7 ms today. TEE v1 adds hashing only |
| Wallet CPU per request | dealing 9 scalars at `t = 7`: about 80 multiplications, 4 ms; v1 `authorize` proof: one Compact proof (seconds, Midnight's figure, not measured here); v2: plus one STARK over about 100 SHA-256 compressions and one wrap (not measured) |
| Latency | board commits (4) plus Midnight finality of the authorization; the second dominates |
| Ethereum birth | per slot: one `F_presig` and 18 `F_mul` calls with the user. No figure is given, because neither functionality is instantiated. This is the most expensive part of the design; it is paid at birth, not per spend |
| Rotation | one resharing of `x_f` per suite (`t × (486 + 164)` B each) plus unspent ECDSA slots; no per-address work |

**What breaks in SCHEME.** The rule that `reshare` needs `t = f + 1` (§5), which the root key's rotation overrides without a proof. The public header (§3.2), the public checks that read the intent (§3.4 checks 3 and 8), public PARTIAL posts (§3.7), and the assumption that the owner holds `x` (§2). Open mode stops being a launch mode for network-created addresses. Eligibility checks that read the address (trigger id 2, "pin unspent") run only in TEE v1; in v2 the committee does not check the pin, which is safe because every variant conflicts on it.

**New assumptions.** Midnight: soundness and zero knowledge of `authorize`, finality, and availability (a spend needs Midnight live). Guardians: fewer than `t_g` collude with `t` nodes. Schnorr suites: AOMDL for the committee half with an adversarial additive share. ECDSA: secure instantiations of `F_presig` and `F_mul` at `t = n − f`, and a composition proof not yet written. Rotation: a proof of resharing at `t = n − f` (S9). Exit on Ethereum and Solana: a time-release service that does not release early (candidate open). TEE mode: SEV-SNP, the Azure paravisor and vTPM, Warden's verification, reproducible images.

## 9. Changes to SCHEME.md

- **§1.** Add the split line and the half-point; state that the owner of a network-created address holds `x_u`, not `x`.
- **§2.** Parties: add guardians, Midnight, the receive key. Setup: committee DKG per suite; node keys attested in TEE mode. Suites: network-created Bitcoin addresses are P2TR only; add the Ethereum birth session. Assumptions: add those of §8.
- **§3.1.** New labels `SL1/addr`, `SL1/st`, `SL1/pm`, `SL1/bind`, `SL1/dkg-*`, `SL1/kdf`.
- **§3.2.** Replace `OwnerMsg` by the envelope: `pub`, dealing of `κ_0` and half-points with explicit constant terms, encrypted header and capsules. Remove `X`, `address`, `intent` and `trigger` from the clear.
- **§3.3.** "Sealed points" become sealed half-points; add the escrow dealing. Open lines move to an optional profile.
- **§3.4.** Split Step A into order (content-free checks, ACK), open (header shares after the certificate) and admit (`ticket_ok`, Midnight `auth`, slot claims).
- **§3.5.** New states ORDERED, OPENED; remove LOCKED for the launch profile.
- **§3.6.** Eligibility per mode; fee selection on disclosed rates.
- **§3.7.** Release sends two partials per node over node channels; the board gets `RELEASED` hashes; add combine and capsule opening.
- **§3.8.** Becomes the optional open profile.
- **§3.9.** Add: nonce and envelope shares are RAM only; share repair; `boot_seq`.
- **§3.10.** Add erasure of header keys and capsules.
- **§4.** `Variant` unchanged; add exit variants with a timelock and the capsule destination.
- **§5.** Epoch-level resharing of `x_f` and ECDSA slots at `t = n − f` with a complaint window, marked unproved; nonce pools discarded; requests `finish` or `void`.
- **§6.** Replace `F_OMS` by a functionality with three sources and a co-signer; restate Claims 1 to 7 as S1 to S8; add the TEE-broken table.
- **§7.** New cost rows of §8.
- **§8, §10.** Close gap 10 (request privacy). Add risks: Midnight liveness, hold horizon, guardian collusion, Ethereum slot exhaustion, timing correlation, the host chain's coin graph.
- **New §.** Veritee integration (§5 here).

## 10. Sources

**Read and relied on.**

| Source | Read | What it contributed |
|---|---|---|
| BIP327, MuSig2 for BIP340. https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki | specification page | A signer may publish its nonce before the message and the other keys are known; the aggregate is an ordinary BIP340 key and signature; x-only tweaking for Taproot; a secret nonce must never sign twice. Basis of the pre-published committee nonce pair and the offline user half. |
| BIP341, Taproot. https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki | specification page | `Q = P + hashTapTweak(P)·G` for a key with no script path, and the warning that an aggregate key without this commitment lets one party hide a script path. Basis of the key-path-only address. |
| ERC-3643. https://eips.ethereum.org/EIPS/eip-3643 | specification page | Forced transfer by an agent that skips compliance rules, whole and partial freezing, recovery to a new wallet. The feature set R4 asks for, done there by a contract role; here by guardian escrow and Midnight flags on a native key. |
| Groth, Shoup, ePrint 2021/1330 and 2022/506 | read in full by the project (SCHEME §12, `design/notes-2022-506.md`); this lane used those notes and did not reopen the papers | ECDSA with presignatures (Theorem 3), the share-encryption proofs that S2, S4 and S6 reuse, and the quadruple presignature that realizes `F_presig` at `t = f + 1`. |
| `design/SCHEME.md`, `requirements/catalogue/FACTS.md` | in full | Dealing, complaint, anchor, ledger and rotation machinery, all reused. |
| Veritee VM, local checkout and `VERITEE-MODEL.md` | files listed at the top | Every statement of §5 about what exists and what is missing. |

**Abstract page only; noted as prior art, not relied on.** The ePrint PDFs returned HTTP 403 on 2026-11-14, as they did for the SCHEME lane. No mechanism of this proposal is taken from the body of these papers. Where a mechanism would need one, the proposal states a functionality and marks the instantiation open.

| Source | What the abstract says | Consequence here |
|---|---|---|
| Friedman et al., 2PC-MPC. https://eprint.iacr.org/2024/253 | A user as one party and a network emulating the second party of two-party ECDSA; user cost independent of the network. | Same custody shape. This proposal moves the product to birth so that signing is linear; it does not use the paper's protocol. |
| Doerner, Kondi, Lee, shelat, Threshold ECDSA in Three Rounds. https://eprint.iacr.org/2023/765 | Three-round threshold ECDSA against a dishonest majority from commitments and OT-based two-party multiplication. | Candidate for `F_presig` and `F_mul` at `t = n − f`. **Open** until read in full. |
| Komlo, Goldberg, FROST. https://eprint.iacr.org/2020/852 | One-round threshold Schnorr signing after preprocessing. | Names the shape of the committee half. The security argument used is SCHEME Theorem B, not FROST's. |
| Benhamouda et al., On the (in)security of ROS. https://eprint.iacr.org/2020/945 | Concurrent-session attacks on blind Schnorr, original FROST and two-round MuSig. | Reason the binder `ρ` hashes values that fix the challenge. |
| Bebel, Ojha, Ferveo. https://eprint.iacr.org/2022/898 | Transactions stay encrypted until inclusion is final; a DKG gives the committee a threshold key. | Prior art for B3. This proposal gets order-then-decrypt from a dealer-based sharing with no committee encryption key. |
| Gailly, Melissaris, Romailler, tlock. https://eprint.iacr.org/2023/189 | Encryption to a future round of a threshold BLS network. | Candidate time lock for exit certificates on Ethereum and Solana. **Open** until read in full; without it those chains have no exit path and R5 is NOT MET there. |
| Lindell, Fast Secure Two-Party ECDSA Signing. https://eprint.iacr.org/2017/552 | Two-party ECDSA with no honest majority. | Ancestor of the two-key shape; nothing taken. |
