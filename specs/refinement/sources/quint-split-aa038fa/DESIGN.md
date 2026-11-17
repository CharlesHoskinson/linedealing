# Split-line dealing: co-custody and operator blindness for line dealing

Status words in this document: **proved** (a complete argument exists, here or in `design/PROOFS.md`), **sketched** (the reduction is named and its steps are given, no written proof), **open** (an obligation of §12), **assumed** (a stated assumption), **estimate** (a derived figure, not a measurement). `q` is the board quorum. The order of a signature group is `N_s` (secp256k1) or `ℓ` (edwards25519).

## 1. Summary

**The idea.** A Schnorr signature is one point on the line `s(c) = k + c·x`. An ECDSA signature is one point on the line `s(h) = h·w + r·μ` with `w = k⁻¹` and `μ = k⁻¹x`. Line dealing lets an owner who holds both coefficients deal the line. Split-line dealing cuts the line at address birth into a **committee half**, which the Fenrir committee holds in Shamir form, and one or more **shards**, which outside parties hold. The address key is

`x = x_f + tw + Σ_{a∈A} x_a`

over a set `A` of **shard holders** (actors): the user, an issuer, a custodian, an approver, a guardian group, a regulator, or any party the charter names. Nobody holds `x`. Fenrir holds only `x_f` and runs the MPC. The outside parties provide the shards. The charter fixes at birth which sets of actors may sign, its **access structure**, and every admitted set signs only together with the committee.

To spend, an **initiator** posts one sealed envelope that names a **signing set** of actors, their nonce slots and a fee grid that spends one pinned input or one account nonce. Each named actor then makes one offline move: its **sealed contribution**, which is its shard already evaluated at the sighash of every variant of the grid. The committee selects one variant per fee generation and adds its half with one linear partial per node, on one committee nonce slot per generation and input. The sum is an ordinary single-key BIP340, Ed25519 or ECDSA signature. The single-user form, one **user half** held by the holder's wallet plus the committee half, is the case `|A| = 1`, in which the initiator is the only actor and its contribution is the **user half-signature**.

A contribution alone signs nothing, and completing a set of contributions is linear. Three properties follow.

1. **Co-custody without a signing round.** Each actor computes its contribution offline from public nonce points. The committee adds its half with one linear partial per node. No secret multiplication runs at signing time. ECDSA pays for its non-linearity once, at address birth, in an interactive session among the committee and every actor that prepares one-use presignature slots.
2. **The sealed guarantee survives for every actor.** A committee that is corrupt in full, together with any coalition of actors that the access structure does not admit, holds its own key and every dealt contribution. It completes the variants that an admitted signing set sealed and nothing else, because every other message needs a fresh point of a shard line that an honest actor of every admitted set holds and never deals.
3. **Blind co-signing.** The committee half needs only a challenge scalar, a binding factor and a nonce slot. Every address-specific term and every actor-specific term sits in the actors' contributions. A node signs a **ticket**: a few scalars and one aggregate actor nonce point. Midnight proves that the ticket's scalar is the sighash challenge of a transaction the charter admits.

**Three charter custody profiles.** Every address carries a profile fixed at birth in its charter. The protocol, the envelope and the committee state machine are the same for all three. A profile only adds authorization sources and checks.

| Profile | Key | Authorization | Exit when Fenrir disappears |
|---|---|---|---|
| **P0 existing** | the owner's existing key `x`, unchanged line dealing | the owner's sealed signatures | the owner holds `x` |
| **P1 co-custody** | `x = x_f + tw + Σ_{a∈A} x_a`; launch form `A = {user}`, `x = x_u + x_f + tw` | contributions of a signing set the access structure admits (launch form: the owner's half-signature), plus covenant predicates and approver vetoes the charter chose | unconditional: recovery group `E` with an admitted signing set, or the Bitcoin exit leaf |
| **P2 regulated** | as P1, with an OR branch that escrows the user shard at a guardian group `G`: `Fenrir AND (user OR G)` | P1, plus the charter's seize, freeze, blacklist and hold entries | as P1, subordinate to a live hold |

Nothing in P0 or P1 depends on `G`, on the seizure sink `D_reg` or on the hold accumulator. No P2 component is needed to run Fenrir. The number of shards and the access structure are charter choices in P1 and P2. They change no committee step (§2.4).

**Two modes, one protocol.** The request travels as a fixed-size padded **envelope**. Its data key `κ_0` is the only secret the envelope deals: one Feldman-committed `t`-of-`n` Shamir sharing to the nodes' dealing keys `PK_i`, with the encryption and public complaint of line dealing. Every key of the envelope is an output of the threshold PRF `κ_0·H_c(dd ‖ label)` over the digest `dd` of that dealing, and a node contributes to a key with one partial. No partial leaves a node before the quorum certificate of the board fixes the envelope's order, and nobody reconstructs `κ_0`.

- **TEE mode** runs each node inside a hardened Veritee confidential VM (§7). Every node key is born and held in the enclave, so an operator sees ciphertext, sizes and timing. In v1 the enclave recomputes the sighash from the opened intent and the Midnight authorization proves the charter predicate alone. The enclave enforces authorizations and holds even when every operator is malicious, while the TEE holds and at most `n − 1 − 2f` operators roll back or clone their nodes (§7.7).
- **Non-TEE mode** is the same protocol with no hardware trust. Nodes sign address-free tickets, and the Midnight authorization also proves, in one PLONK circuit of Midnight's own proof library at `k = 18`, that each ticket is the sighash challenge of an admitted transaction. The ticket commits `x(R)`, so the circuit holds hashes and no curve arithmetic. Authorizations and holds are then honest-threshold guarantees.

The TEE is an extra condition on the same messages. A break of fewer than `t` enclaves costs those operators' blindness after ordering. It costs no signature, no early decryption and no key.

**Launch parameters.** `n = 9`, `f = 2`, `q = 6`, `t = n − f = 7`. Later `n = 17`, `f = 5`, `q = 12`, `t = 12`. Rotation reshares the committee's root keys and never moves a coin.

**The request path.** The initiator posts the envelope while its Midnight authorization finalizes. The board orders and opens the envelope during that wait, and two board commits remain after finality: the one that orders the envelope and the one that admits it and anchors the fee. A charter of profile P0, or of P1 with stateless predicates, may authorize board-first and wait for no Midnight finality (§5.3). A request with a full Taproot fee grid costs each node about 2 to 6 ms of one core, slot pool included (estimate, §11).

**Limits stated once.** An admitted signing set that colludes with `t` committee nodes (TEEs broken, or non-TEE mode) holds the whole key, so covenant enforcement in P1 and P2 is a threshold guarantee. A charter whose every admitted set needs one actor traps the funds if that actor disappears for good, unless the charter gives that actor an OR branch or a threshold group. A signature released to a host chain cannot be recalled. A matured Bitcoin exit leaf pays any destination. Host-chain graph analysis of a coin's own history is outside the protocol. The ECDSA birth session rests on two functionalities whose instantiation at `t = n − f` is open, with every actor online at birth and at each refill, and resharing at `t = n − f` is an open proof obligation.

## 2. Parties, keys and parameters

### 2.1 Parties

| Party | Role | Size and threshold |
|---|---|---|
| Shard holders (actors) `A` | each holds one shard of each address, or a member share of a group shard; each named actor makes one offline move per request | per charter; `|A| = 1` (the holder) in the launch form |
| Holder (owner) | the actor of the `|A| = 1` form: holds the user shard (user element) and makes the one move | one wallet; a companion device may prove and relay |
| Initiator | the actor that builds and posts a request envelope; a member of the signing set it names | any actor the charter admits as initiator |
| Committee | holds the committee half; orders, opens, checks and co-signs | `n = 9`, `f = 2`, `q = 6`, `t = 7`; later 17, 5, 12, 12 |
| Board | BFT total-order log run by the committee; orders posts, interprets nothing | `f < n/3` |
| Midnight | authorization, registries, checkpoints, holds; Compact contracts with zero-knowledge proofs | assumed sound, live and final |
| Guardian set `G` (P2 only) | the group branch of `user OR G`: holds a 3-of-5 escrow of the user shard; its members contribute as actors for a settled seizure | `n_g = 5`, `f_g = 1`, `q_g = 4`, `t_g = 3`; disjoint from committee operators |
| Recovery group `E` (P1, P2) | backup sharing of `x_f` and of unused ECDSA committee slot state; reprovisions a successor committee | 3 of 5; disjoint from `G` and from committee operators |
| Charter authorities (P2 only) | registry authority, hold authority, named approvers | keys registered in the charter |
| Approvers (P1, P2) | named approvers the owner chose: their signature or veto is a charter predicate checked by `authorize`. An approver whose consent must be cryptographic in the host signature is instead a shard holder of the access structure | keys registered in the charter |

The guardian escrow reuses the dealing, ACK and complaint machinery of line dealing with its own parameters. The value `t_g = 3` is legal for this group because the honest guardians number `n_g − f_g = 4 ≥ t_g`, so a seizure completes, and the `f_g = 1` Byzantine guardian stays below `t_g`, so it learns nothing about the escrowed shard. Guardians sign as actors from their own nonce pools (§3.10), so no lock round runs among them.

### 2.2 Keys

| Key | Curve or primitive | Holder | Threshold | Lifetime | Purpose |
|---|---|---|---|---|---|
| `x_a`, `X_a = x_a·G` | secp256k1 (suites 1, 2), edwards25519 (suite 3) | actor `a` | none | per address | shard of actor `a`; fresh for every new and change address |
| `x_u`, `X_u = x_u·G` | as `x_a` | holder's wallet | none | per address | user element: the user's shard, `x_a` for `a = user` |
| `x_γ`, `X_γ`; member shares `x_{γ,i}`, `X_{γ,i}` | suite curve | members of group `γ` | Shamir `k_γ` of `m_γ`, Feldman commitments public to the actors | per address | group shard of a threshold gate (§2.4), born by a DKG among the members |
| `tw` | scalar of the suite group | every actor of `A`; revealed to the committee only inside the sealed birth request | none | per address | secret address tweak: makes `X` unlinkable to every `X_a` and to `X_f` for any party without the tweak seed |
| `x_A = tw + Σ_a x_a`, `Y_A = X − X_f = x_A·G` | scalar, point | nobody whole; the actors' parts | none | per address | the actors' whole additive part; `x_U' = x_u + tw` when `A = {user}` |
| `x_f`, `X_f = x_f·G` | one per suite curve (secp256k1, edwards25519) | committee | Shamir `t = n − f`, Feldman commitments `X_{f,i}` public | permanent; reshared at rotation, constant term fixed | committee half of every address |
| `x = x_A + x_f`, `X = X_f + tw·G + Σ_a X_a` | suite curve | nobody | — | per address | address key |
| `t_tap` | scalar, `H_TapTweak(x(P) ‖ root)` | public once `X` is known | — | per address | BIP341 output-key tweak |
| `K_exit` | secp256k1 x-only key | holder | none | per address, Bitcoin only, optional | exit leaf key |
| `U = u·G` | suite curve | holder | none | per charter | receive key for network-created user elements |
| Owner spend key | Midnight's embedded curve | holder | none | per charter | signs `ic` for the owner source of `authorize`; signs P0 registrations |
| Approver keys | Ed25519 or Midnight's embedded curve | named approvers | per charter | per charter; P1, P2 if chosen | approver signatures and vetoes in `authorize` |
| Guardian keys `PK_{g,j}` | suite curve (dealing) and Ed25519 (posts) | guardian `j` | none | standing; **P2 only** | receive escrow dealings, post ACKs |
| Recovery group keys `PK_{E,j}` | suite curve (dealing) and Ed25519 (posts) | member `j` of `E` | none | standing | receive backup dealings, sign reprovisioning |
| Registry authority key | Midnight's embedded curve | charter registry authority | per charter | **P2 only** | seizure orders and blacklist updates |
| Committee nonce slot `(d_ℓ, e_ℓ)`, `D_ℓ = d_ℓ·G`, `E_ℓ = e_ℓ·G` | suite curve | committee | Shamir `t`, each the sum of `t` dealers' polynomials | per epoch, single use; TEE: session-sealed in the seat's pool session `slots-s-e` of suite `s` and epoch `e`, witness-fenced (§7.4); non-TEE: process memory | committee nonce of one Schnorr or Ed25519 half |
| ECDSA slot `(R_ℓ; (w_a, μ_a)_{a∈A}; w_f, μ_f)` | secp256k1 | actor `a`: `(w_a, μ_a)` (a group: Shamir shares); committee: Shamir `t` of `(w_f, μ_f)` | `t` | per address, single use; TEE: session-sealed in the seat's account pool of the address, witness-fenced (§7.4); non-TEE: process memory; backed up at `E` | one ECDSA half pair per shard and the committee half |
| Actor nonce pool pair `(d_{a,ν}, e_{a,ν})`, `D_{a,ν}`, `E_{a,ν}` | suite curve | actor `a` (each member of a group) | none | per pool, single use | two-nonce commitment of one contribution (§3.10) |
| Pool key `pk_{pool,a}` | Ed25519 | actor `a` | none | per pool | signs the pool post; a pseudonym under one of the actor's pool-key roots in the shielded charter record (§3.10) |
| Actor request key `AK_a` | X25519 HPKE | actor `a` | none | per charter | receives actor capsules (§4.6) |
| Contribution token `τ_a` | 16 random bytes | initiator, then actor `a` | none | per request and actor | authorizes one contribution post for slot `a` (§5.9) |
| `κ_0`, `K_0 = κ_0·G` | secp256k1 | dealt by the initiator; by an actor for its contribution frame | Shamir `t`; never reconstructed | per envelope | envelope data key: the key of the threshold PRF that yields every key of the envelope (§4.6) |
| `Z_lab = κ_0·H_c(dd ‖ lab)`; `k_hdr`; `k_{v,g}`, `y_{v,g}`, `P_{v,g} = y_{v,g}·G` | secp256k1 | the initiator; the committee after `t` partials | `t` partials `Y_{i,lab} = κ_{0,i}·H_c(dd ‖ lab)` | per envelope and label | PRF point of a label; header key; body key, contribution secret and contribution public key of variant `v` in generation `g` |
| `ck_v` | 32 random bytes | initiator; named actors; the committee after the variant's release | none | per envelope and variant | capsule key of variant `v` |
| `PK_i = sk_i·G` | one per suite curve | node `i` (enclave in TEE mode) | none | per epoch | dealing key: share encryption of line dealing |
| `EK_i` | X25519 HPKE | node `i` | none | per epoch | single-node envelopes (`SealedToNode`) |
| `post_i` | Ed25519 | node `i` | none | per epoch | board posts, witness acks, certificates |
| `bk_sig`, `bk_kem` | Ed25519, X25519 | enclave of node `i` | none | per boot | boot key: admission, peer channels, witness |
| `PVK` | X25519 | enclave of node `i` | none | per VM and image | provisioning key for operator secrets |
| akx epoch key `pk_e` | Ed25519 | attestation server | none | per process | Veritee attested channel, evidence class 0x01 |
| `K_tpm` | 32 bytes in a vTPM keyed-hash object | enclave of node `i` | none | per VM | local factor of the storage key |
| `σ_e`, `S_j = σ_j·G` | ristretto255 | committee; node `i` keeps `σ_i` in tier 0 under `K_tpm` | Shamir `t_s = n − f` | per epoch | seal-group threshold PRF: `K_grp`, the keyring ratchet and the session keys |
| `K_sess,v` | HKDF-SHA256 of `PRF_σe(committee ‖ epoch ‖ node_id ‖ sid ‖ v)` | enclave of node `i`, from `t` partials | `t_s` partials, from share holders that serve only the latest boot ticket of the seat and an approved app image | one seal or one open, then erased | session key of version `v` of session `sid` of seat `node_id` (§7.4) |
| `K_vol`, `K_ring,v` | HKDF-SHA256 outputs | enclave of node `i` | none | per boot (RAM) | tier 0 volume key, tier 1 keyring key |
| TLS key | P-256 | enclave of node `i` | none | per boot or ACME renewal | attested TLS endpoint |
| Escrow of `x_u` with `tw` (Schnorr suites) or of `(w_u, μ_u)` for reserved slots (ECDSA) | suite curve | guardian set `G` | `t_g = 3` of 5 | per address; **P2 only** | the `G` branch of `user OR G`: guardian contributions for a settled seizure |
| Backup of `x_f` and of unused ECDSA committee slot shares, with `k_nf` | suite curve | recovery group `E` | 3 of 5 | per epoch | reprovision a successor committee; ECDSA slot shares and `k_nf` only on a committee that anchors slot bindings, and only for a slot that no seat log under a checkpoint root binds (§7.11) |
| Slot-nullifier key `k_nf` | 32 bytes | committee, in session `keys`; `E` on a committee with slot anchors | none | per epoch | keys the slot nullifier of each slot-anchor entry, so the seat log shows no slot id (§4.1) |
| Hold authority key `PK_H` | Midnight's embedded curve | charter hold authority | per charter | per charter; **P2 only** | decrypts hold handles to flip pending authorizations |
| Operator key | Ed25519 | node operator | none | per slot | signs `admitBoot`, `replaceSlot` |
| Governance keys | Ed25519 | governance members | 7 of 9 separate members | standing | Image Registry approvals |

### 2.3 Parameters

| Parameter | Launch value | Meaning |
|---|---|---|
| `n, f, q, t` | 9, 2, 6, 7 | committee size, Byzantine bound, board quorum `⌈(n+f+1)/2⌉`, key and decryption threshold `n − f` |
| `w` | `n − 1 − f` = 6 (11 at `n = 17`) | peer acks a node needs for admission and for a witnessed commitment |
| `t_s` | `n − f` = 7 | seal-group threshold: the node's own partial plus `w` peer partials |
| `K` | 8 on Bitcoin P2TR, 3 on P2WPKH, 1 on Ethereum and Solana | variants in a fee grid |
| `G_max` | 2 | fee generations per request, a protocol constant; a request runs `G = min(K, G_max)` generations, and a further fee bump is a new request |
| `N_h` | `L·Σ_{v=1..K} min(v, G_max)` on Schnorr suites (30 at `K = 8`, `L = 2`); `K·L` on ECDSA | halves of a request: the triples `(v, g, j)` with `g ≤ min(v, G_max)` (§4.1) |
| `L` | ≤ 2 inputs at launch | inputs per transaction |
| `N_slot` | 32 | ECDSA slots prepared per address and birth session, each bound to one leaf set (§3.6 step 7); at P2WPKH `K·L = 6` a leaf set with 12 slots serves two spends, so the single-user form gets five spends per session and a charter with two leaf sets two or three each |
| `G_g` | `2·K·L_max`, 12 on P2WPKH | ECDSA slots per address reserved for `G` (P2), bound to two guardian leaf sets of `K·L_max` slots each, so two seizures of the largest grid run, each by one fixed subset of `t_g` guardians |
| `N_pk` | 1,024 | pool keys under one pool-key root (§3.10); at `N_pool = 64` and `N_h = 30` one root serves about 2,000 requests that name the actor |
| `N_pool` | 64 | pair commitments per actor pool post; a request uses one pair per half of each named actor, `N_h` pairs |
| `B_slot` | set by measurement | committee slot dealings in one dealer message (§4.1) |
| `B` | set by measurement, at least the largest number of committee slot reservations between two Midnight checkpoints | reservation window: a header names committee slots only in `(h, h + B]` above the floor `h` of the latest checkpoint (§4.1); seald `session_window` |
| `S_max` | set by measurement, at most 2 MiB | largest accounted size of one session (§7.4); seald `session_max_bytes` |
| `Δ_hold` | 2 Midnight blocks | P2 only: generation 1 waits until the authorization has been final this long (§5.5) |
| `Δ_c` | 600 board blocks | collection window: `exp_c` = ordering height + `Δ_c` (§5.9) |
| `T_exit` | 26,280 blocks (about 26 weeks) | exit leaf relative lock; below the BIP68 limit of 65,535 blocks |
| `Δ_rec` | charter value, launch 30 days of Midnight blocks | delay after the last committee checkpoint before `E` may reprovision |
| Frame | 16,384 bytes | one envelope size class at launch |
| Checkpoint interval | 60 s of board time | Midnight checkpoint of board state |
| Grace period | 1 epoch boundary + 2 days | lifetime of epoch keys after `ROTATE` |

Two thresholds and one quorum stay distinct. Six board votes never reconstruct a seven-share secret. A board certificate authorizes no use of a key share by itself.

### 2.4 Shard holders and the access structure

The charter fixes at birth a monotone access structure `Γ` over the actors. The address signs only for a signing set `S ∈ Γ` together with `t` committee nodes, so the committee is always ANDed with `Γ`. `Γ` is a formula of three gates over shards.

| Gate | Meaning | How the gate's secret is shared |
|---|---|---|
| AND | every child signs | additive: the gate's secret is the sum of the children's secrets. The top gate of every charter is `Fenrir AND …`, and `x = x_f + tw + Σ x_a` is its sum |
| `k_γ`-of-`m_γ` group `γ` | any `k_γ` of `m_γ` members sign | Shamir: the members hold shares `x_{γ,i}` of the group shard `x_γ` at degree `k_γ − 1`, born by a DKG among the members |
| OR | either child signs | escrow: each child holds the whole gate secret. The primary holder deals its shard to the other child at birth (§3.8) |

Gates nest. A leaf is one actor's secret: a shard, a member share or an escrow share. For a signing set `S`, every threshold gate on the path from the root to a leaf names the `k_γ` children that sign, and every OR gate names one child. The leaf's **weight** `λ_a` is the product of the Lagrange coefficients at zero of those children sets along its path. An AND child and an OR child have weight 1. Member ids are nonzero and distinct within a group, and no leaf appears twice in `Γ`. The secrecy of C17 needs both. Then

`x = x_f + tw + Σ_{a∈S} λ_a·x_a`

for every `S ∈ Γ`, where `x_a` is the leaf's secret. Every formula of this document that names a shard of the single-user form takes a weighted leaf in the general form.

**Examples.**

| Charter | `Γ` (always ANDed with Fenrir) | Signing sets |
|---|---|---|
| P1 launch form | `user` | `{user}` |
| Two-party co-custody | `user AND issuer` | `{user, issuer}` |
| Corporate treasury | `2-of-3 officers` | any two officers, weights `λ_{i,T}` |
| Regulated custody | `user AND (custodian OR G)` with `G` 3-of-5 | `{user, custodian}`, or `user` with any three guardians |
| P2 seizure | `user OR G` with `G` 3-of-5 | `{user}`, or any three guardians |

**Rules.**

1. Each leaf is one actor's secret per address. An actor that serves many addresses derives a fresh shard for each one, so shard points do not link addresses.
2. The initiator is a member of the signing set it names. Its contribution carries the tweak term once (§4.2).
3. A signing set names exactly `k_γ` members of each threshold gate it uses and one child of each OR gate. The weights follow from the set alone, so every actor and every TEE node computes them from the header.
4. A charter admits one or more actors as initiators. `authorize` checks that the initiator is one of them and that the named set satisfies `Γ` (§5.3).

## 3. Address birth per chain

### 3.1 Common steps

The committee runs one DKG per suite curve at genesis with the dealing, ACK and complaint machinery of line dealing (labels `SL1/dkg-*`). The qualified set is the first `t` dealers in board order with no valid complaint, each with a proof of knowledge of its constant term. `x_f` is the sum of their constant terms. `X_f` and the share commitments `X_{f,i}` are public. No DKG runs per address and no node stores anything per Schnorr-suite address.

A P1 or P2 address is born in four steps. One actor, the **birth coordinator**, collects the actors' points and posts the birth request. In the single-user form the holder's wallet is the coordinator and the only actor.

1. **Shards.** Every leaf of `Γ` receives its secret.
   - *Actor shard, actor-supplied.* Actor `a` picks `x_a` uniformly at random (for Ed25519 a uniform scalar mod `ℓ` with no seed clamping, because verification needs only the scalar).
   - *User shard, network-created for an offline holder.* The holder registers a receive key `U = u·G` once per charter, in shielded form on Midnight. A creator (payer, issuer or committee) picks `e_c`, puts `E_c = e_c·G`, encrypted to the holder, into the shielded asset record of the new address (step 4), and sets `X_u = U + Hq_st(e_c·U)·G`. Only the holder computes `x_u = u + Hq_st(u·E_c)`. `E_c` is the element the holder needs to start spends. The creator and the committee know `X_u` and never `x_u`. The same path serves any actor that registers a receive key. The holder cannot sign a proof of possession for `X_u` while offline, so this shard is proved differently at birth (step 3): the registration of `U` carries `pop_U = Schnorr_u(Hq_pop(SL1/pop-rk ‖ U ‖ charter_id))`, and the creator proves knowledge of `δ = Hq_st(e_c·U)` with `X_u − U = δ·G` by a Schnorr proof bound to the birth context.
   - *Group shard.* The `m_γ` members of a threshold gate run a DKG at degree `k_γ − 1` among themselves (the dealing of line dealing with the group as the committee). Each dealer attaches a Schnorr proof of knowledge of its constant term bound to the birth context. `X_γ` is the sum of the dealers' constant terms, and the Feldman commitments give every member point `X_{γ,i}`.
   - *Nested gate.* A child of a threshold gate may itself be a gate. The group's DKG dealers deal that child's member share to the child's own members by the child's rule (Shamir at its threshold, a sum for AND), so each leaf holds a share of a share, and its weight is the product along its path (§2.4).
   - *Escrow.* The primary holder of an OR gate deals its shard to the other child (§3.8).
   A change address is born the same way inside the spend that creates it, from fresh shards. A charter with one actor needs no coordination. A charter with several actors runs this step with every actor online, once per address, or in batches of addresses.
2. **Tweak.** The coordinator picks a 32-byte seed and sets `tw = Hq_tw(X_f ‖ X_{a_1} ‖ … ‖ X_{a_r} ‖ charter_id ‖ seed)`, with the top-level shard points in charter slot order. The address key is `X = X_f + tw·G + Σ_a X_a`. The coordinator sends `seed` to every actor, sealed to `AK_a`, because an initiator places the tweak term and every actor recomputes `X`.
3. **Birth check.** The coordinator sends a `BIRTH` envelope (§4.6 format, request type 0x01) carrying every shard point `X_a` with its proof of possession, every group's dealer proofs and commitments, `tw`, the charter commitment and the access structure. Each top-level shard carries
   `pop_a = Schnorr_{x_a}(Hq_pop(SL1/pop ‖ X_f ‖ X_a ‖ slot_a ‖ charter_id ‖ chain_id))`,
   bound to the actor's own point, its charter slot `slot_a`, the committee key and the charter. A network-created shard carries instead the reference to `U` with its registration proof `pop_U` and the creator's proof of `δ` for `X_u − U` (step 1). An extractor then obtains `u` from `pop_U` and `δ` from the creator's proof, so the rogue-key argument below covers it. The node sees `U`, so in non-TEE mode the network-created addresses of one holder link at birth (§6.4). After ordering and opening, each node (each enclave in TEE mode) checks every `pop_a` and every dealer proof, recomputes `X_γ` from the group commitments, computes `X`, checks the address encoding for the chain, and checks that the commitment `cm_addr = Commit(X ‖ chain_id ‖ root ‖ charter_id ‖ profile ‖ H(Γ); r)` in the request opens, with `root` the Taproot script root (empty when there is none). It signs `BIRTH_OK(eid, cm_addr)` and sends it to the coordinator over the node channel, not to the board, so a board observer cannot link the envelope to the Midnight record. `q` such signatures form the **birth certificate**. Midnight's `FenrirAssets` contract accepts a P1 or P2 address record only with a birth certificate. A P0 record needs instead a registration signed by the owner's existing key.
   **Rogue-key defence.** The proofs of possession stop a rogue-key address. Without them the last actor to publish picks `X_r = z·G − X_f − Σ_{a≠r} X_a` and, with the other actors corrupt or not, holds a key the committee does not share in. With every shard proved, an extractor obtains each corrupt `x_a`. A coalition that also knows `z` then knows `x_f` plus the honest actors' shards, which contradicts the discrete-log assumption. Every point in the sum carries its own proof, so the order of publication does not matter and no commit round is needed. A proof is bound to its slot and charter, so it cannot be copied to another slot or address. A group shard is proved by its dealers' proofs, because `X_γ` is the sum of their proved constant terms. The tweak does not replace the proofs, because `tw` is a function the attacker evaluates after choosing its point. `tw` is shown as a scalar for the same reason: a point `T` in its place lets an actor set `T = z·G − X_f − Σ_a X_a`.
4. **Record.** The coordinator registers on Midnight the shielded asset record `(cm_addr, charter, profile, Γ, the initiator list, the actors' pool-key roots, on ECDSA the slot roots `slr_own` and, in P2, `slr_G` (§5.3), exit record D_exit, approver set, for P2 the hold tag and escrow certificate, and for a network-created shard `E_c` encrypted to its holder)`. The address becomes fundable once the record is final.

In TEE mode only enclaves see the shard points, `tw` and `X` at birth. In non-TEE mode each operator learns `X`, the number of shards and the time of birth, and nothing about who the actors are. This is a stated leakage (§6). Moving the birth check into a Midnight proof removes it and is open item O8.

### 3.2 Bitcoin P2TR (suite 2, BIP340)

The internal key is `P = g_P·X`, with `g_P = −1` when `X` has odd y, so that `P` has even y. The script tree is empty, or one exit leaf (§3.7). The output key is `Q = P + t_tap·G` with `t_tap = H_TapTweak(x(P) ‖ root)`, where `root` is empty for the key-path-only form. Let `g_Q = −1` when `Q` has odd y. The key that signs for `Q` is

`d = g_Q·(g_P·x + t_tap) = g·x_A + g_Q·t_tap + g·x_f`, with `g = g_P·g_Q`.

The actors' contributions together carry `g·x_A + g_Q·t_tap`, with `g_Q·t_tap` and `g·tw` in the initiator's contribution only (§4.2). In the single-user form that is the user half `g·x_U' + g_Q·t_tap`. The committee half carries `g·x_f`, and the sign `g` reaches the committee folded into the ticket challenge (§4.1). The output script is `OP_1 <x(Q)>`. A key-path spend is one 64-byte BIP340 signature. The chain sees an ordinary P2TR output and, if the leaf is never used, never learns that a script path exists. The birth check computes `Q` and checks the address.

### 3.3 Bitcoin P2WPKH (suite 1, ECDSA)

`X` is compressed, the address is `HASH160(X)`, and the network-created path applies as in §3.1. Each spend consumes `K·L` ECDSA slots, so P2WPKH uses `K = 3`. The slot session of §3.6 runs at birth with `N_slot = 32`. P2TR is the default Bitcoin output for P1 and P2. P2WPKH serves holders whose counterparties require it.

### 3.4 Ethereum EOA (suite 1, ECDSA)

`X` is secp256k1, the address is `Keccak-256(X uncompressed without prefix)[12..32]`, and the pin is the account nonce. One type-2 transaction with `maxFeePerGas` at the ceiling needs no fee grid, so `K = 1` and one slot is consumed per spend. The slot session of §3.6 runs at birth with `N_slot = 32`, and a refill is another session with every session party online. No contract account is used.

Regulated tokens (P2) keep their asset-level controls. ERC-3643 forced transfer and freeze, and on Solana the Token-2022 permanent delegate and freeze authority, are held by an **authority address**: a Fenrir-born address whose user element the guardian set `G` holds. Using that authority therefore needs `G`, the committee and a settled Midnight seizure or hold, and the authorization pins the destination to `D_reg`. A charter that demands on-chain seizure of native coins may also choose a minimal vault contract. That option replaces the native single-key output for that charter and is not the default.

### 3.5 Solana (suite 3, Ed25519)

`X` is a point of the prime-order subgroup of edwards25519 (each summand is a multiple of the base point). A spend is one Ed25519 signature `(R, s)` with `[s]B = R + [c]X` and `c = SHA-512(R ‖ X ‖ M) mod ℓ`. The pin is a durable nonce account whose authority is `X`. The wallet creates that account from a throwaway key. After creation only the authority `X` can advance or withdraw it. The first instruction of every spend advances the nonce. A transaction that passes nonce validation and then fails still consumes the nonce and the fee. The request then ends without a claim that the payment succeeded. The Solana adapter is acceptance-tested before launch (open item O13).

### 3.6 ECDSA presignature slot setup

ECDSA is not linear in the nonce, so the split is made in advance, in one interactive session per address among the committee and every **session party**. The session parties are every actor that holds a top-level shard and every member of every group. An escrow holder of an OR gate is not a session party (§3.8). Every session party is online for the session. Each slot `ℓ` gets a point `R_ℓ` and an additive split of both line coefficients:

`w_f + Σ_{p} w_p = k⁻¹`, `μ_f + Σ_{p} μ_p = k⁻¹·x`, `R_ℓ = k·G`, `k = k_f·Π_p k_p`,

over the `n_A` session parties `p`. The single-user form is `n_A = 1`, with `(w_u, μ_u)` for `(w_1, μ_1)`. Each party enters the session with an additive part `x'_p` of `x_A`: an actor's shard, or for a group member `λ_{p,T_0}·x_{γ,p}` for a fixed birth subset `T_0` of `k_γ` members (zero for the others). The initiator-eligible party `p = 1` adds `tw`, so `Σ_p x'_p = x_A`.

The session uses two functionalities. Their instantiation at `t = n − f` is open (O1, O2), and their instantiation among many session parties is open (O19).

- **`F_presig`** gives the committee a threshold presignature for the key `x_f`: a public point `R_f = k_f·G` and Shamir shares, at threshold `t`, of `φ = k_f⁻¹` and `ψ = k_f⁻¹·x_f`, with Feldman commitments `Φ`, `Ψ` in base `R_f` whose constant terms are `G` and `X_f`. Named candidates: the OT-based multiplication of DKLs23 (ePrint 2023/765), the Paillier-based presigning of CGGMP21, and the class-group two-party emulation of 2PC-MPC. The quadruple protocol of ePrint 2022/506 realizes `F_presig` at `t = f + 1` only.
- **`F_mul`** takes one scalar from each of two parties, a session party and node `i` or two session parties, and outputs an additive sharing of their product. Named candidates: OT-based and Paillier-based MtA.

Per slot:

1. The committee runs `F_presig` and posts `R_f`, `Φ`, `Ψ`.
2. **Nonce chain.** In charter slot order each party `p` picks `k_p`, sets `a_p = k_p⁻¹` and posts `R^{(p)} = k_p·R^{(p−1)}` with `R^{(0)} = R_f`. The slot point is `R_ℓ = R^{(n_A)}`. With `a = Π_p a_p`, `a·R_ℓ = R_f`, `k⁻¹ = a·φ` and `k⁻¹·x = a·x_A·φ + a·ψ`.
3. **Actor products.** The parties turn their factors into additive shares `α_p` of `a` and `β_p` of `a·x_A`. For `α`, `n_A − 1` sequential levels: at level `j` every party `b < j` runs `F_mul` with party `j` on `(α_b, a_j)`. For `β`, party `b` starts from `α_b·x'_b` and runs `F_mul` with every other party `c` on `(α_b, x'_c)`. These are `n_A·(n_A − 1)/2 + n_A·(n_A − 1) = 3·n_A·(n_A − 1)/2` instances. In the single-user form there are none and `α_1 = a`, `β_1 = a·x_U'`.
4. **Committee products.** For each node `i` each party runs `F_mul` with the node three times: on `(α_p, φ_i)`, on `(β_p, φ_i)` and on `(α_p, ψ_i)`. These are `3·n_A·n` instances. Party `p` holds `c_{p,i}`, the node `δ_{p,i}`, with `c_{p,i} + δ_{p,i}` equal to the product, and likewise for the other two.
5. **Corrections.** Each party picks polynomials `P_{w,p}`, `P_{μ,p}` of degree `t − 1` with `P_{w,p}(0) = w_p` and `P_{μ,p}(0) = μ_p`, and sends node `i` the corrections `c_{p,i,w} − P_{w,p}(i)` and `c_{p,i,μ} − P_{μ,p}(i)`. Node `i` holds `w_{f,i} = Σ_p (δ_{p,i,w} + c_{p,i,w} − P_{w,p}(i))` and `μ_{f,i}` likewise. Because `Σ_p α_p·φ_i = a·φ_i` are Shamir shares of `a·φ`, the values `w_{f,i}` are Shamir shares of `k⁻¹ − Σ_p w_p = w_f`.
6. **Public check, no proof system.** Since `a·R_ℓ = R_f`, the identity `(a·φ_i)·R_ℓ = φ_i·R_f` holds. Each party publishes `Com_{R_ℓ}(P_{w,p})`, `Com_{R_ℓ}(P_{μ,p})` (constant terms `W_p = w_p·R_ℓ`, `M_p = μ_p·R_ℓ`) and `x'_p·Φ_k` for every coefficient of `Φ`, with one batched DLEQ proof against `(G, x'_p·G)`. The point `x'_p·G` is `X_a` for an actor, `λ_{p,T_0}·X_{γ,p}` for a group member, plus `tw·G` for party 1. Let `Φ' = Σ_p x'_p·Φ`. Node `i` checks
   `w_{f,i}·R_ℓ = Eval(Φ, i) − Σ_p Eval(Com_{R_ℓ}(P_{w,p}), i)`,
   `μ_{f,i}·R_ℓ = Eval(Φ', i) + Eval(Ψ, i) − Σ_p Eval(Com_{R_ℓ}(P_{μ,p}), i)`.
   The implied constant terms are `W_f = G − Σ_p W_p` and `M_f = Y_A + X_f − Σ_p M_p = X − Σ_p M_p`, so `W_f + Σ_p W_p = G` and `M_f + Σ_p M_p = X` in base `R_ℓ`. The check passes only if `Σ_p α_p = a` for the posted chain, so a party that corrupts the actor products is caught. A node whose share fails posts a complaint and the slot is dropped.
7. **Group halves.** Each member of a threshold group deals its additive halves `(w_p, μ_p)` to the group at degree `k_γ − 1` with commitments in base `R_ℓ`. A nested gate repeats this step at each level. Member `i` sums what it receives and holds Shamir shares `(w_{γ,i}, μ_{γ,i})` of the group's half `(w_γ, μ_γ) = Σ_{p∈γ} (w_p, μ_p)`. An escrow holder receives the primary's halves of each reserved slot the same way (§3.8).
   **One leaf set per slot.** The session binds each slot `ℓ` to one **leaf set** `T_ℓ`: one `k_γ`-subset of every threshold gate and one child of every OR gate on the path. The slot record carries `H(T_ℓ)`, and every session party stores it with its halves. A member of `T_ℓ` contributes on slot `ℓ` only to a request whose signing set has the leaf set `T_ℓ`, and only once. A slot never serves two leaf sets, because two subsets `T ≠ T'` of one group on one slot give two evaluations `u = h·w_γ + r·μ_γ` and `u' = h'·w_γ + r·μ_γ` of the group's half line. Each honest member answers once, yet the two evaluations give the group's half line: `w_γ = (u − u')/(h − h')`, and `μ_γ` when `r ≠ 0`. That leaks the group's shard. Recovering `x` also needs the halves of every other actor on the slot, so in `user AND group` an honest user's halves still block it (§4.4). The committee cannot prevent this when every node is corrupt (C17), so the rule is enforced by the members. The same holds across the branches of an OR gate: a slot reserved for the escrow branch is never used by the primary holder. The birth session spreads `N_slot` over the leaf sets the charter expects to use, and a refill session adds slots for one leaf set.
8. Before a slot is usable, each node of the first `t` dealers reshares its `(w_{f,i}, μ_{f,i})` to the recovery group `E` (§3.9), and `E` acknowledges.

**Cost.** Per slot, `3·n_A·(n_A − 1)/2` party-to-party and `3·n_A·n` party-to-node multiplications, `3·n_A` posted commitment vectors, and about `2·n_A + 2` rounds, because the nonce chain and the `α` levels are sequential. At `n = 9`: `n_A = 1` needs 27 multiplications, `n_A = 3` needs 9 + 81, `n_A = 5` needs 30 + 135. A birth with `N_slot = 32` multiplies these by 32. Every session party is online for the whole session, at birth and at every refill.

The committee learns `X` and every `R_ℓ` of the address. On ECDSA chains operators therefore know which account a slot belongs to. Each party stores `(R_ℓ, w_p, μ_p)` per slot (a group member its Shamir shares). In TEE mode each node puts its committee shares of a slot into the account pool of the address with `slot_put`, which also appends a put entry with the share's digest to the seat's log on the board. A put counts once a Midnight checkpoint root covers it, and a share goes into a slot once (§7.4). In non-TEE mode a node keeps them in process memory. A whole-committee restart burns the unused slots of every ECDSA address, and the address refills by a new session before its next ECDSA spend (§7.11).

### 3.7 Exit leaf (Bitcoin, charter option)

A charter may add one tapscript leaf

`<T_exit> OP_CHECKSEQUENCEVERIFY OP_DROP <x(K_exit)> OP_CHECKSIG`

with `T_exit` in blocks. The spend uses transaction version 2 and `nSequence = T_exit` on that input. The lock is relative to the confirmation of each output, so every spend that pays change restarts the clock for the change. A matured leaf lets the holder of `K_exit` spend that coin **to any destination** with no committee, no Midnight and no charter check. It ends every covenant and, in P2, every hold for that coin. P1 charters may enable it. P2 charters enable it only where the charter accepts that a hold on a coin older than `T_exit` binds only if the guardians seize first. A matured leaf also bypasses the access structure `Γ`. A charter with several actors that enables the leaf therefore names as `K_exit` a key its actors agree on, for example a MuSig2 aggregate of the keys of one admitted signing set. The universal exit path is the recovery group `E` (§3.9).

### 3.8 OR gates by escrow and the guardian escrow (P2)

An OR gate `a OR γ` gives the second child a copy of the first child's secret. At birth the primary holder `a` posts an escrow dealing to the holders of `γ`. It is the open mode of line dealing with `γ` as the committee:

- Schnorr suites: `Share_{k_γ}(x_a)` with implied constant term `X_a`, plus the tweak seed sealed to every member, so that a member can initiate. Members contribute from their own nonce pools (§3.10), with weights `λ_{i,T}`.
- ECDSA: the half-lines `(w_a, μ_a)` of the reserved slots of the birth session, with commitments in base `R_ℓ` and implied constant terms `W_a`, `M_a`. An escrow of `x_a` alone would be useless, because an ECDSA half is the per-slot line. Each reserved slot is bound to one leaf set of the escrow branch (§3.6 step 7). The primary holder never contributes on a reserved slot.

The members ACK on the board. A record whose `Γ` has an OR gate is valid only with an escrow certificate of a quorum of the escrow holders.

**Guardian escrow (P2 only).** A P2 charter names a guardian set `G` with keys on Midnight, and its access structure contains `user OR G` with `G` at `t_g = 3` of 5. The user shard `x_u` is escrowed to `G` as above, with `G_g` reserved ECDSA slots. The guardians ACK, and a P2 asset record is valid only with an escrow certificate of `q_g` guardian ACKs. Guardians never hold `x_f`, and `t_g − 1` of them learn nothing about the user shard. A P1 address has no escrow and nobody can seize it.

### 3.9 Recovery group backup

At genesis and after every rotation, each of the first `t` qualified committee dealers deals its share of `x_f` to `E` at threshold 3, with Feldman commitments whose constant term is implied by `Eval(X_f commitments, i)`. `E` members combine with Lagrange weights over the dealer set and hold a 3-of-5 sharing of `x_f`. The public check is that its implied constant term equals `X_f`. On a committee that anchors slot bindings (seald's `slot_anchor`, §7.7), each new ECDSA slot's committee shares reach `E` the same way before the slot is usable, with the slot key `(node_id, account-pool id, ℓ)` of each seat. `E` also holds the committee's slot-nullifier key `k_nf`, which keys the slot nullifiers of the anchor entries, so it can read the binding entries of each seat log (§4.1, §7.11). Without anchors `E` reissues no ECDSA slot (§7.11), so no ECDSA share reaches it. Schnorr nonce slots are not backed up; a successor committee makes its own.

`E` acts only on a Midnight recovery transition (§5.8). It holds no shard. `E` together with an admitted signing set holds the whole key, so fewer than three corrupt `E` members is an assumption of P1 and P2.

### 3.10 Actor nonce pools

Each actor that may contribute to a Schnorr-suite signature, including every member of a group and every escrow holder, keeps a **nonce pool**. A pool is `N_pool` pairs `(d_{a,ν}, e_{a,ν})` with points `(D_{a,ν}, E_{a,ν})`, posted on the board as one `POOL(pool_id, (D_{a,ν}, E_{a,ν})_p)` record signed by the pool key `pk_{pool,a}`. The pool key is a fresh pseudonym per pool. The actor derives a batch of `N_pk` future pool keys and registers one Merkle root over them, its **pool-key root**, in the shielded charter record: one Midnight write per batch, not per pool. `authorize` proves in zero knowledge that the key of every pool that the request names lies under a pool-key root of its actor (§5.3 statement item 3). A board observer therefore sees pools and not actors, and Midnight shows no pool key. Pool posts need no ordering guarantee beyond their presence on the board, and the committee neither checks nor claims them.

1. An actor answers at most once per pair, whatever request names it. Its software marks the pair used when it computes a contribution and erases `(d_{a,ν}, e_{a,ν})` in the same step.
2. A pair that a request named and the actor never answered stays unused. It revealed no response, so it carries no state an attacker can use.
3. An actor refills its pool before fewer than `N_h` unused pairs remain, because one request consumes one pair per half: 30 pairs at `K = 8`, `L = 2`. A pair never serves two halves, even two variants of one input on one committee slot (§4.1).
4. The initiator draws no pair from its own pool for its own contribution. It uses a fresh single nonce per half, because it computes its contribution after the commitment list is fixed (§4.2).

ECDSA needs no actor pool. An ECDSA contribution uses the per-address slot halves of §3.6.

## 4. The one move

The initiator builds every transaction of a fee grid, names a signing set `S ∈ Γ` with itself as a member, assigns each other named actor one pool pair per half (§4.1), computes its own contribution for each half, and posts one envelope. Each other named actor then makes its one move: it reads the request, recomputes every value it signs over, and posts its sealed contribution before the collection deadline `exp_c` (§5.9). Nothing else is sent before the result. In the single-user form the initiator is the holder's wallet, `S = {user}`, and the envelope is the whole request.

The algebra below is checked numerically for all eight parity cases of BIP340, with and without a script root, for Ed25519 and for ECDSA, each with AND sets of one to five actors, every subset of a 2-of-3 group, a 2-of-3 group with a nested 2-of-3 member (BIP340), both branches of `user OR G` with `G` 3-of-5, and one key signed under several signing sets. The vectors also check the slot sharing of §4.1 (several candidate halves on one committee slot, one of them completed, in two generations), the threshold PRF keys of §4.6 with their partial proofs, a contribution sealed to `P_{v,g}`, and the batch equation and small-index evaluation of §5.10 (§12, O18 keeps the test vectors in the repository).

### 4.1 Committee nonce slots

A Schnorr-suite **nonce slot** `ℓ` is a pair of committee nonces `(d_ℓ, e_ℓ)` with public points `D_ℓ`, `E_ℓ` and Feldman commitments. Each slot is the sum of `t` dealers' random polynomials, dealt on the board with the encryption and complaint machinery of line dealing (label `SL1/slot`), at epoch start and whenever the pool falls below its low-water mark. The qualified dealer set is the first `t` dealers without a valid complaint. At least one is honest, so no coalition of `t − 1` nodes knows `d_ℓ` or `e_ℓ`. The epoch pool is public: the initiator fetches unclaimed slot points from any node or from the board. The slots of one suite in one epoch form one **committee pool** with indices `ℓ = 1, 2, …` in dealing order. Each suite has its own pool, because the floor of one shared index space would pass over the unreserved slots of the less used suite. In TEE mode each node keeps its shares of a pool in its pool session `slots-s-e`, a sequential pool of seald: sealed under a session key of its seat and fenced by the peer witness (§7.4). In non-TEE mode a node keeps them in process memory and never writes them to disk.

**Dealing in batches.** A dealer posts the dealings of `B_slot` slots in one message: one ephemeral point `E`, one proof `π`, and `2·B_slot` polynomials, each with its own pad label. Node `i` decrypts its `2·B_slot` shares and checks them with one equation,

`(Σ_m r_m·share_m)·G = Σ_m r_m·Eval(C_m, i)`,

with coefficients `r_m` of 128 bits that the node draws after it holds the message and never reveals. If the equation fails, the node checks each polynomial alone, finds the bad one and posts the complaint of line dealing, which names that dealing. The rules of §5.10 apply.

**Lazy per-node commitments.** For each slot a node stores the slot points `D_ℓ`, `E_ℓ` and the summed commitment vectors of the `t` qualified dealers. It evaluates the per-node points `D_{ℓ,i}`, `E_{ℓ,i}` only when a partial must be checked, which happens when a combined signature fails (§5.6), and it caches them.

**One slot per generation and input.** A request runs at most `G = min(K, G_max)` fee generations, and `G_max = 2` is a protocol constant. The header names one slot `ℓ(g, j)` for every generation `g ≤ G` and every input `j`: `G·L` slots, which is 4 at `K = 8`, `L = 2`. Each generation selects a higher variant than the one before it (§5.6), so variant `v` can be selected in generation `g` only if `g ≤ min(v, G_max)`. Every such triple `(v, g, j)` is a **half**: the initiator and every named actor contribute to it with a nonce of its own, bound to slot `ℓ(g, j)` (§4.2). A request has `N_h = L·Σ_v min(v, G_max)` halves, 30 at `K = 8`, `L = 2`.

The committee releases one partial per slot: the partial for the ticket of the variant that the anchor of generation `g` selects. The halves of the other variants on that slot are never completed. The `K` candidate tickets on one slot give no party anything it lacks without them, because any party can already evaluate `Hq_bind` and the challenge hash for as many pairs `(R_A, pm)` as it likes. The slot may be shared among candidates because the committee's partial is computed at release and for one ticket only. An actor's nonce is not shared in this way, because its contributions are sealed in advance and the committee holds them all (§5.11). A fee bump beyond `G_max` generations is a new request with new slots.

**Reservation.** A slot is **named** by a request when the request's header, opened after ordering, lists it. The earliest request in board order that names a slot and is still live has **precedence** on it. Honest nodes refuse a later request that names a slot under the precedence of another request, even when the later request's authorization comes into force first. Precedence lapses when its request ends, or when the request's authorization is not in force by its ordering height plus `Δ_c`. A request with precedence **reserves** the slot when `q` nodes vote one header hash for it while its authorization is in force (§5.3). Those votes are the OPENED votes of a collecting request and the ADMIT votes of every other request (§5.1). The reservation holds through COLLECTING. The slot is **claimed** when that request reaches ADMITTED. A named committee slot is burned when the request that had precedence on it ends or lapses, whether a partial was released on it or not, and it never returns to the pool. Precedence by board order means that a node which reads a header after ordering cannot copy its slots into a request of its own and void the first one, and no request can void a collecting request by taking its slots after its actors have answered. A header names exactly `G·L` slots (§4.7 item 2), so an envelope that never comes into force burns at most that many committee slots. Such an envelope needs no authorization, so a spammer can burn committee slots at the cost of one ordered frame per `G·L` slots. Burning keeps the rule simple: a committee slot whose id a header showed is never dealt to another request. The pool cost of this spam is part of O34.

**ECDSA precedence.** An ECDSA slot belongs to one address, and the committee knows its id (§3.6). A request has precedence on an ECDSA slot only while its authorization is in force, and only when the slot lies under the slot root that the authorization's source opens (§5.3 item 4). Of the requests that meet both conditions and name the slot, the earliest in board order has precedence. A request whose authorization is not in force takes no precedence on an ECDSA slot. It voids no other request on that slot, and its end burns no ECDSA slot. An ECDSA slot is burned when a request that reserved it ends. Without this rule, anyone can name the slot ids of an account in envelopes that need no authorization, void the requests that use those slots and burn them. A P2 user can burn the guardian slots `G_g` that way and then stay offline, because their refill needs every session party online (§5.8). A copy of a header takes no ECDSA slot either: the copy needs an authorization in force for the same record, and Midnight accepts one `authorize` per `nf` (§5.3). Before its authorization is in force, a request releases nothing on a slot, so a slot without a reservation holds no partial and needs no burn. The proof of this rule is open item O38.

**Reservation window.** Each Midnight checkpoint records four fixed fields for each committee pool (§7.13). The **floor** `h` is the highest index that a request has reserved or that a restart burn has retired. The **pending floor** `pending_min` is the lowest index that a request live at the checkpoint holds, or `h + 1` when no request holds one. `pending_root` is a Merkle root over the sorted list of the **pending** indices, the slots of every request that is live at the checkpoint, and `pending_count` is the length of that list. The list itself stays on the board, under the board root of the same checkpoint. Indices are reserved in increasing order, so every pending index lies in `[pending_min, h]`. A header names only indices in the window `(h, h + B]` of the latest checkpoint, or pending indices of its own request. An honest node votes OPENED or ADMIT for a header only when every slot that it names meets this rule against the latest checkpoint at the time of the vote. It reads the pending list from the board and checks it against `pending_root`. A header that names an index below `pending_min`, or an index in `[pending_min, h]` that the list does not hold for its own request, never gets an honest vote, because that index was reserved by an earlier request, skipped or burned. The request ends VOID with SLOT_TAKEN. A header that names an index above `h + B` waits for a checkpoint that brings the index into the window. A node votes for no header that names a slot of a pool before a checkpoint lists that pool. An index that no request reserves before a checkpoint passes above it is lost: it falls below `h` and never binds. Initiators therefore name unclaimed indices near the bottom of the window. How they spread over the window to keep SLOT_TAKEN rare is part of O34. In TEE mode seald enforces the same bounds again at `slot_bind` (§7.7), so a node that votes wrongly still never binds such an index. seald refuses an index below `pending_min` from the checkpoint alone, and accepts an index in `[pending_min, h]` only with its membership path under `pending_root`.

**Slot states.** In a seat's session a slot is `free` from its dealing, `bound(H(tk))` once the node binds it to the one ticket that it signs (§7.7), and `burned` at the end of its request (§4.5). States only move forward. A `burned` slot holds no share and keeps its index, so no later dealing reuses the index. A named slot stays `free` until the anchor of its generation selects a ticket. A reserved slot is `free` or `bound`. A claimed slot is `bound` once its generation releases.

**Agreement on a slot's ticket.** Honest nodes agree on the one ticket of a slot because they read one board: one order of requests and one anchor per generation. Board safety holds for `|C| ≤ f`. A coalition of `f < |C| < t` corrupt nodes in non-TEE mode can certify conflicting board histories and show different honest nodes different requests on one slot, or different anchors for one request. Each history then gets `t − |C|` honest partials on its own ticket of the slot. Three histories with distinct `(ρ, c̃)` give three equations `σ_b·s_f^{(b)} = d_ℓ + ρ_b·e_ℓ + σ_b·c̃_b·x_f` and reveal `x_f`. The nonce rules of this section therefore hold against `|C| ≤ f` in non-TEE mode. In TEE mode the enclaves sign the board votes and never sign two blocks at one height, so the rules hold while the TEEs hold, within the rollback bound of §7.7. A committee that must hold them against `|C| < t` in non-TEE mode runs with `slot_anchor`: each node appends the entry `ℓ → H(tk)`, keyed by an unlinkable slot nullifier under the committee key `k_nf`, to its seat log on the board, and releases on the slot only after a Midnight checkpoint root covers the entry and no covered entry of any seat binds that nullifier to another ticket. One Midnight root gives every honest node one view, also across forked board histories. It adds no Midnight transaction: each checkpoint carries one 32-byte root per seat. It adds about one checkpoint interval plus Midnight finality to the release of each generation. This is open item O32. No authorization record carries a slot id, so it does not show the curve, the variant count or, for ECDSA, the account. The checkpoint shows the floor, the pending floor and the pending root of each committee pool, which name a suite but no request and no address (§6.4 item 16). No ECDSA slot id appears on Midnight, which holds only roots over the seat logs (§7.4).

### 4.2 BIP340 (suite 2)

For half `(v, g, j)`, which is input `j` of variant `v` in generation `g`, with committee slot `ℓ = ℓ(g, j)`, signing set `S` with initiator `a_0`, and for each other named actor `a ∈ S' = S ∖ {a_0}` its assigned pool pair `ν = ν(a, v, g, j)`:

1. The initiator picks a fresh `k_0` for this half and sets `R_0 = k_0·G`.
2. Let `pm = H_pm(x(Q) ‖ m ‖ salt)` where `m` is the BIP341 sighash and `salt = H(salt_v ‖ g ‖ j)` with `salt_v` 32 random bytes per variant, carried in capsule `v`.
3. The **commitment list** is
   `CL = R_0 ‖ (slot_a ‖ pool_id_a ‖ ν ‖ D_{a,ν} ‖ E_{a,ν})_{a∈S'} ‖ ℓ ‖ D_ℓ ‖ E_ℓ`,
   with the actors in leaf-id order. The **leaf id** of an actor is `(slot_a, gate path, member index)`: its top-level charter slot, the path of gates below it and its index in the lowest group. Two members of one group therefore have different leaf ids. Each actor's binding factor is
   `ρ_a = Hq_bind(SL1/bind-act ‖ suite ‖ epoch ‖ leaf_a ‖ CL ‖ pm)`, with `leaf_a` the actor's leaf id, and `slot_a` in `CL` stands for `leaf_a`.
4. The **aggregate actor nonce** is `R_A = R_0 + Σ_{a∈S'} (D_{a,ν} + ρ_a·E_{a,ν})`. The committee's binding factor is
   `ρ = Hq_bind(SL1/bind ‖ suite ‖ epoch ‖ ℓ ‖ R_A ‖ pm)`.
5. The nonce point is `R = R_A + D_ℓ + ρ·E_ℓ`. Let `σ = −1` if `R` has odd y, else `σ = 1`.
6. The challenge is `c = H_BIP0340/challenge(x(R) ‖ x(Q) ‖ m)`, and `c̃ = g·c`.
7. The **contributions** are, with `λ_a` the weight of actor `a`'s leaf for `S` and `x_a` its leaf secret (§2.4):
   - initiator: `s_0 = σ·k_0 + c̃·(λ_0·x_0 + tw) + c·g_Q·t_tap`,
   - actor `a ∈ S'`: `s_a = σ·(d_{a,ν} + ρ_a·e_{a,ν}) + c̃·λ_a·x_a`.
8. The **ticket** for the committee is `tk = (ℓ, R_A, pm, c̃, x(R), fee_rate, not_before)`.

The halves of all variants `v ≥ g` name the same slot `ℓ(g, j)` and differ in `k_0`, in every pool pair, and so in `R_A`, `pm`, `ρ`, `R` and `c`.

The actors' sum is `s_A = Σ_{a∈S} s_a = σ·k_A + c·(g·x_A + g_Q·t_tap)` with `k_A = k_0 + Σ_{a∈S'} (d_{a,ν} + ρ_a·e_{a,ν})`, because `Σ λ_a·x_a + tw = x_A` for every `S ∈ Γ`. In the single-user form `S' = ∅`, `R_A = R_u`, `k_0 = k_u`, `λ_0 = 1`, and `s_A` is the **user half-signature** `s_u = σ·k_u + c·(g·x_U' + g_Q·t_tap)`. The committee's binding factor and ticket are then those of the single-user form unchanged.

Each contribution is checkable against public points:

`s_0·G = σ·R_0 + c̃·(λ_0·X_0 + tw·G) + c·g_Q·t_tap·G`, `s_a·G = σ·(D_{a,ν} + ρ_a·E_{a,ν}) + c̃·λ_a·X_a`,

where `X_a` is the leaf's public point (`X_a`, `X_{γ,i}` or the escrow member point). The check needs the scalar and address knowledge. The scalars of a variant are readable only when that variant is released (§4.6), so the check runs at combine, and only when the combined signature fails (§5.6).

The committee half is `s_f = σ·(d_ℓ + ρ·e_ℓ) + c̃·x_f`. Node `i` computes the **partial**

`s_{f,i} = σ·(d_{ℓ,i} + ρ·e_{ℓ,i}) + c̃·x_{f,i}`

and any party checks it against public commitments: `s_{f,i}·G = σ·(D_{ℓ,i} + ρ·E_{ℓ,i}) + c̃·X_{f,i}`. A node recomputes `ρ` from the ticket, and `R` and `σ` from `R_A` and the slot points, and never takes `R` or `σ` from the initiator. It releases no partial for a ticket whose `x(R)` differs from the x-coordinate of the `R` it computed (§5.6). Lagrange combination of any `t` partials gives `s_f`, and

`s = s_A + s_f = σ·k + c·d`, with `k = k_A + d_ℓ + ρ·e_ℓ`.

Because `σ·k` is the nonce of the even-y point `σ·R`, `(x(R), s)` verifies under `x(Q)`. The signs combine as follows.

| Sign | Set by | Applies to | Reaches the committee as |
|---|---|---|---|
| `g_P` | y-parity of `X` | every leaf secret, `tw`, `x_f` | factor of `c̃` |
| `g_Q` | y-parity of `Q` | every leaf secret, `tw`, `x_f`, `t_tap` | factor of `c̃` |
| `σ` | y-parity of `R` | `k_0`, every actor pair `(d_{a,ν}, e_{a,ν})`, `d_ℓ`, `e_ℓ` | recomputed by the node |
| none | — | the term `c·g_Q·t_tap` | stays in the initiator's contribution |

Every actor applies the same `σ`, `g_P` and `g_Q`, because each one recomputes `R`, `X` and `Q` from the same inputs. The tweak term `c̃·tw + c·g_Q·t_tap` is placed exactly once, in the initiator's contribution. A formula without `c·g_Q·t_tap` produces a signature for `P` and not for `Q`, and fails verification for every Taproot output. A second copy of the tweak term in another contribution also fails verification.

**Binding against ROS and Wagner.** The pool pairs of every non-initiator actor are public before any message exists, as the committee's slots are. An adversary that controls the initiator and other actors may open many requests that name one honest actor's pairs. Each `ρ_a` hashes the whole list `CL` and `pm`, which fix `R_A`, hence `ρ`, `R` and `c`. So no adversary chooses `c` as a function of `E_{a,ν}` after seeing it, because `E_{a,ν}` enters `R` scaled by a hash of everything that determines `c`. The committee's `ρ` hashes `R_A`, `ℓ` and `pm`, which also fix `R` and `c`. This is the two-nonce binding of FROST (RFC 9591) and MuSig2 (BIP327), with every actor and the committee as signers. A single pre-published nonce per pair is not used, because concurrent sessions with one nonce are open to the ROS attack. The initiator needs one fresh nonce only, because it computes its contribution after `CL` is fixed and reveals `R_0` only with it. The initiator and every actor are adversaries in this argument, and the binding holds against them.

**The actor's rules.** Before it contributes, actor `a`:

1. reads the transaction of every variant from the capsules (§4.6) and recomputes every sighash `m`, `X`, `Q`, `g_P`, `g_Q`, `pm`, `CL`, every `ρ_a`, `R_A`, `ρ`, `R`, `σ` and `c` itself, from the request and from the public pool and slot points. The capsules give it each half's `R_0`, the salt seed `salt_v`, the signing set and the initiator's term point. It never takes `R`, `σ`, `c` or a weight from the initiator. It checks that `R_A` in each ticket equals the sum it computed.
2. checks that `S ∈ Γ`, that its own weight `λ_a` follows from `S`, and that the pairs named for it are unused pairs of its own pool, a different pair for every half.
3. checks the transactions against its own policy. The actor is a party to the request and may refuse it.
4. answers once per pair (§3.10) and never after `exp_c`.

**What the ticket hides.** The ticket carries no `X`, `Q`, `m`, `t_tap`, actor point or pool point. `c̃` is a hash output times a sign. `R_A` is a sum that contains a fresh uniform point. `pm` is a salted hash. `x(R)` is the x-coordinate of `R_A + D_ℓ + ρ·E_ℓ`, which the node computes from the other fields and the slot points in any case, so the field adds nothing to what the node sees. It is in the ticket for the ticket proof of §5.3, which then proves hashes only. `R` appears on the host chain, so a node that keeps `R` can link the ticket to the host transaction after broadcast (§6.4). `c̃` is not salted: a node that can list the candidate pairs `(x(Q), m)` of a request, such as a known input paid to one of two known destinations, computes `±H_BIP0340/challenge(x(R) ‖ x(Q) ‖ m)` for each candidate and finds the one that matches. The ticket hides the address and the message only from a node that cannot enumerate them (§6.4).

### 4.3 Ed25519 (suite 3)

The same slot, commitment list, binding factors and nonce: `R = R_A + D_ℓ + ρ·E_ℓ`, with `pm = H_pm(X ‖ M ‖ salt)`. Edwards points need no parity rule. With `c = SHA-512(R ‖ X ‖ M) mod ℓ`:

`s_0 = k_0 + c·(λ_0·x_0 + tw)`, `s_a = d_{a,ν} + ρ_a·e_{a,ν} + c·λ_a·x_a`, `s_{f,i} = d_{ℓ,i} + ρ·e_{ℓ,i} + c·x_{f,i}`, `s = Σ_{a∈S} s_a + s_f`.

Verification `[s]B = R + [c]X` holds because `x = x_f + tw + Σ_{a∈S} λ_a·x_a`. In the single-user form `s_0 = s_u = k_u + c·x_U'`. The ticket carries `c̃ = c` and the 32-byte encoding of `R` in place of `x(R)`. Clamping applies to seed-derived keys only and plays no role: every scalar here is uniform mod `ℓ` and the signature equation uses the scalar directly.

### 4.4 ECDSA (suite 1)

For input `j` of variant `v`, the initiator takes an unused slot `ℓ` with `R_ℓ = k·G`, `r = x(R_ℓ) mod N_s`, and `h` the message hash (BIP143 sighash, or the Keccak-256 of the EIP-1559 payload). Each actor `a ∈ S` contributes from its slot halves `(w_a, μ_a)` (a group member: its Shamir shares, an escrow holder: its escrow shares):

`s_a = λ_a·(h·w_a + r·μ_a)`, checked by anyone as `s_a·R_ℓ = λ_a·(h·W_a + r·M_a)`,

with `W_a`, `M_a` the leaf's points in base `R_ℓ` (for a group member `Eval` of the group's commitments, for an escrow holder `Eval` of the escrow dealing's commitments of §3.8). The slot record of every node holds those commitments keyed by leaf id, so the combiner can check every contribution, including an escrow holder's. The tweak needs no separate term, because the session folded `tw` into party 1's halves (§3.6). The ticket is `tk = (ℓ, h)`. Node `i` computes `s_{f,i} = h·w_{f,i} + r·μ_{f,i}`, checked as `s_{f,i}·R_ℓ = h·Eval(W_f, i) + r·Eval(M_f, i)`. The sum is

`s = Σ_{a∈S} s_a + s_f = h·k⁻¹ + r·k⁻¹·x = k⁻¹·(h + r·x)`,

an ordinary ECDSA signature. In the single-user form `s_u = h·w_u + r·μ_u`. The combiner normalizes to low `s` and computes the Ethereum `yParity` from the y-parity of `R_ℓ`, flipped when `s` was negated, as in line dealing.

A slot signs one message. Two contributions on one slot with hashes `h ≠ h'` give two equations in `(w_a, μ_a)` and reveal both, and with every other half reveal `k` and `x`. The initiator therefore assigns one slot per `(variant, input)` from the slots bound to the leaf set of `S`, every actor refuses a second message on a slot and a slot whose leaf set `T_ℓ` differs from that of `S` (§3.6 step 7), and honest nodes refuse a second claim on the board. The actors' rule holds against a fully corrupt committee. The board rule does not. The slot sharing of §4.1 does not apply to ECDSA: a request keeps `K·L` ECDSA slots and `K·L` halves, one per `(variant, input)`, and a variant uses its own slots in whichever generation selects it.

### 4.5 Nonce hygiene

1. `k_0` is fresh for every initiator contribution, drawn from the OS generator and hedged with a hash of `(x_0, tw, ℓ, m)`. Pool pairs are drawn the same way at pool creation.
2. Every `R_A` and every ECDSA `R_ℓ` in an envelope is distinct, and so are its committee slots `ℓ(g, j)`. A node rejects an envelope that repeats one. In TEE mode the enclave also rejects an envelope that names one actor pair twice.
3. A Schnorr committee slot serves one `(generation, input)` of one request and signs one ticket. An ECDSA slot serves one `(variant, input)` of one leaf set, and unselected variants burn their ECDSA slots.
4. A committee slot is burned when the request that had precedence on it ends FINAL, VOID or EXPIRED or its precedence lapses, used or not. An ECDSA slot is burned when the request that reserved it ends (§4.1). A burned slot never returns to the pool, and its index never takes a share again.
5. Nodes erase a slot's shares when the request ends FINAL, VOID or EXPIRED. In TEE mode the node calls `slot_burn`, which removes the share from the session and seals a new version. Peers then refuse the session key of every older version, so the share does not open again from an old record within the bound of §7.7.
6. In TEE mode no partial on a slot leaves a node before `slot_bind` has fixed the slot to the one ticket that the node signs (§7.7). After a restore the node releases on a `bound` slot again only for the same ticket, which repeats the same partial.
7. In TEE mode an ECDSA committee share goes into a slot once. Its put entry, once a Midnight checkpoint root covers it, stops a second put of the same share, also after a rollback of every disk (§7.4).
8. An actor answers at most once per pool pair and never after `exp_c` (§3.10). It erases the pair when it answers.
9. No actor nonce serves two halves. The initiator draws a fresh `k_0` per half and every other actor uses one pool pair per half, because all contributions are sealed in advance and the committee holds them, and two of them on one nonce give the shard by subtraction.

### 4.6 The envelope

Every request type travels in one fixed-size frame of 16,384 bytes. The frame size is the only public size class at launch. The frame is padded to its class with random bytes under the AEAD.

```
Envelope (16,384 bytes)
  pub (public, 96 bytes)
    version        1      0x01
    epoch          4
    keylist_hash  32      H of the epoch's PK_i list
    exp            8      board height after which the envelope is void
    size_class     1      0x00 = 16 KiB
    auth_ref      32      Midnight authorization id (random for BIRTH, slot refill, CONTRIB and P0)
    reserved      18
  outer dealing of κ_0 (n = 9: 748 bytes), the only dealing in the envelope
    commitments   t·33    Feldman commitments of κ_0's polynomial in base G
    ciphertexts   n·32    line-dealing share ciphertexts to PK_i
    E             33      ephemeral point of the encryption
    π            196      encryption proof (line dealing §3.3)
  body_0         AEAD(k_hdr, header)
  var_{v,g}      AEAD(k_{v,g}, variant body)   for each variant v and generation g ≤ min(v, G)
  cap_v          AEAD(ck_v, capsule v)         for each variant v
  padding        random to 16,384 bytes
  act_a          HPKE(AK_a, actor capsule a)   for each a ∈ S', at fixed
                 positions counted from the end of the frame
```

The public part names no chain, suite or variant count, so ordering is blind to the request type. `hd = H(pub* ‖ commitments ‖ ciphertexts ‖ E ‖ body_0 ‖ var… ‖ cap… ‖ tail)`, where `pub*` is `pub` with `auth_ref` set to zero and `tail` is the padding with the actor capsules in it. `hd` covers everything except `π` and `auth_ref`. `auth_ref` is outside `hd` because the Midnight authorization commits to `hd`. The envelope id is `eid = H(hd ‖ auth_ref)`, and the encryption proof binds `eid` as its context. The wallet computes `hd`, then `auth`, then `π`, so nothing is circular. A party that rewrites `auth_ref` in a posted envelope has no proof for the new `eid`, so the copy fails the public checks. An envelope with no authorization carries 32 random bytes in `auth_ref`, so the field does not show the request type.

**One polynomial, and keys by threshold PRF.** The envelope deals `κ_0` and nothing else. Let `dd = H(pub* ‖ commitments ‖ ciphertexts ‖ E)` be the digest of the outer dealing and `H_c` a hash to the curve. For a label `lab`, the **PRF point** is

`Z_lab = κ_0·H_c(dd ‖ lab)`.

Node `i` holds the share `κ_{0,i}` and computes the **PRF partial** `Y_{i,lab} = κ_{0,i}·H_c(dd ‖ lab)`. Any `t` partials combine with Lagrange weights to `Z_lab`. This is the threshold PRF of §7.4 on secp256k1. Nobody reconstructs `κ_0`. The initiator knows `κ_0` and computes every key itself. The keys are

- `k_hdr = KDF(Z_hdr)` for `body_0`,
- for variant `v` in generation `g`, from `Z_{v,g}`: the body key `k_{v,g} = KDF(Z_{v,g} ‖ "body")`, the contribution secret `y_{v,g} = Hq(Z_{v,g} ‖ "ctb")` and the contribution public key `P_{v,g} = y_{v,g}·G`.

The labels are `hdr` and `(v, g)`. An ECDSA request has one body per variant, with label `(v, 0)`. `dd` is used in place of `hd` because `hd` covers the bodies and the bodies are encrypted under these keys. Because `dd` is inside `H_c`, a partial opens keys of one outer dealing only. An envelope that copies an outer dealing under other bodies has another `hd` and needs a proof `π` for its `eid`, which needs the ephemeral secret of the dealer. Honest nodes release partials only for an envelope whose `π` verified and whose QC exists.

A partial is checked only when something fails. The receiver combines `t` partials and tries the AEAD. If the tag fails, it asks the senders for the Chaum-Pedersen proofs `DLEQ(G, Eval(C, i); H_c(dd ‖ lab), Y_{i,lab})`. The challenge of a proof hashes the label `SL1/dleq`, `dd`, `lab`, `i`, the whole statement `(G, Eval(C, i), H_c(dd ‖ lab), Y_{i,lab})` and both commitments. A challenge without `Y_{i,lab}` lets a shareholder build a proof for a false partial before it picks the partial. The receiver verifies the proofs against the outer commitments, drops each bad partial and combines again. If `t` proved partials still fail the tag, the dealer is at fault and the request ends VOID.

The **header** inside `body_0` holds:

- request type (spend, birth, slot refill, exit, P0 line-dealing spend, contribution).
- `K`, `L`, the generation count `G`, and the slot `ℓ(g, j)` of every generation and input.
- for every half `(v, g, j)`: the ticket (Schnorr suites 149 bytes: `ℓ` 4, `R_A` 33, `pm` 32, `c̃` 32, `x(R)` 32, fee rate 8, `not_before` 8; ECDSA 36 bytes: `ℓ` 4, `h` 32).
- the **actor slot table**: the count `|S'|`, the collection window `Δ_c`, and for each `a ∈ S'` its position `1..|S'|` in this request (not its charter slot), the commitment `H(τ_a)` of its contribution token, and on ECDSA its session party index (the weight follows from the signing set, §2.4 rule 3).
- the intent commitment `ic` and the randomness `r_tkc` of the ticket commitment, so that every node recomputes `tkc` from the tickets and checks `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)` against the record of `auth_ref`. `ic` is hiding, so it shows nothing of the intent. A contribution that arrives before the post is embedded here instead (its sealed scalars and token), so that the request needs no collection.
- when `S'` is not empty: the contribution public key `P_{v,g}` of every variant body.
- the selection rule: the fee ladder order and the rule "first variant whose fee rate meets the anchored median, else the highest".
- in TEE mode v1: the intent, `X`, the leaf root, the commitment randomness `r_ic` and the salt seeds `salt_v`, so the enclave recomputes every sighash, every `pm` and every `c`, and for each `a ∈ S'` the weighted leaf point `λ_a·X_a` and its pool pair ids, so the enclave can check every contribution at release (§4.2).

The **variant body** `(v, g)` holds the initiator's scalars `s_{0,v,g,j}` for `j = 1..L` and the capsule key `ck_v`. It is `32·L + 48` bytes with its tag. The committee derives `k_{v,g}` only for the variant that generation `g` selects, so the scalars of every other body stay sealed, and a capsule opens in whichever generation selects its variant.

Each **capsule** `v` holds the unsigned transaction bytes and prevouts of variant `v`, the initiator's nonce `R_0` (Schnorr) or the slot point `R_ℓ` (ECDSA) of each of its halves, the salt seed `salt_v` and the destination record. It also holds the initiator's term point `T_0 = λ_0·X_0 + tw·G`, the signing set `S` with its initiator by leaf id, and for each `a ∈ S'` its pool id, its pair index per half and its weighted leaf point `λ_a·X_a`. A reader recomputes each half's `R` from `R_A` and the slot points. The capsule key `ck_v` is 32 random bytes that the initiator picks. A combiner reads `ck_v` from the variant body of the released variant, so only that capsule is ever readable by the committee, and the combiner can then check every contribution of §4.2.

Each **actor capsule** `act_a` is an HPKE ciphertext to the actor's request key `AK_a`. It holds the header key `k_hdr`, the position of `a`, the token `τ_a`, and the `K` capsule keys `ck_v`. With them the actor reads the header and every capsule, which is the whole request. It does not hold `κ_0`, so it derives no variant body key: it reads neither `s_0` nor another actor's contribution. The initiator tells each actor `hd` and its position through the charter's notification channel. An actor without it trial-decrypts the positions of new frames, one X25519 operation per position. The padding is random, so the number of actor capsules is not visible.

**A sealed contribution.** An outside actor deals no contribution. For each variant body `(v, g)` it picks an ephemeral scalar `e`, and its contribution to that body is

`(E_{a,v,g} = e·G, AEAD(KDF(e·P_{v,g} ‖ E_{a,v,g} ‖ dd ‖ position ‖ v ‖ g), s_{a,v,g,1} ‖ … ‖ s_{a,v,g,L}))`,

`49 + 32·L` bytes. The context is the outer-dealing digest `dd`, not `hd`: an embedded contribution sits inside `body_0`, which `hd` covers, so a key bound to `hd` would depend on its own ciphertext. `dd` is fixed before any body is built, and the initiator gives it to an actor that contributes before the post. The committee opens it with `y_{v,g}·E_{a,v,g}` once it has derived `y_{v,g}`, which happens only for a released variant. An actor cannot check that `P_{v,g}` is the PRF key of its label, because it does not hold `κ_0`. The combiner checks `y_{v,g}·G = P_{v,g}` at release, and a mismatch ends the request VOID and names the initiator (§6.4 item 10).

A **contribution frame** is an ordinary envelope of request type CONTRIB (0x06) with its own outer dealing of a fresh `κ_c` and 32 random bytes in `auth_ref`, as every envelope without an authorization carries. A zero `auth_ref` would mark the frame as a contribution. That dealing is the one polynomial every envelope has, and it keeps the frame's public shape equal to every other frame's. Its header, under the frame's own `k_hdr`, holds the target `hd`, the actor's position, `τ_a` and the sealed contribution to every variant body. An embedded contribution is the same sealed contribution inside the request's header, with no frame and no dealing.

**Sizes.** A P2TR request with `K = 8`, `L = 2` has 30 tickets (4.5 KB), 15 variant bodies (1.7 KB), 8 capsules of at most 465 bytes plus tag (3.8 KB; each grows by `39` bytes and 2 bytes per half per other actor), the outer dealing (0.75 KB), the public part and the header's fixed fields with `ic` and `r_tkc` (0.33 KB). The total is about 11.1 KB at `n = 9`, inside the frame. At `n = 17`, `t = 12`, only the outer dealing grows, to 1,169 bytes, and the same request is about 11.5 KB. The frame holds the full grid `K = 8`, `L = 2` at both committee sizes. Larger requests use the second size class (64 KiB), added only when the board can carry it, so that its anonymity set is not empty.

**Sizes per actor.** Each actor of `S'` adds an actor capsule of `97 + 32·K` bytes, 33 bytes to the header (35 on ECDSA), and `39·K + 2·N_h` bytes to the capsules (pool id, charter slot, pair indices, weighted leaf point), and in TEE mode a further `33 + 4·N_h` header bytes. A request with any other actor also carries the 33-byte key `P_{v,g}` of every body once. At `K = 8`, `L = 2` an actor costs 758 bytes (911 in TEE mode), so the frame holds `|S| ≤ 7` (6 in TEE mode) at `n = 9` and `|S| ≤ 6` (5) at `n = 17`. At `K = 8`, `L = 1` it costs 728 bytes (821), and the frame holds `|S| ≤ 11` (10) at `n = 9` and `|S| ≤ 10` (9) at `n = 17`. Larger signing sets use a smaller grid or the second size class. The ticket does not grow with `|S|`. A contribution frame uses 2.8 KB of its 16 KiB at `K = 8`, `L = 2` and `n = 9`, and 3.2 KB at `n = 17`. An embedded contribution costs 1.7 KB at `K = 8`, `L = 2` in place of the actor capsule, so the frame embeds two. On Ethereum (`K = L = 1`) an envelope embeds the contributions of more than 70 other actors. These figures come from `vectors/sizes.py`.

**P0 inside the frame.** A P0 holder uses the same frame. `body_0`, under `k_hdr`, carries the sealed line dealing of line dealing §3 for each variant (the owner's full line, its commitments and per-node ciphertexts) and the capsules. Those dealings are line dealing's own and stay. The committee runs the line-dealing protocol after OPENED. P0 gains blind ordering. It gains no co-custody and no exit guarantee, because the owner holds `x`.

### 4.7 Checks before ordering, after opening and at release

Before ordering, any node checks the envelope's public shape: the frame size, the version, the epoch and keylist hash, `exp`, and `π` against `hd` (line dealing encryption proof), and that no earlier envelope of the epoch has the same outer-dealing digest `dd`. An envelope that fails is not ordered. The `dd` rule stops a dealer from putting one outer dealing under two sets of bodies: both would share every PRF key, so the release of a variant of one would open the same label of the other. Nothing inside `body_0` is checked before ordering, because nothing inside is readable.

At the QC, before it sends its header partial, each node checks its own share of `κ_0` against the outer commitments. A node whose share fails posts the public complaint of line dealing with the decrypted share and a DLEQ proof of correct decryption, and sends no partial. A verified complaint and `f + 1` VOID posts void the envelope, unless it is ordered after the first ADMIT vote: then it records the dealer's fault and voids nothing (§5.6). The envelope has no other dealing to check.

After the header opens (§5.2), each node checks:

1. `body_0` decrypts under `k_hdr`.
2. The header is well formed: the ticket count equals `N_h` for its `K`, `L` and `G`, every half names the slot `ℓ(g, j)` of its generation and input, and the bodies and capsules have the lengths the header implies.
3. This request has precedence on every slot it names (§4.1), and all points are distinct (§4.5). A node that finds a named slot under the precedence of an earlier live request posts VOID with reason SLOT_TAKEN.
4. TEE mode: the enclave recomputes every sighash from the intent and checks, for every ticket, `pm` and the challenge `c̃` against the ticket's own `x(R)` (Schnorr suites) or `h` (ECDSA). These are hashes only.
5. The authorization of §5.3 is in force and commits to `hd` and the ticket commitment `tkc`.
6. Contributions (§5.9): each contribution frame names the `hd` of a request, a slot of its actor slot table, and a token that opens `H(τ_a)`, and it carries one sealed contribution of the right length for every variant body. A node keeps the first such frame per slot in board order and ignores the rest. A node holds a frame whose target is not yet OPENED until the target opens, and ignores a frame ordered after `exp_c`.

**Checks at release.** A check that concerns one variant runs when that variant is released, because a wrong ticket or a wrong scalar on an unselected variant harms nobody.

7. For each ticket of the selected variant and generation, the node recomputes `ρ`, `R` and `σ` from `R_A` and the slot points and compares its `x(R)` with the ticket's. On ECDSA it recomputes `r` from the slot record. A mismatch makes every honest node refuse the release and post VOID.
8. At combine, and only if the combined signature fails: each contribution against its equation, `s_0·G = σ·R_0 + c̃·(λ_0·X_0 + tw·G) + c·g_Q·t_tap·G` and `s_a·G = σ·(D_{a,ν} + ρ_a·E_{a,ν}) + c̃·λ_a·X_a` on Schnorr suites (in the single-user form `s_u·G = σ·R_u + c̃·Y_A + c·g_Q·t_tap·G`, because `c·g·Y_A = c̃·Y_A`), and `s_a·R_ℓ = λ_a·(h·W_a + r·M_a)` on ECDSA with `W_a`, `M_a` from the slot record; and each committee partial against the per-node commitments.

A scalar is readable only at release, so a wrong contribution is found there, in both modes. It ends the request: the slots it reserved are burned and the initiator reissues (§5.9). Finding a wrong contribution before ADMIT is open item O21.

## 5. Committee processing

### 5.1 States

One state machine serves both modes and all three profiles. A profile changes only the authorization sources of §5.3 and adds the hold check of §5.5 for P2.

| State | Entered when | Evidence |
|---|---|---|
| POSTED | a node accepts the envelope after the public checks of §4.7 | board mempool |
| ORDERED | the board commits the envelope in a block with a quorum certificate. Each node then checks its share of `κ_0` and sends its header partial to its peers in the same step | QC over the block |
| OPENED | a node combines `t` header partials and decrypts `body_0`. A request with no collection has no OPENED post: its ADMIT vote carries `H(header)`. For a collecting request `q` nodes vote OPENED with `H(header)` once the authorization is in force, which reserves its slots | `q` votes with one header hash |
| COLLECTING | the header names actors whose contributions are not embedded; ends when every slot of the actor slot table holds a contribution | contribution frames, ordered and opened |
| ADMITTED | `q` nodes vote ADMIT after the checks of §4.7 and §5.4 and, for a request with actors, after collection. Each ADMIT vote carries `H(header)` and the node's OBS report for generation 1 | `q` ADMIT votes with one header hash |
| ANCHORED(g) | generation 1: with ADMITTED, from the OBS reports of the first `q` ADMIT votes. Generation 2: the board commits the OBS set of line dealing | OBS anchor |
| RELEASED(g, j) | `t` nodes release their PRF partial for the variant body `(j, g)` and their signature partials on the slots `ℓ(g, ·)`, for the variant `j` that the rule selects at anchor `g` | witnessed release records |
| FINAL | `q` nodes observe the host transaction at the confirmation depth of the chain | `q` FINAL votes with `Enc_{k_fin}(txid)` |
| VOID | `f + 1` VOID posts (a share complaint verified, an authorization refused, a revoked authorization before any release, a failed release check, a failed contribution, SLOT_TAKEN: a named slot is under the precedence of an earlier live request (§4.1), or STALLED: `exp_c` passed with a slot of the actor slot table empty) | VOID posts |
| EXPIRED | `exp` passes with no FINAL | board height |
| RELEASED (settlement) | a VOID or EXPIRED request on which a partial was released; the Midnight record stays locked to the pinned input (§5.6) | the RELEASE votes or witnessed `release` entries |

**Board votes.** A node signs once per board block. Its **vote** covers the block and the list of the node's posts for that block: `(eid, kind, digest)` triples for ACK, OPENED, ADMIT with OBS, RELEASE and FINAL across all requests. The quorum certificate of a block is `q` votes, and a node verifies them as one Ed25519 batch. The certificate is not an aggregate signature (§5.11). Complaints and VOID posts stay individually signed, because they void a request and any party verifies them. Shares, PRF partials and signature partials travel on the attested peer channel (TEE) or the authenticated node channel (non-TEE) and carry no signature of their own. Each is checked against a public commitment or by the final signature.

The normal path of a request with no collection has two board commits: the commit that orders the envelope and the commit that carries its ADMIT votes. A collecting request adds the commit of its OPENED votes and the commits of its contribution frames.

### 5.2 Ordering and opening

1. A node that receives an envelope runs the public checks and gossips it. The board leader includes it in the next block.
2. **Share check and partial, in one step.** At the QC, each node decrypts its share of `κ_0` from the outer dealing and checks it against the commitments. If the share is good, the node sends its header partial `Y_{i,hdr} = κ_{0,i}·H_c(dd ‖ hdr)` to every other node at once and records ACK in its next vote. It does not wait for other ACKs. A node whose share fails posts the public complaint of line dealing and sends no partial. No partial leaves a node before the QC that orders its envelope.
3. **Header key.** Any `t` partials combine to `Z_hdr`, and `k_hdr = KDF(Z_hdr)`. The node decrypts `body_0`. If the tag fails, it runs the proof fallback of §4.6.
4. The node runs the checks of §4.7. Different header hashes from honest nodes cannot occur, because `body_0` is fixed under `hd`.

A node that sends its partial without waiting for `q` ACKs may help open an envelope that a valid complaint later voids. The nodes then know the header of a void envelope. Only the dealer of a malformed envelope is exposed in this way.

There is no lock round. Selection is a deterministic function of the anchored fee median and the selection rule in the header, so every honest node selects the same variant at the same anchor.

### 5.3 Authorization on Midnight

The initiator (or the companion that proves for it) submits `authorize` to the `FenrirAssets` contract and posts the envelope at the same moment. The call publishes

`auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)`

where `ic` is a hiding commitment to the intent (inputs, outputs, fee ceiling), `tkc` a hiding commitment to the ticket list padded to 32 entries, `nf` the nullifier of the asset record's current state, and `rh` the hold handle (§5.5). `authorize` publishes `auth`, `nf`, `rh` and the proof, and nothing else. A reissue's call also carries the VOID leaf of its stalled request with `q` signatures (§5.9). One circuit serves every suite, profile and variant count, so the record shows none of them. The contract checks the proof of the following statement and moves the asset record to PENDING.

The wallet knows `auth` before it submits anything, so `auth_ref` is in the envelope, and the board orders and opens the envelope while Midnight finalizes. Only the votes that reserve slots and admit the request wait for the authorization. An authorization is **in force** for a node when the `authorize` transaction is final on Midnight, or, for a board-first charter, when the conditions at the end of this section hold. No node votes ADMIT and no node releases before the authorization is in force. Inclusion on Midnight without finality does not count, because a signature released to a host chain cannot be recalled.

**Statement (all profiles):**
1. The asset record committed under `cm_addr` exists and is unspent (`nf` is fresh), or is RELEASED and the intent spends the pinned input or nonce of its released request (§5.6). A record that is the successor of a settled request exists once its settlement counts (§5.6): the proof shows the settlement leaf of that request under a landed `settle_root`, or the call carries the VOID settlement of that request (§5.9). The cost of this item is open item O37. A P1 or P2 record has a birth certificate. A P0 record has a registration signed by the owner's existing key.
2. The intent's inputs belong to that record and the outputs respect the fee ceiling.
3. Exactly one of the charter's **admitted sources** authorizes the intent, and every **check** that applies to that source passes. For P1 and P2, the intent names the signing set `S` and the initiator, `S` satisfies the charter's `Γ`, and the initiator belongs to `S`. The key of every pool that the intent assigns to an actor of `S` lies under a pool-key root of that actor (§3.10).

| Source | P0 | P1 | P2 |
|---|---|---|---|
| Owner or initiator: a signature over `ic` by the Midnight spend key of an actor the charter admits as initiator (the owner in the single-user form) | yes | yes | yes |
| Seizure order: a settled registry order pays the record to `D_reg` | — | — | yes |
| Recovery exit: a spend to `D_exit` after a recovery transition (§5.8) | — | yes | yes |

| Check | Applies to | P0 | P1 | P2 |
|---|---|---|---|---|
| Owner-chosen covenant predicates (spend limits, destination allow-lists, time locks) | owner or initiator source | — | if the owner chose them | yes |
| Owner-chosen approver signatures or vetoes | owner or initiator source | — | if the owner chose them | yes |
| Registry blacklist: no output is a blacklisted destination | owner or initiator source | — | — | yes |
| Hold accumulator: the record's tag is not in the hold set | owner and recovery sources | — | — | yes |

A P1 recovery exit has no checks. That is the unconditional exit of P1.

4. `tkc` opens to the tickets of the intent's variants and inputs. On ECDSA, every ticket's slot `ℓ` lies in the record's slot root: the asset record commits at birth and at each refill the roots `slr_own` of the owner's slots and, in P2, `slr_G` of the slots reserved for `G`, each certified by `q` committee signatures. The owner and recovery sources open slots only under `slr_own`, the seizure source only under `slr_G`. An Ethereum message hash does not contain the sender, so without this item an owner could authorize a spend on one record and name a slot of another, held record.
5. **Non-TEE mode only (v2): the ticket proof.** For each ticket the proof shows two hash relations over committed values,
   `pm = H_pm(x(Q) ‖ m ‖ salt)` and `c̃ = g·H_BIP0340/challenge(x(R) ‖ x(Q) ‖ m)`,
   where `m` is the sighash of the variant's transaction under the committed intent and `x(R)` is the ticket's own field. The Ed25519 analogue is `c = SHA-512(R ‖ X ‖ M) mod ℓ` with the ticket's encoding of `R`, and the ECDSA analogue is the message hash `h`. It shows a node that the address-free ticket it signs is the challenge of an admitted transaction.
   The proof holds no curve arithmetic, because `ρ` and `R` never enter it. The node recomputes `ρ` and `R = R_A + D_ℓ + ρ·E_ℓ` itself and releases nothing for a ticket whose `x(R)` differs (§4.7 item 7). Both relations are needed. Without the `pm` relation an initiator could hold `R` fixed and search over messages, which reopens the ROS attack that `ρ` closes.
   The relations are one PLONK circuit of Midnight's proof library (midnight-zk, KZG on BLS12-381) at `k = 18`, built from the library's own SHA-256, SHA-512 and Keccak gadgets. The circuit shares the sighash prefixes and midstates that the variants of one request have in common (§11.4). There is no STARK and no wrap, and Midnight needs no new verifier. Host-chain sighashes stay SHA-256, SHA-512 or Keccak. Poseidon2 serves only protocol-internal hashes, such as `H_pm` and the commitments `ic` and `tkc`.
   Whether a Compact contract can call the hash gadgets is open item O25. If it cannot, the fallback proves the same two relations in a KoalaBear STARK with Poseidon2 commitments, aggregates the proofs and wraps the result once in a BLS12-381 circuit that Midnight verifies, at `k ≤ 21`.

In TEE mode v1 the statement stops at item 4. The enclave recomputes every sighash and every challenge from the intent in the header and checks it against the tickets.

A P0 authorization proves items 1 to 3 with the owner key as its only source. A P0 charter may also skip `authorize` and use line dealing without Midnight.

Midnight rejects a second `authorize` on the same `nf`. That is the single-spend rule for one asset record state. Slot uniqueness is a board rule (§4.1).

**Board-first authorization (charter option).** A charter of profile P0, or a P1 charter whose predicates read no mutable Midnight state, may set `board_first`. The eligible P1 predicates are the owner or initiator source with fixed destination allow-lists, time locks and approver signatures checked inside the proof. For a request of such a charter:

1. The initiator posts the `authorize` call itself to the board next to the envelope: the proof and its public inputs `auth`, `nf` and `rh`, and the Midnight state root it was proved against.
2. Each node verifies the proof and checks that the root is a finalized Midnight root not older than the charter's bound minus one checkpoint interval and `F_M`, so that the checkpoint that carries the call still lands within the bound. It checks that `nf` is unused: no leaf of a landed `bf_root` holds it, and the node holds those leaves from the board archive and checks them against the roots. For a reissue it also checks the `q` signatures on the carried VOID leaf of the stalled request (§5.6). In TEE mode the enclave runs the verifier.
3. The board orders the call. A node records `nf` in its pending set only after the proof verifies, so a copied `nf` under an invalid proof blocks nothing. A second verified call with the same `nf` is refused in board order. The pending set holds the `nf` of each call that the board ordered after the latest landed checkpoint. It lives on the board and is part of the rotation handover. No checkpoint carries it.
4. The authorization is in force for a node once the node has verified the call and the board has ordered it as the first call for its `nf`. The request waits for no Midnight finality.
5. The committee submits no Midnight transaction per call. The next checkpoint carries `bf_root`, a Merkle root over the tuples `(auth, nf, rh, root)` of the board-first calls that the board ordered in the interval. The ordering blocks and their QCs stay on the board. `bf_root` is also the nullifier root of those calls. `FenrirAssets` accepts no direct `authorize` for a record of a board-first charter. Such a record changes only through the `bf_root` of a landed checkpoint, so a direct call cannot race the board. A checkpoint signer signs `bf_root` only when no two of its leaves hold one `nf` and no leaf holds an `nf` of an earlier landed `bf_root`. Duplicate `nf` values are therefore refused at three places: the node check of step 2, board order in step 3 and the checkpoint signers. The contract holds roots and not nullifiers, so it does not check them. Settlement follows §5.6.

Board-first is forbidden for P2 and for every charter with a cumulative limit, a veto or any other predicate over state that other requests change. A hold authority revokes on Midnight and cannot revoke an authorization that is not there. Two requests proved against one finalized root would both pass a cumulative limit that only one of them meets.

### 5.4 Admission

A node votes ADMIT only when all hold:

1. The checks of §4.7 after opening pass, including item 6 for every slot of the actor slot table.
2. The authorization `auth_ref` is in force (§5.3), and `auth` opens to `hd` and to the `tkc` of the header. This request has precedence on every slot of the header (§4.1), and the vote reserves the slots it does not yet hold.
3. The authorization is not revoked (P2: a hold authority can revoke a PENDING authorization, §5.5).
4. TEE mode: every recomputed sighash and challenge matches its ticket, every transaction pays only outputs of the intent, and every ECDSA slot of the header belongs to the address `X` of the intent.

The ADMIT vote carries `H(header)`, which also serves as the node's OPENED, and the node's report `OBS(eid, 1, 1, h)` with the height `h` of its finalized host tip. The first `q` ADMIT votes in board order with one header hash move the request to ADMITTED and claim its slots. Their OBS reports are the OBS set of generation 1, and the anchor height is entry `f + 1` of them, as in line dealing §3.6. An OBS report counts only if the request reaches ADMITTED. A node that sees a failed condition posts VOID with the reason. `f + 1` VOID posts void the request.

### 5.5 Hold check (P2 only)

The hold handle `rh` is a fresh key-private ElGamal encryption of the record's hold tag to the charter's hold key `PK_H`. Key privacy makes every `rh` indistinguishable from every other, whatever the charter. A P0 or P1 charter has a hold key derived by hash-to-curve from the charter id, whose discrete log nobody knows, so its handles have the same shape and nobody can open them. The hold authority trial-decrypts every new `rh` of its charters. To freeze a pending spend it posts `revoke(auth_id)` together with `SetHold(tag)` on Midnight. `SetHold` adds the tag to the hold accumulator, so later authorizations for that record fail item 3 of the statement.

Before each release, a node checks on Midnight that `auth_ref` is not revoked, at a finalized Midnight height at least as new as the Midnight heights reported with the generation's OBS set (each OBS report carries the node's finalized Midnight height beside its host height). A P2 charter sets `Δ_hold` Midnight blocks (launch value 2): generation 1 is released only once the authorization has been final for `Δ_hold` blocks, so the hold authority has a window to read `rh` and finalize `revoke`. A revoked authorization moves the request to VOID if nothing was released, and stops further generations otherwise.

In TEE mode the enclave makes this check, so it binds every operator while the TEE holds. In non-TEE mode `t` colluding nodes can release variants already dealt to them and ignore a revocation. A P0 or P1 charter has no hold authority, nobody can revoke its authorizations, and the check passes by construction.

### 5.6 Select, witness, release, combine, broadcast and erase

For each generation `g ≤ G`:

1. **Anchor.** Generation 1 takes its anchor from the ADMIT votes (§5.4). Generation 2 takes it from an OBS set that the board commits as in line dealing §3.6. Each node computes the median fee rate and selects variant `j_g` by the header's rule. Nodes compare only `j_g`, never the fee rate of a ticket, with the anchor.
2. **Hold check** (P2): §5.5.
3. **Release checks.** The node runs item 7 of §4.7 on the `L` tickets of `(j_g, g)`: it recomputes `ρ`, `R` and `σ` and compares `x(R)`. If a ticket fails, the node releases nothing and posts VOID.
4. **Witness.** Before it releases anything, a TEE node records `release(node, eid, g) → (j_g, H(tk_1 ‖ … ‖ tk_L))` at `w` peers and waits for `w` acks. It then binds each slot `ℓ(g, j)` to `H(tk_j)` with `slot_bind`, which witnesses the `slot` entry and seals the `bound` state (§7.7). A non-TEE node records RELEASE(eid, g, j_g) in its vote. A node never releases two different variants for one generation, and never computes a partial for two tickets on one slot.
5. **Release.** The node sends its PRF partial `Y_{i,(j_g, g)}` for the variant body and its signature partial `s_{f,i}` for each input of `j_g` to the **combiners**. It releases no partial for any other label.
   - Non-TEE: the combiners are `f + 1` nodes chosen by `H(eid ‖ g)` from the committee, so at least one is honest.
   - TEE: every node combines inside its enclave.
6. **Combine.** A combiner combines `t` PRF partials to `Z_{j_g, g}` and derives `k_{j_g, g}` and `y_{j_g, g}`. It decrypts the variant body, which gives the initiator's scalars and `ck_{j_g}`, opens capsule `j_g`, checks `y_{j_g, g}·G = P_{j_g, g}`, and opens every actor's sealed contribution to that body with `y_{j_g, g}·E_{a, j_g, g}`. It interpolates `s_f` from `t` signature partials without checking them, sets `s = Σ_{a∈S} s_a + s_f`, and verifies the whole signature against the capsule's transaction and prevouts. If the signature verifies, nothing else is checked. If it fails, the combiner runs item 8 of §4.7: it finds a failing signature partial by its commitment check, with per-node commitments evaluated on first use (§4.1), drops it and combines again, or it finds the failing actor or initiator by its contribution equation. A failing contribution ends the request: its slots are burned and the initiator reissues without the failing actor (§5.9). In non-TEE mode the honest combiner sends `Z_{j_g, g}` with the `t` proved partials and the failing equation to every node, so each node verifies the failure and posts VOID, and `f + 1` VOID posts form even when the other combiners stay silent.
7. **Broadcast.** The combiner sends the signed transaction to the host chain. Non-TEE combiners send it directly. TEE nodes send it through an egress proxy that strips the node's network identity.
8. **Erase.** At FINAL, VOID or EXPIRED each node zeroizes the slot shares, its share of `κ_0`, every PRF point and key it derived, every `κ_c` share, the scalars it opened, the header and the capsules of the request. A node keeps only the board record and `Enc_{k_fin}(txid)`.

Generation 2 starts when the variant of generation 1 has not confirmed by its deadline and a newer anchor selects a higher variant. It uses the slots `ℓ(2, ·)` and the variant bodies `(·, 2)`. All variants spend the same pinned input, so at most one confirms. A request has no generation beyond `G`. A further fee bump is a new request with a new authorization, new slots and new halves.

**Finality.** Nodes observe the host chain. At confirmation depth, each node votes FINAL with `Enc_{k_fin}(txid)`, under the subkey `k_fin = KDF(Z_hdr ‖ "final")`. Every AEAD key of the envelope and of the FINAL vote encrypts one message, under a zero nonce, so the `q` FINAL votes carry one ciphertext and no key stream is reused. `q` FINAL votes end the request.

**Settlement.** When a request ends, each node signs the **settlement leaf** `(auth, outcome)` with `post_i` on the board. The committee submits no Midnight transaction per request. The next checkpoint carries `settle_root`, a Merkle root over the leaves of every request that ended since the previous checkpoint (§7.13). `outcome` is FINAL, VOID or RELEASED:

- FINAL: `q` FINAL votes. The successor of the asset record is the change record, if any.
- VOID: a VOID request, or an EXPIRED request, with no release. The successor is the same record under a fresh nullifier.
- RELEASED: a VOID or EXPIRED request on which any node released a partial (a RELEASE in a committed vote, or a witnessed `release` entry). Its signed transaction may still confirm, so the record never returns to unspent. The successor is the record locked to the pinned input. A later authorization for that record must spend the same pinned input or nonce, so at most one transaction confirms, and in P2 a hold or seizure spends it too.

`ic` commits to the intent, so `auth` and the outcome fix the successor, and the leaf needs no other field. The wallet derives the successor's nullifier from the record's nullifier secret, `auth` and the outcome, so the successor has one nullifier whichever way its settlement counts. The fresh nullifier of a VOID successor is this value. A settlement counts on Midnight in one of two ways, whichever lands first:

- *Root path.* A checkpoint with a `settle_root` that covers the leaf lands. The next `authorize` on the successor shows inside its proof that the leaf lies under a landed root (§5.3 statement item 1). This is the path of every FINAL and RELEASED settlement.
- *Carried path, VOID only.* The reissue's `authorize` carries the VOID leaf of the stalled request with `q` signatures (§5.9 item 7). The contract checks the signatures against the epoch key set and records `auth` as settled VOID. A board-first reissue carries the leaf in its call on the board. The nodes check the signatures at step 2 of §5.3, and the next `bf_root` covers the call with its leaf.

Honest nodes sign one outcome per `auth`, and two sets of `q` signers share an honest node, so no `auth` settles with two outcomes. Midnight refuses a second `authorize` on the successor's nullifier, so a successor whose leaf counts on both paths is still spent once.

**Next-spend wait.** After FINAL the next spend of the successor waits until a root covers the leaf: at most one checkpoint interval plus `F_M`, 60 s plus `F_M`. The host transaction already waited for its confirmation depth, so the wait adds little. A reissue after VOID carries its settlement and waits for no checkpoint.

**Availability.** The leaves stay on the board. Each wallet keeps its leaf and the path to the root. Nodes and `E` archive the board up to each landed root. A wallet that lost its path asks any node for it and checks it against the root on Midnight. A request that ended after the latest landed checkpoint and before a whole-committee restart still holds slots in `[pending_min, h + B]` of that checkpoint, so the restart ends it again (§7.11). A node settles such a request as FINAL when the host chain shows one of its own variant transactions at confirmation depth, and as RELEASED otherwise. An unspent pinned input does not show that no partial left: the release evidence of the request may lie in the lost board tail and in rolled-back witness logs, and a signed transaction can confirm later. The same rule settles every request that a whole-committee restart ends (§7.11). The owner's re-post spends the same pinned input or nonce, so the lock costs nothing. A carried VOID settlement of a Midnight-first record is on Midnight, so a node that replays the board after a restart refuses a request whose `auth` Midnight shows as settled. A board-first carry reaches Midnight only with the next `bf_root`, as every board-first call does (§5.3). A share complaint ordered after the first ADMIT vote voids nothing. It records the dealer's fault, because partials may already have left.

A non-TEE committee does not read the host chain for a foreign spend of the pinned input before release. Such a request ends EXPIRED. A TEE committee checks the input's balance and status before each release (trigger 2) and voids the request early.

### 5.7 Birth, slot refill and P0 requests

- **BIRTH** (request type 0x01): ordering and opening as above, then the birth check of §3.1. Nodes sign BIRTH_OK and send it to the coordinator (§3.1). No signing and no Midnight authorization.
- **SLOT REFILL** (ECDSA): the envelope announces the session. The session of §3.6 runs on the board between every session party and the nodes, with every session party online.
- **CONTRIB** (request type 0x06): ordering and opening as above, then item 6 of §4.7 against the target request. A contribution frame has no state of its own after it is attached or ignored.
- **P0 spend**: after OPENED the committee runs line dealing on the sealed lines in the header: anchor, lock, select, decrypt and combine. The P0 owner's line needs no committee half.

### 5.8 Seizure and exit flows

**Seizure (P2 only).** A seizure is a spend whose admitted source is a settled seizure order.

1. The charter's registry authority posts a seizure order on Midnight for the record, after the charter's process. The order fixes the destination `D_reg`.
2. The seizure takes the `G` branch of `user OR G`. One guardian is the initiator and names a signing set `T` of `t_g` guardians, with weights `λ_{i,T}`. Each guardian contributes as an actor (§4.2 to §4.4) from its escrow share: for Schnorr suites `σ·(d_{i,p} + ρ_i·e_{i,p}) + c̃·λ_{i,T}·x_{u,i}` from its own pool, with the initiating guardian's contribution using a fresh `k_0` and carrying `c̃·tw + c·g_Q·t_tap` once. For ECDSA it is `λ_{i,T}·(h·w_{u,i} + r·μ_{u,i})` on a reserved slot.
3. The initiating guardian posts an ordinary envelope, and the other guardians of `T` post contribution frames or hand their sealed contributions to it for embedding. The authorization proves the seizure-order source. The envelope has the same frame and shape as an owner's envelope.
4. The committee processes it as any spend. Admission checks that every output pays `D_reg`.

No envelope without a seizure authorization in force takes precedence on the slots `G_g` or burns them (§4.1). On an ECDSA chain the reserved slots `G_g` burn at a whole-committee restart without slot anchors (§7.11), and the refill session needs every session party online, the user included. Until that refill runs, a user who stays offline delays a seizure on that address. Guardians produce a half only for a settled order paid to `D_reg`. Guardians never hold `x_f`, and the committee never holds the escrow, so neither group can seize alone. A P1 record has no escrow and no seizure source, and no party can seize it.

**Exit with Fenrir live.** An admitted signing set sends an ordinary spend to any destination its charter admits, including a P0 address the owner holds alone. A P1 charter always admits the standing exit record `D_exit`.

**Exit through the recovery group.** When no committee checkpoint lands on Midnight for `Δ_rec` blocks, anyone may call `recover(committee_id)`. Midnight records a recovery transition. `E` then reshares `x_f` and, under the rule of §7.11 item 2, the ECDSA slot shares that no covered seat log binds to a successor committee whose nodes are registered in the Node Registry, with the same reshare protocol as rotation (§8). The successor's charter mode is **exit only**: it admits only spends to `D_exit` signed by an admitted signing set, plus seizure in P2. A charter transition on Midnight returns the successor to normal service.

- P1: the exit is unconditional. No hold, registry or approver source applies to a recovery exit.
- P2: a live hold blocks the exit. Guardians may seize under a settled order.

**Exit through the leaf (Bitcoin).** After `T_exit` blocks the holder of `K_exit` spends alone (§3.7).

### 5.9 Collection and reissue

A request whose signing set has more than one actor waits for the actors' contributions between OPENED and ADMITTED.

1. **Post.** The initiator posts the envelope. Its header carries the actor slot table with `Δ_c` and the contribution public keys `P_{v,g}`. Every node sets `exp_c` = ordering height + `Δ_c`, and the initiator keeps `exp_c < exp`. Contributions that the initiator collected before the post sit embedded in the header, and their slots need no collection. A request whose contributions are all embedded has no collection and follows the two-commit path of §5.1.
2. **Open and reserve.** When the header is open and the authorization is in force, each node votes OPENED with `H(header)`. `q` such votes reserve the request's slots (§4.1). This vote is the one commit a collecting request adds to the path. It exists because a collecting request must hold its slots before its actors answer, and it cannot be admitted in the vote that opens it.
3. **Read.** Each named actor obtains its actor capsule, reads the header with `k_hdr` and the capsules with the capsule keys, and applies the actor's rules of §4.2. An actor can read the request as soon as the envelope is on the board. It does not wait for ordering.
4. **Contribute.** The actor posts one contribution frame (§4.6) with `τ_a` and its sealed contribution to every variant body: its scalars `s_{a,v,g,j}` for every half, encrypted to `P_{v,g}`. The frame is ordered and its header opened like every other envelope. Nodes attach the first well-formed frame per slot in board order (§4.7 item 6).
5. **Complete.** When every slot holds a contribution, nodes vote ADMIT with their OBS reports and the request continues as in §5.6. Selection, release and combination treat every contribution of a variant together.
6. **Stall.** If the board reaches height `exp_c` and no `q` ADMIT votes for the request are committed, every honest node posts VOID with reason STALLED, whatever its own view of the actor slot table. A contribution frame against which a verified share complaint is ordered is detached. Nothing was released, because release needs ADMITTED. The committee burns every slot the request reserved, and each actor that answered has burned its pairs. The request settles as VOID, and the asset record returns to unspent with a fresh nullifier once the settlement counts (§5.6).
7. **Reissue.** The initiator builds a new envelope with another signing set `S_2 ∈ Γ` that omits the silent or failing actor, new committee slots, new pool pairs and new nonces `k_0`, and submits a new `authorize` for it. The new `authorize` carries the VOID leaf of the stalled request with `q` signatures, so one Midnight transaction, the wallet's, settles the stalled request and authorizes the new one. The reissue waits for no checkpoint. Every actor of `S_2` contributes again, because `R` and `c` change with the set. A reissue is a new request. It is not a fee generation `g` of §5.6.

A late contribution to a stalled request is ignored, and its scalars are never opened, because no honest node releases a variant partial for a VOID request. A charter whose `Γ` has no admitted set without a silent actor cannot reissue. That actor's silence stops spending until it returns, which the charter must accept or avoid with an OR branch or a threshold group (R5, §10).

### 5.10 Arithmetic and batch verification rules

These rules change no message and no claim. Every implementation of a node, a combiner or a wallet follows them.

1. **Commitment evaluation.** `Eval(C, i) = Σ_k i^k·C_k` is computed by Horner's rule with the node index `i ≤ n` as a small integer: each step is a double-and-add over the bits of `i`, or a fixed addition chain. No step multiplies a point by `i` as a full-width scalar.
2. **Generator multiplication** uses the library's fixed-base table.
3. **Decoded points.** A point is checked for torsion once, when it is decoded from the wire. A hash over points takes the wire bytes. No point is encoded again to be hashed.
4. **Hash to scalar.** A 512-bit hash output is reduced to a scalar in one wide reduction.
5. **Affine conversion.** Points that must be affine are converted together with one field inversion.
6. **Batch verification.** A set of public equations of one form is checked as one random linear combination: the slot dealings of a dealer message (§4.1), the three equations of `π`, the vote signatures of a block, and the same checks across the requests of one block. The verifier draws coefficients of 128 bits after it holds every input and never reveals them. Shorter coefficients are forbidden. Every batch has a fallback that checks each item alone and names the bad one, because the public complaint of line dealing needs a named dealing.
7. **Optimistic combine.** The combiner interpolates, verifies the final signature, and checks signature partials and contributions only when the signature fails (§5.6).
8. **Lazy checks.** A check that concerns one variant runs when that variant is released (§4.7).
9. **Constant time.** Variable-time arithmetic touches public data only: commitments, tickets, partials already released, signatures. The Diffie-Hellman with `sk_i`, every operation on a share value, the PRF partials and their combination are constant time. In TEE mode the operator measures time, and those values open the header.
10. **No GPU on a node.** A request costs a node a few milliseconds of short operations on one core (§11.3).

### 5.11 Rules that no optimization breaks

Each rule names the claim of §9 that fails without it.

| Rule | Reason |
|---|---|
| A user or actor nonce serves one half. No nonce is shared across the variants of an input | two sealed contributions on one nonce give the shard by subtraction (C3, C17) |
| An ECDSA slot serves one `(variant, input)`. ECDSA slots are not shared across variants | two contributions `h·w_a + r·μ_a` on one slot reveal `(w_a, μ_a)`, and with the committee's halves `k` and `x` (C3) |
| An ECDSA slot serves one leaf set, and its members enforce it | two subsets of one group on one slot give two evaluations of the group's half line, and with them the group's shard. Recovering `x` also needs the halves of every other actor on the slot. The committee cannot stop it when every node is corrupt (C12, C17) |
| No two envelopes of an epoch share an outer dealing | both would share every PRF key, so a release on one opens the same label on the other (C9) |
| A slot that a request reserved never returns to the pool | contributions and `ρ`-bound points exist against it, and the counting of C12 needs it gone |
| A committee slot is two nonces `(d_ℓ, e_ℓ)` with a binding factor, never one | one nonce per slot opens the ROS attack (C5) |
| No share and no partial leaves a node before the QC that orders its envelope | that is the statement of C8 |
| No release at Midnight inclusion; release waits for finality or for board-first | C6 needs an authorization in force, and a released signature cannot be recalled |
| No board-first authorization for P2 or for a charter with stateful predicates | a hold cannot revoke what is not on Midnight (C7), and a cumulative limit checked against one root admits two requests (C6) |
| No release without the witness, on any path, and in TEE mode no partial on a slot before `slot_bind` | a rolled-back enclave would sign twice on one slot (§7.7) |
| Batch coefficients have 128 bits, and every batch has a per-item fallback | a dealer that can retry beats short coefficients, and a complaint needs a named dealing |
| No variable-time arithmetic on `sk_i`, on share values or on PRF partials | a TEE operator measures time (C10) |
| Committee nonces are Feldman-committed dealings, not replicated pseudorandom shares | replicated shares give no commitments `D_{ℓ,i}`, `E_{ℓ,i}` for partial checks and need `C(n, t − 1)` keys |
| No anchor output for fee bumps | it adds a distinguishable output (B5) |
| No smaller or second frame class is added for speed | the frame is the anonymity set; a second class waits for O7 |
| The quorum certificate is batched Ed25519 signatures, not an aggregate signature | a pairing check costs about 1.3 ms and twelve Ed25519 checks about 0.4 ms, less in a batch; aggregation pays at hundreds of signers |
| No curve arithmetic inside the ticket proof, and no wrapped STARK while the hash gadgets are callable | the ticket commits `x(R)` (§5.3); a wrap costs more rows than the statement it wraps |

### 5.12 Deferred changes

Three changes are not part of the protocol. Each one waits for a proof (O30).

- **Seeded shares.** A dealing sends `f + 1` ciphertexts and defines the shares of `t − 1` nodes as their pads. It touches the public complaint and the related-dealing defence of Theorem E of `design/PROOFS.md`.
- **Derived slot shares.** A slot dealing derives `t − 1` shares from the Diffie-Hellman key. It touches the same two arguments.
- **Vandermonde extraction of slots.** A round of `n` dealings yields `n − t + 1` slots through a fixed matrix. It waits for the Schnorr reduction of O6, which must first cover linearly related slots.

## 6. Blindness

### 6.1 What each party sees

"Operator" means the person who runs a node. In TEE mode the operator and the enclave are different parties. In non-TEE mode the node process is the operator.

| Step | Board observer, host chain | Operator, TEE mode | Node, non-TEE mode | Midnight observer |
|---|---|---|---|---|
| Birth | nothing | ciphertext and time | every shard point, `tw`, `X`, `H(Γ)`, chain, profile, time | a shielded record and a birth certificate |
| Actor pools | pool posts under pseudonym keys | the same | the same | nothing |
| ECDSA slot session | `X`, every `R_ℓ`, every party's commitments (§6.4 item 3) | the same | the same | nothing |
| Post and order | a 16 KiB frame, epoch, `exp`, `auth_ref`; for a board-first charter also the `authorize` call next to the frame | the same | the same | `authorize` is submitted with the post and finalizes while the board orders; board-first: nothing per call, the next checkpoint carries `bf_root` |
| Open | nothing new | nothing new | header: request type, tickets with `x(R)`, fee rates, selection rule, slot ids, `|S'|` and `exp_c`; for ECDSA the slot ids name the account. A header can open before its authorization is in force | nothing |
| Collect | frames of the common shape | the same | which contribution frames attach to which request, and per position its token; on ECDSA the session party index of each contribution | nothing |
| Admit | ADMIT votes with OBS reports | the same | the authorization record | `authorize`: nullifier, `auth`, `rh`, a proof; for a reissue also the VOID leaf of the stalled request |
| Anchor and select | the selected index `j_g` per generation | the same | the same | nothing |
| Release and combine | nothing | ciphertext | combiners: every contribution to the released variant, its capsule, the transaction, `R`, the weighted leaf points and pool ids of the signing set. The bodies of the other variants stay sealed | nothing |
| Broadcast | the transaction | egress through a proxy | the transaction and the combiner's IP | nothing |
| Final | FINAL votes, `Enc_{k_fin}(txid)`, settlement leaves | the same | `txid` | nothing per request: the checkpoint carries `settle_root` |

In TEE mode every cell of the operator column after "post" is ciphertext, sizes and timing. The enclave sees all the request data, so the TEE's confidentiality carries the guarantee.

In non-TEE mode the address-free ticket hides `X`, `Q`, `m` and the destination from every node until release. After release the `f + 1` combiners see the transaction. Every node can keep `R_A` and the slot points, recompute `R`, and match `R` against signatures on the host chain after broadcast. Non-TEE blindness is therefore **blindness until release**: a node cannot select, delay or refuse a request by its address, amount, destination or chain before it releases its share.

**Actors.** Blindness is a property toward Fenrir operators and outside observers. It is not a property toward the actors of a request.

| Party | Sees |
|---|---|
| Initiator | the whole request it builds; the other actors' pool ids and leaf points; never another actor's pair secrets or shard |
| Named actor | the header and every capsule of the request it co-signs, through the header key and the capsule keys: intent, every variant's transaction, the signing set, the weighted leaf points and pool ids of the other actors. It holds no `κ_0` and opens no variant body, so it never sees `s_0`, another actor's contribution or the committee's shares |
| Actor not named | nothing about the request; an actor capsule it cannot open looks like padding |
| Escrow holder | its escrow share at birth; a request only when it is named |
| Non-TEE node | the count `|S'|`, the attachment of contribution frames, and at release the combiners' view above. It does not learn actor identities: pools are posted under pseudonym keys, the ticket carries only `R_A`, and leaf points reach only the combiners after release |
| TEE operator | ciphertext, sizes and timing. Contribution frames have the shape of every other envelope, so the operator cannot tell a contribution from a request |

Actor identities stay hidden from operators wherever `Γ` allows it. They do not stay hidden from the combiners of a released variant, which see the leaf points and pool ids, and on ECDSA chains every node sees each contribution's session party index. Pool keys are fresh per pool, so a node that sees two requests drawing on one pool learns only that they share a pool pseudonym, and only after release.

### 6.2 Censorship resistance

A node decides to order an envelope before it can read anything inside it. The frame is one size, the public part names no chain or suite, and `auth_ref` is a Midnight id whose record shows no address. A coalition that refuses to order an envelope must refuse blindly. With `f` or fewer such nodes the board still orders it, because the BFT board orders any envelope a correct leader proposes.

After ordering, censorship needs `n − t + 1 = f + 1` nodes that refuse to release. With at most `f` Byzantine nodes, `t = n − f` honest nodes remain and release. In non-TEE mode Byzantine nodes see the header after OPENED and can refuse by request type or fee rate. They cannot stop the release, because `t` honest nodes suffice.

A board leader can delay an envelope by up to `f` leader turns. The initiator re-posts an unordered envelope to another node. The envelope is valid until `exp`.

### 6.3 Unlinkability

1. **Between addresses.** Each address has a fresh `x_u` and a fresh tweak. `X` is uniform to anyone without `tw`, so two addresses of one holder do not link on chain, and an address does not link to `X_f`.
2. **Between requests on the board.** Every envelope is one frame with fresh randomness. Requests of one holder link only through timing and `auth_ref`, and the Midnight record behind `auth_ref` is shielded. A reissue links to its stalled request on Midnight (§6.4 item 17).
3. **P0, P1 and P2 on chain.** All three profiles produce a native single-key output and an ordinary signature. A P2 address is indistinguishable on chain from a P0 or P1 address, unless the charter uses the vault option of §3.4 or the exit leaf is revealed by a script-path spend.

### 6.4 Limits

1. **Host-chain graph.** A spend links its inputs and outputs on the host chain. Change returns to a fresh address, but amounts, timing and common-input heuristics remain. The protocol does not hide the transaction graph.
2. **Release to broadcast.** In non-TEE mode the combiners see each transaction, and any node can link its envelope to the host transaction by `R`. A node learns which board envelope produced which host transaction. It learns that after the release, too late to censor.
3. **ECDSA accounts.** The slot session runs on the board in the clear: it shows every node, every operator and every board observer `X` and every slot point `R_ℓ`, in both modes. An ECDSA signature on the host chain shows `r = x(R_ℓ)`, so any of them links an ECDSA spend to its account and its birth or refill session. The guardian escrow dealings of §3.8 also show which addresses are P2. Encrypting the session messages is open item O35.
4. **Birth in non-TEE mode.** Nodes see `X` at birth. With the spend link of item 2 they can follow an address from birth to spend. A zero-knowledge birth proof (O8) removes this.
5. **Midnight timing.** `authorize` reaches Midnight at the moment the envelope reaches the board. An observer of both chains can match them by timing within each block window. Batching authorizations per Midnight block shrinks this to the block's anonymity set.
6. **Exit leaf.** A script-path spend reveals the leaf and shows that the output was a Fenrir address with an exit option.
7. **Collection timing.** Contribution frames between an envelope's ordering and its ADMIT let a board observer bound `|S'|` by timing, when the board is quiet. Pre-collected contributions embedded in the envelope leave no such trace.
8. **Named actors.** Every named actor holds the header key `k_hdr` and the capsule keys from its actor capsule. A named actor that colludes with an operator lets that operator read the header and the capsules before the quorum certificate. Sealing until order protects a request against nodes and against actors it does not name, not against its own parties.
9. **Board-first requests.** A board-first request shows its `authorize` call on the board next to its envelope. A board observer learns that the request belongs to a board-first charter, so it is not a P2 request and has no stateful predicate, and it links the call to the envelope without timing analysis.
10. **A dishonest initiator and its actors' scalars.** An actor cannot check that `P_{v,g}` is the PRF key of its label. An initiator that puts a key of its own there reads the scalars that the actors of its request seal to it. It gains no signature: the scalars complete only the halves the actors read and accepted, and the committee, which cannot open them, ends the request VOID at release.
11. **Opened and never admitted.** The board opens an envelope while its authorization finalizes. If the authorization never comes into force, the header was still opened: enclaves in TEE mode and nodes in non-TEE mode have read it. No variant body, capsule or contribution of such a request is opened.
12. **Guessable transactions.** In non-TEE mode a node that knows an address and can list the candidate transactions of a request finds the one in the ticket by recomputing `c̃` (§4.2). Ticket blindness hides the address and the message only when the node cannot enumerate them.
13. **Network-created shards.** The birth check of a network-created shard shows the holder's receive key `U` (§3.1). In non-TEE mode nodes link the network-created addresses of one holder at birth. A zero-knowledge birth proof (O8) removes this.
14. **`t` or more nodes.** Every confidentiality claim of this section holds against fewer than `t` nodes or intact enclaves. `t` corrupt non-TEE nodes, or `t` broken enclaves, decrypt their shares of `κ_0` from the outer dealing of any envelope before ordering and read every body and capsule.
15. **Vote kinds.** Board votes are public. After ordering, the kinds a request collects (OPENED before ADMIT for a collecting request, ACK and nothing more for a contribution frame, no ADMIT for a birth) show its class in both modes, and the number of contribution frames bounds `|S'|`.
16. **Checkpoint pool fields and seat logs.** Each Midnight checkpoint shows the floor `h`, the pending floor `pending_min`, the pending root and the pending count of each committee pool. The pending list is on the board, and each seat log on the board shows when that seat puts an ECDSA share. Anyone learns, per suite, how many committee slots were reserved in each checkpoint interval and how many live requests hold, and when ECDSA slots are born. No field names a request, an address or an account. A run of pending indices that one request holds can show its slot count `G·L`, which hints at its chain. A new account-pool session appears at the time of the birth session that created it.
17. **Reissue link.** A reissue's `authorize` carries the VOID settlement of the stalled request, so a Midnight observer links the two `auth` values and learns that both spend one record. A reissue that waits for the root path instead shows no link, at the cost of one checkpoint interval plus `F_M`.

## 7. Hardened Veritee

TEE mode runs each node in a Veritee confidential VM on Azure SEV-SNP with a vTPM behind the HCL paravisor. This section specifies the node lifecycle. The trust base of a TEE-mode node is the AMD SEV-SNP firmware and its signing chain, the HCL paravisor measured into the launch report, the measured guest image, and Midnight. The Microsoft Azure Attestation service (MAA), the Warden, Azure Key Vault and the operator are outside it.

### 7.1 Lifecycle overview

| Step | What happens | Section |
|---|---|---|
| Boot | measured boot, fresh boot keys, `admitBoot` on Midnight | 7.3 |
| Attest | peers verify raw SNP and HCL evidence and the boot ticket | 7.2, 7.3 |
| Unseal | local TPM factor plus peer PRF partials open the volume, the keyring and the sessions of the seat | 7.4 |
| Join epoch | generate epoch keys, record them on Midnight, receive shares by DKG, reshare or repair | 7.5 |
| Receive | send header partials after QC, open envelopes | §5.2 |
| Sign | witness before every output, then release | 7.6, 7.7 |
| Erase | zeroize per request, ratchet per keyring version, discard per epoch | 7.8 |
| Upgrade | approved image, reshare to the new image's nodes | 7.9 |
| Retire | zeroize, record retirement, power off | 7.10 |
| Cold start | whole-committee restart from tier 0 and the sessions, or from `E` | 7.11 |

### 7.2 Attestation evidence classes

Every evidence request names a class byte. The node puts the class and a hash of the payload into the SNP `REPORT_DATA` and the TPM quote's qualifying data, so evidence of one class never verifies as another.

| Class | Name | Payload | Served on |
|---|---|---|---|
| 0x00 | public | caller-chosen 32-byte nonce | the public attestation endpoint |
| 0x01 | akx | Veritee attested-channel key `pk_e` | Unix socket |
| 0x02 | NodeKeys | the epoch keys of §7.5 | Unix socket |
| 0x03 | BootClaim | the boot claim of §7.3 | Unix socket |
| 0x04 | PVK | the provisioning key of §7.12 | Unix socket |

A caller-chosen payload gets class 0x00 only. A caller cannot obtain evidence that binds a key the enclave did not generate, which closes the attestation oracle. TPM quotes always carry qualifying data equal to `H(class ‖ payload)`.

### 7.3 Boot and attest

1. The VM boots the measured image. Measured boot extends PCR 4 (boot loader and kernel). The image's setup extends PCR 15 once with the image id and then never again.
2. The enclave generates fresh boot keys `bk_sig` (Ed25519) and `bk_kem` (X25519).
3. It builds the **BootClaim**
   `(committee_id, node_id, vm_id, image_id, boot_ctr + 1, bk_sig.pub, bk_kem.pub, rand)`
   and obtains class 0x03 evidence for it.
4. The operator submits `admitBoot(BootClaim)` to the Midnight Node Registry with the operator key. The contract checks the operator signature, that `image_id` is approved in the Image Registry, and that `boot_ctr + 1` is one more than the recorded counter. It records the **boot ticket**. No Warden signature is needed, so the Warden is not in the signing path.
5. The node sends `ADMIT(BootClaim, evidence)` to every peer. Each peer verifies the raw evidence itself: the AMD VCEK chain to the AMD root, the SNP report, the HCL report and its runtime claims, the vTPM attestation key bound in the HCL report, the TPM quote over PCR 4, 14 and 15, and the BootClaim hash in the quote. It then checks the boot ticket on Midnight. MAA is not consulted.
6. A peer that accepts returns `ADMIT_ACK`: its signed witness entries for this node (§7.7), with the session versions it holds and the seat's signed statement of each, its PRF partial for the node's unseal (§7.4) and its current board height. The node needs `w` acks. These entries are the first witness sync of the boot, which the restore of every session and the restart decision of §7.11 wait for.

The counter fences clones and superseded boots. Two boots of one VM, or a restored snapshot, cannot both hold the current ticket. Peers serve PRF partials and witness entries only to the boot that holds the ticket with the highest counter.

### 7.4 Unseal

The persistent volume `/mnt/persist` is dm-crypt over dm-integrity.

1. **Local factor.** `K_tpm` is a vTPM keyed-hash object sealed with `PolicyPCR` over PCR 4, PCR 15 (post-setup value) and PCR 14. Before unseal the enclave extends PCR 14 with the committee role id. After unseal it extends PCR 14 with the cap `"VT1/seal-cap"`, so no later process in the same boot can unseal again.
2. **Group factor.** After it opens tier 0 (step 3), the node needs `K_grp,e`. `σ_e` is the epoch's seal-group secret on ristretto255, Shamir-shared at `t_s = n − f`, regenerated by DKG every epoch. Peer `j` returns `y_j = σ_j·H_r(ctx_e ‖ node_id)` with a Chaum-Pedersen proof against `S_j`. The node combines its own partial, from `σ_i` in tier 0, and `w = n − 1 − f` peer partials. That is `n − f = t_s` partials, which always arrive. The result is `K_grp,e = H(σ_e·H_r(ctx_e ‖ node_id))`.
3. **Tier 0.** The volume key is `K_vol = HKDF(K_tpm ‖ "VT1/vol")`. Tier 0 is the volume content that `K_vol` alone opens: the node's seal-group share `σ_i` for the current and the previous epoch, its witness log with the session and `slot` entries that it holds for the other seats, its peers' witness entries for it. The board blocks are not in tier 0. Nodes and `E` archive the board up to each landed checkpoint root (§5.6), so a rollback of every VM disk loses at most the board tail past the latest landed checkpoint. Session records and the replicas of other seats' records live on `/mnt/persist` outside the 16 MiB seal partition of tier 0. Tier 0 needs no peer, so a lone reboot reads it. A disk rollback of tier 0 makes the node forgetful, which the witness bound of §7.7 already counts, and the boot ticket fences clones.
4. **Keyring ratchet (tier 1).** Keyring version `v` is sealed under `K_ring,v = HKDF(K_tpm ‖ K_grp,e ‖ a_v)` with `a_v = PRF_σe(ctx_e ‖ node_id ‖ v)`. Peers serve the partials of `a_v` only for the highest version they have witnessed for this node (§7.7). Once the node commits version `v + 1`, no peer serves `a_v`, so old keyrings stay sealed for good.

**Sessions.** The committee state of a seat lives in **sessions**: named, versioned records of seald, sealed under `K_sess,v` (§2.2) and fenced by the peer witness (§7.7). The session key needs PRF partials from `t` share holders and no `K_tpm`, so a replacement VM in the same seat reopens the sessions of the seat, and no other seat opens them. Peers serve a session partial only to the latest boot ticket of the seat, with evidence of an approved app image, and never for a version below the highest one that they have witnessed for that session. An old record from a snapshot or a stale replica therefore does not open. Each node keeps its records on `/mnt/persist` and sends each new version to every peer in its witness message. A version is current after `w` acks. The OpenSpec change `add-seald-sessions` of Veritee specifies the store (SS-001 to SS-141).

| State | Where it lives | After a loss |
|---|---|---|
| `σ_i` of the current and the previous epoch | tier 0 under `K_tpm` (step 3) | share repair from `t` holders, or `E` (§7.11) |
| shares of `x_f`, the private epoch keys of §7.5, `k_nf`, and the map from each ECDSA address to its account-pool id | session `keys` | restore of the session |
| committee nonce slot shares of suite `s` and epoch `e` | session `slots-s-e`, a sequential pool (§4.1) | restore; a whole-committee restart burns the range `[pending_min, h + B]` (§7.11) |
| ECDSA committee slot shares `(w_{f,i}, μ_{f,i})` of one address, with its slot records | one account pool per address, named by a random 16-byte id drawn at birth | restore; a whole-committee restart burns every `free` and `bound` slot (§7.11) |
| request state: admitted envelopes, `release` entries, generations, slot bindings | session `requests`, a cache | restore, then every entry is checked again against the board before use |
| shares of `κ_0` | not sealed | decrypted again from the outer dealing on the board with `sk_i` |
| boot keys, TLS keys, `K_sess,v`, `K_vol`, `K_ring,v` | RAM | made again at the next boot or operation |

Tier 1 stays bound to the VM through `K_tpm`. It holds no committee state that a replacement VM needs. An account-pool id names no address, so the session id `sid` in a record header does not name the account. Its first appearance still falls at the time of the birth session (O35).

**Seat log.** Each seat keeps an append-only log on the board: its put entries, its slot bindings when slot anchors are on, and its `RestoreDone` statements. Each Midnight checkpoint carries one Merkle root per seat over that seat's log, so Midnight receives no transaction per put, per binding or per boot. An entry counts once a landed checkpoint root covers it. Each `slot_put` on an account pool appends the put entry `(node_id, SHA-256("VT1/slot-put" ‖ share), put_tag)`, and seald refuses a share whose put digest a covered entry already holds. The entry names no slot and no address. A node binds an account-pool slot only after a covered entry holds its own `put_tag`, so no rollback removes the put of a share that a release used. In the Veritee change `add-seald-sessions` the seat log carries the put rules (SS-128 to SS-131, SS-137, SS-138), the anchors (SS-070 to SS-073, SS-092, SS-119, SS-139) and the `RestoreDone` statements (SS-112, SS-117, SS-120 to SS-122). Its roots form one chain across checkpoints (SS-136), and the first covered entry of a share counts (SS-131).

**Blank tier 0.** A VM that boots with an empty tier 0 fetches the witness entries and the replicas of every other seat from `w + 1` peers before it serves an ack or a partial. It keeps, for each seat, the highest version that a peer other than that seat reports with the seat's signed statement. Until this fetch completes, the seat counts among the `c` of §7.7.

**Non-TEE mode.** A non-TEE node has no seald and no witness fence. It keeps nonce slot shares and ECDSA slot shares in process memory and never writes them to disk. After a whole-committee restart it gets `x_f` back by repair or from `E`, and every slot that it held is gone: Schnorr requests that held slots end VOID, and ECDSA addresses refill (§7.11).

SNP-derived keys (`MSG_KEY_REQ`) are not used. On Azure the paravisor owns the SNP guest messaging interface, and the derived key would bind the paravisor's measurement, not the guest image.

### 7.5 Join epoch and offline encryption to the committee

At each epoch start the enclave generates `EK_i` (X25519 HPKE), `PK_i` per suite curve, `post_i` and the Schnorr share key `S_i`. It obtains class 0x02 evidence for `NodeKeys = (epoch, node_id, EK_i, PK_i, post_i)`. Peers verify the evidence and post signed acks on the board. Once every node of the epoch has `w` acks, the committee writes the epoch key set `EKS_e`, the list of all `n` `NodeKeys`, to the Midnight Key Registry as one record with `q` signatures by the boot keys `bk_sig` of the boot tickets that the Node Registry holds. Its hash is `keylist_hash`. The acks stay on the board, and each signer checks them before it signs. The node set changes only by rotation (§7.9, §7.10, §8), which opens a new epoch, so one record per epoch serves every node. A Warden signature is optional and not checked.

An initiator or an actor reads `EKS_e` once from Midnight and builds envelopes and contribution frames offline. It needs no live contact with any node.

The node then receives its shares: by DKG at genesis, by reshare at rotation (§8), or by repair from `t` peers after a loss.

### 7.6 Sign

Before any output that depends on a secret leaves the node, the node records a witness entry at `w` peers (§7.7). The outputs are a line-dealing PREVOTE (P0), a PRF partial for a header key, a PRF partial for a variant body, a partial signature, a decryption share and a sealed release. A peer refuses a second digest for one key. A partial signature on a slot also needs `slot_bind` of that slot (§7.7). The node then sends the output. No path skips the witness (§5.11).

### 7.7 Peer witness protocol

A **witness entry** maps a key to a digest. Each peer enclave keeps an append-only log of entries it has acked for every node, with the board height. The kinds:

| Kind | Key | Digest |
|---|---|---|
| open | `eid` | QC position; batched per board height |
| release | `(node, eid, g)` | `(j, H(tk_1 ‖ … ‖ tk_L))` |
| slot | `(node, purpose, ℓ)`: purpose `slots-s-e` for a committee slot of suite `s` and epoch `e`, the account-pool id for an ECDSA slot | `H(tk)`: the one ticket the node signs on that slot, among the candidates that name it |
| session | `(node, sid)` | version `v`, epoch and record digest, with the record and the seat's signed statement |
| keyring | `node` | version `v` |
| secret | `(node, secret id)` | version |

A node sends `WITNESS(kind, key, digest)` signed with `bk_sig`. A peer acks if it has no entry for the key, or the same digest. It refuses a different digest. The node proceeds after `w = n − 1 − f` acks from distinct peers. The `q` voters of a quorum certificate do not stand in for them.

**Carriage on board votes.** Witness entries have no message round of their own where a vote already travels. A node attaches to its vote for a block every entry whose digest that block fixes, under one `bk_sig` signature: the `open` entries of the envelopes the block orders, with their QC positions. Every peer receives the vote in any case. A peer appends all entries of one board height to its log with one group-committed flush and returns one signed ack for the whole batch, so a peer performs one flush per block and not one per entry. The acks arrive with the QC, and the header partial leaves after them. An `open` entry is provisional until the block that it names has a QC. A peer that holds a provisional `open` entry for `eid` replaces it with an entry whose block carries the QC that ordered `eid`, and never replaces an entry whose block carries a QC. A vote for a proposal that never got a QC therefore does not block the node from opening the envelope at its committed position. Board safety gives one QC per height, so a rolled-back node still cannot open one envelope at two committed positions.

The digest of a `release` entry and of its `slot` entries is fixed only by the anchor, which the committed block of the ADMIT votes determines. A node cannot attach it to its own ADMIT vote. It sends its `release` entries in one batched `WITNESS` message per peer and board height right after that block commits, and the peers ack them with the same group commit. A TEE node then binds, in one batch per pool session, every slot that the anchors of that board height fix: the `slot` entries `(node, purpose, ℓ) → H(tk)` go to the peers in one message and get `w` acks, and then the pool session seals one version that records `bound(H(tk))` for all of them and gets `w` acks. `slot_release_ok` is true only after that version is current, and only then does a partial leave. A release therefore waits for the batched `release` round and two batched bind rounds, whatever the number of slots or requests at that height. seald binds a batch of slots in one call (SS-140, SS-141, O36).

**Safety.** Let `c` operators collude and roll back or clone their nodes. The colluding node's own peers include at most `c − 1` forgetful colluders. Two ack sets of size `w` drawn from `n − 1` peers intersect in at least `2w − (n − 1)` peers. A conflicting second digest needs that intersection to consist of forgetful peers only, so it needs `c − 1 ≥ 2w − (n − 1)`. With `w = n − 1 − f` this gives `c ≥ n − 2f`. The witness is therefore safe for `c ≤ n − 1 − 2f`: 4 colluders at launch, 6 at `n = 17`. The count `c` includes honest seats that forget. A seat whose tier 0 was lost counts among the `c` colluders until its peer-state fetch of §7.4 completes. A seat whose tier 0 was rolled back counts for a session from the commit of that session's current version until a later version of that session commits. The seat that restores counts too. The bound therefore limits the losses at one time, and a series of replacements with completed fetches stays inside it. A rollback of more than `c` seats can reopen erased session entries inside the enclaves. The window burn, `slot_stale` and the monotone floor of §7.11 still stop every second use of a slot, because they rest on Midnight and not on the fence.

**Liveness.** A node has `n − 1` peers and at most `f` are faulty, so `w = n − 1 − f` acks always arrive. At launch `w = 6 = q`. At `n = 17`, `w = 11` and `q = 12` would exceed the 11 honest peers, so the witness count is `n − 1 − f`, not `q`.

**Replay floor.** On admission the node takes the maximum of the board heights its peers report and the board height of the latest Midnight checkpoint. It refuses any request ordered below that floor that it cannot prove it has not already served.

**High-value profile.** A charter may set `anchor_before_release`. Each node appends the `release` entry `(eid, g, digest)` of that charter's requests to its seat log and releases only after a Midnight checkpoint root covers it. That makes the witness safe against any number of colluding operators, at the cost of one checkpoint interval plus Midnight finality per release and no Midnight transaction of its own. It is a charter option, not the default. It does not protect the committee slots, which every charter shares. That is the committee-wide `slot_anchor` of §4.1 (O32). seald implements a per-seat slot anchor as its committee parameter `slot_anchor`, which is off at launch. With it on, `slot_bind` appends the binding `(purpose, ℓ, H(tk))` to the seat log and succeeds only when a landed checkpoint root covers it, and a whole-committee restart burns nothing.

### 7.8 Erase

The node process runs with `mlock` on all secret pages, no swap, `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`, `kernel.yama.ptrace_scope = 2`, `kexec_load_disabled = 1` and `init_on_free = 1`. Every secret type implements zeroize on drop.

| Scope | Erased | When |
|---|---|---|
| Request | slot shares (TEE: `slot_burn`), the share of `κ_0`, PRF points and keys, opened scalars, header, capsules, the request's entries in the `requests` session | FINAL, VOID or EXPIRED |
| Session version | `K_sess,v` | the end of each seal or open (§7.4) |
| Keyring version | `K_ring,v` | the ratchet to `v + 1` (§7.4) |
| Epoch | `σ_e` from RAM and tier 0 (`close_epoch`), epoch keys, the pool sessions `slots-s-e` | grace period end after `ROTATE`; `close_epoch` waits until no session, local record or peer entry of any seat uses epoch `e` |
| Boot | boot keys, RAM | retire or reboot |

In TEE mode an erasure in a session is durable. `slot_burn` and `session_destroy` seal a new version and return success only after `w` acks. Peers then refuse the session key of every older version, so an erased share does not open again from a snapshot or a stale replica within the bound of §7.7. At `ROTATE` the node calls `rekey`, which seals each of its sessions again in the new epoch before `close_epoch` can erase the old share.

### 7.9 Upgrade

Governance approves a new image in the Image Registry with 7 of 9 separate member signatures. Each operator boots a node on the new image as a new slot (`replaceSlot`), and the committee reshares to the new node set as in rotation (§8). The old node keeps signing until HANDOVER and then retires. An upgrade never moves a coin and never exports a share in the clear.

### 7.10 Retire

The node zeroizes its keyring and RAM, posts `retire(node_id)` to the Node Registry with its boot key, and powers off. The registry stops admitting boots of that `node_id`. A node that disappears without retiring is replaced by `replaceSlot` and a reshare that excludes it.

### 7.11 Cold start

All `n` nodes may reboot at once (a region outage, a fleet patch).

**Restart decision.** A seat is **continuous** when the boot counter of its latest boot ticket equals the boot counter that the latest Midnight checkpoint records for it. A checkpoint records a boot counter only from the seat's signed `RestoreDone` statement (§7.13). After its first witness sync, each TEE node reads the boot tickets and the latest checkpoint `cp` from one verified ledger snapshot. With fewer than `w + 1` continuous seats the boot is a **whole-committee restart**. The node decides from the ledger only, because a rolled-back node cannot tell from its own disk. A ledger that does not read or verify leaves the node not ready, and it reads again. A node that did not reboot also burns when the ledger shows a whole-committee restart. With at least `w + 1` continuous seats the restart is partial: every session resumes and pending requests continue. The committee posts a checkpoint after each `RestoreDone` and before the next planned reboot, so `f + 1` reboots one at a time stay partial.

1. **Tier 0 intact on at least `t` nodes.** Each node boots, takes a new boot ticket, unseals `K_tpm` and opens tier 0, which holds its `σ_i`. The PRF partials of `w` peers need those peers to be admitted, so nodes admit each other first by evidence and tickets alone, then exchange PRF partials. With `t` nodes up, each recovers `K_grp,e`, the keyring, the witness log and its sessions. A seat with a blank disk restores its sessions from the peer replicas with `t` peer partials. Each node appends `RestoreDone(committee, node_id, boot_ctr, cp.seq, whole_restart)` to its seat log, and the next checkpoint carries it (§7.13). Before a session opens, the node burns two kinds of slots:
   - in the committee pool, every index in `[pending_min, h + B]` of `cp`. The range holds the window `(h, h + B]` and every pending index of `cp`. A slot reserved before `cp` can be bound after it, and a rolled-back disk shows it `free`. The other indices of the range were reserved by a request that ended, skipped or burned before `cp`, so no request can bind them, and the burn loses no usable slot.
   - in every account pool, every `free` and `bound` slot, once for each whole-committee restart. Only the board knows the ECDSA claims, and a rolled-back disk can show a claimed slot `free`.

   The burn applies also to a session created after the restart, because every disk can roll back to a state before that session existed. The session opens with the list of burned indices, the requests that hold them end VOID, and the owner re-posts them. Each such request settles FINAL or RELEASED by the rule of §5.6, never as VOID with a fresh nullifier. Every other slot, every key and every session resumes. The next checkpoint must raise `h` to at least `h + B` and `pending_min` above `h + B` of `cp`, and it sets the restart marker `restart_seq` (§7.13). A node that classified the restart binds no account-pool slot until that checkpoint exists, and then writes the marker into each burned account pool. A node that boots after that checkpoint sees continuous seats. `slot_stale` refuses each burned committee index, and each account pool whose recorded mark is below `restart_seq` burns at its open. A running node keeps the restart open until a checkpoint carries the new marker and `w + 1` continuous seats, so a later loss of continuity burns again. Nodes that read different checkpoints at one restart burn the union of their sets. Each ECDSA address refills by a new session (§3.6) before its next ECDSA spend. No slot is used twice, also when every disk was rolled back to the same old state. No coin moves.

   With seald's `slot_anchor` on (§7.7), nothing burns: each `free` slot with a covered binding in the seat log becomes `bound` to that digest, and a slot whose restored digest differs from its covered binding never releases.
2. **Fewer than `t` intact.** The seal-group shares are lost, so no session key can be derived. The recovery group `E` reprovisions the committee: the nodes boot fresh, `E` reshares `x_f` to them (§8 protocol), the Midnight checkpoints give the replay floor and the committee deals a new nonce pool. Pending requests that held committee slots end VOID, settle FINAL or RELEASED by the rule of §5.6, and the owner re-posts them.

   **ECDSA slots after a recovery.** A reshare of an ECDSA slot gives new share bytes with the same nonce `R_ℓ`, so neither the put entry of §7.4 nor a new index stops a second use of that nonce. The board tail past the latest Midnight checkpoint may be lost or rolled back, and a board record with valid QCs cannot show that no later block claimed a slot. `E` therefore reshares an ECDSA slot only when the checkpoint roots show that no seat bound it. On a committee with seald's `slot_anchor` on, a binding counts only once a root covers it, so `E` reads each seat log up to the root of the latest checkpoint, checks it against that root, and reshares a slot that no covered entry binds. A seat log that `E` cannot read in full counts as binding every slot of that seat. Without anchors `E` reshares no ECDSA slot, and every ECDSA address, including the guardian slots `G_g` of a P2 address, refills by a new session (§3.6) before its next ECDSA spend. No slot is used twice.

A non-TEE committee keeps no slot share across a whole-committee restart. Its pending requests that held slots end VOID and settle FINAL or RELEASED by the rule of §5.6, it deals a new nonce pool, and its ECDSA addresses refill.

This path needs no live Midnight recovery transition, because the committee identity and its Node Registry entries are unchanged. `E` acts on a Midnight `coldStart(committee_id)` record signed by `q` registered operators.

### 7.12 Secret release and operator inputs

Committee secrets exist only through DKG, reshare and peer repair between attested enclaves. No operator, cloud service or key vault ever holds a committee secret.

- Operator inputs (host-chain RPC credentials, egress proxy credentials) reach the node only as `SealedToNode` HPKE envelopes to the node's attested provisioning key `PVK` (class 0x04).
- TLS keys are generated in the guest. Certificates come from the committee's internal CA or from ACME with TLS-ALPN-01.
- Key Vault and managed identity are removed from committee images. Azure Secure Key Release is not used, because the operator controls its policy and its identity.

### 7.13 Midnight records

| Record | Fields | Written by | Checked by |
|---|---|---|---|
| Image Registry | `image_id`, measurement (launch digest, PCR 4 and 15 values), approvals | governance, 7 of 9 | peers at admission |
| Node Registry | `committee_id`, `node_id`, operator key, `vm_id`, `boot_ctr`, current BootClaim hash, status | operator (`admitBoot`, `replaceSlot`), node (`retire`) | peers at admission, `E` at cold start |
| Key Registry | one record per epoch: `epoch`, the `n` `NodeKeys` of `EKS_e`, `keylist_hash` | committee, `q` signatures | wallets, peers, the contract for carried VOID settlements |
| Checkpoints | `checkpoint(seq, epoch, board_height, board_root, witness_root, pools, settle_root, bf_root, boot_counters, restart_seq, seat_roots, restores)`, every 60 s and after each `RestoreDone`: `pools` holds `(h, pending_min, pending_root, pending_count)` of each committee pool, 52 bytes (§4.1), `settle_root` covers the settlement leaves of the interval (§5.6), `bf_root` covers the board-first calls of the interval (§5.3), the boot counter of each seat with a `RestoreDone`, the restart marker, one Merkle root per seat log (§7.4), and the new `RestoreDone` statements | `q` node signatures | nodes at boot (replay floor, restart decision), `slot_bind` (window), `recover` (liveness) |
| FenrirAssets | asset records, `authorize` (with the VOID settlement that a reissue carries), `revoke`, the `settle_root` and `bf_root` of each landed checkpoint, birth certificates. A record of a board-first charter takes no direct `authorize` and changes only through a landed `bf_root` | wallets, committee, hold authorities (P2) | nodes before admission and release |
| Charters | profile, sources, `D_exit`, `Δ_rec`, `T_exit` option, the `board_first` option (P0 and stateless P1 only) with its root-age bound; P2: `D_reg`, `PK_H`, guardian set, registry authority | charter creator | `authorize` |
| Recovery | `recover`, `coldStart`, recovery group keys | anyone after `Δ_rec`; `q` operators | `E` |

The seat log of §7.4 lives on the board and holds `RestoreDone(committee, node_id, boot_ctr, cp.seq, whole_restart)` signed with `bk_sig`, put entries, the slot bindings of seald's `slot_anchor`, the `release` entries of `anchor_before_release` charters and the slot entries of `slot_anchor`. Midnight holds only its roots, in the checkpoint. A checkpoint signer checks each seat log that a root covers and signs no root over a log that holds a second binding for one slot key or a second put of one digest. It signs `pending_root` only over the list of the slots that live requests hold on the board, with `pending_min` its lowest entry or `h + 1`, and `pending_count` its length. It signs `settle_root` only when its leaves are exactly the requests that ended between the board heights of the previous checkpoint and this one, each with the outcome of the board record, and when no leaf gives an `auth` an outcome other than the VOID that Midnight records for it.

The committee contract refuses a checkpoint that lowers `h`, and a checkpoint with `pending_min > h + 1` for any pool. Without that check an index in `(h, pending_min)` would pass the window and escape the restart burn `[pending_min, h + B]`. After a checkpoint `cp1`, it refuses a checkpoint `cp2` at which fewer than `w + 1` seats keep their boot counters when, for any committee pool, `cp2.h < cp1.h + B` or `cp2.pending_min ≤ cp1.h + B`, unless seald's `slot_anchor` is on. It reads two integers per pool. It refuses a boot counter without its `RestoreDone` statement in the same or an earlier checkpoint. The first checkpoint after a `RestoreDone` with `whole_restart = true` that names a checkpoint at or above the current marker sets `restart_seq` to its own `seq`. Every other checkpoint keeps it. seald cannot enforce these rules, because the committee application writes the checkpoint.

**Why `pending_min` is enough.** The restart burn and the contract rule read only `h`, `pending_min` and `B` of a landed checkpoint.

1. *The burn covers the list.* Every pending index of `cp1` lies in `[cp1.pending_min, cp1.h]`. The window `(cp1.h, cp1.h + B]` and the pending indices are therefore a subset of `[cp1.pending_min, cp1.h + B]`.
2. *The extra indices are dead.* An index in `[cp1.pending_min, cp1.h]` that is not pending was reserved by a request that ended, skipped, or burned. It gets no honest vote (§4.1) and seald refuses it at `slot_bind`, so its burn loses no slot that could bind.
3. *The rule implies the list rule.* `cp2.pending` lies in `[cp2.pending_min, cp2.h]`. If `cp2.pending_min > cp1.h + B`, then `cp2.pending` holds no index of `cp1.pending` and none of `(cp1.h, cp1.h + B]`.
4. *An honest `cp2` passes.* The restart ends every request that holds an index at or below `cp1.h + B`. Until `cp2` lands, the window is `(cp1.h, cp1.h + B]`, which is burned, so no request reserves an index. A request that was not live at `cp1` holds no index at or below `cp1.h`. Every request live at `cp2` therefore holds only indices above `cp1.h + B`.
5. *A rollback of every disk changes nothing.* The burn range and the rule use only fields of a checkpoint that landed on Midnight. A rolled-back disk or a lost board tail does not change them, and Midnight enforces the rule. The burns therefore hold when every disk is rolled back, as C16 requires.

## 8. Rotation and reshare at `t = n − f`

Rotation replaces the committee, or part of it, without moving a coin. The secrets that move are `x_f` per curve, the unused ECDSA committee slot shares, and the seal-group secret (which is regenerated, not moved). Schnorr nonce pools are discarded and rebuilt.

**Status: open proof obligation (O5).** The mechanism below is specified. Its security proof at `t = n − f` with a Byzantine old committee and a partially synchronous network is not written. A publicly verifiable secret sharing (PVSS) reshare, which needs no complaint window, is the named candidate for removing the synchrony assumption.

### 8.1 Mechanism

Let the old committee have `(n, f, t)` and the new one `(n', f', t' = n' − f')`.

1. **ROTATE.** Governance or the epoch schedule posts `ROTATE(epoch + 1, new node list)` on the board. The new nodes are admitted (§7.3) and register their epoch keys (§7.5).
2. **Reshare dealings.** Each old node `i` deals its share `x_{f,i}` to the new nodes at threshold `t'`: a polynomial `P_i` of degree `t' − 1` with `P_i(0) = x_{f,i}`, Feldman commitments, and per-node ciphertexts to the new `PK'_j`. Every old node also deals each unused ECDSA slot share pair `(w_{f,i}, μ_{f,i})` the same way, with commitments in base `R_ℓ`. Each dealing is publicly checked against the old commitments: the constant term of `P_i`'s commitments equals `Eval(old commitments, i)`.
3. **Complaint window.** After the last dealing a window of fixed board length opens. A new node whose share fails posts the complaint of line dealing with its decrypted share and a DLEQ proof. A valid complaint disqualifies the dealer. The window length assumes that every honest new node's complaint is ordered within it. That is the synchrony assumption of this step.
4. **Qualified set.** `Q` is the first `t` old dealers in board order with no valid complaint. With at most `f` Byzantine old dealers and `n − f = t` honest ones, `Q` exists.
5. **New shares.** New node `j` sets `x'_{f,j} = Σ_{i∈Q} λ_i·P_i(j)` with the Lagrange weights of `Q` at zero. The new commitments are the same combination of the dealers' commitments. Their constant term is `Σ λ_i·Eval(old, i) = X_f`, which every party checks.
6. **READY.** Each new node that holds valid shares for every secret posts READY. **HANDOVER** needs READY from `n' − f'` new nodes. A count of `q' = 6` is not enough: it leaves as few as `q' − f' = 4` honest confirmed holders, fewer than `t' = 7`, so the old committee could stop signing while the new one cannot sign. Under the complaint rule of step 3 every honest new node holds valid shares, and `n' − f'` READY posts confirm that the new committee as a whole is live. The proof that this count suffices is part of O5.
7. **HANDOVER.** The board records HANDOVER. The new committee takes over signing at the next epoch. The old committee signs until HANDOVER. Old nodes erase their shares after the grace period.
8. **Failure.** If HANDOVER does not happen before a deadline, the rotation aborts. The old committee stays in place with its old shares, and nothing was lost.

In-flight requests either finish before HANDOVER or end VOID, and their owners re-post. New Schnorr nonce pools are dealt by the new committee. `E` receives a fresh backup from `Q` (§3.9).

The public consistency check of step 2 shows that each dealing matches the old commitments. It does not prove the whole reshare at `t = n − f`, which also needs the qualified-set argument of step 4 and the complaint window of step 3.

## 9. Security claims

The adversary corrupts nodes statically per epoch and controls the network subject to partial synchrony. `C` is the set of corrupt nodes. "All `n`" means every node is corrupt. Hash functions are random oracles where a claim says ROM. The claims hold in both modes unless the mode is named. A cell that names an obligation states a hypothesis whose proof is not written. §9.3 lists those obligations.

### 9.1 Claims

| Id | Claim | Adversary | Status | Argument |
|---|---|---|---|---|
| C1 | **Address binding.** An address certified by a birth certificate has key `X = X_f + tw·G + Σ_a X_a` for shard points whose discrete logs their holders know (a group shard: the sum of its dealers' proved constant terms). | any coalition of actors, with `|C| < q` | sketched | each `pop_a` is a Schnorr proof of knowledge of `x_a` bound to the slot and the birth context, and each group dealer proves its constant term. Extraction gives every corrupt shard. A coalition that also knows `z` with `X = z·G` knows `x_f` plus the honest shards, which breaks DL. `q` honest-majority BIRTH_OK posts include an honest check. |
| C2 | **Birth proof of possession (rogue key).** No coalition of actors obtains a birth certificate for an `X` whose full key it knows, whatever the order in which the actors publish. | any coalition of actors, up to all of `A`, with `|C| < q` | sketched | as C1. Every summand carries its own proof, so the last publisher gains nothing. |
| C3 | **Sealed user half (single-user form).** All `n` nodes together cannot produce a valid signature on any message outside the dealt variants. | all `n`, plus the host chain | Schnorr: sketched (DL, ROM); ECDSA: sketched, conditional on O1 and O2 | Schnorr: the adversary holds `x_f` and every dealt `s_u`. A signature on a new message `m*` needs `s_u*` for a fresh challenge. Simulate dealt halves by programming `H_challenge`: pick `s_u` and `c`, set `R_u = σ·(s_u·G − c·(g·Y_A + g_Q·t_tap·G))`, derive `R` through `ρ`, program the challenge at `(x(R), x(Q), m)`, and retry when the parity of `R` differs from `σ`. A forgery on `m*` yields `x_U'` by forking, hence a DL solution of `Y_A`. Every half `(v, g, j)` has its own `k_u`, so the simulation programs one challenge per half. The claim's hypothesis is that no user nonce serves two halves (§5.11); the count of dealt halves is `N_h`, and a variant dealt in two generations is one message with two independent halves. ECDSA: given the slot functionalities, the adversary sees `(R_ℓ, s_u)` for one message per slot. Each slot is used once, which is the setting of the presignature theorem of ePrint 2021/1330 (Theorem 3), as line dealing uses it (PROOFS.md Theorem A). |
| C4 | **No spend without an admitted signing set.** Every valid spend uses the contributions of a signing set `S ∈ Γ`: the owner's half in the single-user form, `t_g` guardians on the `G` branch of P2. | all `n` | follows from C3 and C17 (C17 open for pool actors, O20) | the committee holds no shard. |
| C5 | **No spend without the committee.** Every actor of `A` together, with `t − 1` nodes, cannot sign. | all actors plus `t − 1` nodes; in non-TEE mode the slot rules need `|C| ≤ f`, or `slot_anchor` (§4.1, O32); in TEE mode at most `n − 1 − 2f` operators roll back, counted with the seats whose tier 0 is lost (§7.7) | Schnorr: open (O6); ECDSA: sketched, conditional on O1, O2, O19 and O32 | Schnorr: a one-more-DL argument over nonce slots, in the style of the FROST proofs, adapted to a public additive actor part; the reduction is open. Changed hypothesis: up to `K` tickets of one request name one committee slot, and the committee answers one signing query per slot, on the ticket that the board anchor selects. The reduction of O6 states its signing oracle in that form and shows that the unanswered candidate tickets, which the adversary could evaluate without the committee, give it no advantage. ECDSA: reduces to the same presignature theorem with the session parties as more parties; ECDSA slots are not shared. |
| C6 | **Authorization enforcement.** No node releases a variant partial or a signature partial for an envelope without an unrevoked authorization in force that matches `hd` and `tkc`, on slots this request reserved. | TEE: all operators, enclaves intact, at most `n − 1 − 2f` of them rolling back or cloning (§7.7). Non-TEE: `|C| < t` | Midnight-first: TEE assumed TEE, non-TEE sketched, conditional on O4, O22 and O25. Board-first: open (O29) | honest nodes check §5.4. A release needs `t` nodes, so `t − 1` corrupt nodes cannot complete it. Changed hypothesis 1: an envelope is ordered and its header opened before its authorization is final. The claim covers release, not opening: the header partial is the only output before ADMIT, and the pre-ordering checks never looked at `auth_ref`. Changed hypothesis 2: for a board-first charter "in force" means that the node verified the proof against a finalized Midnight root and that the board ordered the nullifier first. The proof that this is as strong as Midnight finality for stateless predicates, and that the root-age bound and the pending set leave no replay, is O29. |
| C7 | **Hold enforcement (P2).** A revoked authorization releases no new generation. | as C6 | as C6, Midnight-first only, and conditional on O3 | as C6. In non-TEE mode, `t` corrupt nodes release already-dealt variants. Board-first is forbidden for P2, so every P2 authorization is on Midnight, where the hold authority can revoke it, before any release. |
| C8 | **Sealed until order (B3).** No coalition of fewer than `t` nodes learns anything about `body_0`, a variant body or a capsule before the QC that orders the envelope. A named actor holds the header key and the capsule keys and can disclose the request it co-signs, as the owner can in the single-user form, so the claim covers nodes and actors not named. | `|C| < t`, plus actors not named | sketched (DDH, ROM); the written proof is O26 | the outer dealing, its encryption and `π` are those of line dealing, so Theorem C of `design/PROOFS.md` applies unchanged: the corrupt nodes learn nothing about honest shares beyond the commitments. Changed hypothesis: `body_0` is keyed by `KDF(κ_0·H_c(dd ‖ hdr))`, a threshold PRF output, and not by a dealt scalar. Theorem D restated (§9.3) gives: a key whose label has no honest partial is pseudorandom under DDH. Steps: (1) Theorem C; (2) simulate the corrupt nodes' partials from their shares and replace `Z_lab` by a random point, by DDH with `H_c` programmed; (3) `dd` inside `H_c` confines a partial to one outer dealing, and a copied dealing under other bodies needs a new `π`, the event `Reuse` of Theorem C; (4) honest nodes send the header partial only after the QC. |
| C9 | **Unselected variants stay sealed.** No variant body of a variant that the rule never selects is ever opened. Its contributions stay unread: the initiator's scalars, and every actor's scalars sealed to that body's key. | `|C| < t`, plus actors other than the initiator; in non-TEE mode `|C| ≤ f`, because a forked board shows honest nodes different anchors (§4.1) | sketched (DDH, ROM), computational; the written proof is O26 | honest nodes release a variant partial only for the selected `(j_g, g)`. The key of every other body is a PRF output on a label with no honest partial, so it is pseudorandom by Theorem D restated, and an actor's scalars for that body are encrypted to `P_{v,g} = y_{v,g}·G` with `y_{v,g}` derived from the same PRF point. Changed hypothesis: the argument is computational (DDH, ROM). It is not the unconditional hiding that fewer than `t` shares of a dealt scalar give. For an actor's scalars the hypothesis also needs an honest initiator (C18). |
| C10 | **Blindness.** TEE mode: operators see only ciphertext, sizes, timing, vote kinds (§6.4 item 15), the ECDSA slot sessions (§6.4 item 3) and the committee pool fields of the Midnight checkpoint (§6.4 item 16). Non-TEE: nodes see only §6.1 before release, and the ticket hides the address and the message from a node that cannot enumerate the candidate pairs `(x(Q), m)`. | TEE: all operators, enclaves intact; non-TEE: `|C| < t` | TEE: assumed TEE; non-TEE: sketched | non-TEE: `R_A` contains a fresh uniform point and `pm` is a salted hash. `c̃` is a random-oracle output on `(x(R), x(Q), m)`, so it is independent of the address and message only for a node that cannot query the oracle on the right pair; a node that can list the candidates finds the pair (§6.4 item 12). With `t` or more nodes, `κ_0` of every envelope is readable and nothing is blind (§6.4 item 14). The ticket's `x(R)` is a function of `R_A`, the slot points and `ρ` that the node computes itself, so it adds nothing. TEE: constant-time arithmetic on shares and PRF partials (§5.10) is part of the assumption. |
| C11 | **One spend per record state.** Two FINAL settlements cannot follow one asset record state. | any | Midnight-first: sketched. Board-first: sketched, with obligation O29 | Midnight nullifier uniqueness and the pinned host input or nonce. A settlement selects one successor by `(auth, outcome)`, and two sets of `q` signers share an honest node, so no `auth` has two outcomes. The successor has one nullifier on the root path and on the carried path (§5.6). Board-first: the board refuses a second call on one `nf` in board order, each node checks `nf` against the leaves of every landed `bf_root`, and the checkpoint signers refuse a `bf_root` that repeats an `nf`. `FenrirAssets` accepts no direct `authorize` for a board-first record, so a direct call cannot race the board. The pinned input bounds the host chain to one spend. The obligation is the case of a board that orders a call whose `nf` a landed `bf_root` holds after the node's check. |
| C12 | **One nonce use.** No committee slot and no ECDSA slot signs two messages. | TEE: all operators, enclaves intact, within the rollback bound of §7.7, where `c` also counts the seats whose tier 0 is lost; across a whole-committee restart, any number of rolled-back disks (§7.11). Non-TEE: `|C| ≤ f`, or `|C| < t` with `slot_anchor` (O32). ECDSA slots against actors: all `n` plus a coalition outside `Γ`, by the leaf-set binding of §3.6 | sketched; the counting with the anchor is O27 | a Schnorr slot `ℓ(g, j)` is reserved by one request, and up to `K` of its tickets name it. An honest node computes a partial on the slot for one ticket: the ticket of the variant that the anchor of generation `g` selects. The anchor is a function of the committed board record, so all honest nodes that release use one ticket. A second ticket on the slot needs `t` partials and gets at most `t − 1`, from corrupt nodes. A reserved slot is burned at the end of its request. An ECDSA slot serves one `(variant, input)` and is claimed once. The agreement of honest nodes on one anchor and one request per slot is board safety, which holds for `|C| ≤ f`; between `f` and `t − 1` corrupt nodes a forked board breaks it (§4.1), and only `slot_anchor` restores it. An ECDSA slot is bound to one leaf set, and its members answer once, so a fully corrupt committee cannot obtain two group evaluations on it. Changed hypothesis: honest nodes agree on a slot's one ticket because they read one anchor from the board, where each `(variant, input)` used to claim a slot of its own. O27 rewrites the counting with that step, for two generations on separate slots, and for a rolled-back enclave held to one ticket by the `slot` witness entry and the `bound` state of its session within the bound of §7.7. Beyond that bound a whole-committee restart burns every slot that a rolled-back disk could show `free` after a release: the range `[pending_min, h + B]`, which holds the window and the pending slots, and every unburned account-pool slot (§7.11). |
| C13 | **Liveness.** A valid, authorized envelope reaches FINAL or EXPIRED, or VOID with reason SLOT_TAKEN when an earlier live request named one of its slots (for an ECDSA slot, an earlier request whose authorization was in force) or one of its slots lies at or below the floor `h` and is not pending (§4.1), after which the initiator reissues it. A slot above `h + B`, or of a pool that no checkpoint lists yet, delays the votes until a checkpoint brings it into the window. | `|C| ≤ f`, partial synchrony | sketched; the merged step is O28, the ECDSA precedence rule is O38 | the board orders it. Precedence by board order (§4.1) means a later request never takes its slots, so SLOT_TAKEN needs an earlier envelope that named the slot before its header was readable. An ECDSA slot also needs that envelope's authorization in force, so an envelope without one voids no request on an ECDSA slot. `t = n − f` honest nodes hold good shares of `κ_0`, or an honest complaint voids the envelope. They send header partials, vote ADMIT with OBS once the authorization is in force, and release. `f + 1` combiners include an honest one. Changed hypotheses: (a) a node sends its partial without waiting for `q` ACKs, and the ADMIT vote serves as OPENED; (b) the OBS of generation 1 rides on the ADMIT vote and counts only if the request reaches ADMITTED. The anchor lemma of line dealing speaks about `q` reports with at most `f` Byzantine ones and does not use the arming order, so it applies to the reports of the first `q` ADMIT votes; (c) lazy checks move a VOID for a wrong ticket from ADMIT to release. O28 is the refinement argument that the merged votes reproduce the transitions of the unmerged machine, with complaints, expiry, view changes and a collecting request's separate OPENED vote. |
| C14 | **Rotation.** Reshare at `t = n − f` preserves `X_f` and secrecy. | `|C_old| ≤ f`, `|C_new| ≤ f'` | open (O5) | §8. |
| C15 | **Recovery.** After `Δ_rec` without a checkpoint, the owner exits to `D_exit` (P1 unconditionally, P2 unless held). | fewer than 3 corrupt `E` members, Midnight live | sketched, conditional on O5 and O10 | `E` holds `x_f` at 3 of 5 and reshares to a successor whose charter mode admits only exits. On ECDSA chains without slot anchors the exit first runs a refill session (§3.6) with the successor, with every session party online, because `E` reshares only ECDSA slots that no covered seat log binds (§7.11). |
| C16 | **Cold start.** A whole-committee restart loses no key, moves no coin and uses no slot twice, also when every disk was rolled back. | TEE: `|C| ≤ f`, any number of rolled-back disks; keys need tier 0 intact on `t` nodes or `E`. Non-TEE: `|C| ≤ f` | sketched, conditional on O5, O10 and O17, and on the restart checks of DECISIONS 51 | §7.11. Keys: `σ_i` in tier 0 on `t` nodes gives every session key, and the sessions hold `x_f` shares and slot shares; with fewer, `E` reshares `x_f`. Slots: the restart decision reads the ledger only. The burn of `[pending_min, h + B]` of each checkpoint read, the contract rules on `h` and `pending_min`, `slot_stale` and the restart marker make every slot that a rolled-back disk could show `free` unusable, and a put entry that a checkpoint root covers stops a second put of an account-pool share. `E` reshares only ECDSA slots that the covered seat logs show unbound. The loss is bounded: at most `B` usable committee indices plus the pending slots for each checkpoint read, the unused ECDSA slots of every address, and the requests that held them, which end VOID. |
| C17 | **Unadmitted coalitions cannot sign.** Any set of Fenrir nodes, up to all `n`, together with any coalition `C_A ∉ Γ` of actors, cannot produce a valid signature on a message `m*` unless the honest actors of some `S ∈ Γ` dealt contributions for `m*`. | all `n` plus `C_A ∉ Γ`, with every dealt contribution | Schnorr: sketched for an honest initiator, open for honest pool actors (O20); ECDSA: sketched, conditional on O1, O2, O19 | with nonzero member ids and no repeated leaf, the recursive sharing of §2.4 gives a coalition outside `Γ` a view independent of the honest residual `x_A − Σ_{C_A} λ_a·x_a` for every admitted set. A forgery yields the discrete log of the honest residual point. An honest initiator's contributions are simulated by programming the challenge, as in C3. Pool actors publish their pairs before the message, so their contributions are simulated by an AOMDL reduction in the style of the FROST proofs, which is O20. The adversary already holds every dealt contribution, so sealing contributions to `P_{v,g}` in place of dealing them changes nothing here. Hypothesis kept by rule: one pool pair and one fresh `k_0` per half, so the candidates on a shared committee slot add no second equation on any actor nonce. ECDSA: each slot signs one message, the setting of the presignature theorem. |
| C18 | **Sealed confinement per actor.** An honest actor's contribution completes only the half `(v, g, j)` it was computed for. With an honest initiator, fewer than `t` nodes and the other actors learn nothing about it before its variant is released. | confinement: all `n` plus every other actor. Secrecy: `|C| < t` (non-TEE: `|C| ≤ f`, as C9) plus the actors other than the initiator | confinement: as C17. Secrecy: sketched (DDH, ROM), part of O26 | the contribution is a point on the actor's shard line at the challenge of one `(R, m)`. `CL` and `pm` fix `R` and `m` through `ρ_a`, and the actor answers once per pair. Its scalars are encrypted to `P_{v,g}`, whose secret `y_{v,g}` the committee derives only for a released variant (C9). Changed hypothesis: secrecy needs an honest initiator, because the actor cannot check that `P_{v,g}` is the PRF key. A dishonest initiator that substitutes a key reads the scalars of the request it built. The adversary of C17 holds them in any case, and the request then ends VOID at release (§6.4 item 10). |
| C19 | **No concurrent-session forgery against an actor.** An adversary that names one honest actor's pool pairs in many concurrent requests learns no signature outside those requests. | initiator, other actors and all `n` | open (O20) | two-nonce binding over the whole list `CL` (§4.2), the setting of FROST against ROS and Wagner attacks. A request names `N_h` pairs of an actor, one per half, and several halves bind one committee slot. O20 covers that form. |
| C20 | **Reissue safety.** A stalled request releases nothing, and a reissue never reuses a committee slot or an actor pair. | `|C| < t` for release; `|C| ≤ f` (non-TEE) for slot reuse, as C12 | sketched | release needs ADMITTED, which needs every contribution. A collecting request reserves its slots with its OPENED votes, and VOID burns them. An actor that answered burned its pairs, and an actor that did not answer revealed no response. A contribution to a VOID request is never opened, because no honest node releases a variant partial for it. |
| C21 | **Actor identity hiding.** Before release, a non-TEE node learns of the actors only `|S'|`, the frame attachments and, on ECDSA chains, each contribution's session party index. A TEE operator learns only the frame count, timing and the vote kinds of §6.4 item 15. | non-TEE: `|C| < t`; TEE: all operators, enclaves intact | non-TEE: sketched; TEE: assumed TEE | the ticket carries `R_A` only. A contribution frame is an ordinary envelope with its own outer dealing and proof `π`, so it passes the same public checks and has the common shape. Leaf points sit in the header (TEE) or in capsules read after release. |

### 9.2 What fails when TEEs are broken

The claims C3, C4, C11 and C17 to C19 do not use the TEE and hold in every row. C1 and C2 hold while fewer than `q` enclaves are broken, because `q` broken enclaves sign a birth certificate without the proofs. C8, C9 and the secrecy part of C18 hold against fewer than `t` broken enclaves only: `t` broken enclaves expose their dealing keys, decrypt `t` shares of `κ_0` from any outer dealing and read every envelope before ordering.

| Broken enclaves | Lost | Kept |
|---|---|---|
| Fewer than `t` | blindness of those operators after ordering (C10 for those nodes); their witness entries; their PRF partials | every signature property, with C5 and C12 under the board and rollback bounds of §4.1 and §7.7; sealing until order (C8); authorization and hold enforcement (C6, C7), because a release needs `t` nodes |
| `t` or more | authorization and hold enforcement (C6, C7) against those operators: they can release already-dealt variants of an admitted envelope despite a hold, and they can ignore approver vetoes; every confidentiality claim, before and after ordering (C8, C9, C10, C21), because the broken enclaves reconstruct `κ_0`; every session record of every seat, because `t` broken enclaves derive any session key; witness safety and with it C12 for committee slots | C3: no message outside the dealt variants; C4: no spend without the owner or guardians; C11 |
| All `n` | everything of the row above, for every request; `x_f` and every committee nonce | C3, C4, C11, C17 |

A broken enclave never yields a signature on a message that no admitted signing set sealed, because no shard is in an enclave. In P0 and P1 that is the whole of R1. Every branch of `Γ` adds its own colluding set: `t` broken enclaves and any admitted signing set can sign without the charter's authorization, so in P2 `t` broken enclaves and `t_g` colluding guardians can seize without a settled order. For a board-first charter the enclave is also the verifier of the authorization proof, so `t` broken enclaves release without a valid proof. That is the same loss as in the row above, and such a charter is P0 or stateless P1, where C3 and C4 still hold.

### 9.3 Changed hypotheses and proof obligations

No proof exists for any item of this list. Each is an open item of §12.

**Theorem D restated (O26).** Theorem D of `design/PROOFS.md` states that sealed points stay sealed below `t` when the sealed value is a dealt scalar. Here the sealed values are keys. Statement to prove: let `|C| ≤ t − 1`, let an honest party deal `κ_0` in an envelope with outer digest `dd`, and let `lab` be a label on which no honest node has released a partial. Then the PRF point `Z_lab = κ_0·H_c(dd ‖ lab)` is indistinguishable from a uniform point, so `KDF(Z_lab)` is indistinguishable from a uniform key. For a variant label, the pair `(y, P) = (Hq(Z_lab ‖ "ctb"), Hq(Z_lab ‖ "ctb")·G)` is distributed as a fresh key pair whose public half `P` is published in the header, and a sealed contribution to `P` (§4.6) hides its scalars, as hashed ElGamal does under CDH with `KDF` as a random oracle. The scalar `y` is not claimed indistinguishable from uniform given `P`, because `y·G = P` tests it. All of this holds under DDH on secp256k1 with `H_c`, `KDF` and `Hq` as random oracles, given the commitments, the corrupt shares, every partial released on other labels with its Chaum-Pedersen proof, and the answers to complaints, which the reduction gives as Theorem C does. The proof includes the binding of a partial to one outer dealing through `dd`, with the event `Reuse` of Theorem C for an envelope that copies an outer dealing under other bodies. C8, C9 and the secrecy part of C18 rest on it.

| Claim | Changed hypothesis | Proof obligation |
|---|---|---|
| C8, C9, C18 secrecy | keys are threshold PRF outputs; hiding is computational (DDH, ROM); an actor's scalars need an honest initiator | O26: Theorem D restated, with the confinement to one outer dealing |
| C12 | one Schnorr slot per `(generation, input)` carries up to `K` candidate tickets; agreement on the one signed ticket comes from the board anchor, which is safe for `|C| ≤ f` only; ECDSA slots are bound to one leaf set | O27: the counting argument with the anchor, two generations, and the `slot` witness entry under rollback, for `|C| ≤ f`; O32: `slot_anchor` for `|C| < t` |
| C5 | one signing query per committee slot, chosen by the anchor among the dealt tickets; the oracle is enforced by board safety, `|C| ≤ f`, or by `slot_anchor` | O6, restated with that oracle; O32 |
| C17, C19 | `N_h` pairs per actor and request; several halves bind one committee slot; contributions are sealed to `P_{v,g}` | O20, restated for that form |
| C13 | ACK merged with the partial; ADMIT serves as OPENED and carries OBS; lazy checks; a separate OPENED vote for collecting requests | O28: refinement of the unmerged state machine, and the anchor lemma for OBS reports that count only on ADMITTED |
| C6, C11 | board-first: an authorization is in force by a node-verified proof against a finalized root and a board-ordered nullifier | O29: C6 and C11 for board-first charters with stateless predicates |
| C6, C13 | the header opens before the authorization is in force | none for C6: the claim is about release, and §6.4 item 11 states what an opened, never admitted envelope reveals. For C13, a node that reads an opened header cannot take its slots, because precedence follows board order (§4.1); O27 covers it. An ECDSA slot takes precedence only from an authorization in force for its record (§4.1); O38 covers it |
| §7.7 witness | `open` entries ride on votes; `release` entries are sent after the anchor in one batch per height; one flush per height; each slot then binds by `slot_bind`; `c` counts the seats whose tier 0 is lost until their fetch completes | none for the bound: every entry still needs `w` distinct acks before the output leaves. The `slot` entry and the `bound` state of the session now carry part of C12 (O27) |
| C3, C10, C20, C21 | per-half nonces; `x(R)` in the ticket; reservation by OPENED votes; contribution frames keep their dealing | none: the arguments in §9.1 hold as written |

## 10. Requirements

R1 is read per profile. In P0 and P1 no spend results without the owner's own authorization, which is the owner's half-signature (in P0 the owner's sealed line). With several actors the owner's authorization generalizes to the contributions of an admitted signing set `S ∈ Γ`. In P2 no spend results without one of the charter's admitted sources: the owner, a settled seizure order through the guardians, or a recovery exit. Seizure, freeze, blacklist, reversal and holds are charter options of P2. They are not requirements of the protocol, and a P0 or P1 charter has none of them.

Each cell gives TEE mode / non-TEE mode.

| Req | P0 existing | P1 co-custody | P2 regulated | Why |
|---|---|---|---|---|
| R1 | MET / MET | MET / MET | MET / PARTIAL | P0, P1: every spend needs the owner's sealed half, which all `n` nodes cannot forge (C3, C4). Owner-chosen vetoes and predicates in P1 bind all operators in TEE mode and `|C| < t` in non-TEE mode. P2 non-TEE: `t` corrupt nodes can release a dealt variant despite a hold, and `t` nodes with `t_g` guardians can seize without an order (C6, C7). |
| R2 | NOT MET / NOT MET | Schnorr MET, ECDSA PARTIAL (both modes); PARTIAL with the exit leaf | as P1 | P0: the owner holds `x`. P1, P2: `x = x_U' + x_f`, nobody holds `x`, and every spend needs the committee half from `t` nodes. In non-TEE mode the committee half resists `t − 1` corrupt nodes only with `slot_anchor`; without it, more than `f` corrupt nodes can fork the board and recover `x_f` from one slot (§4.1, O32). The Schnorr grade carries the open proof O6. The ECDSA grade depends on the slot functionalities O1 and O2, as R3 does. A matured exit leaf lets the holder move a coin alone. |
| R3 | NOT MET / NOT MET | Schnorr MET, ECDSA PARTIAL (both modes) | as P1 | Wallet-supplied or network-created user element, fresh per address. The committee never holds `x` (C1, C2). ECDSA birth depends on `F_presig` and `F_mul` at `t = n − f` (O1, O2). |
| R4 | NOT MET / NOT MET | PARTIAL / PARTIAL | PARTIAL / PARTIAL | P1: the owner's own covenants bind the holder and a wallet thief while the committee enforces them. Freeze, blacklist, reversal and seizure do not exist in P1 by design. P2: sources (a), (b), (c) are enforced and holds block the owner's route. A signature released to a host chain cannot be recalled, reversal reaches only funds still under Fenrir, the exit leaf ends a hold, and non-TEE enforcement is threshold. |
| R5 | PARTIAL / PARTIAL | MET on Bitcoin with the exit leaf, else PARTIAL | PARTIAL / PARTIAL | P0 is one key: the owner is never trapped, but there is no two-key custody. P1: two keys. The exit leaf is unconditional, and the recovery group `E` serves every chain under the assumption that fewer than three members are corrupt and Midnight is live. P2: a live hold blocks exit by design. |
| B1 | MET, ECDSA PARTIAL / PARTIAL | MET, ECDSA PARTIAL / PARTIAL | MET, ECDSA PARTIAL / PARTIAL | TEE: operators see ciphertext, size and timing, except the ECDSA slot session, which runs in the clear (§6.4 item 3, O35). Non-TEE: nodes see the header after ordering, `X` at birth and on ECDSA chains, and the combiners see the transaction at release (§6.1). |
| B2 | MET / PARTIAL | MET / PARTIAL | MET / PARTIAL | Before ordering nothing is selectable in either mode. Non-TEE nodes see request type and fee rate after ordering. They cannot stop a release, because `t` honest nodes suffice (§6.2). TEE grade assumes the wallet posts through an anonymizing relay. |
| B3 | MET / MET | MET / MET | MET / MET | The outer dealing is line dealing's sealed encryption. No partial moves before the QC (C8). The grade carries the open proof O26. |
| B4 | MET / PARTIAL | MET / PARTIAL | MET / PARTIAL | TEE v1 runs node, mempool and erasure in hardened Veritee. Non-TEE mode is the same messages with ticket blindness and the ticket proof, so it layers on without a redesign. It gives blindness until release, not full content hiding. The ticket circuit is not yet measured (O4), and its use from Compact is open (O25). |
| B5 | PARTIAL / PARTIAL | PARTIAL / PARTIAL | PARTIAL / PARTIAL | Fresh keys and tweaks unlink addresses, and the frame hides who started a request. The host-chain graph, Midnight timing and, in non-TEE mode, the `R` link from envelope to transaction remain (§6.4). |
| B6 | PARTIAL / PARTIAL | PARTIAL / PARTIAL | PARTIAL / PARTIAL | Until broadcast only the enclaves (TEE mode) or the combiners (non-TEE mode) and the named actors hold the message. Between broadcast and inclusion the host chain's mempool and the combiner's RPC endpoint see it. A private submission path to block producers is not specified. |

**Charters with several actors.** The table above grades the single-user form. A P1 or P2 charter with `|A| ≥ 2` changes the grades below. Each cell gives TEE mode / non-TEE mode. Rows not listed keep their P1 or P2 grade.

| Req | P1 or P2 with `|A| ≥ 2` | Why |
|---|---|---|
| R1 | MET / MET (P2: MET / PARTIAL), Schnorr conditional on O20 | all `n` nodes plus any actor coalition outside `Γ` cannot sign (C17). An honest actor's contribution signs only what it read (C18). The P2 limits of the single-user form remain. |
| R2 | Schnorr MET, ECDSA PARTIAL (both modes) | every spend needs `t` nodes and an admitted set, and nobody holds `x`. Schnorr carries O6 and O20, ECDSA carries O1, O2 and O19. |
| R3 | Schnorr MET, ECDSA PARTIAL (both modes) | every shard is fresh per address and proved at birth (C1, C2). ECDSA birth needs every session party online and the many-party session of O19. |
| R5 | PARTIAL / PARTIAL | the launch shape adds a third key where a third party joins, as R5 asks. Exit through `E` needs an admitted signing set. A charter whose every admitted set needs one actor traps the funds while that actor is silent. An OR branch or a threshold group removes that trap, and reissue (§5.9) uses it. |
| B1 | MET / PARTIAL | content stays hidden from operators. Each actor sees the request it co-signs, by design. |
| B2, B3 | as P1 | against nodes and actors not named. A named actor holds the header key and can disclose its own request before ordering, which a colluding operator could use to select (§6.4). |
| B5 | PARTIAL / PARTIAL | as P1, plus the collection timing of §6.4 and, after release, pool pseudonyms at the combiners. Contribution frames have the common shape before ordering. After ordering the vote kinds show which envelopes are contribution frames and which requests collect (§6.4 item 15). |

## 11. Costs

All figures are **estimates**. None is a measurement of split-line dealing. They are operation counts multiplied by unit costs taken on one aarch64 laptop core (Cortex-X925, k256 0.13.4, curve25519-dalek 4.1.3), each with about ±15%: a variable-base scalar multiplication costs 56 µs on secp256k1 and 31 µs on edwards25519, a table-driven generator multiplication 26 µs and 10 µs, a share check with small-index evaluation 36 to 52 µs at `t = 7` or `t = 12`, and an Ed25519 signature check 34 µs. Committee nodes run on other hardware. Ratios carry over, absolutes do not, and every figure of this section is measured before anyone relies on it (O31). The request is a Bitcoin P2TR spend with `K = 8`, `L = 2`, `G_max = 2`: 30 halves, 15 variant bodies, 4 committee slots.

### 11.1 Message sizes

| Message | Launch, `n = 9` | `n = 17` |
|---|---|---|
| Envelope | 16,384 B, of which the request uses about 11.1 KB | 16,384 B, about 11.5 KB used; the full grid fits |
| Outer dealing, the only dealing of an envelope | 748 B | 1,169 B |
| Schnorr ticket / ECDSA ticket | 149 B / 36 B | same |
| Variant body | `32·L + 48` = 112 B | same |
| Sealed contribution, per actor and variant body | `49 + 32·L` = 113 B | same |
| PRF partial, node to node | 33 B on the peer channel; a 97 B Chaum-Pedersen proof only after a failed tag | same |
| Signature partial, per input | 32 B on the peer channel | same |
| Board vote | one Ed25519 signature per node and block, plus about 40 B per post it lists; under 1 KB per request | under 2 KB per request |
| Witness entry and ack | about 100 B per entry, one signature per batch and board height | same |
| Schnorr slot on the board (all `t` dealers) | `t·2·(t·33 + n·32)` = 7.3 KB | 22.6 KB |
| Schnorr slots of one request | 4 slots, 29 KB | 4 slots, 90 KB |
| ECDSA slot session per slot | `3·n_A` `F_mul` instances per node plus 64 B corrections per party and node, and `3·n_A·(n_A − 1)/2` instances among session parties; size depends on O2 and O19 | same |
| Midnight `authorize` | proof plus about 300 B of public inputs | same |
| Actor capsule, per other actor | `97 + 32·K` B = 353 B | same |
| Envelope growth per other actor | 758 B (911 B TEE), plus 495 B once for the keys `P_{v,g}` | same |
| Contribution frame | 16,384 B, 2.8 KB used | 16,384 B, 3.2 KB used |
| Embedded contribution | 1.7 KB in place of the actor capsule | same |
| Actor pool post | about 4.3 KB per `N_pool = 64` pairs; a request burns 30 pairs per named actor | same |
| **Board bytes per request** | **about 46 KB**: frame 16.4 KB, slots 29 KB, votes under 1 KB | **about 108 KB**: frame 16.4 KB, slots 90 KB, votes under 2 KB |

The slot bytes are paid when the pool is dealt, not on the request path.

**Signing sets per frame** (from `vectors/sizes.py`; the largest `|S|`, initiator included, whose actor capsules fit beside the request):

| Grid | `n = 9`, non-TEE / TEE | `n = 17`, non-TEE / TEE |
|---|---|---|
| P2TR `K = 8`, `L = 2` | 7 / 6 | 6 / 5 |
| P2TR `K = 8`, `L = 1` | 11 / 10 | 10 / 9 |
| P2TR `K = 5`, `L = 2` | 18 / 15 | 17 / 14 |
| P2WPKH `K = 3`, `L = 2` | 41 / 37 | 40 / 36 |
| Ethereum or Solana `K = 1`, `L = 1` | more than 60 | more than 60 |

### 11.2 Rounds and latency

`C` is one board commit, `h` one peer hop (about 50 ms), `F_M` Midnight finality. Midnight produces a block about every 6 seconds and publishes no finality time, so `F_M` stays a symbol.

| Step | Board commits | Wait |
|---|---|---|
| `authorize` on Midnight, in parallel with the next row | none | `F_M` |
| Order, share check, header partials, open | 1 | `C + h` |
| ADMIT votes with OBS, once the authorization is in force; anchor | 1 | `C` |
| Release witness | none | `h` |
| Release, combine and broadcast | none | `h` |
| Host inclusion | host chain | host block time and depth |

| Path | Post to broadcast | `C = 1 s` | `C = 0.5 s` |
|---|---|---|---|
| Every profile, Midnight-first | `max(F_M, C + h) + C + 2h` | `F_M` + 1.1 s | `F_M` + 0.6 s |
| Board-first (P0, stateless P1) | `2C + 3h` | 2.15 s | 1.15 s |

The normal path has two board commits and three peer rounds: the partial exchange, the release witness and the release. A collecting request adds the commit of its OPENED votes, the actors' response time bounded by `Δ_c`, and the order commit of each contribution frame. A second generation adds the commit of its OBS set. The `anchor_before_release` profile adds one `F_M` per generation.

### 11.3 Node CPU per request

Per node, secp256k1, TEE mode, `n = 9`:

| Step | Cost | How |
|---|---|---|
| `π` check before ordering | 0.20 ms | the three equations as one variable-time multi-scalar check |
| Outer share: Diffie-Hellman and check | 0.11 ms | small-index evaluation |
| Header key | 0.45 ms | one partial; `t` partials combined in constant time |
| Tickets of the selected variant: `ρ`, `R`, `σ`, `x(R)` | 0.11 ms | `L` tickets, at release |
| Own signature partials | 0.01 ms | two field multiplications each |
| Variant key | 0.45 ms | as the header key |
| Combine (TEE: every node) | 0.15 ms | interpolate, verify the signature |
| Vote signatures | 0.1 to 1.0 ms | `q` signatures per block in one batch, shared by the requests of the block |
| Contribution equations and partial checks | 0 on the normal path, about 0.25 ms after a failed combination | §4.7 item 8 |
| **Request path** | **1.8 to 2.7 ms** | the planning figure, with the failure-path checks counted; about 1.6 to 2.5 ms when the combination succeeds; 2.4 to 3.3 ms at `n = 17` |

Non-TEE mode combines partials in variable time: subtract about 0.7 ms at `n = 9` and 1.2 ms at `n = 17`. A node that verifies a board-first authorization adds one proof check, about 1.4 ms.

| Per request, one core | `n = 9` | `n = 17` |
|---|---|---|
| Request path, TEE mode | 1.8 to 2.7 ms | 2.4 to 3.3 ms |
| Slot replenishment, 4 slots | 1.2 to 3.6 ms | 2.0 to 7.2 ms |
| Total | 2.5 to 6.3 ms | 3.8 to 10.5 ms |
| Requests per second and core | about 160 to 400 | about 95 to 260 |
| Combiner, per request | 0.15 ms | 0.2 ms |

The low end of each slot figure uses the batch equation of §4.1 and the generator table. The high end uses small-index evaluation alone. A second estimate that assumes server-class x86 cores and every batch gain gives 730 and 395 requests per second and core. It is not the planning figure.

The wallet computes one polynomial, `n` pads, `π` and 30 nonce points: 51 multiplications at `n = 9`, about 2.8 ms, and 64 at `n = 17`, about 3.5 ms, before the generator table.

### 11.4 Proof cost (non-TEE mode)

The ticket proof is one circuit at `k = 18`. For a BIP341 spend with SIGHASH_DEFAULT, two inputs and two outputs, the SHA-256 compressions are:

| Hash | Compressions | Shared by |
|---|---|---|
| `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`, `sha_sequences` | 6 | the request |
| first two blocks of the tagged `SigMsg` | 2 | the request |
| `sha_outputs` | 2 | each variant |
| third block of `SigMsg` | 1 | each `(variant, input)` |
| challenge, with the tag midstate fixed | 2 | each half |

With `H_pm` a Poseidon2 hash that is 8 + 16 + 16 + 60 = 100 compressions for 30 halves. The SHA-256 gadget of midnight-zk takes 1,911 rows for one compression, so the hashes take about 190,000 rows of the 262,144 at `k = 18`. A published benchmark of Midnight's prover reports 24.6 s at `k = 18` on a server CPU and 8.8 s on an RTX 5090 for a circuit it does not name, so the proving time of this circuit is about 25 s on that CPU. The companion device or a desktop proves it. The circuit stays below the limit `k ≤ 21`. Measuring it is O4. The fallback of O25 costs a STARK of about 2^18 rows and a wrap budgeted at 2^20 constraints.

### 11.5 Costs per actor

For the same request at `n = 9` and a signing set with `|S'|` actors besides the initiator:

| Item | Cost |
|---|---|
| Dealings by the actor | none for the contribution. A contribution frame has the one outer dealing of every envelope; an embedded contribution has none |
| Actor work per request | per half the recomputation of `R` (`|S'| + 1` multiplications plus the sighash) and one scalar; per variant body one ephemeral point and one Diffie-Hellman; for a frame the outer dealing and `π` (`t + n + 5` multiplications). About `30·(|S'| + 1) + 30 + 21` multiplications, about 8 ms at `|S'| = 2` |
| Actor pairs per request | `N_h` = 30 pairs per named actor, burned whether the variant is selected or not |
| Board bytes per actor | 758 B in the request (911 B TEE) and one contribution frame, or 1.7 KB embedded |
| Node CPU per contribution frame | the frame's own open: `π` check, outer share and header key, about 0.8 ms |
| Node CPU per contribution at release | one Diffie-Hellman per actor for the released body, about 0.06 ms, at the combiner |
| Contribution check | none on the normal path; one equation of §4.2 per input, 3 multiplications, after a failed combination |
| Latency | the actors' response time, bounded by `Δ_c`, plus the OPENED commit and one frame cycle for the last contribution. Embedded contributions add nothing. A reissue adds a new authorization and a full request path |
| ECDSA birth | `3·n_A·(n_A − 1)/2 + 3·n_A·n` multiplications per slot and about `2·n_A + 2` rounds, with every session party online (§3.6) |

The committee's work per request does not depend on `|S|` except through the contribution frames it opens and the one Diffie-Hellman per actor at release. The ticket, the partial and the ticket proof of §11.4 are unchanged, because the committee binds only `R_A`.

### 11.6 Midnight writes

The committee writes Midnight per checkpoint, per epoch and per boot, never per request. Puts, slot bindings, release anchors and boot statements go to the seat logs on the board. Settlements and board-first calls go to the board. Each checkpoint carries fixed-size roots over them (§5.3, §5.6, §7.4, §7.13). Only the user's own transactions grow with the request rate.

**Committee writes.** `P` is the number of committee pools, 2 at launch (one per Schnorr suite) and up to 4 while two epochs overlap. Sizes count the payload. Midnight's transaction overhead is not stated, so it is not counted.

| Write | When | Transactions | Payload at `n = 9` (`q = 6`) | Payload at `n = 17` (`q = 12`) |
|---|---|---|---|---|
| Checkpoint: `seq`, `epoch`, `board_height`, `board_root`, `witness_root` (88 B); `(h, pending_min, pending_root, pending_count)` per pool (`52·P` B); `settle_root`, `bf_root` (64 B); `n` boot counters (`8·n` B); `restart_seq` (8 B); `n` seat roots (`32·n` B); `q` signatures (`64·q` B) | every 60 s | 1 | 1,008 B at `P = 2` | 1,712 B at `P = 2` |
| `RestoreDone` statements in a checkpoint | after a restore | 1 more checkpoint | about 115 B per restored seat, at most 1,035 B | at most 1,955 B |
| Epoch key set `EKS_e`: `n` `NodeKeys` of 133 B, `keylist_hash`, `q` signatures | per epoch | 1 | 1,621 B | 3,069 B |
| `admitBoot` | per node boot | 1, by the operator | one boot ticket | one boot ticket |
| `retire`, `replaceSlot`, `coldStart`, `recover`, Image Registry approvals | per event of that kind, never per request | 1 each | one record | one record |

Per committee, at any request rate: one checkpoint transaction per 60 s, which is 1/60 transaction and about 17 B per second at `n = 9` (29 B at `n = 17`), or 1,440 transactions and 1.5 MB per day (2.5 MB at `n = 17`). At 160 to 400 requests per second that is one committee transaction per 9,600 to 24,000 requests. One checkpoint covers 9,600 to 24,000 settlement leaves, and its size does not change with that count.

**User writes.** These are the writes that grow with requests. Each one is the user's own transaction.

| Event | Transactions | Payload | At 160 to 400 requests per second |
|---|---|---|---|
| Spend request, Midnight-first | 1 `authorize` | the proof plus about 300 B of public inputs (§11.1) | 160 to 400 per second, 9,600 to 24,000 per 60 s |
| Spend request, board-first | 0: the call goes to the board and the checkpoint's `bf_root` covers it | none per request | 0 |
| Reissue of a stalled request | 1 `authorize` that also carries the VOID settlement of the stalled request | as a spend request, plus `auth` and `q` signatures: about 420 B at `n = 9`, 800 B at `n = 17` | one per reissue |
| Next spend after FINAL | 0 extra: the next `authorize` proves its settlement leaf under a landed `settle_root` | none | 0 |
| Address birth | 1: the shielded asset record with its birth certificate (on ECDSA its slot roots, for a network-created shard `E_c`) | one record | one per address |
| ECDSA refill session | 1: the new slot roots `slr_own` (and `slr_G` in P2) | two roots and `q` signatures | one per refill session |
| Actor pool-key root | 1 per `N_pk` pools | one root | about one per 2,000 requests that name the actor |
| P2 hold, revocation, seizure order | 1 each, by its authority | one record | one per authority action |

At `n = 9` and `n = 17` the user rows are the same, except the reissue signatures. The node capacity of §11.3 is lower at `n = 17` (about 95 to 260 requests per second and core), but a committee with more cores reaches 160 to 400 per second at either size, and the committee rows stay as above.

`slot_anchor` (O32), which seald implements as its committee parameter of that name, and the charter option `anchor_before_release` add no transaction and no row. They add the latency of one checkpoint interval plus Midnight finality to each release that waits for a root.

## 12. Open items

Each item is a concrete obligation with a pass condition.

| Id | Obligation | Done when |
|---|---|---|
| O1 | `F_presig` at `t = n − f` | a protocol with a written proof (DKLs23-style OT multiplication, CGGMP21 presigning, or a 2PC-MPC emulation) outputs `R_f` and Shamir `t`-of-`n` shares of `k_f⁻¹` and `k_f⁻¹·x_f` with Feldman commitments in base `R_f`, secure with `f` Byzantine nodes |
| O2 | `F_mul` between each session party and each node, and between session parties | a malicious-secure two-party multiplication is chosen and its cost per slot is measured |
| O3 | Hold contract | `revoke`, `SetHold` and the key-private hold handle are implemented in Compact and a test shows that a revoked authorization stops release in TEE mode |
| O4 | Ticket circuit | the circuit for the three suites is composed from the SHA-256, SHA-512 and Keccak gadgets of midnight-zk, a request with 32 tickets measures at `k ≤ 18` (limit `k ≤ 21`), and its proving time is measured on a server CPU and on the companion device |
| O5 | Reshare at `t = n − f` | a proof of §8 (secrecy of `x_f`, preservation of `X_f`, liveness of HANDOVER) under a stated network model, or a PVSS reshare with a proof. The fixed complaint window of §8.1 needs synchrony: under partial synchrony `f'` corrupt new nodes can supply `READY` while honest holders of bad shares complain late, leaving `n' − 2f' < t'` good holders, so a partially synchronous committee needs the PVSS reshare |
| O6 | Schnorr committee unforgeability with a user half (C5) | a reduction to AOMDL in the ROM for an owner plus `t − 1` nodes, with the signing oracle "one query per committee slot, on the ticket the board anchor selects among the up to `K` tickets dealt on that slot" |
| O7 | Second size class | board throughput is measured with 64 KiB frames and the class is added only with a minimum anonymity set |
| O8 | Zero-knowledge birth | a Midnight proof replaces the non-TEE birth check, so nodes never learn `X` at birth |
| O9 | Time-locked exit for Ethereum and Solana | a tlock-style exit certificate or an equivalent is specified, or `E` stays the only exit on those chains |
| O10 | Recovery group protocol | the verifiable backup of `x_f` and of slot shares, the `recover` and `coldStart` contracts and the exit-only successor charter are written and tested |
| O11 | ECDSA slot exhaustion | the initiator starts a refill session below 8 unused slots, and a test shows spending stops cleanly at zero |
| O12 | Authorization batching | Midnight `authorize` batches per block and the timing link of §6.4 is measured |
| O13 | Solana adapter | acceptance tests for durable nonce advance, failed-execution handling and Token-2022 controls pass |
| O14 | Guardian nonce binding | guardians contribute from their own pools with the `ρ_a` binding of §4.2, and the proof of O20 covers seizure signing |
| O15 | Witness log compaction | witness entries below the latest checkpoint are pruned without weakening the replay floor |
| O16 | TEE v1 to v2 switch | TEE nodes accept authorizations that carry the ticket proof through the same interface and drop the header intent |
| O17 | Cold start drill | a test reboots all nine nodes with tier 0 intact, with tier 0 lost, and with every disk rolled back to one old state, and also reboots `f + 1` nodes one at a time; it shows no key loss, no coin movement, no slot bound for two tickets, burned sets within `B` plus the pending slots for each checkpoint read, and the restart marker burning the account pools of a node that boots late |
| O18 | Test vectors | the parity, Ed25519, ECDSA and slot-algebra vectors, single-user and multi-shard (AND of one to five actors, every subset of 2-of-3, both branches of `user OR G`, one key under several signing sets, the many-party ECDSA session over ideal multiplication), the shared committee slot over two generations, the threshold PRF keys with their partial proofs, the sealed contribution, and the batch equation with its fallback, are committed and run in CI |
| O19 | Many-party ECDSA session | the session of §3.6 among `n_A` session parties and the committee is instantiated with malicious-secure party-to-party multiplication with input consistency across its instances, identifiable abort that names a cheating party, and a proof at `t = n − f`. Its cost per slot is measured at `n_A = 1` to 5 |
| O20 | Unforgeability with pool actors (C17, C19) | a reduction to AOMDL in the ROM, in the style of the FROST proofs, for an adversary that holds all `n` nodes, the initiator and every actor outside an admitted set and opens concurrent requests on honest actors' pools, with `N_h` pairs of an actor per request and several halves bound to one committee slot |
| O21 | Early contribution check | a node checks each contribution before ADMIT, in either mode, without reading the scalar or learning leaf points, for example by a point `s_a·G` in the contribution with a proof that it matches a committed leaf point of the charter and the sealed scalar; until then a bad contribution is found at release and costs a reissue |
| O22 | Access structure in `authorize` | the circuit encodes `Γ` (AND, threshold, OR gates) in the charter commitment and proves `S ∈ Γ` and the initiator's membership; its row count is measured for formulas of up to 16 leaves |
| O23 | Actor pools and notification | pool posting, pseudonym registration in the shielded charter, refill thresholds, the notification channel for actor capsules and the cost of trial decryption are specified and tested |
| O24 | Exit leaf with several actors | the `K_exit` construction for a charter with several actors (an aggregate key of an admitted set, or several leaves, one per admitted set) is chosen and its script cost measured |
| O25 | Compact access to the hash gadgets | a Compact contract calls the SHA-256, SHA-512 and Keccak gadgets of midnight-zk, or Midnight accepts a circuit written against the library for the ticket proof. If neither holds, the fallback of §5.3 is built: a KoalaBear STARK with Poseidon2 commitments, aggregation and one BLS12-381 wrap at `k ≤ 21` |
| O26 | Sealing by threshold PRF (C8, C9, C18) | a written proof of Theorem D restated (§9.3): pseudorandomness of `Z_lab` and `KDF(Z_lab)` on labels with no honest partial under DDH in the ROM, and security of a contribution sealed to the published key `P_{v,g}` in one joint hybrid that replaces `y_{v,g}` and `P_{v,g}` together, with complaints answered as in Theorem C, the confinement of a partial to one outer dealing, and the full-statement Chaum-Pedersen transcript of §4.6 |
| O27 | One nonce use with shared slots (C12) | the counting argument rewritten with the anchor: one signed ticket per `(generation, input)` slot among up to `K` candidates, two generations, precedence of slots by board order, and the `slot` witness entry with the `bound` session state under rollback and blank tier 0, for `|C| ≤ f` |
| O28 | Liveness of the merged path (C13) | a refinement argument that the merged votes (ACK with the partial, ADMIT as OPENED with OBS, the separate OPENED vote of a collecting request, lazy checks) reproduce the transitions of the unmerged state machine, that the anchor lemma holds for OBS reports that count only on ADMITTED, and that a provisional `open` witness entry of a proposal without a QC never blocks the opening at the committed position |
| O29 | Board-first authorization (C6, C11) | a proof of C6 and C11 for board-first charters: node-verified proof against a finalized root within the root-age bound, nullifier ordered by the board, the batch under `bf_root` with the duplicate-`nf` checks of the nodes and the checkpoint signers, and no race with a direct call; the contract rule is implemented in Compact |
| O30 | Deferred share compression | seeded shares and derived slot shares each get a proof that the public complaint and the related-dealing defence of Theorem E still hold; Vandermonde extraction of slots gets a proof that linearly related slots serve the reduction of O6 |
| O32 | Slot anchor | `slot_anchor` is specified and built, and it also lifts the rollback bound of §7.7 for committee slots, because `x_f` is shared by every charter and a per-charter `anchor_before_release` cannot protect it: an entry `ℓ → H(tk)` per committee slot and generation in each seat log on the board, keyed by an unlinkable slot nullifier, with one Merkle root per seat log in each Midnight checkpoint and no Midnight transaction per slot; each node releases on a slot only after a landed root covers its entry and no covered entry of any seat binds the nullifier to another ticket; the seald bindings of `anchor_before_release` use the same nullifier key, with `H(tk)` hidden, so no seat log shows a slot id or an account-pool id; a proof that C12 and the oracle of O6 then hold for `|C| < t` in non-TEE mode; the tight bound on corrupt nodes that recover `x_f` from forked boards without it; the added release latency of about one checkpoint interval plus Midnight finality per generation measured |
| O33 | ECDSA leaf-set slots | the birth and refill sessions of §3.6 assign slots to leaf sets with the charter's expected use; a test shows that every member and every escrow holder refuses a slot of another leaf set, and that a silent member leaves the slots of the other leaf sets usable |
| O34 | Slot pool sizing | the committee slot pool, the reservation window `B` and the way initiators pick indices near the bottom of the window keep honest SLOT_TAKEN collisions and indices lost below the floor below stated rates at the measured request rate, over the window from post to authorization in force (proving time plus `F_M`) and one checkpoint interval |
| O35 | Encrypted ECDSA slot sessions | the messages of the slot session of §3.6 and the escrow dealings of §3.8 run inside fixed-size envelopes to the enclaves and the session parties' keys, so TEE operators and board observers do not see `X` or `R_ℓ`. The state that the enclaves keep from those messages already lives in sealed account pools under random ids (§7.4), so no node needs a clear board transcript to restore a slot, and the record headers, seat logs and checkpoints name no account. What stays open is the transport of those messages, the time at which a new account pool first appears, and the slot anchor of O32 |
| O36 | Batched bind | seald binds every slot of one pool session that one board height anchors with one `slot` entry batch and one sealed version (§7.7), its refusal rules apply per slot, a Quint check shows that G2 holds for a batch with a refused slot, and the two bind rounds are measured at the measured request rate with a pool session of `S_max` |
| O37 | Batched settlement in `authorize` | the `authorize` circuit shows a settlement leaf under a landed `settle_root` (a path of about 15 levels at 24,000 leaves per checkpoint) and each named actor's pool key under a pool-key root of `N_pk` keys (§3.10); the added rows are measured beside the ticket proof of §11.4 and the circuit stays at `k ≤ 21`; the contract checks the `q` signatures of a carried VOID settlement against `EKS_e` |
| O38 | ECDSA precedence from the authorization (C12, C13) | a proof that the ECDSA precedence rule of §4.1 keeps C12 for ECDSA slots and gives C13 against an adversary that names an account's slot ids in envelopes with no authorization in force, a P2 user who names the guardian slots included; the Quint check `formal/quint/splitline.qnt` (rule `ecdsaPrecInForce`, invariant `C13_EcdsaPrecOnlyInForce`) holds; the prototype gives no precedence and no burn to such an envelope |
| O31 | Measured costs | the figures of §11 are measured in `impl/benches` with the rules of §5.10 implemented, on the benchmark machine under exclusive use and on the node hardware, for both committee sizes and both modes |

## 13. Changes to SCHEME.md

| SCHEME section | Change |
|---|---|
| §1 Scheme in one paragraph | Add one paragraph for split-line dealing with `n` shards over an access structure, always ANDed with the committee, and the three profiles. Line dealing becomes profile P0. |
| §2 Setting and assumptions | Add shard holders and the access structure `Γ` (§2.4), the guardian set (P2) as the `G` branch of `user OR G`, the recovery group, Midnight as the authorization ledger, and the TEE assumption of TEE mode. Add `w = n − 1 − f`, `N_pool` and `Δ_c`. |
| §3.1 Notation, hashes and labels | Add labels `SL1/dkg-*`, `SL1/slot`, `SL1/bind`, `SL1/bind-act`, `SL1/pop`, `SL1/pop-rk`, `SL1/dleq`, `SL1/seal-cap`, the PRF labels `hdr` and `(v, g)`, the hash to the curve `H_c` and the hashes `Hq_bind`, `Hq_tw`, `Hq_pop`, `H_pm`. |
| §3.2 The owner's message | Add the envelope of §4.6 as the carrier of every request type, P0 included, with the actor slot table, actor capsules and the contribution frame (request type 0x06). |
| §3.3 What is dealt | Add the one outer dealing of `κ_0` with keys derived by threshold PRF, variant bodies, sealed contributions (initiator and actors), tickets with `R_A` and `x(R)`, capsules under random capsule keys, and actor nonce pools. |
| §3.4 Step A: accept | Replace with ordering, the header partial sent with the share check after the QC, OPENED and ADMIT (§5.2 to §5.4), and one signed vote per node and block. |
| §3.5 Request states | Add OPENED, COLLECTING, ADMITTED, VOID with reason STALLED, reissue (§5.9), the Midnight PENDING state and the settlement leaf (§5.6). |
| §3.6 Step B: anchor selection | Rule change: the OBS of generation 1 is posted with ADMIT and counts only if the request reaches ADMITTED. Later generations are unchanged. Add `G_max = 2` and the hold check before each release. |
| §3.7 Step C, sealed: release | Add the split release: the PRF partial of the selected variant body plus the committee partial, combiners, the optimistic combine, and the witness before release. |
| §3.8 Step C, open: lock, then sign | Restrict to P0 open mode. The guardian escrow keeps the open-mode dealing and ACK only, because guardians sign as actors. |
| §3.9 Local rules | Add nonce hygiene (§4.5), the slot reservation rule with one slot per generation and input, the actor's rules of §4.2, one answer per pool pair, and the rules of §5.10 and §5.11. |
| §3.10 Finish | Add the settlement leaf under the checkpoint's `settle_root` and erasure per request. |
| §4 Transaction construction | Add the Taproot exit leaf, the authority address for token controls, and the durable nonce rule for Solana. |
| §5 Committee change | Add reshare of `x_f` and of ECDSA slot shares, READY from `n' − f'`, and the backup to `E`. |
| §6 Security | Add claims C1 to C21 of §9 and the TEE-break table. Keep claims 1 to 7 for P0. |
| §7 Costs | Add §11. |
| §8 Gaps closed and left open | Add O1 to O31. |
| §10 Risks and attacks considered | Add the rogue-key birth attack with many shards and its per-shard proofs of possession, ROS and Wagner attacks on single-nonce slots and on actor pools, the tweak term placed twice, slot reuse in ECDSA, a silent actor and reissue, the witness collusion bound, and the rules of §5.11. |
| §12 References | Add the sources of §15. |

## 14. Implementation plan

### 14.1 veritee-vm

Order follows dependency. Sizes are estimates of new or changed lines.

| Step | Files | Change | Size |
|---|---|---|---|
| 1 | `server/azure_attestation_server/src/main.rs`, `src/enclave_key.rs`, `server/guest_attestation/veritee_attestation/document.py`, `tpm_quote.py` | evidence class byte in `REPORT_DATA` and TPM qualifying data; public endpoint serves class 0x00 only; internal classes move to a Unix socket | 400 |
| 2 | `server/akx/src/epoch.rs`, `src/attest.rs` | akx keys under class 0x01 | 150 |
| 3 | new crate `server/veritee_verify` | raw SNP and HCL verification: VCEK chain, SNP report, HCL report, vTPM AK binding, quote over PCR 4, 14, 15; no MAA | 1,500 |
| 4 | `veritee-os/mkosi/combined.repart/30-persist.conf`, `veritee-os/mkosi/rootfs/mkosi.extra/usr/lib/temenos/mount-persist`, `etc/fstab`, `veritee-os/measured_setup/main.py` | dm-crypt over dm-integrity; PCR 14 extend and cap; sealed `K_tpm` | 500 |
| 5 | new crate `server/veritee_seal` | seal-group DKG on ristretto255, PRF partials with Chaum-Pedersen proofs, `K_vol`, keyring ratchet | 1,800 |
| 6 | new crate `server/veritee_witness` | witness entries, logs, ack rules, replay floor | 1,200 |
| 7 | new crate `server/veritee_boot` | BootClaim under class 0x03, `admitBoot` client, ADMIT and ADMIT_ACK | 900 |
| 8 | new crate `server/veritee_keys` | NodeKeys under class 0x02, Key Registry client, PVK under class 0x04, `SealedToNode` | 700 |
| 9 | `projects/templates/run.d/main`, `projects/mpc-node/run.d/docker-compose.yml`, `Caddyfile.template`, `projects/mpc-node/metadata.json` | guest-generated TLS keys (internal CA or ACME TLS-ALPN-01); remove Key Vault and managed identity | 300 |
| 10 | `cli/deploy-azure-snp/main.tf`, `cli/veritee/cli.py` | remove Key Vault and identity resources; add `admitBoot`, `replaceSlot`, `retire` commands | 400 |
| 11 | `veritee-os/mkosi/rootfs/mkosi.conf.j2`, sysctl and service files | erasure hardening: no swap, no core dumps, `ptrace_scope = 2`, `kexec_load_disabled`, `init_on_free` | 150 |
| 12 | `server/egress_proxy/src/main.rs` | broadcast egress that strips node identity | 200 |
| 13 | `projects/mpc-node` | node service: envelope with PRF keys, state machine of §5, board votes, split signing, batched slot pool, the arithmetic rules of §5.10, checkpoints with the pool fields of §7.13; the sessions of §7.4, the reservation window at the vote (§4.1), `slot_bind` before release, `slot_burn` at the end of a request, VOID on burned slots | 6,000 |
| 14 | `server/seald` (`session`, `store.rs`, `group.rs`, `witness.rs`, `peer.rs`, `api.rs`, `recovery.rs`), `veritee-seald.service` | seald Sessions as specified in the Veritee OpenSpec change `add-seald-sessions` (SS-001 to SS-141): `σ_i` in tier 0, session keys from the threshold PRF, versions fenced by the witness, slot states, the window, the restart burns, the restart marker, put entries and bindings in the seat log, and the batched bind of O36; `/mnt/persist` in `ReadWritePaths`; 4 MiB peer lines for sessions | per `tasks.md` of the change |

### 14.2 Warden

The Warden leaves the signing path. It keeps operations duties:

- submit `admitBoot`, `replaceSlot` and `retire` on behalf of operators who choose it, signed with the operator's key.
- watch checkpoints and alert when the interval exceeds a threshold well below `Δ_rec`.
- publish Image Registry proposals for governance signature.
- optionally countersign Key Registry records. Nodes never check that signature.

### 14.3 Midnight contracts

| Contract | Additions |
|---|---|
| `ImageRegistry` | images, measurements, 7-of-9 approvals |
| `NodeRegistry` | `admitBoot`, `replaceSlot`, `retire`, boot counters |
| `KeyRegistry` | one `EKS_e` record per epoch: the `n` `NodeKeys`, `keylist_hash` and `q` signatures |
| `Checkpoints` | `checkpoint` with `q` signatures, the pool fields `(h, pending_min, pending_root, pending_count)`, boot counters, restart marker, seat-log roots and new `RestoreDone` statements, and the checkpoint rules of §7.13 |
| `Charters` | profiles P0, P1, P2, the access structure `Γ`, the initiator list and the actors' pool-key roots, sources, `D_exit`, `Δ_rec`, exit leaf option, the `board_first` option; P2 fields |
| `FenrirAssets` | asset records with birth certificates (P1, P2) or owner registrations (P0), `authorize` with the carried VOID settlement of a reissue, the `settle_root` and `bf_root` of each landed checkpoint; for board-first charters no direct `authorize`; P2: `revoke`, `SetHold`, hold accumulator, seizure orders |
| `Recovery` | `recover`, `coldStart`, the recovery group's keys and the exit-only successor charter |
| Ticket proof | the ticket circuit of §5.3 on Midnight's own PLONK verifier (non-TEE v2), with no new verifier contract. Only the fallback of O25 adds a verifier for a wrapped STARK |

## 15. Sources

**Protocols and standards**

- BIP340, Schnorr signatures for secp256k1, https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki: challenge hash, even-y rules, the batch verification equation with coefficients drawn after all inputs are fixed.
- midnight-zk, https://github.com/midnightntwrk/midnight-zk: PLONK with KZG on BLS12-381; SHA-256, SHA-512, Keccak and Poseidon gadgets; no STARK verifier gadget; the SHA-256 preimage example of 1,911 rows.
- Midnight consensus, https://docs.midnight.network/concepts/network-architecture/consensus: AURA block production and GRANDPA finality, with no published finality time.
- Midnight forum, GPU proof server, https://forum.midnight.network/t/open-source-drop-cuda-accelerated-midnight-proof-server-nocy-gpu-proof-server/972: proving times at `k = 17` and `k = 18`, used as an estimate in §11.4.
- BIP341, Taproot, https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki: output key `Q = P + t·G`, TapTweak, sighash, script tree.
- BIP327, MuSig2, https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki: two-nonce binding against concurrent-session attacks, nonce publication before the message.
- RFC 9591, FROST, https://www.rfc-editor.org/rfc/rfc9591.html: binding factor, nonce commitments, Ed25519 and secp256k1 ciphersuites.
- RFC 9180, HPKE, https://www.rfc-editor.org/rfc/rfc9180.html: single-node envelopes, with no replay protection and no forward secrecy toward the recipient.
- ERC-3643, https://eips.ethereum.org/EIPS/eip-3643: forced transfer, freeze, recovery.
- Solana permanent delegate, https://solana.com/docs/tokens/extensions/permanent-delegate, and durable nonces, https://solana.com/docs/core/transactions/durable-nonces: token controls, nonce advance and failed-execution behavior.
- Groth and Shoup, ePrint 2021/1330 and 2022/506, read in full for line dealing: presignature security (2021/1330 Theorem 3) and the quadruple protocol at `t = f + 1` (2022/506).
- cggmp21 presignature API, https://docs.rs/cggmp21/latest/cggmp21/signing/struct.Presignature.html: candidate for `F_presig`.
- Ika whitepaper, https://docs.ika.xyz/whitepaper.pdf: user-as-party custody shape, import of existing keys.
- NEAR chain signatures, https://docs.near.org/chain-abstraction/chain-signatures: key-independent presignatures with additive tweaks.
- MP-SPDZ, https://mp-spdz.readthedocs.io/en/latest/readme.html: general MPC alternative for the non-TEE committee, not used.
- Ferveo cryptography overview, https://anoma.net/blog/ferveo-cryptography-overview: order before decryption.

**Confidential computing and Azure**

- Veritee code, `/home/hoskinson/Projects/veritee/veritee-vm`: measured setup, attestation server, akx, deployment, project templates.
- AMD SEV-SNP ABI, https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf and revision 1.59 https://docs.amd.com/api/khub/documents/NJQrpYY7KZGtlxDEdBGtzA/content: report format, `MSG_KEY_REQ`, derived-key inputs.
- Linux SEV guest API, https://docs.kernel.org/virt/coco/sev-guest.html: `SNP_GET_DERIVED_KEY`.
- dm-integrity, https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html: authenticated sectors under dm-crypt for the persistent volume.
- Azure confidential VM FAQ, https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-faq: vTPM sealing, VMGS.
- Azure vTPM in confidential VMs, https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-tpms-in-azure-confidential-vm: vTPM inside the protected guest context, measured boot into PCRs.
- Azure guest attestation design, https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design: HCL report, AK binding.
- Azure attest a Linux workload, https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-attest-linux-workload: guest measurements beyond the paravisor report.
- Azure Trusted Launch FAQ, https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq: VMGS lifecycle, snapshots.
- Azure BCDR guidance, https://learn.microsoft.com/en-us/azure/azure-sovereign-clouds/public/bcdr-impacts-sovereign-controls: preserved vTPM state on recovery.
- sevctl on Azure CVM, https://learn.microsoft.com/en-us/answers/a/1844982: paravisor hides the SNP guest interface.
- Azure Secure Key Release, https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation, flow https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp, policy grammar https://learn.microsoft.com/en-us/azure/key-vault/keys/policy-grammar, examples https://learn.microsoft.com/en-us/azure/confidential-computing/skr-policy-examples: reasons SKR is not the gate.
- Azure confidential ledger, https://learn.microsoft.com/en-us/azure/confidential-ledger/overview: alternative freshness service, not used.
- Trustee, https://confidentialcontainers.org/docs/attestation/ and policies https://confidentialcontainers.org/docs/attestation/policies/: separation of evidence appraisal from secret release, the model for peer-quorum release.
- AWS Nitro Enclaves KMS conditions, https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html: image-bound key release, a cloud-operated gate of the kind the peer quorum replaces.
- Google Confidential Space, https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview: workload identity on attestation, another cloud-operated gate.
- dstack KMS, https://docs.phala.com/dstack-cloud/kms-and-key-delivery.md, key management protocol https://docs.phala.com/dstack/design-documents/key-management-protocol.md, audit https://docs.phala.com/images/audits/dstack-audit.pdf.
- Oasis key manager, https://docs.oasis.io/core/consensus/services/keymanager/, ephemeral secrets ADR https://docs.oasis.io/adrs/0021-keymanager-ephemeral-secrets/.
- BuilderNet v1.2, https://buildernet.org/blog/2025/02/19/buildernet-v1.2: disk keys pulled from a central service, the dependency that peer-released `K_grp` removes.
- ROTE, https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-matetic.pdf: rollback protection by peer platforms.
- Nimble, https://www.usenix.org/system/files/osdi23-angel.pdf: append-only freshness, reconfiguration.
- Narrator, https://pw0rld.github.io/files/Narrator_ccs_22.pdf: state continuity from a blockchain plus peer quorums.
- RustCrypto zeroize, https://docs.rs/zeroize/latest/zeroize/: zeroize on drop and its limits for copies and registers.

**Attacks on SEV-SNP**

- CacheWarp, https://cachewarpattack.com/. WeSee, https://ahoi-attacks.github.io/wesee/. Ahoi and Heckler, https://ahoi-attacks.github.io/. BadRAM, https://badram.eu/. Heracles, https://heracles-attack.github.io/. TEE.fail, https://tee.fail/. Fabricked, https://xca-attacks.github.io/fabricked/. AMD-SB-3034, https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3034.html. AMD-SB-3038, https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3038.html. AMD-SB-3054, https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3054.html. They set the limits of §9.2: a TEE break is a realistic event, and every property in the "kept" column holds without the TEE.

**Project documents**

- `design/SCHEME.md` and `design/PROOFS.md`: line dealing, its dealing, complaint, anchor and rotation machinery, Theorems A to E.
