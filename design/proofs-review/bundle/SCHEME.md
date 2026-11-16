# Line dealing: the owner deals the signature equation, sealed or open

## 1. Scheme in one paragraph

A Schnorr signature is one point on the line `s(c) = k + c·x`, and an ECDSA signature is one point on the line `s(h) = h·k⁻¹ + r·k⁻¹x`. The owner knows both coefficients, so the owner deals the line and not the key. The owner's one message is a Feldman-committed Shamir dealing, on the signature curve, of **sealed points** or **open lines**. A sealed point is the line already evaluated at the sighash of one fully specified transaction; its constant-term commitment is forced to `R + cX` (Schnorr) or `hG + rX` in base `R` (ECDSA), so the committed secret is a valid signature of the address key on that transaction and on nothing else. The owner seals a fee grid of transactions that all spend one pinned input or one account nonce, and the committee chooses and releases one. An open line is both coefficients with constant terms forced to `G` and `X` in base `R`; the committee builds the transaction from chain state, locks its digest with a quorum certificate, and each node sends one linear partial signature that anyone can check. There is no DKG, no presignature protocol, no secret multiplication, no Paillier, no OT and no class group. A request is identified by `rid = H(chain, board, X, owner_nonce)` (sealed mode adds the dealing digest), no share is released before a digest lock exists, every nonce slot is consumed in durable state, and a committee change freezes a request before it moves. Sealed mode gives a cryptographic one-spend limit that holds with every node corrupt, for an existing address and a wallet that only signs transactions. Open mode gives full committee-side construction with an honest-threshold one-spend limit, and section 6.6 shows that no protocol of this shape does better.

## 2. Setting and assumptions

**Parties.** One owner with the key `x` of an existing address, `X = xG`. A committee of `n = 3f + 1` nodes per epoch. Anyone can combine partial signatures and broadcast.

**Suites and chains.**

| Suite | Chains and address types covered | Pin |
|---|---|---|
| 1: secp256k1 ECDSA | Bitcoin P2PKH (compressed or uncompressed key), P2WPKH; Ethereum-style EOA with type-2 transactions | one outpoint; exact account nonce |
| 2: BIP340 | Bitcoin P2TR key path | one outpoint |
| 3: Ed25519 | Solana, only for an account that already has a durable nonce account | the durable nonce value |

Sui, Aptos and NEAR Ed25519 accounts are out of scope: their addresses are not the raw public key, or their keys rotate, and no adapter is specified. The Solana adapter is an outline from memory and is not acceptance-tested.

**Thresholds.** `f = (n − 1)/3` is the Byzantine bound. The reconstruction threshold `t` is a header field with two legal values.

| Profile | `t` | Modes and rotation rules allowed | What it buys |
|---|---|---|---|
| T1 | `f + 1` | sealed, open; `finish`, `reshare`, `void` | every guarantee holds against any coalition below `t` |
| T2 | `n − f` | sealed, open; `finish`, `void` only | sealed: early release needs `n − f` corrupt nodes. Open: share leakage from up to `2f` nodes in total is tolerated, but only `f` of them may be Byzantine |

T1 is the default for open mode. T2 is the default for sealed mode. An open T2 request does not meet the brief's below-threshold criterion (section 6.9).

**Corruption model.** Static. A fixed adversarial set must respect the bound in every committee that serves a request. A node restored to an old state counts as Byzantine. In open T2 the passive nodes leak the epoch decryption key and the dealt shares only: each node's board-post key and any board consensus key live in a separate non-exportable keystore, and a node whose post or consensus key leaks counts as Byzantine. Nothing is claimed for adaptive corruption.

**Network.** Partial synchrony. Safety never depends on timing. The **board** is a total-order broadcast with `f < n/3` (a BFT log run by the committee, or a host chain). It orders posts and does not interpret them; every state below is a pure function of the ordered log. The target chain has a finality rule (native finality, or depth `c` on Bitcoin, which is then an assumption).

**Setup.** No trusted setup. Per epoch `e`, node `i` registers an encryption key `PK_i = sk_i·G` on the suite curve with a proof of possession, and a post key for signing board posts. `sk_i` is erased when the epoch and its grace period end. Public parameters: suites, the hash labels of section 3.1, a builder specification named by its hash, and `(n, f)`.

**Assumptions.**

- Discrete log on the suite curve; random oracles for the labelled hashes.
- Gap Diffie-Hellman for the share encryption (hashed ElGamal with a public complaint that reveals one DH value).
- Unforgeability of the post-key signature scheme.
- Sealed mode: standard unforgeability of ECDSA, BIP340 or Ed25519.
- Open ECDSA: unforgeability of ECDSA with public single-use presignatures, [GS22] Theorem 3 (EC generic group model; the hash is collision resistant, random-preimage resistant and ratio resistant).
- Open Schnorr: unforgeability of single-signer two-nonce Schnorr with pre-published nonces (from memory, not checked).
- The owner's device is honest when it writes the message, knows the current epoch keys, and never reuses a nonce across messages.

## 3. Protocol

### 3.1 Notation, hashes and labels

`q` is the group order. `Share_t(v)` picks a random polynomial `p` of degree `t − 1` with `p(0) = v`; share `i` is `p(i)`. `Com_B(p)` is the list `a_u·B` for `u = 1..t−1`. The constant-term commitment is never sent; verifiers compute it. `Eval(C_0, C, i) = C_0 + Σ_u i^u·C_u`.

All integers are big-endian and fixed width. `H_tag(m) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ m)`. `Hq_tag(m)` is the same construction with SHA-512 as the outer hash, read as an integer and reduced mod `q`. Every input is a concatenation of fixed-width fields, or carries a 4-byte length prefix, so each encoding is injective, and distinct tags give independent oracles.

| Tag | Input | Use |
|---|---|---|
| `LD1/rid` | `chain_id(32) ‖ board_id(32) ‖ X(33) ‖ owner_nonce(32) ‖ tie(32)` | request identity; `tie` is 32 zero bytes in open mode and `hd` in sealed mode |
| `LD1/hd` | `len(hdr) ‖ hdr ‖ len(deal) ‖ deal` | dealing digest |
| `LD1/mid` | the whole message | message identity before binding |
| `LD1/enc` (Hq) | `hd(32) ‖ i(2) ‖ PK_i(33) ‖ K_i(33) ‖ slot(8)` | share pad |
| `LD1/auth` (Hq) | `hd ‖ SHA-256(ct) ‖ T_e(33) ‖ T_a(33)` | challenge of `π` |
| `LD1/bind` (Hq) | `hd ‖ g(2) ‖ ℓ(2) ‖ dg(32)` | Schnorr binding factor `ρ` |
| `LD1/dg` | `rid ‖ epoch(8) ‖ g(2) ‖ a(2) ‖ anchor_height(8) ‖ anchor_hash(32) ‖ SHA-256(tx) ‖ L'(2) ‖ m_1 ‖ … ‖ m_L'` | lock digest |
| `LD1/post` | `board_id ‖ epoch(8) ‖ type(1) ‖ node(2) ‖ len ‖ body` | message signed by a post key |
| `LD1/dleq` (Hq) | `G ‖ PK_i ‖ E ‖ K_i ‖ T_1 ‖ T_2 ‖ mid` | complaint proof |
| `LD1/pop` (Hq) | `epoch ‖ node ‖ PK_i ‖ T` | key registration |
| `LD1/rs-hd`, `LD1/rs-enc`, `LD1/rs-auth` | as `hd`, `enc`, `auth`, with `rid ‖ old_epoch ‖ new_epoch ‖ dealer(2)` prepended | resharing |

The **slot label** is 8 bytes: `mode(1) ‖ comp(1) ‖ g_or_j(2) ‖ ℓ(2) ‖ 0x0000`. `mode` is 1 (sealed) or 2 (open). `comp` is `0x01` sealed-s, `0x02` ecdsa-w, `0x03` ecdsa-mu, `0x04` schnorr-x (with `g = ℓ = 0`), `0x05` schnorr-d, `0x06` schnorr-e. Every dealt polynomial has its own label, so no two ciphertexts of one node share a pad.

None of these hashes is a suite challenge hash or a sighash. `π` is never a chain signature.

### 3.2 The owner's message

`OwnerMsg = hdr ‖ deal ‖ ct ‖ π`, canonical, no trailing bytes.

| `hdr` field | Bytes | Meaning |
|---|---|---|
| `version, suite, mode, addr_type, on_rotation, late_inputs` | 6 | `mode` 1 sealed, 2 open. `addr_type` 1 P2PKH compressed, 2 P2PKH uncompressed, 3 P2WPKH, 4 P2TR, 5 EOA, 6 Solana. `on_rotation` 1 finish, 2 reshare, 3 void |
| `chain_id, board_id, owner_nonce, keylist_hash, builder_hash` | 160 | `chain_id = SHA-256(CAIP-2 id ‖ genesis hash)`; `owner_nonce` fresh and random |
| `X` | 33 | address key. Suite 2: the output key with prefix `0x02`. Suite 3: `0x00 ‖` the 32-byte Ed25519 key |
| `E` | 33 | ephemeral encryption key `e·G`, fresh per message |
| `address` | 36 | length byte, then the script hash, x-only key, account address or public key |
| `epoch, nb, exp` | 24 | epoch; window in board heights |
| `n, t, f, K, L, G` | 12 | committee profile; `K` sealed variants, `L` slots per transaction, `G` open generations in total |
| `trigger` | 34 | `id(2) ‖ params(32)`. Id 0: true. Id 1: target height `≥` the last 8 bytes of `params`. Id 2: value held by `address` `≥` the last 16 bytes. Other ids are defined by the builder specification |
| `intent` | 186 with one output and no extra outpoint | see the next table |

| `intent` field | Bytes | Meaning |
|---|---|---|
| `n_out` | 1 | 1 or 2 |
| `outputs` | 52 each | `script_len(1) ‖ script(35, zero padded) ‖ amount(16)`. For an account chain the script is the 20-byte or 32-byte recipient. `amount = 2^128 − 1` means `ALL`; it is legal on one output only and then no change is paid |
| `change_to` | 36 | `script_len(1) ‖ script(35)` |
| `pin` | 72 | `kind(1) ‖ payload(71)`, zero padded. Kind 1, outpoint: `txid(32) ‖ vout(4) ‖ value(8)`. Kind 2, account nonce: `nonce(8)`. Kind 3, durable nonce: `nonce_account(32) ‖ nonce_value(32)` |
| `n_allowed`, `allowed` | 1 + 36 each | up to 7 further outpoints `txid(32) ‖ vout(4)` |
| `fee_ceiling` | 16 | the most the transaction may pay, in base units |
| `fee_rule, Δ, γ, min_conf` | 2 + 2 + 2 + 2 | fee statistic id; bump delay in target blocks; grid ratio as `numerator(1) ‖ denominator(1)`; confirmations required of inputs |

This version carries payments only. A contract call needs a calldata field and a gas table entry.

`deal`:

- sealed, variant `j = 1..K`, input `ℓ = 1..L`: `R ‖ Com(p_s)`. `R` is 33 bytes (suite 1), 32 bytes x-only (suite 2), 32 bytes (suite 3).
- open ECDSA, generation `g = 1..G`, slot `ℓ = 1..L`: `R(33) ‖ Com_R(p_w) ‖ Com_R(p_μ)`.
- open Schnorr: `Com_G(p_x)` once, then per `(g, ℓ)`: `D ‖ E' ‖ Com_G(p_d) ‖ Com_G(p_e)`.

`ct`: for node `i = 1..n` and each dealt polynomial `p` in `deal` order, the 32-byte scalar `p(i) + Hq_enc(hd, i, PK_i, K_i, slot(p)) mod q`, with `K_i = e·PK_i`.

`π = (T_e, z_e, T_a, z_a)`, 130 bytes, two Schnorr proofs under one challenge `c = Hq_auth(hd ‖ SHA-256(ct) ‖ T_e ‖ T_a)`:

- knowledge of `e`: `z_e·G = T_e + c·E`;
- authorship. Open: knowledge of `x`, `z_a·G = T_a + c·X`. Sealed: knowledge of the first sealed signature `s_{1,1}`, `z_a·B = T_a + c·F_0^{(1,1)}` with `B = G` (suites 2, 3) or `B = R_{1,1}` (suite 1). Until a variant is released only the owner knows a signature on variant 1, so only the owner can write a message that carries unreleased signatures, and a hardware wallet that never exports `x` can still do it. A released signature is public; the `rid` rule below covers that case.

`hd = H_hd(hdr, deal)`, `mid = H_mid(OwnerMsg)`, `rid = H_rid(chain_id, board_id, X, owner_nonce, tie)`.

- Open mode: `tie = 0`. `rid` excludes the epoch, the dealing, the ciphertexts and the proof, so no re-encoding, re-randomization or migration yields a second identity, and only a holder of `x` can bind it.
- Sealed mode: `tie = hd`. A sealed signature becomes public when it is released, and from then on anyone can prove knowledge of it. Tying `rid` to the dealing stops a third party from wrapping a released signature in a new message that claims the `owner_nonce` of another pending request. No allowance is created this way: a sealed message authorizes only the owner-made signatures it contains, and they all spend the pin. `rid` still excludes the ciphertexts and the proof.

### 3.3 What is dealt

**Sealed points.** For each variant `j` the owner computes `tx_j = Variant(intent, j)` (section 4) and each input's sighash `m`, signs `m` in the ordinary way with a fresh nonce to get `(R, s)`, and deals `Share_t(s)`.

- Suites 2 and 3: commitments in base `G`; implied constant term `F_0 = R + c·X` with `c` the suite challenge of `(R, X, m)`.
- Suite 1: commitments in base `R`; implied constant term `F_0 = h·G + r·X`, `h` the sighash, `r = x(R) mod q`. This equals `s·R`. An ordinary wallet signature `(r, s)` suffices; the owner recovers `R = s⁻¹(hG + rX)`.

**Open lines, ECDSA.** Per slot the owner picks `k`, sets `R = kG`, `w = k⁻¹`, `μ = k⁻¹x`, and deals `Share_t(w)` and `Share_t(μ)` in base `R`. The implied constant terms are `G` and `X`. They hold exactly when `w(0) = k⁻¹` and `μ(0) = x·k⁻¹`.

**Open lines, Schnorr.** The owner deals `Share_t(x)` once (implied constant term `X`) and per slot two nonces `d, e'` with `D = dG`, `E' = e'G`.

**Key formats.** The owner normalizes before dealing. Suite 2: the dealt scalar is the one whose public key is the even-y output key (for a BIP341 address, `±(d_even + tweak)`). Suite 3: `a = clamp(SHA-512(seed)[0..32]) mod ℓ`; nonces are random scalars.

### 3.4 Step A: accept

Public checks, by every node, on a `MSG` post:

1. Canonical encoding, known version and suite, no trailing bytes.
2. Every point is a canonical encoding of a curve point and is not the identity. Suite 3: canonical `y < p` and `[ℓ]P = O`.
3. `X`: suite 2 requires prefix `0x02`. Address check: P2PKH and P2WPKH `HASH160(X in the stated encoding) = address`; P2TR `address = x(X)`; EOA `Keccak-256(uncompressed X without prefix)[12..32] = address`; Solana `address = X`.
4. `chain_id`, `board_id`, epoch and `keylist_hash` are current; `(n, f)` match the registered committee; `t ∈ {f+1, n−f}`; `on_rotation = reshare` requires `t = f + 1`; `on_rotation = finish` requires `exp` inside the epoch's grace period; board height `≤ exp`.
5. `rid` is not bound and has no tombstone.
6. Per sealed point. Suite 1: `x(R) < q`, `r = x(R) mod q ≠ 0`, `F_0 = hG + rX ≠ O`. Suite 2: `R := lift_x` of the 32 bytes (even y by construction; reject if not on the curve), `F_0 = R + cX ≠ O`. Suite 3: `F_0 = R + cA ≠ O`. Per open ECDSA slot: `x(R) < q`, `r ≠ 0`. Per open Schnorr slot: `D, E' ≠ O`.
7. The x-coordinates of all `R` (and of all `D`, `E'`) in the message are pairwise distinct.
8. Sealed: recompute every `tx_j` and sighash from the intent. Every variant spends the pin, pays the intent outputs, has fee `≤ fee_ceiling`, and `fee_{j+1} − fee_j` is at least the chain's replacement minimum.
9. `π` verifies.

The first `MSG` in board order that passes checks 1 to 9 **binds** `rid` to its `mid`. A message that fails binds nothing and blocks nothing. A later message with a bound `rid` is ignored.

Private check, by node `i`: compute `K_i = sk_i·E`, decrypt every share, and check it in the right base: `s_i·B = Eval(F_0, C, i)`; `w_i·R = Eval(G, C_w, i)`; `μ_i·R = Eval(X, C_μ, i)`; `x_i·G = Eval(X, C_x, i)`; `d_i·G = Eval(D, C_d, i)`; `e'_i·G = Eval(E', C_e, i)`. Post `ACK(rid, mid)` or `COMPLAINT(rid, mid, K_i, DLEQ(G, PK_i; E, K_i))`. Anyone verifies a complaint by decrypting share `i` with `K_i`. A valid complaint voids `rid`; an honest owner never causes one, and `π` stops a third party from reusing an honest `E`.

The request is **armed** when `2f + 1` ACKs are on the board.

### 3.5 Request states

```
(unbound) -> BOUND -> ARMED -> per generation g:  attempt a: ANCHORED -> FAILED (next attempt, nothing consumed)
                                                                     -> LOCKED(g, dg)  [open]  -> SIGNED
                                                                     -> RELEASED(j_g)  [sealed]
          -> FINAL (an authorized transaction is final on the target chain)
          -> VOID  (valid complaint, pin spent by a foreign transaction, rotation with void, failed handover)
          -> EXPIRED (board height > exp with no generation locked or released)
```

Only FINAL, VOID and EXPIRED are tombstones. Early inclusion, a false trigger, missing confirmations, a fee above the ceiling, or missing funds change no state: the request stays ARMED and waits.

### 3.6 Step B: anchor selection

`Eligible(intent, S, g, prev)` holds for the state `S` at a finalized target block when: `trigger(S)`; the pin is unspent in `S` and belongs to `address`; the inputs have `min_conf` confirmations; for `g > 1`, `height(S) ≥ h*_{g−1} + Δ`; and `Build(intent, S, g, prev) ≠ ⊥` (open) or `Select(intent, S, j_{g−1}) ≠ ⊥` (sealed).

Attempt `a` of generation `g` is open when: `g = a = 1`, the request is ARMED and the board height is in `[nb, exp]`; or `a > 1` and attempt `a − 1` FAILED with no lock or release in `g`; or `g > 1`, `g ≤ G` (open) or `j_{g−1} < K` (sealed), and generation `g − 1` has an anchor.

1. A node whose own finalized tip, at height `h`, is eligible posts `OBS(rid, g, a, h)`, once per attempt. An OBS post carries a height and no block hash.
2. The **OBS set** is the first `2f + 1` such posts from distinct nodes in board order. Sort the heights, highest first. The **anchor height** `h*` is entry number `f + 1`. At least one honest node reported a height at or above it, so a block at `h*` is final; at least one honest node reported a height at or below it, so it is not older than an honest tip. `f` Byzantine reports cannot move it outside the range of honest reports, and they have no hash to falsify.
3. Each node waits until its own finalized chain reaches `h*`. The **anchor** `B*` is its own finalized block at that height; by finality all honest nodes hold the same block, and its hash enters only through the lock digest. If `Eligible` fails at `B*`, the node posts `NACK(rid, g, a)`. `f + 1` NACKs make the attempt FAILED. A NACK therefore always means that an honest node found the state ineligible.

**Board cut.** Everything an attempt reads from earlier generations is taken at the board position `c` where its OBS set completes. The anchor of an earlier generation `g'`, as seen at `c`, is the anchor of its lock certificate (sealed: of its release) if that precedes `c`, else the anchor of its latest attempt not FAILED before `c`. `h*_{g'}`, `j_{g'}` and `prev = (tx_1, …, tx_{g−1})` are computed from those anchors, so every honest node evaluates `Eligible`, `Select` and `Build` on the same inputs.

**Anchor replacement before signing.** A FAILED attempt consumes nothing: honest nodes that judge the anchor ineligible do not vote and do not release, so attempt `a + 1` selects a newer anchor inside the same generation with the same nonce material. Once a node has voted in generation `g` it never votes again in `g`. A replacement digest after any vote therefore uses generation `g + 1`, which has its own lines.

### 3.7 Step C, sealed: release

Each node that finds `B*` eligible computes `j_g = Select(intent, state(B*), j_{g−1})` and posts `PARTIAL(rid, g, j_g, {s_{j,ℓ,i}})`. Anyone checks each partial against `Eval(F_0, C, i)` and interpolates `s` from `t` of them.

Output per input: suites 2 and 3, `(R, s)`. Suite 1: `s' = min(s, q − s)`, signature `(r, s')`; for an EOA, `yParity = (y(R) mod 2) XOR [s' ≠ s]` with the dealt `R`.

### 3.8 Step C, open: lock, then sign

```
tx  = Build(intent, state(B*), g, prev)        # section 4
dg  = H_dg(rid, epoch, g, a, B*, tx, m_1..m_L')
write (rid, g) -> dg to the slot ledger (durable), then
post PREVOTE(rid, g, a, B*, dg)                # at most one PREVOTE per (rid, g), ever

LOCK(rid, g) = the first 2f+1 PREVOTE posts for (rid, g) from distinct nodes
               with identical (a, B*, dg)

on LOCK(rid, g) with dg equal to the digest this node built itself
   (a node that has not voted writes its ledger entry now; a node whose
    ledger holds another digest for (rid, g) abstains):
for each input ℓ:
  ECDSA:   r   = x(R_ℓ) mod q
           s_i = m_ℓ·w_i + r·μ_i
           check by others:  s_i·R_ℓ = m_ℓ·W_i + r·M_i
  Schnorr: ρ   = Hq_bind(hd, g, ℓ, dg)
           R   = D_ℓ + ρ·E'_ℓ            (R = O: the generation is dead)
           σ   = −1 if suite 2 and R has odd y, else 1
           c   = suite challenge of (σR, X, m_ℓ)
           s_i = σ·(d_i + ρ·e'_i) + c·x_i
           check by others:  s_i·G = σ·(D_i + ρ·E'_i) + c·X_i
post PARTIAL(rid, g, {s_i}); erase the nonce shares of generation g
```

`W_i, M_i, D_i, E'_i, X_i` are `Eval` of the commitments at `i`. The combiner interpolates `t` partials, checks the final signature first, and checks single partials only if that fails. ECDSA output is normalized as in 3.7; `s = 0` kills the generation. No share leaves a node before the lock certificate exists, and the locked transaction of a generation never changes. A partial is a deterministic function of the slot and the digest, so a resend is byte-identical.

### 3.9 Local rules

1. One PREVOTE per `(rid, g)`, written to durable storage before it is posted.
2. A node signs only the digest it built itself, and only after the lock certificate.
3. One digest per slot, ever. The slot ledger is durable and is consulted before every PARTIAL.
4. After a restart a node replays the board for its own posts. It abstains on every `(rid, g)` for which the board shows its PREVOTE or PARTIAL and its ledger has no entry.
5. No PREVOTE after board height `exp`.

### 3.10 Finish

`f + 1` posts `FINAL(rid, txid)` or `VOID(rid)` (pin spent by another transaction) set the tombstone. Nodes then erase every share of `rid`. At `exp` nodes erase the shares of every generation that has no lock or release.

## 4. Transaction construction

**The pin.** Every transaction a message can authorize spends the pin: one named outpoint, the exact account nonce `N`, or the current value of a durable nonce account. All variants and all generations therefore conflict on the target chain. A chain without such a conflict object is not supported.

**Sealed: construction is selection.** `Variant(intent, j)` is a pure function. All variants spend the pin and the same further inputs and pay the same outputs. Fees form a grid: `fee_K = fee_ceiling`, `fee_j = ⌊fee_{j+1}/γ⌋`; on a UTXO chain the change output absorbs the difference. `Select(intent, S, j_prev)` is the least `j > j_prev` with `fee_j / vsize ≥ FeeRule(S)`, else ⊥. On an EIP-1559 chain `K = 1` with `maxFeePerGas` at the ceiling is enough.

**Open: `Build(intent, S, g, prev)`** is a pure function of the intent, the state `S` at the anchor, and `prev = (tx_1, …, tx_{g−1})`, the transactions of earlier generations. `prev` is recomputed from the anchors on the board at the board cut of section 3.6, so no node takes transaction bytes from another node and all honest nodes use the same `prev`.

- ⊥ if the pin is spent in `S`.
- UTXO chains. Inputs: the pin, then the allowed outpoints, then with `late_inputs` every output of the address with `min_conf` confirmations at `S`. For `ALL` take every eligible input, else the pin plus largest-first until outputs and fee are covered, at most `L` inputs, ordered by `(txid, vout)`. Outputs in intent order; change to `change_to`. Fee: `rate = FeeRule(S)` (median of the last six blocks' median rates), `fee = ⌈rate·vsize⌉`. Resolve the outputs first: if the change is below dust, drop it and recompute. Then enforce the ceiling on the real fee, `Σ inputs − Σ outputs ≤ fee_ceiling`, else ⊥. `nLockTime = height(S)`; sequence numbers signal replacement; sighash ALL (DEFAULT for Taproot).
- Type-2 account transaction: `nonce = N`; the account nonce at `S` must equal `N` (below `N`: wait; above: the pin is spent). `gasLimit` from a fixed table for the call type; `tip = FeeRule(S)`; `maxFeePerGas = 2·basefee(S) + tip`; ⊥ if `gasLimit·maxFeePerGas > fee_ceiling`. `value` is the intent amount, or for `ALL` the balance minus `gasLimit·maxFeePerGas`; the chain charges less than the maximum, so `ALL` leaves a remainder on the account. Sighash `Keccak-256(0x02 ‖ RLP(...))`.
- Solana outline: first instruction advances the pinned durable nonce; `recent_blockhash` is the nonce value.

**Generation and fee-bump rule.** Generation `g > 1` may be anchored only at a block `Δ` or more above the anchor of generation `g − 1` in which the pin is still unspent. Its transaction spends the pin and pays the same outputs. UTXO: `fee_g = max(⌈rate·vsize_g⌉, max_{g'<g} fee_{g'} + ρ_min·vsize_g)` and a strictly higher fee rate than every `tx_{g'}`, where `ρ_min` is the chain's replacement increment. Type-2: `maxFeePerGas` and `tip` are each at least `⌈1.125 ×⌉` the largest earlier value. ⊥ if the ceiling is exceeded. A flat or falling market therefore still yields a valid replacement.

**Agreement.** The board orders the OBS posts, so the anchor is unique, and `Build` is deterministic, so honest nodes compute the same bytes. The lock quorum is the safety net when they do not: at most one digest per `(rid, g)` gathers `2f + 1` PREVOTEs. A divergence stalls the generation and never produces two signatures under one nonce.

## 5. Committee change

`on_rotation` decides the fate of a request when the board commits `ROTATE(e → e+1)`.

- **finish.** The epoch-`e` nodes serve the request until it is FINAL or `exp` passes, then erase. Step A guarantees `exp` is inside the grace period.
- **void.** The request becomes VOID and all shares are erased.
- **reshare** (`t = f + 1` only). `ROTATE` at board position `p_F` is a `FREEZE(rid)` for the request.

**Freeze rule.** A generation is *in flight* if its lock certificate (sealed: its first PARTIAL after an anchor) lies before `p_F` in board order. The old committee finishes in-flight generations and never reshares them. For every other generation, old-committee OBS, NACK, PREVOTE and PARTIAL posts after `p_F` are void, and an old node releases a partial only when the lock certificate it acts on precedes `p_F` in its own view of the log. A stray PREVOTE burns nothing: only a full pre-freeze certificate keeps a generation with the old committee.

**Transfer.** For each dealt polynomial of each generation not in flight (and `p_x` in open Schnorr), old node `i` deals `Share_{t'}(v_i)` of its share `v_i` to the new epoch keys, in the same base, with its own ephemeral key and proof of knowledge, using the `LD1/rs-*` labels. The constant-term commitment is implied: it must be `Eval(·, i)` of the previous commitments. New nodes check their sub-shares and post an ACK or a complaint per dealer. The candidate set `Q` is the first `t_old` dealers in board order with no valid complaint. A new node that holds valid sub-shares from all of `Q` posts `READY(rid, H(Q))`. `HANDOVER(rid, Q)` is the first `Q` with `2f' + 1` READY posts. New shares are `v'_j = Σ_{i∈Q} λ_i^Q·g_i(j)` and the new commitments are the same combination; the new constant terms equal the old ones. Because `t' = f' + 1`, the `f' + 1` honest READY nodes alone can sign; a node that received a bad sub-share and was too slow to complain is not needed.

The board carries the tombstones, anchors, lock certificates and generation counters across the change, so key material and request state move together. The new committee resumes at the lowest generation not in flight, with epoch `e + 1` post keys. Old nodes erase transferred shares when HANDOVER is on the board. A handover that does not complete before `exp` leaves the request EXPIRED; the coins never moved.

Whether a generation stays or moves is decided by board order. With `t_old = f + 1`, a lock quorum and a resharing set can overlap in Byzantine nodes only, so this rule rests on the consistency of the board.

## 6. Security

### 6.1 Ideal functionality `F_OMS`

Parameters: suite, `Variant`, `Select`, `Build`, `(n, t, f)`, a ledger `L` for the target chain, a clock.

- **Post.** On `(post, hdr)` from the owner of `X`: if `rid` is unused, store `(rid, hdr, live, g = 0)` and leak `(rid, hdr)`. The owner takes no further action. Sealed: store `σ_j = Sign(x, Variant(intent, j))` for all `j`.
- **Anchor.** On `(anchor, rid, S)` from the adversary, with `S` a finalized state of `L`, the clock in the window, status live, and `Eligible(intent, S, g + 1, prev)`: set `g = g + 1`. Sealed: output `(rid, tx_j, σ_j)` for `j = Select(·)`. Open: if `g ≤ G` output `(rid, tx, Sign(x, tx))` for `tx = Build(·)`. The adversary delays outputs, not beyond a bound after stabilization while eligibility persists.
- **Close.** Final, void or expired: no further anchors.
- **Corruption** (static set `C`, of which `b` Byzantine).
  - `|C| < t` and `b ≤ f`: nothing beyond the outputs.
  - Sealed, `|C| ≥ t`: the adversary gets every `σ_j` of every request of that epoch, at any time, including after close. Never `x`.
  - Sealed, `|C| < t`, `b > f`: the adversary chooses anchors among real finalized eligible states and can block. Never `x`.
  - Open, `|C| ≥ t` or `b > f`: the adversary gets `x`.
- **Never.** Outside the two key-exposure cases, `F_OMS` signs nothing outside `{Variant(intent, j)}` or the image of `Build` on anchored states, at most `G` transactions per open request, and nothing for an unknown `rid`.

The authorization is the owner's `post`; the binding is `Variant` and `Build`; freshness is the window, the pin, the anchor and the generation counter; the owner is offline after one input.

### 6.2 Claim 1: address binding. Status: proved (direct calculation), checked numerically

A message that passes Step A commits to sharings of exactly the stated objects for `X`. Feldman commitments in base `B` fix a polynomial. Sealed Schnorr: `p(0)·G = R + cX` with `R` of even y (suite 2), so `(R, p(0))` verifies. Sealed ECDSA: `p(0)·R = hG + rX ≠ O` with `r ≠ 0`, the ECDSA equation with `s ≠ 0`. Open ECDSA: `w(0)·R = G`, `μ(0)·R = X`, so `m·w(0) + r·μ(0)` is the signature for any `m`. Open Schnorr: constant terms `X, D, E'`. The commitments do not prove delivery; delivery is shown by the ACK quorum and the absence of a valid complaint.

### 6.3 Claim 2: sealed mode is unforgeable against a fully corrupt committee. Status: sketched

A forgery outside the variant sighashes breaks the suite's standard unforgeability. The reduction asks its signing oracle for every variant, recovers `R`, deals honestly, and proves `π` honestly, since it knows `e` and `s_{1,1}`. A fully corrupt committee can release any variant at any time; all spend the pin, so the chain executes at most one, and each pays the owner's outputs and at most the ceiling.

### 6.4 Claim 3: sealed points stay sealed below `t`. Status: sketched

With at most `t − 1` shares the adversary cannot output a variant signature for which honest nodes released fewer than `t − |C|` partials, under unforgeability, gap DH and the random oracle model, with loss `K·L`. Honest ciphertexts are replaced by random scalars (a distinguisher queries `Hq_enc` on `K_i`); the target variant is simulated from public values by interpolation in the exponent, and its `π` by programming `Hq_auth`.

### 6.5 Claim 4: open mode is unforgeable with at most `f` Byzantine nodes. Status: sketched; the single-signer games are cited, not proved here

1. *One digest per slot.* Two lock certificates for `(rid, g)` share `f + 1` nodes, so an honest node voted twice, against rule 1. This step uses signed votes only and holds on an inconsistent board. Rules 3 and 4 extend it across restarts. Across a freeze it holds on a consistent board (section 5).
2. *Dealing simulation.* The reduction gets `X` and the nonce points from the single-signer game, picks the corrupt shares at random (padding to `t − 1` points), and interpolates every coefficient commitment in the exponent; in base `R` this uses only `G`, `X`, `R`. Honest ciphertexts are random as in claim 3. `π` is simulated by programming.
3. *Partials.* When the quorum fixes `m`, the reduction asks the single-signer oracle for `s` and interpolates each honest `s_i`.
4. *Forgery.* A signature on another message wins the single-signer game.

ECDSA: [GS22] Theorem 3 bounds the game with a term `U·N` in the number `U` of outstanding presignatures and needs ratio resistance; raw-hash signing would break it, and every node hashes its own preimage. Schnorr: one nonce per slot would allow a ROS-type search across outstanding slots, so the design deals two and binds `ρ` to the digest; the proof of that single-signer game is from memory.

In profile T1 this covers every coalition below `t`. In profile T2 it covers `b ≤ f` plus share leakage up to `t − 1` nodes whose post keys are intact; `f < b < t` Byzantine nodes can certify two digests under one nonce and recover `x`.

### 6.6 Claim 5: no one-move protocol confines a qualified coalition to one of two unknown messages. Status: proved (the argument is complete)

If the honest committee signs `m_0` under one chain state and `m_1 ≠ m_0` under another, a coalition whose joint state finishes the honest protocol copies that state after the owner's message and runs the continuation twice. Erasure does not bind it. The strongest limit against a qualified coalition is therefore "only messages the owner's move already determines", and two such signatures are harmless only if the chain rejects one. Sealed mode reaches this bound. For an open line two points determine the line, and the line is the key, so the open one-spend limit is policy.

### 6.7 Claim 6: authorization and replay. Status: sketched

- Open: only the owner binds `rid`, because `π` proves knowledge of `x` and its challenge covers `hd` and the ciphertexts. Sealed: only the owner writes a message with unreleased signatures, and a message built from released signatures has another `rid` and adds no spend. In both modes a third party cannot alter a field, re-encrypt, take the `rid` of a pending request, or void it.
- A repost, a re-encoding or a migrated copy has the same `rid` and is ignored. Tombstones survive rotation.
- Every authorized transaction spends the pin, so the chain executes at most one per message. Sealed: any corruption. Open: at most `G` signed transactions below the bounds of claim 4.

### 6.8 Claim 7: liveness. Status: sketched

With an honest owner, at most `f` Byzantine nodes, a live board, target-chain finality, and a state that stays eligible (funded, trigger true, fee within the ceiling) from some finalized height until the partials are posted before `exp`: the spend completes one ACK round plus two (sealed) or three (open) board rounds after stabilization. All `2f + 1` honest nodes hold valid shares, report eligible tips, agree on the anchor, compute the same digest and release `t` valid partials in either profile. Bad partials are publicly identified. If eligibility flickers, Byzantine nodes can steer the anchor to an ineligible height and delay; they cannot consume a generation that way. A malicious owner harms only its own request.

### 6.9 Acceptance criteria

| Criterion | Sealed | Open T1 | Open T2 |
|---|---|---|---|
| One owner message, no later action | met | met | met |
| Below `t`: nothing about the key | met at any corruption level; the key is never dealt | met, static | met for leakage; **unmet** for `f < b < t` Byzantine |
| Below `t`: no signature | met for unreleased variants | met | **unmet** for `f < b < t` Byzantine |
| Committee signs only what the owner authorized | cryptographic, all nodes corrupt | honest-threshold policy | honest-threshold policy |
| No replay | met | met | met |
| Liveness | partial synchrony, `f < n/3`, conditional on eligibility | same | same |
| Corruption model | static | static | static, mixed |
| Public proof that the committee holds the object | algebra public; **delivery by ACK quorum, not by the message alone** | same | same |

## 7. Costs

`n = 16, 64, 256` give `f = 5, 21, 85`. A point is 33 bytes, a scalar 32. One dealt polynomial costs `P = 33(t − 1) + 32n` bytes. The fixed part is 654 bytes (header 524 with one output, `π` 130). Computation is counted in curve scalar multiplications at a planning figure of 50 µs each (from memory, not measured); a signature verification counts as 2. All figures are derived, none is measured.

**Owner message, bytes.**

| | T1 16 | T1 64 | T1 256 | T2 16 | T2 64 | T2 256 |
|---|---|---|---|---|---|---|
| `t` | 6 | 22 | 86 | 11 | 43 | 171 |
| `P` | 677 | 2,741 | 10,997 | 842 | 3,434 | 13,802 |
| Sealed point, `33 + P` | 710 | 2,774 | 11,030 | 875 | 3,467 | 13,835 |
| Open ECDSA slot, `33 + 2P` | 1,387 | 5,515 | 22,027 | 1,717 | 6,901 | 27,637 |
| Open Schnorr slot, `2(33 + P)`, plus `P` once | 1,420 | 5,548 | 22,060 | 1,750 | 6,934 | 27,670 |
| Message, sealed `K = 8`, one input | 6,334 | 22,846 | 88,894 | 7,654 | 28,390 | 111,334 |
| Message, sealed `K = 1` | 1,364 | 3,428 | 11,684 | 1,529 | 4,121 | 14,489 |
| Message, open ECDSA, `G = 1` | 2,041 | 6,169 | 22,681 | 2,371 | 7,555 | 28,291 |
| Message, open ECDSA, `G = 2` | 3,428 | 11,684 | 44,708 | 4,088 | 14,456 | 55,928 |
| Message, open Schnorr, `G = 1` | 2,751 | 8,943 | 33,711 | 3,246 | 11,022 | 42,126 |

Every further input multiplies the slot count.

**Owner computation, multiplications (ms).** Open ECDSA: `GL(2t − 1) + n + 3`. Sealed: `KL·t + n + 3`. Open Schnorr: `(t − 1) + 2GL·t + n + 3`. The `+3` is `E` and the two commitments of `π`.

| | T1 16 | T1 64 | T1 256 | T2 16 | T2 64 | T2 256 |
|---|---|---|---|---|---|---|
| Open ECDSA, `G = 1` | 30 (1.5) | 110 (5.5) | 430 (21.5) | 40 (2.0) | 152 (7.6) | 600 (30.0) |
| Sealed, `K = 8` | 67 (3.4) | 243 (12.2) | 947 (47.4) | 107 (5.4) | 411 (20.6) | 1,627 (81.4) |
| Open Schnorr, `G = 1` | 36 (1.8) | 132 (6.6) | 516 (25.8) | 51 (2.6) | 195 (9.8) | 771 (38.6) |

A hardware wallet adds `K·L` wallet signatures in sealed mode.

**Committee, per node.**

| | T1 16 | T1 64 | T1 256 | T2 16 | T2 64 | T2 256 |
|---|---|---|---|---|---|---|
| Offline rounds | 0 | 0 | 0 | 0 | 0 | 0 |
| Board rounds before the trigger (ACK) | 1 | 1 | 1 | 1 | 1 | 1 |
| Board rounds after the trigger: sealed (OBS, PARTIAL) / open (OBS, PREVOTE, PARTIAL) | 2 / 3 | 2 / 3 | 2 / 3 | 2 / 3 | 2 / 3 | 2 / 3 |
| Step A, open ECDSA `G = 1`: `π` 4, DH 1, two share checks `2t` | 17 | 49 | 177 | 27 | 91 | 347 |
| Step A, sealed `K = 8`: `π` 4, DH 1, `F_0` 16, share checks `8t` | 69 | 197 | 709 | 109 | 365 | 1,389 |
| Step A, open Schnorr `G = 1`: `3t + 5` | 23 | 71 | 263 | 38 | 134 | 518 |
| PREVOTE certificate check, `2(2f + 1)` | 22 | 86 | 342 | 22 | 86 | 342 |
| All post signatures, open, quorum minimum `3(2f+1) + t` posts | 78 | 302 | 1,198 | 88 | 344 | 1,368 |
| Node total, open ECDSA, minimum to maximum (`4n` posts) | 95–145 (4.8–7.2 ms) | 351–561 (18–28 ms) | 1,375–2,225 (69–111 ms) | 115–155 (5.8–7.8 ms) | 435–603 (22–30 ms) | 1,715–2,395 (86–120 ms) |
| Node total, sealed `K = 8`, minimum to maximum (`3n` posts) | 125–165 (6.2–8.2 ms) | 413–581 (21–29 ms) | 1,565–2,245 (78–112 ms) | 175–205 (8.8–10 ms) | 623–749 (31–37 ms) | 2,415–2,925 (121–146 ms) |
| Signing | 2 field multiplications per slot | | | | | |
| Combiner, optimistic | `t` Lagrange coefficients, 1 signature check | | | | | |
| Combiner, fallback, ECDSA, `t(2t + 3)` | 90 | 1,034 | 15,050 (0.75 s) | 275 | 3,827 | 58,995 (2.9 s) |
| Node posts, open (ACK 131, OBS 111, PREVOTE 167, PARTIAL 167 bytes) | 576 B | 576 B | 576 B | 576 B | 576 B | 576 B |
| Node download, open ECDSA `G = 1` (message plus `n` × 576) | 11.3 KB | 43.0 KB | 170.1 KB | 11.6 KB | 44.4 KB | 175.7 KB |
| Node download, sealed `K = 8` (message plus `n` × 409) | 12.9 KB | 49.0 KB | 193.6 KB | 14.2 KB | 54.6 KB | 216.0 KB |
| Resharing, per dealt polynomial, `t_old(P + 98)` bytes | 4.7 KB | 62.5 KB | 954 KB | not allowed | | |

Post signatures dominate node computation at large `n`; batch verification or an aggregate certificate from the board would remove most of it. A multi-scalar multiplication makes the share checks several times cheaper than the counts shown. Wall-clock time is set by the board: three or four commits in total.

## 8. Gaps closed and left open

1. **Address-bound import in one message.** Closed for the algebra: implied constant terms bind the dealing to `X` on the signature curve with no proof object, and Step A checks the address hash. Delivery is shown by the ACK quorum, not by the message alone; a proof of delivery inside the message needs verifiable encryption, which this design does not include. Static corruption only.
2. **Dealt shares to signing state.** Closed, for ECDSA as well as Schnorr. The dealt shares are the signing state.
3. **Single-transaction capability.** Closed cryptographically in sealed mode against a fully corrupt committee, for families the owner can enumerate. Policy in open mode, up to `f` Byzantine nodes; claim 5 gives the reason.
4. **Committee-side construction.** Closed in open mode: deterministic builder, pin, median anchor, digest lock. In sealed mode the committee selects.
5. **Formal model.** Partly closed: `F_OMS` and a sketch per claim. No UC proof.
6. **Committee change.** Closed by rule: `finish`, `void`, or freeze-and-transfer. Resharing is limited to `t = f + 1`.

Left open: gap 7 (committee size under adaptive corruption), gap 10 (spam and request privacy; a posting fee is assumed), gap 11 (measured latency). Gap 8 does not arise in sealed mode and is reduced in open mode by sweeping to a fresh `change_to`. Gap 9 is closed for dealing and resharing.

## 9. Comparison with Form A and Form B

| | Form A | Form B | Sealed | Open |
|---|---|---|---|---|
| Existing address | separate dealing first | two owner transactions and a key registration | one message | one message |
| Owner reads committee state first | no | yes, a presignature | epoch keys only | epoch keys only |
| Raw key leaves the wallet | yes | yes, to split it | no | yes |
| Committee preprocessing | presignature protocol | network presign | none | none |
| Committee rounds after the request is fixed | 1 | network rounds | 1 release round after the anchor | lock vote, then 1 round of partials |
| ECDSA machinery | Shamir-native multiplication | class-group encryption, eight owner proofs | Feldman VSS | Feldman VSS |
| What a threshold coalition gets | the key, for all time | one stored partial signature | signatures on the owner's conflicting variants, never the key | the key |
| One-spend limit | policy | cryptographic, one message | cryptographic, one conflicting family | policy |
| Who builds the transaction | caller | owner or contract | owner builds variants, committee selects | committee |
| Failure before the spend | key stays with the committee | presignature consumed | coins never moved | coins never moved; nodes erase |

The Form A and Form B columns follow REPORT.md sections 1, 2.4 and 3. Sealed mode matches Form B's cryptographic limit with one message and widens it from one message to a fee grid. Open mode is Form A with the presignature work moved to the one party who does it for free.

## 10. Risks and attacks considered

Stopped:

- **Pad reuse.** Each polynomial has its own pad label; the difference of two ciphertexts of one node reveals nothing.
- **Related dealing.** Pads depend on `hd`, `π` covers everything, and an attacker cannot re-encrypt.
- **Complaint oracle.** The proof of knowledge of `e` stops reuse of an honest `E`.
- **Identity squatting and replay.** `rid` is bound only by a message with a valid authorship proof, it ignores the ciphertexts and the proof, and in sealed mode it is tied to the dealing so a released signature cannot claim another request's identity.
- **Burned request.** No transient condition and no single node can tombstone a request or consume a generation.
- **Anchor deadlock.** The median rule always yields an anchor from `2f + 1` reports.
- **Nonce reuse** through divergent views, restarts, anchor replacement or rotation: one vote per generation, the durable slot ledger, the freeze rule.
- **Double payment across generations.** Every generation spends the pin.
- **Invalid sealed dealings**: odd-y `R`, `F_0 = O`, `r = 0`, repeated `R`.
- **Raw-hash and ratio attacks on presignatures; ROS-type attacks on pre-published Schnorr nonces.**

Not stopped:

- **Open mode, `t` colluding nodes take the key.** Inherent (claim 5).
- **Open mode, more than `f` Byzantine or rolled-back nodes** can certify two digests under one nonce. The result is the key, not only a double spend.
- **Rotation safety rests on board consistency.**
- **Sealed mode, colluding nodes release the highest-fee variant** or release before the trigger. Loss is bounded by the ceiling and the intent.
- **A signed transaction outlives the window.** A released Bitcoin transaction stays valid after `exp`. An owner who posts a second request must name the same pin or move the pin first.
- **Fee and trigger manipulation** up to the ceiling. **Stale pin**: the request fails safely.
- **Residual value** on account chains stays under a key the open committee has seen.
- **Old ciphertexts.** `t` epoch keys compromised before erasure open every dealing of that epoch.
- **Owner nonce reuse across messages**, and a compromised owner device.
- **Message size** grows with `K·L·n` in sealed mode; resharing costs `O(n²)` per polynomial.
- **Privacy.** Intents, variants and nonce points are public.
- **Proof status.** Open Schnorr rests on a result cited from memory; open ECDSA on a theorem whose model section was not read; adaptive corruption is not covered.

## 11. Experiment plan

1. **Algebra and interoperability.** `deal`, `verify_share`, `partial`, `verify_partial`, `combine` for three suites and both modes. The outputs must verify under libsecp256k1 (ECDSA, BIP340) and a strict Ed25519 library, and signed transactions must be accepted by Bitcoin regtest (P2WPKH, P2TR with a tweaked key) and an Ethereum dev chain.
2. **The deterministic checks of the findings ledger** as a regression suite, including every negative test.
3. **Sealed mode end to end** with a wallet that only signs: eight fee variants, selection against a simulated fee market, release, replacement.
4. **State machine.** A model of sections 3.5 to 3.9 and 5 with `f` Byzantine nodes, checking: one digest per slot; no tombstone from a transient condition; no generation both in flight and reshared.
5. **Measurements** at `n = 16, 64, 256` with 100 ms links against section 7, with and without batch verification.
6. **Builder determinism.** Two implementations of `Build` and `Variant`, differential fuzzing on recorded chain states, a fault test with one third of the nodes on a divergent builder.
7. **Proof work.** Read [GS22] in full and write the reduction of claim 4; check the two-nonce Schnorr claim against the FROST and MuSig2 proofs.

The design is wrong if: a forgery or key recovery against open ECDSA uses the base-`R` commitments beyond what [GS22] Theorem 3 allows; a practical attack exists on single-signer two-nonce Schnorr with many outstanding slots; a supported chain lets two variants both execute; `f` Byzantine nodes obtain two digests under one slot, or tombstone an eligible request; message size or board latency makes `n = 256` impractical.

## 12. References

- **BRIEF.md**: read in full (`design/BRIEF.md`).
- **REPORT.md**: read in full (`research/REPORT.md`).
- **[GS22]** J. Groth, V. Shoup, *On the security of ECDSA with additive key derivation and presignatures*: from memory, not checked, except these passages read from `research/sources/groth-shoup-2021-1330.txt`: the attack on ECDSA with presignatures in section 1.1, Definitions 1 and 2, the opening of section 7, section 7.3 (Definition 7, Theorem 3, its proof and notes 1 to 4). Not read: the EC generic group model of section 2, Theorem 1 and its proof, section 8 onward. Every use above is limited to the passages read.
- **RFC 9591 (FROST)**, local at `research/sources/lifecycle/rfc9591.txt`: from memory, not checked.
- From memory, not checked: Feldman VSS (1987); Komlo and Goldberg, FROST; Bellare et al. on non-interactive threshold Schnorr; Nick, Ruffing, Seurin, MuSig2; Benhamouda et al. on ROS; Abdalla, Bellare, Rogaway on gap and oracle Diffie-Hellman; BIP125, BIP143, BIP340, BIP341; RFC 8032; EIP-2, EIP-1559, EIP-2718; Solana durable nonces.
- Statements about cgVSS, Groth NI-DKG, Ika and the Internet Computer are taken from REPORT.md.

**Lineage.** The base is the line-dealing proposal cand-3c91. From cand-5d08: the request identity `H(chain, board, X, owner_nonce)` that excludes malleable bytes (used as is in open mode; sealed mode adds `hd`, for the reason in section 3.2), lock before any share, durable slot consumption, and freeze-and-transfer at rotation. From cand-a7e2: the two-valued threshold field and the account-chain builder shape. The fixes follow the blinded reviews of the council round; the findings ledger maps each one.
