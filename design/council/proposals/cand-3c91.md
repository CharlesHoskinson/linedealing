# Line dealing: the owner deals the signature equation, sealed or open

## 1. Scheme in one paragraph

A Schnorr signature is one point on the line `s(c) = k + c·x`, and an ECDSA signature is one point on the line `s(h) = h·k⁻¹ + r·k⁻¹x`. The owner knows both coefficients of that line, so the owner should deal the line and not the key. The owner's one message is a Feldman-committed Shamir dealing, on the signature curve, of either **sealed points** or **open lines**. A sealed point is the line already evaluated by the owner at the sighash of one fully specified transaction variant. Its constant-term commitment is forced to equal `R + cX` (Schnorr) or `hG + rX` in base `R` (ECDSA), so the committed secret is a valid signature of the address key on that transaction and on nothing else. The owner seals a small family of mutually conflicting variants (a fee grid over the same pinned input or the same account nonce), and the committee's work is to choose and release one. An open line is both coefficients, dealt so that the constant terms are forced to `G` and `X` in base `R`. The committee builds the transaction from chain state, votes on its digest, and each node then sends one linear partial signature that anyone can check. There is no DKG, no presignature protocol, no multiplication, no Paillier, no OT and no share conversion, at any threshold. Sealed mode gives a cryptographic single-spend limit that holds even when every node is corrupt, and it works for an existing address with a wallet that can only sign transactions. Open mode gives full committee-side construction, and its one-spend limit is honest-threshold policy. Section 6.6 shows why no protocol of this shape can do better. The owner picks the mode per message.

## 2. Setting and assumptions

**Parties.** One owner with the key `x` of an existing address, `X = xG`. A committee of `n = 3f + 1` nodes. Anyone can act as combiner and broadcaster.

**Suites.** `secp256k1-ECDSA` (Bitcoin legacy and SegWit v0, Ethereum), `BIP340` (Taproot key path), `Ed25519`. `q` is the group order and `G` the generator.

**Thresholds.** Three numbers, stated separately.

- Reconstruction threshold `t = n − f = 2f + 1`. Any `t` valid partial signatures give the signature.
- Privacy threshold `t − 1 = 2f`. A set of `2f` shares gives no information beyond the public values.
- Active corruption bound `f < n/3`. The quorum rules of open mode need it.

The adversary that open mode tolerates is mixed: at most `f` Byzantine nodes, plus at most `f` further nodes whose state leaks but who follow the protocol. A node that is rolled back to an old state counts as Byzantine. Sealed mode's main claim holds with all `n` nodes corrupt.

**Corruption model.** Static. Honest nodes erase used shares and expired epoch keys, and they keep a durable log of their own votes. I claim nothing for adaptive corruption.

**Network.** Partial synchrony. A **board** gives total-order broadcast with `f < n/3` (a BFT ledger run by the committee, or a contract on a host chain). The target chain has a finality rule (native finality, or depth `c` for Bitcoin, which is then an assumption).

**Setup.** No trusted setup. Per epoch `e`, node `i` registers on the board an encryption key `PK_i = sk_i·G` on the suite curve with a proof of possession, and a signature key for its board posts. Nodes erase `sk_i` when the epoch and its grace period end. Public parameters: the suite, hash functions with distinct domain tags (`H_enc`, `H_auth`, `H_1`, the digest hash), a builder specification identified by its hash, and `(n, t, f)`.

**Assumptions.**

- Discrete log on the suite curve, and the random oracle model for the hashes named above.
- Gap Diffie-Hellman for the share encryption (hashed ElGamal with a public complaint that reveals a DH value).
- Sealed mode: standard unforgeability of ECDSA, BIP340 or Ed25519. Nothing else.
- Open mode, ECDSA: unforgeability of ECDSA with public, single-use presignatures. [GS22] states this as Theorem 3, in the EC generic group model, for a hash that is collision resistant, random-preimage resistant and ratio resistant. I read the theorem and its proof but not the whole paper (section 12).
- Open mode, Schnorr: unforgeability of single-signer two-nonce Schnorr with pre-published nonces. This is the one-signer case of MuSig2 and the structure of FROST. The proofs I rely on (algebraic one-more discrete log, in the random oracle and algebraic group models) are from memory, not checked.
- The owner's device is honest when it writes the message, and the owner knows the current epoch keys.

## 3. Protocol

### 3.1 Notation

`Share_t(v)` picks a random polynomial `p` of degree `t − 1` with `p(0) = v` and returns shares `v_i = p(i)`. `Com_B(p)` is the list of coefficient commitments `a_u·B` for `u = 1..t−1` in base `B`. The constant-term commitment is never sent when the verifier can compute it. `Eval(C_0, C, i) = C_0 + Σ_u i^u·C_u` is the public commitment to share `i`.

### 3.2 The owner's message

```
OwnerMsg = (hdr, deal, ct, π)

hdr:
  version, suite, target chain id
  X                 address key (for P2TR: the output key Q, even y)
  committee id, epoch e, hash of the epoch key list, board id
  window [nb, exp]  board heights; on_rotation ∈ {finish, reshare, void}
  trigger           predicate on target-chain state, default "true"
  intent            outputs [(script, amount or ALL)], change_to,
                    pin: one outpoint that every transaction of this
                         message must spend, or the account nonce,
                    further allowed outpoints, late_inputs flag,
                    fee ceiling, fee rule id, builder spec hash
  mode              sealed {K variants, fee grid} or open {L slots, G generations}
  E = e·G           ephemeral encryption key, fresh per message

deal, per signature slot:
  sealed, variant j, input ℓ:   R,  Com(p_s)                 constant term implied
  open ECDSA, gen g, slot ℓ:    R,  Com_R(p_w), Com_R(p_μ)   constant terms implied
  open Schnorr, once:               Com_G(p_x)               constant term X implied
  open Schnorr, gen g, slot ℓ:  D, E', Com_G(p_d), Com_G(p_e)

hd = H(hdr ‖ deal)

ct, per node i and per dealt polynomial p:
  K_i = e·PK_i
  ct = p(i) + H_enc(hd, i, PK_i, K_i, slot id) mod q

π:  Fiat-Shamir Schnorr proof of knowledge of e (and of x in open mode):
    commitments T_e (and T_x), challenge H_auth(hd ‖ ct ‖ T_e ‖ T_x), responses

rid = H(hd ‖ ct ‖ π)
```

**Sealed points.** For each variant `j = 1..K` the owner computes `tx_j = Variant(intent, j)` (section 4) and, for each input `ℓ`, its sighash `m`. The owner signs `m` in the ordinary way with a fresh nonce and obtains `(R, s)`. The owner deals `Share_t(s)`.

- BIP340 and Ed25519: commitments in base `G`. Implied constant term `F_0 = R + c·X`, with `c` the suite's challenge hash of `(R, X, m)`.
- ECDSA: commitments in base `R`. Implied constant term `F_0 = h·G + r·X`, with `h` the sighash and `r = x(R) mod q`. This is `s·R`, because `s·k = h + r·x`.

An ordinary wallet output is enough: `(R, s)` is a standard signature, and for ECDSA the owner recovers `R = s⁻¹(hG + rX)`. A hardware wallet that never exports `x` can therefore produce a sealed message. In that case `π` proves knowledge of `e` only.

**Open lines, ECDSA.** Per slot the owner picks `k`, sets `R = kG`, `w = k⁻¹`, `μ = k⁻¹x`, and deals `Share_t(w)` and `Share_t(μ)` with commitments in base `R`. The implied constant terms are `C_0 = G` and `D_0 = X`. These two equalities hold if and only if the committed polynomials have `w(0) = k⁻¹` and `μ(0) = x·k⁻¹`. No proof object is needed.

**Open lines, Schnorr.** The owner deals `Share_t(x)` once, with implied constant term `X`, and per slot two nonces `d, e'` with `D = dG`, `E' = e'G`.

**Key formats.** The owner does all normalization before dealing, so the committee sees an ordinary key.

- BIP340 and Taproot: the dealt secret is the scalar whose public key is the even-y output key `Q`. For a BIP341 key-path address this is `±(p_even + tweak)`. In sealed mode this is whatever the wallet already signs with.
- Ed25519: the dealt secret is `a = clamp(SHA-512(seed)[0..32]) mod ℓ`. Nonces are random scalars; verification does not depend on how the nonce was derived.
- Nodes reject any commitment or key that is not a canonical encoding of a point in the prime-order subgroup.

**Domain separation.** `π` is a Schnorr proof transcript under `H_auth`, a hash that differs from every suite's challenge hash and sighash. It is never an ECDSA signature and never a native signature, so it cannot be replayed as a chain signature. It is simulatable in the random oracle model.

### 3.3 Committee steps

**Step A, accept (one board round, any time before `nb`).** Node `i` runs the public checks: suite, epoch and key-list hash are current; the window is open; `π` verifies; in sealed mode it recomputes every `tx_j`, sighash and implied constant term from the intent and checks that every variant spends the pin. Among messages that pass the public checks, only the first with a given `hd` is processed. A message that fails them never blocks a later one. The node then computes `K_i = sk_i·E`, decrypts its shares and checks each against `Eval(·, i)` in the right base. It posts `ACK(rid)`, or `COMPLAINT(rid, K_i, DLEQ(G, E; PK_i, K_i))`. Anyone can check a complaint by decrypting share `i`. One valid complaint voids the request. An honest owner never causes one, and `π` prevents a third party from reusing an honest `E` to draw out a node's `K_i`.

The request is **armed** when `2f + 1` ACKs are on the board. Steps B and C run only for an armed request with no valid complaint.

**Step B, observe (one board round).** When the board height is at least `nb` and a node sees a finalized target-chain block `B` in which `trigger` holds and the pin is unspent, it posts `OBS(rid, g, B)`. The anchor block `B*` is the first block that collects `f + 1` OBS posts in board order. A node that does not yet see `B*` as final waits.

**Step C, sealed release (one board round).** Each node computes `j = Select(intent, state(B*))` and posts `PARTIAL(rid, j, {s_{j,ℓ,i}})`. Anyone checks each partial against `Eval(F_0, F, i)` and interpolates `s_{j,ℓ}` from `t` of them. The signature is `(R, s)`, or `(r, s)` with low-s normalization for ECDSA.

**Step C, open vote and sign (two board rounds).**

```
tx  = Build(intent, state(B*))            # section 4; at most L inputs; spends the pin
dg  = H(rid, g, tx, sighashes m_1..m_L')
write (rid, g, dg) to the durable vote log
post PREVOTE(rid, g, dg)                  # once per (rid, g), signed

wait for 2f+1 PREVOTE posts with digest equal to own dg
for each input ℓ:
  ECDSA:   r   = x(R_ℓ) mod q
           s_i = m_ℓ·w_i + r·μ_i
           check by others:  s_i·R_ℓ = m_ℓ·W_i + r·M_i
  Schnorr: ρ   = H_1(hd, g, ℓ, dg)
           R   = D_ℓ + ρ·E'_ℓ ;  σ = −1 if BIP340 and R has odd y, else 1
           c   = suite challenge of (R, X, m_ℓ)
           s_i = σ·(d_i + ρ·e'_i) + c·x_i
           check by others:  s_i·G = σ·(D_i + ρ·E'_i) + c·X_i
post PARTIAL(rid, g, {s_i}); erase the nonce shares of generation g
```

`W_i, M_i, D_i, E'_i, X_i` are `Eval` of the commitments at `i`. The combiner interpolates `t` partials. It first checks only the final signature, and it checks single partials only if that fails.

Four local rules carry the safety of open mode.

1. A node posts at most one PREVOTE per `(rid, g)`, and it writes the vote to durable storage before it posts.
2. A node signs only the digest that it built itself, and only after it sees `2f + 1` matching PREVOTE posts.
3. A node never uses a slot twice. A fee bump uses generation `g + 1`, which has its own lines.
4. A node that restarts replays the board for its own posts before it acts. It abstains on every `(rid, g)` for which the board shows its PREVOTE or PARTIAL, and on every slot it cannot account for. The ciphertexts stay public and `sk_i` lives until the epoch ends, so erasure alone does not survive a restore from a snapshot; this rule and the vote log do.

**Step D, finish.** When the transaction is final on the target chain, or at `exp`, every node erases all shares of `rid`. In open mode a generation `g + 1` may start, under the bump rule of section 4, while `g < G`.

### 3.4 Output

A standard transaction with standard signatures. Verifiers on the target chain see nothing unusual.

### 3.5 Optional compression of sealed mode

Sealed mode costs one dealing per variant. Where public commitments to each sealed signature are not needed, the owner can deal one scalar `σ` and encrypt each variant's signature under `KDF(σ·P_j)` with `P_j = HashToCurve(hd, j)`. Nodes release `σ_i·P_j` with a DLEQ proof against their share commitment. The security of this variant (a hashed threshold Diffie-Hellman release under a one-more gap DH assumption) is from memory, not checked, and it is not part of the core design.

## 4. Transaction construction

**Why a committee at all.** If the intent fixes the transaction and no trigger is set, the owner should sign and broadcast, and no committee is needed. The committee earns its place when the transaction depends on state that exists only after the owner leaves: the fee market at execution time, a trigger, deposits that arrive later, or an amount that depends on other state.

**The pin.** Every transaction that a message can authorize spends the pin: one outpoint that the owner names, or the account nonce. This makes all of them conflict on the target chain, in both modes and across fee-bump generations.

**Sealed mode: construction is selection.** `Variant(intent, j)` is a pure function. All variants spend the pin and the same further inputs, and pay the same outputs. They differ in the fee: `fee_j = ceiling · γ^(j−K)`, for example `γ = 1.5`, so `K = 8` spans a factor of 17 and `K = 16` a factor of 438. On a UTXO chain the change output absorbs the difference. `Select(intent, S)` returns the least `j` whose fee rate meets `FeeRule(S)`. If none does, the nodes wait for a later block. If the transaction is not final after the bump delay, the nodes release the next variant. On an EIP-1559 chain one variant with `maxFeePerGas = ceiling` is enough, because the chain itself charges the current base fee. The owner must know its own outpoints or nonce when it writes the message. It does not need to know future fees.

**Open mode: full construction.** `Build(intent, S)` is a pure function of the intent and of the target-chain state at `B*`. The builder specification fixes every byte.

- `Build` returns ⊥ if the pin is spent at `B*`.
- UTXO chain: the input set always contains the pin. The other eligible inputs are the allowed outpoints, and with `late_inputs` also every output of the address that is final at `B*`. `late_inputs` only adds inputs; it never replaces the pin. Selection is the whole eligible set for `ALL`, otherwise the pin plus largest-first until outputs plus fee are covered, at most `L` inputs. Inputs are ordered by `(txid, vout)`. Outputs are in intent order, and change goes to `change_to` if it is above dust. The fee rate is a fixed statistic of the blocks up to `B*` (for example the median of the last six blocks' median rates), clipped to the ceiling. `nLockTime` is the height of `B*`, sequence numbers signal replacement, and the sighash type is ALL (DEFAULT for Taproot).
- Account chain: the nonce is the pin, `maxFeePerGas = min(ceiling, 2·basefee(B*) + tip)`, gas limit by a fixed table for the call type, chain id from the intent.
- Bump rule: generation `g + 1` may start if generation `g` is not final after `Δ` target blocks. It spends the pin, raises the fee by the chain's replacement minimum and stays below the ceiling.

**Agreement.** The board orders the OBS posts, so `B*` is unique. Honest nodes then compute the same bytes, because `Build` is deterministic. The PREVOTE quorum is the safety net for the case that they do not (a bug, a version skew or a different chain view): at most one digest per `(rid, g)` can gather `2f + 1` prevotes, and a node whose digest differs does not sign. A divergence therefore stalls the request and never produces two signatures under one nonce. The digest certificate is also a public record of what the committee decided to sign.

**Every node hashes the preimage itself.** No node ever signs a digest that it received. This removes the raw-hash weakness of presignatures [GS22, section 7.3, note 1].

## 5. Committee change

The message names one committee and one epoch, and its shares are encrypted to that epoch's keys. The field `on_rotation` selects one of three rules.

- **finish** (default). The window must end no later than the epoch's grace period. Nodes of epoch `e` stay until every armed request of that epoch is final or expired, and then erase `sk_i`. The new committee never sees the request. REPORT.md reports the same rule for matched requests on the Internet Computer.
- **reshare** (long-lived triggers). At rotation, each old node `i` reshares each of its shares `v_i` to the new committee: it deals `Share_{t'}(v_i)` with commitments in the same base as the original dealing. The constant-term commitment must equal `Eval(·, i)` of the old commitments, which is public, so anyone can check that the new sharing continues the owner's dealing. The board fixes a set `Q` of `t` old nodes whose resharings are armed (ACK quorum of the new committee, no valid complaint). The new share is `v'_j = Σ_{i∈Q} λ_i^Q · g_i(j)`, and the new commitments are the same combination. Here the dealers can be malicious, so complaints matter: a valid complaint removes that old node from `Q`. Old nodes erase after the handover certificate is on the board. Cost: `O(n²)` scalars and commitments per dealt polynomial.
- **void**. The request dies at rotation, and all shares are erased.

Two rules protect single use across the change. A request with a PREVOTE on the board for generation `g` is never reshared in that generation: the old committee finishes it or it expires. The handover certificate carries the generation counter, and the new committee starts at the next unused generation only.

A failed handover voids the request. This failure is safe, because the scheme never moves funds ahead of the spend: the coins stay at the owner's address under the owner's key.

Because epoch keys are erased, a public ciphertext from an old epoch cannot be decrypted later. This bounds the replay state: nodes keep the set of seen `hd` values and their vote log only for the epoch and its grace period.

## 6. Security

### 6.1 Ideal functionality `F_OMS` (one-move spend)

Parameters: suite, `Variant`, `Select`, `Build`, `(n, t, f)`, a ledger functionality `L` for the target chain and a clock.

- **Post.** On `(post, hdr)` from the owner of `X`: store `(rid, hdr, status = live, g = 0)`. Send `(rid, hdr)` to the adversary. The owner takes no further action. In sealed mode compute and store `σ_j = Sign(x, Variant(intent, j))` for all `j`.
- **Anchor.** On `(anchor, rid, B*)` from `L`, if the clock is inside the window, `status = live`, `trigger(state(B*))` holds and the pin is unspent:
  - sealed: `j = Select(intent, state(B*))`; output `(rid, tx_j, σ_j)` to all parties.
  - open: if `g < G`, set `g = g + 1`, `tx = Build(intent, state(B*))`; if `tx ≠ ⊥` output `(rid, tx, Sign(x, tx))`.
  The adversary can delay an output, but not beyond `Δ` after global stabilization time.
- **Expire.** At `exp`, or on a void event, set `status = void`.
- **Corruption** (static, set `C`; `b` is the number of Byzantine or rolled-back nodes in `C`).
  - `|C| ≤ 2f` and `b ≤ f`: the adversary gets nothing beyond the outputs.
  - Sealed, `|C| ≥ t`: the adversary gets `{σ_j}` for every `rid` posted to that epoch. It gets nothing about `x`.
  - Sealed, `|C| < t` and `b > f`: the adversary can block outputs and can cause release of any variant of a live `rid`. It gets nothing about `x`.
  - Open, `|C| ≥ t` or `b > f`: the adversary gets `x`. For `b > f` this is the nonce-reuse case of section 10.
- **Never.** Outside the two key-exposure cases, `F_OMS` signs no message outside `{Variant(intent, j)}` or the image of `Build(intent, ·)` on anchored states, at most `1 + G` transactions per open `rid`, and nothing for a void or unknown `rid`.

The functionality joins the four parts that REPORT.md section 5.1 item 5 asks for. The authorization is the owner's `post`. The binding is `Variant` and `Build`. Freshness is the window, the pin, the anchor block and the generation counter. The owner is offline after one input.

The game form used below: the adversary corrupts `C`, drives the owner to post messages of its choice, influences target-chain state, and wins if it outputs a valid signature under `X` on a message that `F_OMS` would not have released to it.

### 6.2 Claim 1: address binding is unconditional

*A message that passes the public checks of step A commits to sharings of exactly the stated objects for key `X`.*

Sketch. Feldman commitments in base `B` fix a polynomial. In sealed Schnorr the constant term is fixed to `R + cX`, so `p(0)·G = R + cX` and `(R, p(0))` verifies. In sealed ECDSA, `p(0)·R = hG + rX`, which is the ECDSA verification equation. In open ECDSA, `w(0)·R = G` and `μ(0)·R = X` give `w(0) = k⁻¹` and `μ(0) = x/k` for `R = kG`, so `m·w(0) + r·μ(0)` is the ECDSA signature for any `m`. In open Schnorr the constant terms are `X`, `D`, `E'`. Partial-signature checks are the same equations at `i`. I checked the open ECDSA partial and combined equations, the sealed ECDSA constant term and the Schnorr line identity numerically on secp256k1 with a short script.

What the commitments do not prove is delivery: that each ciphertext holds the committed share. Delivery is shown by the ACK quorum and the absence of a valid complaint. That part is not contained in the owner's message alone.

### 6.3 Claim 2: sealed mode is unforgeable against a fully corrupt committee

*For any adversary that corrupts all `n` nodes, a forgery on a message outside `{sighashes of Variant(intent, j)}` breaks the standard unforgeability of the suite's signature scheme.*

Sketch. The reduction has a signing oracle for `X`. For each posted message it asks the oracle for a signature on every variant sighash, recovers `R`, and runs the honest dealing on `s`. It produces `π` for `e` honestly. The adversary's view is exactly the real view, and its forgery is on a message that was never queried. No programming, no generic group and no presignature assumption are needed: each `R` is published together with its already fixed message.

Consequence. A fully corrupt committee can do exactly this: release any variant at any time, inside or outside the window. All variants spend the pin, so the target chain executes at most one. Each pays the owner's outputs and a fee at most the ceiling. The single-spend limit is enforced by the signature scheme and the target chain's own double-spend rule, not by the nodes.

### 6.4 Claim 3: sealed points stay sealed below the threshold

*An adversary with at most `2f` shares cannot output the signature of a variant for which no honest node released a partial, under the suite's unforgeability, gap DH and the random oracle model. The loss is a factor `K·L` for guessing the target.*

Sketch. Replace the honest nodes' ciphertexts by random scalars. A distinguisher must query `H_enc` on `K_i`, which solves gap DH (the DLEQ in complaints is the "gap" part, and `π` stops reuse of `E`). For the guessed target variant the reduction does not query its signing oracle: it picks `R = ρG`, computes the implied constant term from public values, picks the corrupt shares at random and interpolates the coefficient commitments in the exponent. For all other variants it deals honestly from oracle signatures. A signature on the target is a forgery on an unqueried message.

### 6.5 Claim 4: open mode is unforgeable below the threshold

*With at most `f` Byzantine or rolled-back nodes and at most `2f` exposed shares in total, a forgery on a message that no honest quorum built reduces to the single-signer scheme with public single-use nonces: ECDSA with presignatures, or two-nonce Schnorr.*

Sketch.

1. *One signing query per slot.* Two different digests for the same `(rid, g)` would each need `2f + 1` prevotes. Two such sets share `f + 1` nodes, so one honest node prevoted twice, against rule 1. Honest nodes sign only their own digest after its quorum (rule 2), never reuse a slot (rule 3) and keep these rules across restarts (rule 4). So the honest nodes together release partials for at most one message per slot. The argument uses signed prevotes and does not depend on the board being consistent.
2. *Dealing simulation.* The reduction gets `X` and the nonce points (`R`, or `D` and `E'`) from the single-signer game. It picks the exposed shares at random (padding to exactly `t − 1` points if fewer are exposed) and interpolates every coefficient commitment in the exponent from the implied constant term and those points. In base `R` this needs only `G`, `X` and `R`. Honest ciphertexts are random as in claim 3. `π` for `x` is simulated by programming `H_auth`.
3. *Partial signatures.* When the honest quorum fixes `m`, the reduction asks the single-signer oracle for `s` and computes each honest `s_i` by interpolation from `s` and the `t − 1` known points. These pass the public checks by linearity.
4. *Forgery.* Any signature on another message is a forgery in the single-signer game.

For ECDSA, [GS22, Theorem 3] bounds that game by collision resistance, random-preimage resistance, ratio resistance and a term `U·N` in the number `U` of outstanding presignatures. The bound is weaker than for plain ECDSA, and the scheme would break under raw-hash signing, which step C forbids. This part of the claim is unverified in one respect: Theorem 3's proof refers to the game definition and to the proof of Theorem 1, and I did not read those.

For Schnorr, one nonce per slot is not enough. With pre-published nonces and adversary-influenced messages, an adversary that holds many outstanding slots under one key can run a generalized-birthday (ROS-type) search. A deterministic multiplicative re-randomization `R' = δR` does not stop it, because each slot still has one unknown that the adversary can eliminate. This is why the design deals two nonces and uses `R = D + ρE'` with `ρ` bound to the whole digest.

Not claimed. Re-randomized presignatures for ECDSA would restore the plain-ECDSA bound [GS22, Theorem 5], but that theorem is for `R' = R + δG`, which is not linear in dealt shares of `k⁻¹`. A multiplicative form `R' = δR` with `δ` from a board beacon is linear (`w' = w/δ`, `μ' = μ/δ`). I believe the proof of Theorem 5 adapts, because `r' = x(δR)` becomes unpredictable at the time the message is fixed, but I have not proved it and the design does not rely on it.

### 6.6 Claim 5: no one-move protocol confines a qualified coalition to one of two unknown messages

*Let a protocol satisfy the pattern: after the owner's message the owner is offline, and there are two chain states under which the honest committee outputs signatures on two different messages `m_0 ≠ m_1`. Then any coalition whose joint state suffices to finish the honest protocol can output valid signatures on both.*

Sketch. The coalition copies its state after the owner's message and runs the honest continuation twice, once with each chain state as input. Honest erasure does not bind it. Nothing outside the coalition takes part.

Consequences. The strongest limit that exists against a qualified coalition is "only messages that the owner's move already determines", and the only way to make two such signatures harmless is for the target chain to reject one of them. Sealed mode reaches exactly this bound. For an open line there is in addition no middle ground: two points determine the line, and the line is the key. Confining a coalition to the image of `Build` would need a constrained signing key for an unmodified ECDSA or Schnorr verification equation. I know of no construction short of obfuscation-strength tools or trusted hardware. In open mode the one-spend limit is therefore policy, enforced by the honest nodes, and the owner who needs more keeps a share (Form B) or uses sealed mode.

### 6.7 Claim 6: authorization and replay

- A third party cannot change any header field of an honest message: the pads depend on `hd`, so shares under a changed header do not decrypt to valid shares, and `π` fails because its challenge covers `hd`, the ciphertexts and the prover's commitments. It cannot re-encrypt the honest shares, because it does not know `e`.
- A repost has the same `hd` and is ignored inside the epoch. After the epoch, the keys are gone.
- Chain-level replay is impossible in both modes: every authorized transaction spends the pin, and `Build` returns ⊥ once the pin is spent.
- Sealed mode, any corruption: at most one execution per message (claim 2). Open mode, below the bounds of claim 4: at most `1 + G` signed transactions per message, all conflicting on the pin, so at most one execution.

### 6.8 Claim 7: liveness

*With an honest owner, at most `f` Byzantine nodes, a live board and target-chain finality, the spend completes within a constant number of board rounds after global stabilization and after the trigger holds.*

Sketch. All `2f + 1` honest nodes decrypt valid shares, so the request is armed and no valid complaint exists. They post OBS, compute the same `tx` or the same `j`, prevote the same digest and release `2f + 1 = t` valid partials. Partials are publicly checkable, so bad ones are discarded. A malicious owner gets no liveness guarantee and harms only its own request.

## 7. Costs

**Parameters.** `n = 16, 64, 256` give `f = 5, 21, 85` and `t = 11, 43, 171`. A compressed point is 33 bytes and a scalar 32 bytes on secp256k1 (32 and 32 on Ed25519, so those figures are slightly lower).

**Owner message size.** One dealt polynomial with implied constant term costs `P = 33(t − 1) + 32n` bytes: `t − 1` coefficient commitments and `n` encrypted shares.

| Item | Formula | n = 16 | n = 64 | n = 256 |
|---|---|---|---|---|
| `P` | `33(t−1) + 32n` | 842 | 3,434 | 13,802 |
| Sealed point (one variant, one input) | `33 + P` | 875 | 3,467 | 13,835 |
| Open ECDSA slot | `33 + 2P` | 1,717 | 6,901 | 27,637 |
| Open Schnorr key sharing, once | `P` | 842 | 3,434 | 13,802 |
| Open Schnorr slot | `2(33 + P)` | 1,750 | 6,934 | 27,670 |
| Fixed part (header about 300, `E` 33, `π` about 100) | about 430 | 430 | 430 | 430 |

| Whole message | n = 16 | n = 64 | n = 256 |
|---|---|---|---|
| Sealed, `K = 8` variants, one input | 7.4 KB | 28.2 KB | 111.1 KB |
| Sealed, `K = 1` (EIP-1559 or fixed fee) | 1.3 KB | 3.9 KB | 14.3 KB |
| Open ECDSA, one slot | 2.1 KB | 7.3 KB | 28.1 KB |
| Open ECDSA, one slot plus one bump generation | 3.9 KB | 14.2 KB | 55.7 KB |
| Open Schnorr, one slot | 3.0 KB | 10.8 KB | 41.9 KB |

Every additional input multiplies the slot count. The optional compression of section 3.5 would bring sealed `K = 8` to about 1.8, 4.4 and 14.8 KB.

**Owner computation.** Counted in curve scalar multiplications: one per coefficient commitment, one per node for `K_i`, a few for nonces and `π`. Field work is negligible.

| | Formula | n = 16 | n = 64 | n = 256 |
|---|---|---|---|---|
| Open ECDSA, one slot | `2t + n + 1` | 39 | 151 | 599 |
| Sealed, `K = 8` | `8t + n + 2` | 106 | 410 | 1,626 |
| Time at 50 µs each, open / sealed | | 2 / 5 ms | 8 / 21 ms | 30 / 81 ms |

The 50 µs figure for a variable-base secp256k1 multiplication is a planning number from memory, not measured here. Sealed mode with a hardware wallet adds `K·L` wallet signatures.

**Committee.**

| | n = 16 | n = 64 | n = 256 |
|---|---|---|---|
| Offline rounds | 0 | 0 | 0 |
| Board rounds before the trigger (ACK) | 1 | 1 | 1 |
| Board rounds after the trigger, sealed (observe, release) | 2 | 2 | 2 |
| Board rounds after the trigger, open (observe, digest vote, partials) | 3 | 3 | 3 |
| Node posts per request (4 posts of about 130 B) | 0.5 KB | 0.5 KB | 0.5 KB |
| Node download (owner message plus all posts), open ECDSA | 10 KB | 39 KB | 156 KB |
| Node verification, open ECDSA: 1 DH and 2 multi-scalar checks of size `t`, upper bound `2t + 1` multiplications | 23 (1.2 ms) | 87 (4.4 ms) | 343 (17 ms) |
| Node verification, sealed `K = 8`, upper bound `8t + 1` | 89 (4.5 ms) | 345 (17 ms) | 1,369 (68 ms) |
| Node signing | 2 field multiplications per slot | same | same |
| Combiner, optimistic | `t` Lagrange coefficients and one signature check | same | same |

Derivation of the download row: the owner message from the table above plus `n × 0.5 KB` of posts. The multiplication counts are upper bounds; a Pippenger multi-scalar multiplication is several times cheaper at `t = 171`. Wall-clock time is set by the board: two or three commits after the trigger. All times are estimates until the experiments of section 11 run.

## 8. Gaps closed and left open

1. **Address-bound key import in one message.** Closed for the algebra: the implied constant terms bind the dealing to `X` unconditionally, on the signature curve, with no proof object. Delivery is shown by the ACK quorum and public complaints, not by the message alone. A proof of delivery inside the message needs verifiable encryption (class groups, as REPORT.md reports for cgVSS); the design leaves that slot open. Static corruption only.
2. **Dealt shares to signing state.** Closed. The dealt shares are the signing state. There is no conversion, no multiplication and no Paillier or OT state, for ECDSA as well as Schnorr.
3. **Single-transaction capability.** Closed cryptographically in sealed mode, against a fully corrupt committee, for families the owner can enumerate. Policy in open mode, with the reason in claim 5.
4. **Committee-side construction.** Closed in open mode by a deterministic builder, a pin, an anchor block and a digest quorum. In sealed mode the committee selects among owner-built variants; it does not construct.
5. **Formal model.** Partly closed: `F_OMS` and the game are stated and each claim has a sketch. There is no full UC proof.
6. **Committee change.** Closed by rule: the message names an epoch and a window, and `finish`, `reshare` or `void` decides its fate.

Left open: gap 7 (committee size under adaptive corruption), gap 10 (spam and request privacy; intents are public), gap 11 (measured latency). Gap 8 (the imported key stays live) does not arise in sealed mode, where no key is imported, and is reduced in open mode by sweeping to a fresh `change_to` address. Gap 9 (key formats) is closed for dealing and resharing, because the owner normalizes before dealing and resharing is linear.

## 9. Comparison with Form A and Form B

| | Form A (committee holds the key, owner posts a request) | Form B (owner share, future sign) | Line dealing, sealed | Line dealing, open |
|---|---|---|---|---|
| Existing address | Needs a separate dealing first | Import with two owner transactions and a key registration | Yes, one message | Yes, one message |
| Owner reads committee state first | No | Yes, a completed presignature | Only the epoch keys | Only the epoch keys |
| Raw key must leave the wallet | Yes, for the dealing | Yes, to split it | No. Ordinary signatures suffice | Yes |
| Committee preprocessing | Presignature protocol, `O(n²λ)` communication | Network presign | None | None |
| Committee rounds after the request is fixed | 1 | Network rounds after the owner message | 1 release round after the anchor block | Digest vote, then 1 round of partials |
| ECDSA machinery | Shamir-native protocol with multiplication | Class-group encryption, eight owner proofs | Feldman VSS only | Feldman VSS only |
| What a threshold coalition gets | The key, for all time | The stored partial signature completes one message; the key needs the owner share | Signatures on the owner's conflicting variants. Never the key | The key, until erasure |
| One-spend limit | Policy | Cryptographic, one fixed message | Cryptographic, one family of conflicting messages | Policy |
| Who builds the transaction | Caller | Owner or contract | Owner builds variants, committee selects | Committee |
| Failure before the spend | Key stays with the committee | Presignature consumed | Coins never moved; nothing to recover | Coins never moved; nodes erase |

The Form A column follows REPORT.md sections 1 and 3 for Groth-Shoup, and the Form B column follows REPORT.md sections 1 and 2.4. Sealed mode matches Form B's cryptographic limit with far less machinery and one message, and widens it from one message to a fee grid. Open mode is Form A with the presignature work moved to the one party who can do it for free: the owner knows `x` and `k`, so the owner can share `k⁻¹` and `k⁻¹x` directly, and the committee never multiplies.

## 10. Risks and attacks considered

Attacks the design stops.

- **Related dealing.** An attacker reposts an honest `R` and ciphertexts under its own key or intent, to obtain a second signature under the same nonce and solve for `x`. Stopped: pads depend on `hd`, `π` covers everything, and the attacker cannot re-encrypt.
- **Complaint oracle.** An attacker reuses an honest `E` in a bad dealing so that a node's complaint reveals `K_i`. Stopped by the proof of knowledge of `e`, whose challenge covers the prover's commitments and the full message.
- **Nonce reuse through divergent views.** Stopped by the one-prevote rule and the `2f + 1` digest quorum for up to `f` Byzantine nodes.
- **Nonce reuse through restart.** A node restored from a snapshot could decrypt its shares again. Stopped by the durable vote log and the board replay of rule 4.
- **Double payment across generations.** Stopped by the pin: every generation spends it.
- **Raw-hash and ratio attacks on presignatures.** Nodes hash their own preimage; the remaining assumption is ratio resistance [GS22].
- **ROS-type attack on pre-published Schnorr nonces.** Stopped by two nonces and a binding factor over the whole digest.
- **Replay** across time, committees and chains. Stopped by `hd` deduplication, epoch keys, the chain id and the pin.
- **Signature reuse as authorization.** `π` is not a chain signature.

Attacks and limits the design does not stop.

- **Open mode, `t` colluding nodes steal the key** during the window. Inherent (claim 5). Mitigation only: short windows, a sweep to a fresh address, epoch key erasure.
- **Open mode, more than `f` Byzantine or rolled-back nodes** can make two honest groups sign different digests under one nonce. The result is key leakage, not just a double spend. A node that loses its vote log and ignores rule 4 counts toward this budget.
- **Sealed mode, colluding nodes release the highest-fee variant** or release before the trigger. The loss is bounded by the fee ceiling and by the intent; honoring the trigger is policy.
- **Fee and trigger manipulation.** Whoever moves the fee statistic or the trigger state moves the outcome up to the ceiling.
- **Stale pin.** If the owner spends the pin elsewhere, or a reorganization removes it, the request fails safely.
- **Residual value.** On an account chain the balance beyond the payment stays under `x`. In open mode that key was exposed to the committee, so the intent should move everything.
- **Old ciphertexts.** A compromise of `t` epoch keys before erasure opens every dealing of that epoch, including finished ones in open mode.
- **Owner device.** Open mode needs the raw key in software. A compromised device loses the key in any design.
- **Message size.** Sealed mode grows with `K·L·n`. Large input sets belong in open mode or need the compression of section 3.5.
- **Malicious owner.** Bad shares stall the owner's own request and cost nodes one verification. A posting fee bounds the spam.
- **Builder nondeterminism.** A divergence stalls requests until expiry.
- **Privacy.** Intents, variants and nonce points are public.
- **Proof status.** The Schnorr part of claim 4 and the optional compression rest on results I cite from memory. The ECDSA part rests on a theorem whose surrounding definitions I did not read. Adaptive corruption is not covered.

## 11. Experiment plan

Build in this order.

1. **Algebra and interoperability.** A library with `deal`, `verify_share`, `partial`, `verify_partial`, `combine` for the three suites and both modes. Acceptance: the outputs verify under independent verifiers (libsecp256k1 ECDSA and BIP340, an Ed25519 library with strict checks), and a signed transaction is accepted by Bitcoin regtest (P2WPKH and P2TR key path, including a tweaked key) and by an Ethereum dev chain.
2. **Sealed mode end to end** with a wallet that only signs: `K = 8` fee variants, selection against a simulated fee market, release, broadcast.
3. **Negative tests.** Two partials under one open slot must recover `x` (this confirms why rules 1 to 4 exist). A header change must make shares undecryptable. A reused `E` must fail `π`. A wrong constant term must fail the share check. A node restored from a snapshot must abstain. A generation that omits the pin must be rejected.
4. **Measurements** at `n = 16, 64, 256` with 100 ms links: message bytes against the table in section 7, owner time, node verification time with and without Pippenger, wall-clock time over a simple BFT board. Baseline: the NEAR figures in REPORT.md section 3.
5. **Builder determinism.** Two independent implementations of `Build` and `Variant`, differential fuzzing over recorded chain states, and a fault test in which one third of the nodes run a divergent builder.
6. **Committee change.** `finish` and `reshare` with a public check of the resharing chain.
7. **Proof work.** Read [GS22] in full and write the reduction of claim 4 for ECDSA against Theorem 3. Check the two-nonce Schnorr claim against the MuSig2 and FROST proofs. Attempt the proof of the multiplicative re-randomization.

What would prove the design wrong.

- A forgery or key recovery against open ECDSA that uses the base-`R` commitments together with the public `R`, beyond what [GS22, Theorem 3] allows. The simulation in claim 4 says the commitments add nothing; a counterexample breaks the design.
- A practical attack on the one-signer two-nonce Schnorr structure with many outstanding slots.
- A chain or script type where variants cannot be made to conflict, or where the sighash commits to data the owner cannot know at move time. Sealed mode does not apply there.
- Message sizes or board latency that make `n = 256` impractical on the chosen board.
- A real use case in which the owner cannot enumerate variants and also cannot accept honest-threshold policy. Then only Form B remains.

## 12. References

Read in full:

- **BRIEF.md**: read in full (`design/BRIEF.md`).
- **REPORT.md**: read in full (`research/REPORT.md`).
- **Lane file `oneshot-bootstrap-primitives.md`**: read in full (`research/lanes/oneshot-bootstrap-primitives.md`).

Not read in full. Under the brief's rule each of these counts as "from memory, not checked", and I list what I did read from the local copy:

- **[GS22]** J. Groth, V. Shoup. *On the security of ECDSA with additive key derivation and presignatures.* Version of 27 April 2022. From memory, not checked, except these passages read from `research/sources/groth-shoup-2021-1330.txt`: abstract, section 1.1 (contributions, both attacks, mitigations, Table 1 and its legend), the opening of section 7, section 7.3 (Definition 7, Theorem 3, its proof and notes), the opening of section 8 and section 8.3 (Theorem 5, its proof and notes). Not read: the EC generic group model, the game definition, Theorem 1 and its proof, sections 9 onward and the appendices. Every use of [GS22] above is limited to the passages read.
- **Chen, Zhang, Cheng.** *Budgeted Threshold Signatures.* ePrint 2026/2176. From memory, not checked, except the abstract and introduction read from `research/sources/eprint/2026-2176.pdf`. Not used for any claim.
- **Other lane files** (`committee-lifecycle-frontier.md` Q3, `owner-authorization.md` Q2 to Q5, `deployed-systems.md` closing sections, `owner-share-and-key-import.md` sections 7 and 8): those passages read, the rest not read. The `terra-*` lane directories were not read.
- **Groth-Shoup signing service paper, cgVSS, Groth NI-DKG, RFC 9591, Ika documents and source, Internet Computer IDKG spec**: from memory, not checked. Every statement about them above is taken from REPORT.md and says so.
- **Other ePrint PDFs in `sources/eprint/`** (including 2026/814, 2025/1475, 2024/253, 2025/297, 2023/451, 2025/1924): not opened. Not cited.
- From memory, not checked: Feldman, verifiable secret sharing (1987). Komlo, Goldberg, FROST (2020). Bellare, Crites, Komlo, Maller, Tessaro, Zhu, security of non-interactive threshold Schnorr (2022). Nick, Ruffing, Seurin, MuSig2 (2021). Benhamouda, Lepoint, Loss, Orrù, Raykova, on the ROS problem (2021). Wagner, generalized birthday problem (2002). Drijvers et al., on two-round multi-signatures (2019). Abdalla, Bellare, Rogaway, DHIES and the gap and oracle Diffie-Hellman assumptions (2001). Shoup, Gennaro, threshold Diffie-Hellman encryption (1998). BIP340, BIP341, BIP125. RFC 8032. EIP-1559.
