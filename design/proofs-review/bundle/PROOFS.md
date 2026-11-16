# Security proofs of line dealing

Scope: the claims of `design/SCHEME.md` section 6 that `design/PROOF-CHECK.md` left open: claim 3 (sealed points stay sealed), claim 4 (open mode, ECDSA and Schnorr), claim 6 (authorization), and the share encryption that claims 3, 4 and 6 use. Section numbers with a paragraph sign (§) refer to SCHEME.md.

The proofs change the scheme in one place and narrow two statements; section 9 lists the corrections. The change: the proof of knowledge of the ephemeral key `e` in `π` is replaced by the ephemeral-key proof of ePrint 2022/506 section 4.1, with the ciphertext hash inside the hash-to-curve input, and the authorship challenge covers the whole message. The narrowed statements: claim 3 holds in the form "no honest partial was released" (Theorem D), and the sealed part of claim 6 needs strong unforgeability (Theorem E(c)). Every theorem below is about the scheme with the corrections of section 9 applied.

## 0. Reading record

| Source | Local path | Read for this document |
|---|---|---|
| [GS21] Groth, Shoup, *On the security of ECDSA with additive key derivation and presignatures*, ePrint 2021/1330, version of 27 April 2022 | `research/sources/groth-shoup-2021-1330.pdf` | Pages 1 to 48 in full (all sections, Theorems 1 to 9, Appendices A to D). Reference list not read |
| [GS22] Groth, Shoup, *Design and analysis of a distributed ECDSA signing service*, ePrint 2022/506, version of 16 February 2023 | `research/sources/eprint/2022-506.pdf` | Section 4 in full (4, 4.1, 4.2, 4.3, 4.4; printed pages 24 to 34). Nothing else. Every statement about this paper is limited to section 4. Section 10.1.1 (adaptive corruption of the encryption) is not read and not used |
| `design/SCHEME.md`, `design/FINDINGS-LEDGER.md`, `design/PROOF-CHECK.md` | | In full |

SCHEME.md calls 2021/1330 "[GS22]". This document calls it [GS21] and keeps [GS22] for 2022/506.

**Downloads blocked.** PROOF-CHECK section 3 names five papers for the Schnorr proof. On 2026-11-13 `curl` requests to `https://eprint.iacr.org/2022/833.pdf`, `/2021/1375.pdf`, `/2020/1261.pdf` and `/2020/945.pdf` each returned HTTP 403 with a Cloudflare challenge page ("Enable JavaScript and cookies to continue"). The block was not worked around; no file was saved. The fifth paper (Bellare, Crites, Komlo, Maller, Tessaro, Zhu, CRYPTO 2022) has no ePrint number in PROOF-CHECK and was not requested. None of the five is cited below. Consequence: the Schnorr result of section 5 is proved here from first principles and is not compared with those papers. I make no statement about what they prove. The definitions of AOMDL and ICDH and the forking lemma are written out in full in section 1 so that nothing rests on an unread source.

## 1. Model, assumptions, and common lemmas

### 1.1 Execution model

- **Parties.** Honest owners with keys `X_1, …, X_{Q_o}`. One committee of `n = 3f + 1` nodes per epoch. The adversary `A` is static: before the epoch keys exist it names the corrupt set `C`, with `|C| ≤ t − 1`, of which at most `f` are Byzantine (the others leak `sk_i` and shares only, §2). Corrupt nodes register any encryption key.
- **Scheduling.** `A` chooses every honest owner's header fields (intent, window, profile), schedules the board subject to the total-order property of §2, controls the target chain's contents subject to its finality rule, and asks any owner's wallet for ordinary signatures on messages of its choice (the oracle `PlainSign`).
- **Rotation.** The theorems cover requests with `on_rotation ∈ {finish, void}`: one committee serves the request. `reshare` is not covered (section 8, item 1).
- **Messages.** For a signature suite, "message" means the byte string that the suite hashes: the sighash preimage (suite 1), the 32-byte sighash (suite 2), the transaction message (suite 3). `Auth(X)` is the set of messages `m` such that the wallet of `X` plain-signed `m`, or some honest node posted a PARTIAL for a slot or sealed point with message `m` that was dealt in a message written by the owner of `X`. A PARTIAL that an honest node posts for a message somebody else wrote under the header key `X` puts nothing into `Auth(X)`.
- **Forgery.** `A` wins the unforgeability experiment if it outputs `(X_v, m*, sig*)` with `X_v` an honest owner key, `sig*` valid for `m*` under the suite's verification rule, and `m* ∉ Auth(X_v)`.

What the cryptographic theorems do not state: that the messages in `Auth(X)` are the right ones. That is the state-machine property "an honest node signs only the digest it built from an eligible anchor, at most `G` times per request" (§3.6 to §3.9), checked in the Quint model and outside this document.

### 1.2 Assumptions

`𝔾` is the suite group of prime order `q` with generator `G`, written additively. `dh(aG, bG) := abG`.

- **AOMDL (algebraic one-more discrete logarithm), parameter `ℓ`.** The challenger gives `Y_0, …, Y_ℓ`, uniform in `𝔾`. The adversary may call `DL(α_0, …, α_ℓ, β)` at most `ℓ` times; the answer is `β + Σ α_i·log_G Y_i`. It wins if it outputs `log_G Y_i` for all `i = 0..ℓ`. `Adv^aomdl_ℓ(B)` is the winning probability. (In OMDL the oracle takes an arbitrary group element. AOMDL restricts the oracle to combinations the adversary declares, so it is the weaker assumption.)
- **ICDH (interactive CDH)** as in [GS22] p. 29: given uniform `U*, V* ∈ 𝔾`, compute `dh(U*, V*)`, with an oracle that decides whether `(A, V*, W)` is a DH triple for `A, W` of the adversary's choice. The paper states the restriction as "one of the first two entries in the triple must be `u`" and its proof calls the oracle only on triples `(·, v*, ·)`; the two forms are the same assumption with the roles of the two challenge points exchanged. `Adv^icdh(B)` is the winning probability.
- **Random oracles.** The labelled hashes of §3.1 and the new `LD1/eph` and `LD1/ephpok` (section 9, C2) are independent random oracles. `HG_eph` has range `𝔾`; `Hq_*` have range `Z_q`; `H_*` have range `{0,1}^256`. For suites 2 and 3 the suite challenge hash `H_sig` is a random oracle with range `Z_q`, independent of the labelled hashes. For suite 3 this ignores that SHA-512(`R ‖ A ‖ M`) has no tag; it is a modelling assumption.
- **Suite 1 only.** The EC generic group model of [GS21] section 2 for secp256k1 (prime order, cofactor 1, [GS21] p. 9 note 4), and four properties of the chain's sighash function `Hash`: collision resistance, random-preimage resistance, zero-preimage resistance, ratio resistance ([GS21] Definitions 3, 4, 5, 7).
- **Sealed mode only.** EUF-CMA of the suite signature scheme; Theorem 6(c) needs SUF-CMA (for ECDSA: strong unforgeability up to sign, [GS21] section 4.1.1).
- **Post keys.** EUF-CMA of the post-key signature scheme, used only in Lemma 1(b).

### 1.3 Lemma 1 (one digest per slot)

For a request served by one committee, all PARTIAL posts of honest nodes for `(rid, g)` use one digest `dg`, under either hypothesis:

(a) the board is a consistent total order. Then `LOCK(rid, g)` is by definition the first `2f + 1` PREVOTE posts from distinct nodes with identical `(a, B*, dg)`; it is unique, and §3.8 lets an honest node sign only the digest of that certificate.

(b) at most `f` nodes are Byzantine and post signatures are unforgeable, with no assumption on board consistency. Two certificates for `(rid, g)` with different digests have `2(2f + 1) − n = f + 1` voters in common, so one honest node's post key signed two PREVOTEs for `(rid, g)`. Rule 1 of §3.9 with the durable ledger (rules 3, 4) excludes that for an honest node, so one of the two posts is a forgery. Probability at most `n·Adv^euf_post`.

Status: **proved here** (counting; the Lean item "quorum intersection" formalizes the arithmetic). Limit: across a `reshare` freeze the statement needs board consistency (§5) and is not used here.

### 1.4 Lemma 2 (Feldman simulation, any base)

Let `B ≠ O` be a base point, `F` a public point, `P ⊂ {1..n}` with `|P| = t − 1`, and `v_j ∈ Z_q` for `j ∈ P`. Let `M` be the inverse of the `t × t` Vandermonde matrix `(j^u)` with rows `j ∈ {0} ∪ P` and columns `u = 0..t−1` (it exists because the points are distinct mod `q`). Define, for `u = 1..t−1`,

`C_u := M_{u,0}·F + (Σ_{j∈P} M_{u,j}·v_j)·B`.

1. `(C_u)` equals `Com_B(p)` for the unique polynomial `p` of degree at most `t − 1` with `p(0)·B = F` and `p(j) = v_j` for `j ∈ P`. Proof: the coefficients of `p` are `a_u = M_{u,0}·p(0) + Σ_j M_{u,j}·v_j`; multiply by `B`.
2. If the `v_j` are uniform and independent, `((C_u)_u, (v_j)_{j∈P})` has exactly the distribution of an honest `Share_t(v)` with `v·B = F`, restricted to the shares of `P`. Proof: for fixed `p(0)` the map from `(a_1..a_{t−1})` to `(p(j))_{j∈P}` is a bijection of `Z_q^{t−1}`.
3. For `i ∉ P`: `p(i) = λ_0(i)·p(0) + Σ_{j∈P} λ_j(i)·v_j`, with `λ` the Lagrange coefficients for the points `{0} ∪ P`.

The simulator needs `F`, `B` and the `v_j`; it does not need `p(0)`. In base `R` with `F = G` or `F = X` it uses only `G`, `X`, `R`. Throughout, `P ⊇ C` is one fixed padded set chosen at the start; the nodes of `P \ C` are honest nodes whose shares the simulator knows.

Status: **proved here.**

### 1.5 Lemma 3 (proofs used inside `π` and in complaints)

- **Schnorr proof of knowledge** of `y` with `Y = y·B`: `(T, z)` with `z·B = T + c·Y`. Simulation: pick `z, c` uniform, set `T := z·B − c·Y`, program the challenge oracle at its input to `c`. The simulated transcript has the real distribution; programming fails only if the point is already defined, probability at most `Q/q` per proof for `Q` oracle queries, since `T` is uniform.
- **DLEQ** for the statement `log_{B_1} Y_1 = log_{B_2} Y_2`: `(T_1, T_2, z)` with `z·B_1 = T_1 + c·Y_1`, `z·B_2 = T_2 + c·Y_2`. Simulation as above. Soundness is statistical: if `Y_1 = y_1·B_1`, `Y_2 = y_2·B_2` with `y_1 ≠ y_2`, and `T_1 = t_1·B_1`, `T_2 = t_2·B_2`, a valid `z` forces `c = (t_1 − t_2)/(y_2 − y_1)`, one value. A false statement is accepted with probability at most `Q/q` over `Q` challenge queries.

Status: **proved here** (standard two-line arguments).

### 1.6 Lemma 4 (forking, with fresh continuation)

Let `W` be a randomized process that receives values `h_1, h_2, …, h_Q`, each uniform in a set of size `q` and independent of everything `W` generated before its delivery, and that outputs `(J, y)` with `J ∈ {0, …, Q}`; `J = j ≥ 1` requires that `h_j` was delivered. Let `acc := Pr[J ≥ 1]`. `Fork` runs `W` once to get `(J, y)`; if `J ≥ 1` it restores the state of `W` just before the delivery of `h_J` and continues with fresh independent randomness for `h'_J`, for every later value, coin and oracle answer, to get `(J', y')`. Then

`Pr[J' = J ≥ 1 and h_J ≠ h'_J] ≥ acc²/Q − acc/q`.

Proof. Fix `j`. Let `S_j` be the state just before the delivery of `h_j` and `f_j(s) := Pr[J = j | S_j = s]`. The two continuations are independent and identically distributed given `S_j`, so `Pr[J = j and J' = j] = E[f_j(S_j)²] ≥ (E f_j(S_j))² = Pr[J = j]²` (Jensen). Given `S_j`, `h_j` is uniform and independent of the second continuation, so `Pr[J = J' = j and h_j = h'_j] ≤ Pr[J' = j]/q = Pr[J = j]/q`. Sum over `j`: `Σ_j Pr[J = j]² ≥ acc²/Q` (Cauchy-Schwarz) and `Σ_j Pr[J = j]/q = acc/q`. ∎

Restoring the state of a black-box adversary means running it again with the same coins and the same answers up to that point. An external oracle is handled by replaying cached answers for the common prefix and making new queries afterwards.

Status: **proved here.**

## 2. Share encryption with public complaint (task item 3)

### 2.1 The associated-data rule of [GS22] and why `ad = hd` fails

[GS22] section 4.1 (p. 28): the encryptor publishes `v = g^β`, the point `v' = (g')^β` with `g' = H_G(enckey-pop, ad, v)`, and a proof that `v` and `v'` have the same exponent; recipient `j` gets `c_j = m_j + H_M(derive-key, ad, id_j, u_j, v, u_j^β)`. A decryption proof reveals `w = v^α`. Theorem 2 (p. 29) proves ADO-CCA security under ICDH with `H_M`, `H_G`, `H_fs` as random oracles. The game (p. 27) allows a decryption or decryption-proof query only on associated data "not previously submitted as part of an encryption query".

Check against line dealing. A Step A decryption by node `i`, and a complaint, are decryption and decryption-proof queries. The natural associated data is `hd = H_hd(hdr, deal)`, which covers `E` and the commitments. It does not cover `ct`. An adversary can copy `hdr`, `deal`, `E`, the ephemeral-key proof, and change one scalar of `ct`. The copy has the `ad` of an honest encryption, so the rule of p. 27 is violated, and the violation is a real attack: node `i` fails its share check and its complaint publishes `K_i = sk_i·E`, which opens the honest ciphertext of node `i`. In SCHEME.md only the authorship half of `π` (knowledge of `x`) stops this copy, which would make the encryption proof depend on claim 6 and claim 6 depend on the encryption proof.

The proof of Theorem 2 uses the rule in one place (p. 30 to 31): a decryption query must hit `H_G` at an input that was programmed as an adversarial query, `g' = u*·g^λ`, and not as an encryption query, `g' = g^ρ`. The input of `H_G` is `(ad, v)`. So the property needed is: **the `H_G` input of every adversarial message differs from the `H_G` input of every honest message, unless the adversarial message carries the honest ciphertexts unchanged.** Putting the ciphertext hash into the `H_G` input gives exactly that. The pads cannot take the same input (the ciphertexts depend on the pads); [GS22] p. 32 note 1 says the associated data inside `H_M` is not needed for the scheme of section 4.1. The construction below therefore uses `hd` in the pad and `(hd, SHA-256(ct), E)` in `H_G`. Theorem 2 of [GS22] does not cover it as a black box, because its syntax has one `ad`; Theorem C below repeats its game sequence with the two inputs.

### 2.2 Construction (replaces the proof of knowledge of `e` in §3.2)

```
g'    = HG_eph(hd ‖ SHA-256(ct) ‖ E)                  hash to the suite group, label LD1/eph
E'    = e·g'
T_1   = a·G,  T_2 = a·g'                              a random
c_e   = Hq_ephpok(hd ‖ SHA-256(ct) ‖ E ‖ E' ‖ T_1 ‖ T_2)
z_e   = a + c_e·e
check: z_e·G = T_1 + c_e·E   and   z_e·g' = T_2 + c_e·E'
```

Pads are unchanged: `Hq_enc(hd, i, PK_i, K_i, slot)`, `K_i = e·PK_i = sk_i·E`. The complaint is unchanged: `K_i` with `DLEQ(G, PK_i; E, K_i)`. A node computes `K_i` for a message only after the public check of `(E', T_1, T_2, z_e)` passed (§3.4 check 9 precedes the private check).

### 2.3 Theorem C (honest pads are random)

Let `Exp` be any experiment of section 1.1 (any suite, any mode, with honest reshare dealers treated as honest dealers). Let `Exp'` be the same experiment with two changes: (i) for every honest dealer's message and every honest node `i`, each ciphertext scalar is uniform and independent of everything else, and node `i` uses its dealt share directly when it processes that message with the ciphertexts unchanged; (ii) the experiment aborts if a message that is not identical in `(hd, ct)` to an honest dealer's message, but carries an honest dealer's `E`, passes the ephemeral-key check. Then for every adversary `A` there is an ICDH adversary `B_C`, with the running time of `A` plus one DH-oracle call per `Hq_enc` query, such that

`|Pr[Exp ⇒ 1] − Pr[Exp' ⇒ 1]| ≤ Adv^icdh(B_C) + δ_C`,
`δ_C = (Q_eph·Q_msg + 2·Q_ephpok + Q_dleq·Q_cmp + Q_pop·n + Q_ephpok·Q_msg + Q_msg²)/q + Q_H²/2^256`,

where `Q_msg` is the number of honest dealer messages, `Q_cmp` the number of honest complaints, `Q_eph, Q_ephpok, Q_dleq, Q_pop` the numbers of queries to those oracles, and `Q_H` the number of queries to `H_hd` and SHA-256.

Proof. Games in the order of [GS22] p. 31. `U*, V*` are the ICDH challenge points.

- **Game 0** is `Exp`. Abort if two different inputs of `H_hd` or of SHA-256 collide (`Q_H²/2^256`). From here `(hd, SHA-256(ct))` determines `(hdr, deal, ct)`.
- **Game 1** (programming, logs still known). Honest node keys are `PK_i = U* + σ_i·G` with `σ_i` uniform. A new adversarial query to `HG_eph` is answered `U* + λ·G`, `λ` uniform. An honest dealer's message uses `E = V* + τ·G`, `τ` uniform, and `HG_eph(hd ‖ SHA-256(ct) ‖ E) := ρ·G`, `ρ` uniform, so `E' = ρ·E`. All values keep their distributions. Programming fails if the adversary queried that input before `E` existed: at most `Q_eph·Q_msg/q`.
- **Game 2.** Honest complaints use simulated DLEQ proofs, and the key-registration proofs of honest nodes (`LD1/pop`, a Schnorr proof of knowledge of `sk_i`) are simulated (Lemma 3): at most `(Q_dleq·Q_cmp + Q_pop·n)/q`. The security argument does not use the registration proofs of corrupt nodes ([GS22] p. 24 needs no proof of possession); the hop is needed only because honest nodes publish one.
- **Game 3.** For a message with an adversarial `HG_eph` input (programmed as `U* + λ·G`) that passes the ephemeral-key check, honest node `i` computes `K_i := E' + (σ_i − λ)·E`. If the DLEQ statement is true, `E' = dh(U* + λG, E) = dh(U*, E) + λE`, so `E' + (σ_i − λ)E = dh(U* + σ_i G, E) = sk_i·E`, the same value. The statement is false and accepted with probability at most `Q_ephpok/q` (Lemma 3, soundness; honest proofs are still real proofs in this game, so plain soundness suffices, as [GS22] p. 31 remarks).
- **Game 4.** Honest dealers' ephemeral-key proofs are simulated: at most `Q_ephpok·Q_msg/q`.
- **Game 5.** Ciphertext scalars for corrupt recipients of an honest message are uniform. When the adversary queries `Hq_enc(hd, j, PK_j, K, slot)` for that message and corrupt `j`, the game asks a DH oracle whether `(PK_j, V*, K − τ·PK_j)` is a DH triple, and if so answers `ct − share`. The triple has the form `(·, V*, ·)`. Identical distribution. (The game still knows the logs and could answer the oracle itself.)
- **Game 6.** Two changes at once. Ciphertext scalars for honest recipients of an honest message are uniform and independent, and an honest node that processes an honest message with `(hd, ct)` unchanged uses its dealt share without decrypting (in Game 5 the decryption gives that share, so this part changes nothing). And the game aborts on the event `Reuse` of change (ii). Games 5 and 6 proceed identically until the first of two events:
  - `Reuse`: a message with an honest `E = V* + τG` and an `HG_eph` input different from the honest one, hence adversarial, `g' = U* + λG`, passes the ephemeral-key check. Unless soundness fails (`Q_ephpok/q`), its `E'` equals `dh(U* + λG, V* + τG)`, so `E' − τ·U* − λ·E = dh(U*, V*)`.
  - `Query`: the adversary queries `Hq_enc(hd, i, PK_i, K, slot)` with `K = dh(PK_i, E)` for an honest `i` and an honest message. Then `K − τ·U* − σ_i·V* − σ_i τ·G = dh(U*, V*)`.

  Why identical until then: before either event, the pad of an honest recipient in an honest message is evaluated only to build the ciphertext. An honest node computes `K_i` in three cases. (1) The message is an honest dealer's with `(hd, ct)` unchanged: no decryption, the node posts ACK and uses the share. (2) The message has an adversarial `E`: Game 3 gives `K_i`, and its pad inputs contain another `hd` and another `K_i`. (3) The message has an honest `E` and other `(hd, ct)`: if it passes the check, that is `Reuse`; if not, the node computes nothing.

  `B_C` gets `U*, V*` and runs Game 6 without the logs: keys and `HG_eph` as in Game 1, `K_i` for adversarial messages as in Game 3, simulated proofs (registration, complaint, ephemeral key), backpatching with its DH oracle, uniform scalars for honest recipients. It watches for `Reuse` (it outputs `E' − τ·U* − λ·E`) and tests every `Hq_enc` query for `Query` with its oracle on `(U*, V*, K − τ·U* − σ_i·V* − σ_i τ·G)`, a triple with `V*` among its first two entries (it outputs the third entry on success). So `Pr[Reuse or Query] ≤ Adv^icdh(B_C) + Q_ephpok/q`.

Game 6 is `Exp'` (with keys generated as in Game 1, which changes no distribution; two honest messages share `E` with probability at most `Q_msg²/q`). ∎

**Status: proved here, following the game sequence of [GS22] Theorem 2, p. 29 to 32.** It is not a black-box use of that theorem, for the reason in 2.1. The differences from the paper's proof: two hash inputs instead of one `ad`; the `Reuse` event; scalar pads; the decryption result leaves a node only as an ACK or a complaint. Limits: static corruption; ICDH and three random oracles; no proof of possession is needed (as in [GS22] p. 24). A proof of delivery inside the message is still absent (§8 gap 1).

After Theorem C an outer reduction generates the honest node keys itself, decrypts adversarial messages normally, and sends uniform scalars to honest nodes in honest messages.

## 3. Open ECDSA (task item 1; claim 4 for suite 1)

### 3.1 The target game

[GS21] Figure 4 (p. 22), in the notation of SCHEME.md: the challenger holds `x ∈ Z_q*` and gives `G, X`. A presignature request returns `R_k = k_k·G` with `r_k = C̄(R_k) ≠ 0`. A signing request names an unused index `k` and a message `m_k`; the challenger computes `h_k = Hash(m_k)` itself and returns `(s_k, r_k)` with `s_k = k_k⁻¹(h_k + r_k·x)`, or `fail` if `h_k + r_k·x = 0`. Each index is used at most once ([GS21] p. 21). The adversary wins with a valid signature on a message it did not submit. `U` is the largest number of unused presignatures at one time, `N` the number of presignature, signing and group queries.

Dictionary: [GS21] `(d, D, r_k, R_k, t_k, h_k, s_k)` is SCHEME.md `(x, X, k, R, r, sighash, s)`. The dealt constants are `w = k⁻¹` and `μ = k⁻¹x`, so `s = h·w + r·μ`.

**[GS21] Theorem 3 (p. 24).** For `A` making at most `N` queries there are adversaries with the running time of `A` plus `O(U·N)` such that

`CMA^ggm_ps adv[A] ≤ CRadv + (4 + o(1))·N·RPRadv + (4 + o(1))·N·RRadv + U·N·RPRadv + ZPRadv + O(N²/q)`.

It also gives strong unforgeability up to sign (p. 26 note 4). Call the right side `Φ_3(N, U)`.

### 3.2 Theorem A (open ECDSA is unforgeable below `t` with at most `f` Byzantine nodes)

Suite 1, the model of 1.1, the assumptions of 1.2, and the hypothesis:

(H-key) no key related to `x` by a known additive offset signs anything. (For BIP32 keys see 3.4.)

Let `A` make `N_A` group-oracle queries. Let `S` be the number of open ECDSA slots dealt by honest owners, `U` the largest number of slots of one key that are *live* at one time (dealt, not signed, request not tombstoned, and not past `exp` without a lock for the slot's generation), and `N_sim` the number of group operations that the honest parties and the final verification perform, plus `4(t − 1)` two-term multi-scalar multiplications per slot (a scalar multiplication of a point other than `G` costs at most `2·log_2 q` `add` queries). Then

`Adv^open-ecdsa(A) ≤ ε_lock + Adv^icdh(B_C) + δ_C + δ_A + Q_o·Φ_3(N_A + N_sim + 3S + 2Q_w, U + 1)`,

with `ε_lock = 0` on a consistent board and `n·Adv^euf_post` otherwise (Lemma 1), `δ_C` from Theorem C, `Q_w` the number of wallet signatures, and `δ_A = (Q_auth·S_msg + S² + 2S)/q + (S + Q_w)/2^256` (`S_msg` honest messages). The hash adversaries inside `Φ_3` run in the time of `A` plus the simulation plus `O(U·N)`. The ICDH adversaries are generic-group adversaries for the same curve; their advantage is an assumption here and is not bounded by [GS21].

Proof.

- **Game 0**: the real experiment.
- **Game 1**: abort if honest nodes post PARTIALs for two digests of one `(rid, g)`. Lemma 1: `ε_lock`. From here each slot is signed by honest nodes on one message, fixed by the lock certificate.
- **Game 2**: `Exp'` of Theorem C. Honest ciphertext scalars for honest nodes are uniform.
- **Game 3**: the authorship half of `π` in honest messages is simulated (Lemma 3): pick `z_a, c`, set `T_a = z_a·G − c·X`, program `Hq_auth`. Loss `Q_auth·S_msg/q`. The ephemeral-key part is still computed with `e`.
- **Game 4**: guess the owner `v` whose key the forgery will name. Factor `Q_o`.

**Reduction `B`** to the game of 3.1, simulating Game 4. `B` gets `(G, D)`, sets `X_v := D`, and generates all other owner keys, all honest node keys and all random oracles itself.

1. *Dealing a slot of `X_v`.* `B` requests a presignature `R`. If `x(R) ≥ q`, or its x-coordinate repeats one in the same message (§3.4 checks 6, 7; the honest owner resamples in these cases), `B` closes the index (step 5) and requests another. This reproduces the owner's rejection sampling. `B` picks `w_j, μ_j` uniform for `j ∈ P` and computes by Lemma 2 in base `R`:
   `C_{w,u} = M_{u,0}·G + (Σ_j M_{u,j} w_j)·R`, `C_{μ,u} = M_{u,0}·X + (Σ_j M_{u,j} μ_j)·R`.
   These are `Com_R(p_w)`, `Com_R(p_μ)` for polynomials with `p_w(0)·R = G`, `p_μ(0)·R = X`, that is `p_w(0) = k⁻¹`, `p_μ(0) = k⁻¹x`, and the shares of `P` are distributed as in an honest dealing (Lemma 2, part 2). `B` uses only `G`, `X`, `R` and group-oracle queries.
2. *Ciphertexts and `π`.* `B` picks `e`, so it computes `K_i = e·PK_i` and the true ciphertexts for `i ∈ C`, the uniform scalars of Game 2 for honest `i`, and `E'`, `T_1`, `T_2`, `z_e` honestly. The authorship proof is the simulation of Game 3.
3. *Honest nodes.* `B` runs them as specified. For an adversarial message they decrypt with their own keys; every value they then hold was supplied by the adversary. For an honest message they hold the shares of `P \ C` and nothing else.
4. *Partials.* When the first honest node must post a PARTIAL for slot `k` with sighash preimage `m`, `B` sends the signing request `(k, m)` and gets `s` (or `fail`, then `s := 0`; §3.8 kills the generation). With `h = Hash(m)` and `r = C̄(R)`, the polynomial `p_s = h·p_w + r·p_μ` has `p_s(0) = s` and `p_s(j) = h·w_j + r·μ_j`. By Lemma 2 part 3, honest node `i` posts `s_i = λ_0(i)·s + Σ_{j∈P} λ_j(i)(h·w_j + r·μ_j)` (directly `h·w_i + r·μ_i` if `i ∈ P`). This is the value the real node posts. By Game 1 every honest PARTIAL for slot `k` uses the same `m`, so one signing request per index suffices, as the game demands ([GS21] p. 21; PROOF-CHECK section 2 condition 2).
5. *Closing a slot.* When a slot stops being live without a signature (tombstone, or `exp` passed with no lock for its generation, after which no honest node holds or uses its shares, §3.9 rule 5 and §3.10), `B` sends the signing request `(k, ζ)` for a fresh uniform 256-bit string `ζ` and discards the answer. The game allows any message, so this is a legal move; it removes `k` from the set of unused presignatures. `A` never sees anything that depends on `ζ`.
6. *Wallet signatures* of `X_v` on `m`: a presignature request followed at once by the signing request `(k, m)`; `B` returns the normalized signature. Seeing `R` first only adds power to the adversary of the game. Each such pair is outstanding for one step, hence `U + 1`.
7. *Output.* When `A` outputs `(X_v, m*, (r*, s*))`, `B` outputs `(m*, (s*, r*))`.

The view of `A` in the reduction is the view in Game 4 except when two slots of one message collide in x-coordinate across retries or a presignature fails `r = 0` (`(S² + 2S)/q`). If `m* ∉ Auth(X_v)`, then `B` did not submit `m*` in steps 4 and 6, and `m*` equals a closing string with probability at most `(S + Q_w)/2^256`. So `B` wins whenever `A` does, up to these terms. `B` makes `N_A + N_sim` group queries and at most `3S + 2Q_w` presignature and signing requests (retries are negligible and counted in `δ_A`), and never has more than `U + 1` unused indices. Theorem 3 of [GS21] gives the bound. ∎

**Status: reduced to [GS21] Theorem 3, p. 24, with the hops proved here.** The hop to the game is black-box and uses no rewinding.

### 3.3 Conditions and limits of Theorem A

1. **EC-GGM only** ([GS21] p. 9). No standard-model or random-oracle-only statement exists for this cell of [GS21] Table 1 (p. 7).
2. **Four hash properties on the real sighash**, including zero-preimage resistance ([GS21] Definition 4; Theorem 3 lists `ZPRadv`). "Ratio resistance is essential" (p. 26 note 2): nothing in the protocol stops the ratio attack; it is assumed infeasible, with a birthday bound if the sighash is a random oracle (p. 23).
3. **The `U·N` terms.** `U·N·RPRadv` in the bound and `O(U·N)` in the running time of the hash adversaries. `U` counts live slots of one key, by step 5. Step 5 is a device of this proof; [GS21] does not mention it, and it is sound because the game of Figure 4 accepts any message in a signing request.
4. **Nodes hash their own preimage.** `B` can only submit a message, never a hash ([GS21] Figure 4 step 5(b)); a node that signed a hash supplied by another party would be outside the theorem, and p. 26 note 1 gives the forgery.
5. **One signing request per presignature** rests on Lemma 1, so on board consistency or on at most `f` Byzantine nodes with unforgeable post keys. With more than `f` Byzantine nodes in profile T2, two digests on one slot give `x` (ledger D7a).
6. **Static corruption**, `|C| ≤ t − 1`. The simulation fixes `P` before the dealing; it does not survive an adaptive choice of `C`.
7. **The base-`R` commitments add nothing.** They are group elements that `B` computes from `G`, `X`, `R` with coefficients independent of `x` and `k`, inside the game. This answers the first "the design is wrong if" item of §11 in the negative, under conditions 1 to 6.
8. **`reshare`** is not covered.
9. **Mixed model** (PROOF-CHECK section 2 condition 6). The sighash is a concrete function with the four properties of item 2; the group is generic; the labelled hashes of §3.1 are random oracles that `B` simulates and programs. `B` is an ordinary adversary of the game of Figure 4, so Theorem 3 applies to it as stated, but the statement "the labelled hashes are random oracles independent of the group encoding and of the sighash" is a modelling assumption that neither paper analyses.

### 3.4 BIP32-derived keys: [GS21] Theorem 4

If the wallet of `X` also signs under keys `X + δ·G` with `δ` known to the adversary (BIP32 non-hardened siblings, or the parent, with a public chain code), hypothesis (H-key) fails: `B` cannot produce those signatures from the game of 3.1. The governing game is ECDSA with additive key derivation and presignatures ([GS21] section 7.4): master key `D`, a tweak set `E ⊆ Z_q` fixed in advance, signing requests `(k, m_k, e_k)`, forgery on a fresh pair `(m*, e*)`.

**Corollary A'.** Let `D` be the wallet's master public key for the relevant chain code and let `E` contain the tweak `e_X` of the dealt address and the tweak of every sibling key that signs. Then Theorem A holds with `Φ_3` replaced by the bound of [GS21] Theorem 4 (p. 27):

`Φ_4 = CRadv + (4+o(1))·N_psig·4sum1adv[E] + (4+o(1))·N·|E|·RPRadv + (4+o(1))·N·4sum2adv[E] + U·N·|E|·RPRadv + ZPRadv + O(N²/q)`.

Proof: the same `B`, with `X_v = D + e_X·G`, slot and closing requests under the tweak `e_X`, and a sibling's wallet signature as a presignature request followed by a signing request under that sibling's tweak. The simulation of the commitments uses `X_v` as a public point, as before. ∎

**Status: reduced to [GS21] Theorem 4, p. 27.** Limits. (i) The bound has the terms `4sum1`, `4sum2` and the factor `|E|`, so it is weaker than `Φ_3`; with `|E|` near `q^{1/3}` the paper gives a forgery in time `q^{1/3}` (pp. 4, 28). (ii) That attack lets the adversary choose the signing tweak after it sees `R`. In line dealing the tweak of a slot is fixed to `e_X` and sibling signatures do not publish `R` in advance, so the bound is not tight for this use. A tighter theorem for "presignatures under one fixed tweak, ordinary signatures under the others" is **open**: [GS21] does not state it and it is not proved here. (iii) Hardened children are not treated in [GS21] (p. 3). Treating a hardened child key as an independent uniform key, which puts it under Theorem A, is a modelling assumption of this document.

## 4. Open Schnorr: the single-signer two-nonce game (task item 2)

### 4.1 Game TNS (two-nonce Schnorr, one signer, pre-published nonces)

Parameters: suite group `𝔾`; the suite challenge oracle `H_sig`; the sign rule `σ(R) ∈ {1, −1}` (suite 2: `−1` iff `R` has odd y; suite 3: always 1); random oracles `H_dg` (range `{0,1}^256`), `H_b` and `H_auth` (range `Z_q`); a fixed efficient function `msg(j, M)` that reads the message of slot `j` out of a digest preimage `M` (in the protocol: `M` is the input of `LD1/dg` and `msg` returns `m_ℓ` for the slot `(hd, g, ℓ)`, or ⊥ if `ℓ > L'`).

1. **Key.** `x ← Z_q*`, `X = x·G` (suite 2: `x` is negated if needed so that `X` has even y). The adversary gets `X`.
2. **`NewSlot()`.** `j ← j + 1`; `d_j, e_j ← Z_q*`; return `(D_j, E_j) = (d_j·G, e_j·G)`. At most `U` calls.
3. **`H_b(j, dg)`** returns ⊥ if slot `j` does not exist yet.
4. **`Sign(j, M)`**, at most once per `j`. If `msg(j, M) = ⊥` return ⊥. Else `dg = H_dg(M)`, `ρ = H_b(j, dg)`, `m = msg(j, M)`, `R = D_j + ρ·E_j`; if `R = O` return ⊥; `c = H_sig(σ(R)·R, X, m)`; return `s = σ(R)·(d_j + ρ·e_j) + c·x`. (Then `s·G = σ(R)·R + c·X`.)
5. **`PlainSign(m)`**: an ordinary suite signature on `m` with a fresh nonce.
6. **`Prove(ctx)`**: `a ← Z_q`, `T = a·G`, `c = H_auth(ctx, T)`, return `(T, a + c·x)`.
7. **Winning.** The adversary outputs one of:
   - a *signature forgery* `(m*, sig*)`: `sig*` verifies for `m*` under `X` and `m*` was neither the message of a `Sign` query nor a `PlainSign` query. Verification, as an equation in the prime-order group: suite 2, `sig* = (r*, s*)`, `s*·G = lift_x(r*) + c*·X`, `c* = H_sig(r*, X, m*)`; suite 3, `sig* = (R*, s*)`, `8·s*·G = 8·R* + 8·c*·X`, `c* = H_sig(R*, X, m*)` (the cofactored equation, which every signature valid under the cofactorless equation also satisfies).
   - a *proof forgery* `(ctx*, T*, z*)`: `z*·G = T* + H_auth(ctx*, T*)·X` and `(ctx*, T*)` was not the context and commitment of a `Prove` answer.

`Adv^tns(A)` is the winning probability. The inputs of `H_sig` are encodings: for suite 2 the pair `(R, X)` enters as x-coordinates, so `R` and `−R` give the same input; `σ(R)·R` is the even-y representative.

How the protocol maps to the game: `X` is the owner key; a slot is `(hd, g, ℓ)` with `(D_j, E_j) = (D, E')` of §3.3; `H_b(j, dg)` is `Hq_bind(hd, g, ℓ, dg)`; `Sign` returns `s(0)` of the partial-signature polynomial of §3.8; `Prove` is the authorship half of `π` with `ctx` = every input of `Hq_auth` except `T_a`.

### 4.2 Theorem B (TNS is hard under AOMDL)

Let `A` make at most `U` `NewSlot` calls, `Q_dg, Q_b, Q_sig, Q_auth` oracle queries, `Q_ps` `PlainSign` and `Q_pr` `Prove` queries. Let `Q := Q_sig + Q_auth + Q_b + U + 1`. There is an adversary `B` against AOMDL with parameter `2U`, running `A` twice, with

`Adv^aomdl_{2U}(B) ≥ acc²/Q − acc/q − 2(Q_b + U)²/q`, where `acc ≥ Adv^tns(A) − δ_B`,
`δ_B = (Q_dg² + Q_dg·Q_b)/2^256 + (2·Q_b·(Q_sig + Q_b + Q_ps) + (Q_ps + Q_pr)·(Q_sig + Q_auth + Q_b + Q_ps + Q_pr) + 2U + 1)/q`.

So `Adv^tns(A) ≤ δ_B + Q/q + sqrt(Q·(Adv^aomdl_{2U}(B) + 2(Q_b + U)²/q))`.

Proof.

**Process `W`.** Input: points `Y_0, …, Y_{2U}` and the oracle `DL`. `W` sets `X := ±Y_0` (sign chosen for even y in suite 2), `D_j := Y_{2j−1}`, `E_j := Y_{2j}`, and runs `A`. If some `Y_i = O`, `W` stops with `J = 0` (`(2U + 1)/q`). The values `h_1, h_2, …` of Lemma 4 are the challenges `c` that `W` assigns as follows; everything else is `W`'s own coins.

- `H_dg(M)`: lazy uniform value. Stop (`J = 0`) on a collision between two inputs (`Coll`, at most `Q_dg²/2^256`), or if the new value equals the `dg` of an earlier `H_b` query that was *unresolved* (below) (`Late`, at most `Q_dg·Q_b/2^256`).
- `H_b(j, dg)`, new input, slot `j` exists: draw `ρ` uniform (a coin). Look for `M` with `H_dg(M) = dg` in the table. If there is none, or `msg(j, M) = ⊥`, mark `(j, dg)` unresolved and return `ρ`. Otherwise let `m = msg(j, M)`, `R = D_j + ρ·E_j`; if `R = O` mark the pair dead and return `ρ`. Else let `R~ = σ(R)·R`. If `H_sig(R~, X, m)` is already defined, stop (`Pre`). Otherwise take the next value `h_i` and set `H_sig(R~, X, m) := h_i`; the pair `(j, dg)` is *resolved* with `(ρ, c = h_i)`. Return `ρ`.
  `Pr[Pre]`: `ρ` is uniform and independent of the earlier `H_sig` inputs, and `D_j + ρ·E_j = ±P` has at most two solutions `ρ` for each earlier point `P`; at most `2·Q_b·(Q_sig + Q_b + Q_ps)/q` in total.
- `H_sig(·)` and `H_auth(·)`, new input queried by `A`: the next `h_i`.
- `PlainSign(m)`: pick `z, c` (coins), `R = z·G − c·X`; in suite 2, if `R` has odd y, replace `(z, c)` by `(−z, −c)`, which replaces `R` by `−R` and keeps `c` uniform. Program `H_sig(R, X, m) := c` and return `(R, z)`. A wallet with deterministic nonces is covered by answering a repeated `m` from a table. `Prove(ctx)`: pick `z, c`, `T = z·G − c·X`, program `H_auth(ctx, T) := c`. Stop if the input is defined (at most `(Q_ps + Q_pr)(Q_sig + Q_auth + Q_b + Q_ps + Q_pr)/q` in total).
- `Sign(j, M)`: if `msg(j, M) = ⊥` return ⊥. Query `H_dg(M)` and then `H_b(j, dg)` internally if they are new. The pair `(j, dg)` is now resolved or dead: it cannot be unresolved, because an unresolved pair whose `dg` later becomes the hash of some `M` is the event `Late`, and if `M` was in the table when `H_b(j, dg)` was first queried the pair was resolved then. Dead: return ⊥. Resolved with `(ρ, c)`: one oracle call
  `s := DL(coefficients of R~ + c·X) = σ(R)·(d_j + ρ·e_j) + c·x`,
  with coefficient `σ(R)` on `Y_{2j−1}`, `σ(R)·ρ` on `Y_{2j}`, `±c` on `Y_0`. Return `s`.
- Output of `A`. Signature forgery: `W` makes sure `H_sig` is defined at the forgery's input (one more `h_i` if not) and outputs `J` = the index of the `h` value stored there. The input is not one programmed by `PlainSign`, because `m*` was not plain-signed. Proof forgery: the same with `H_auth` and `(ctx*, T*)`, which no `Prove` answer programmed. If the forgery is invalid, `J = 0`.

Unless `W` stops, `A` sees exactly game TNS: every oracle value is uniform and assigned once; `Sign` returns the game's value; `PlainSign` and `Prove` are the perfect simulations of Lemma 3; `d_j, e_j ≠ 0` and `x ≠ 0` hold except with probability `(2U + 1)/q`. Hence `acc ≥ Adv^tns(A) − δ_B`. At most `Q` values `h_i` are delivered.

The step that defeats the ROS-type search is in `H_b`: the challenge `c` of a slot and a digest is fixed in the same step as `ρ`, before the adversary sees `ρ`, so `(R, c)` for the pair `(j, dg)` never changes afterwards.

**`B`** runs `Fork` on `W` (Lemma 4), caching `DL` answers: a repeated coefficient vector costs no new call. Suppose `J' = J ≥ 1` and `h_J ≠ h'_J`.

*Extraction of `x`.* The two runs are identical up to the delivery of `h_J`. The oracle input that receives value number `J` is fixed before the delivery, so it is the same in both runs: the same `(R~*, X, m*)`, or the same `(ctx*, T*)`. In the signature case both runs give a valid forgery at that input: `s*·G = R_0 + c*·X` and `s'*·G = R_0 + c'*·X` with the same prime-order point `R_0` (suite 2: `R_0 = lift_x(r*)`. Suite 3: write `R* = R_0 + T` with `T` of order dividing 8; the cofactored equation gives `8(s*·G − R_0 − c*·X) = O` in the prime-order subgroup, hence `s*·G = R_0 + c*·X`; a torsion component in a forged `R*` changes nothing, because the encoding of `R*` is part of the fixed hash input). So `x = (s* − s'*)/(c* − c'*)`. The proof case is the same with `T*` and `z*`.

*No signed pair sits at the fork.* If value `J` was assigned inside an `H_b` query for a pair `(j, dg)`, then `m* = msg(j, M)` for that pair. Had either run signed that pair, `m*` would be the message of a `Sign` query in that run and the forgery of that run would be invalid. So in both runs every signed pair has its challenge index different from `J`.

*Slot accounting.* Fix a slot `j`. Each run signs it at most once. A signed pair costs one `DL` call and gives one equation `d_j + ρ·e_j = σ·(s − c·x)` with known `ρ, σ, s, c` once `x` is known.

| Case for slot `j` | `DL` calls on signing | What `B` knows, what it adds |
|---|---|---|
| signed in neither run | 0 | `B` calls `DL` on `D_j` and on `E_j`: 2 calls |
| signed in one run only; or in both runs on the same pair `(j, dg)` resolved before the fork (same `ρ`, same `c`, same coefficient vector, cached) | 1 | one equation; `B` calls `DL` on `E_j` and solves for `d_j`: 2 calls in all |
| signed in both runs on pairs with different `ρ`: two different pairs resolved before the fork, or one before and one after, or both after | 2 | two equations with `ρ_1 ≠ ρ_2`: solve for `d_j, e_j` |
| a dead pair (`R = O`) in a run | 0 for that run | the relation `d_j = −ρ·e_j`; treated as an equation at no cost |

A pair resolved before the fork has the same `(ρ, c)` in both runs, since both of its values precede `h_J` (its challenge index is not `J` by the previous paragraph, and `ρ` is drawn just before its challenge). Two pairs have equal `ρ` only if two independent uniform draws coincide: all draws of one run plus the post-fork draws of the other are at most `2(Q_b + U)`, so this fails with probability at most `2(Q_b + U)²/q`.

In every case `B` spends at most 2 `DL` calls per slot, `2U` in all, every call is on a declared combination of the challenge points (so the reduction is algebraic), and `B` outputs `x` (hence `log Y_0`) and all `d_j, e_j`: `2U + 1` logarithms. Lemma 4 gives the bound. ∎

**Status: proved here.** Assumption: AOMDL with parameter `2U`, where `U` is the total number of open Schnorr slots ever dealt under `X` (not the number live at one time), plus the random oracles of 4.1. The reduction forks once and loses a square root. Not compared with the unobtained papers (section 0). Covered: the BIP340 sign flip (through `σ` and the x-only hash input), the Ed25519 challenge and cofactor (above), ordinary wallet signatures under the same key, and the authorship proof under the same key.

Why two nonces: with one nonce per slot, `R = D_j` is known before the message, the `H_b` step does not exist, and `W` cannot fix `c` before the adversary chooses among messages; PROOF-CHECK section 3 records the ROS-type attack for that case from the local FROST and Sparkle+ papers.

### 4.3 Theorem B' (claim 4 for suites 2 and 3)

Suites 2 and 3, the model of 1.1. With `S` the number of open Schnorr slots dealt by honest owners under the target key and the other symbols as in Theorem A,

`Adv^open-schnorr(A) ≤ ε_lock + Adv^icdh(B_C) + δ_C + Q_H²/2^256 + 2S²/q + Q_o·Adv^tns(A')`,

where `A'` makes `S` `NewSlot` calls, at most one `Sign` query per slot, `Q_w` `PlainSign` queries and one `Prove` query per honest message, and Theorem B bounds `Adv^tns(A')`.

Proof. Games 1, 2 and 4 of Theorem A (Lemma 1, Theorem C, the guess of the owner). `A'` plays TNS for `X_v` and generates everything else.

- *Dealing.* For a message with slots `j` (from `NewSlot`; two slot points of one message share an x-coordinate, the case in which the owner of §3.4 check 7 resamples, with probability at most `2S²/q`), `A'` picks `x_j', d_{j,j'}, e_{j,j'}` uniform for `j' ∈ P` and computes `Com_G(p_x)`, `Com_G(p_d)`, `Com_G(p_e)` by Lemma 2 with `F = X`, `D_j`, `E_j` and base `G`. Each message has its own polynomial for `x`, as in §3.3.
- *Ciphertexts and `π`.* As in Theorem A step 2; the authorship proof is the answer of `Prove(ctx)` with `ctx = (hd, SHA-256(ct), E', T_1, T_2, z_e)`.
- *Oracles.* `Hq_bind(hd, g, ℓ, dg)` for the `hd` of an honest message of `X_v` is `H_b(j, dg)` with `j` the slot of `(hd, g, ℓ)`; for any other `hd` it is `A'`'s own random function. The map is well defined unless two messages share `hd` or `A` queried an `hd` before the message existed (`Q_H²/2^256`). `LD1/dg` is `H_dg`, `Hq_auth` is `H_auth`, the suite hash is `H_sig`.
- *Honest nodes on messages the owner did not write.* They decrypt with their own keys and compute partials from the values they hold; every such value was supplied by the adversary, and `A'` makes no `Sign` query for them. This is why `Auth` counts owner-written messages only and why the theorem does not use claim 6.
- *Partials.* When the first honest node must post a PARTIAL for slot `j` of an owner-written message under the locked digest with preimage `M`, `A'` calls `Sign(j, M)` and gets `s` (⊥: the generation is dead, §3.8). The partial polynomial is `p_s = σ·(p_d + ρ·p_e) + c·p_x` with `p_s(0) = s`, and honest node `i` posts `λ_0(i)·s + Σ_{j'∈P} λ_{j'}(i)·(σ·(d_{j,j'} + ρ·e_{j,j'}) + c·x_{j'})`. One `Sign` query per slot by Game 1.
- *Output.* A forgery `(X_v, m*, sig*)` with `m* ∉ Auth(X_v)` is a signature forgery in TNS. ∎

**Status: reduced to Theorem B (proved here).** Limits: static corruption; `|C| ≤ t − 1`; at most `f` Byzantine nodes or a consistent board (Lemma 1); `reshare` not covered. Two digests on one slot do not give `x` for this suite (ledger D7(b2)); three do.

## 5. Sealed points stay sealed below `t` (claim 3)

**Theorem D.** Any suite, sealed mode, the model of 1.1 with `|C| ≤ t − 1` and any number of Byzantine nodes among `C`. Let `Q_pt` be the number of sealed points dealt by honest owners. Then

`Adv^sealed(A) ≤ Adv^icdh(B_C) + δ_C + Q_auth·S_msg/q + Q_o·Q_pt·Adv^euf-cma_suite(B_3)`.

Recall that `A` wins with a valid signature on a message outside `Auth(X_v)`: a message for which no honest node released a partial of any sealed point and which the wallet did not sign.

Proof. Game 1: `Exp'` of Theorem C. Game 2: guess the owner `v` and one sealed point `(j*, ℓ*)` of one of its messages; the guess is right if the forgery message `m*` is that point's message (if `m*` is the message of no honest sealed point, any guess works: then `B_3` below never needs the target). `B_3` gets `X_v` from the EUF-CMA challenger.

- A sealed point whose message differs from the target's message `m_t`: `B_3` asks its signing oracle, recovers `R` (suite 1: `R = s⁻¹(h·G + r·X)`, §3.3), and deals `Share_t(s)` honestly.
- A sealed point with message `m_t` (the target, and any other honest point with the same message): `B_3` does not query. It picks `R = k·G` with `k` uniform, resampling until the checks of §3.4 hold, as the owner does. `F_0 = R + c·X` (suites 2, 3) or `h·G + r·X` (suite 1) is public. It picks `s_j` uniform for `j ∈ P` and computes the commitments by Lemma 2 with base `G` (suites 2, 3) or base `R` (suite 1) and `F = F_0`. The committed constant term is the real signature for that `R`; the distribution is that of an honest dealing.
- `π`: the ephemeral-key part is honest. The authorship proof (knowledge of `s_{1,1}`) is honest if `B_3` knows `s_{1,1}` and the simulation of Lemma 3 otherwise (`Q_auth·S_msg/q`).
- Honest nodes on a message that the owner of `X_v` did not write (for example one that wraps a released signature and adds points whose signatures nobody knows): they decrypt with their own keys and release what the adversary dealt them. `B_3` needs no oracle query and no target share for this, and such releases put nothing into `Auth(X_v)`.
- Honest nodes on owner-written messages: uniform ciphertext scalars (Game 1). A point with message `m_t` is never released by an honest node while `m_t ∉ Auth(X_v)`; if an honest node must release such a point, `m_t ∈ Auth(X_v)`, the guess was wrong, and `B_3` stops. All other points have known polynomials.
- Wallet signatures: the signing oracle.

`B_3` never queries `m_t`, so a forgery on `m* = m_t` wins EUF-CMA. ∎

**Status: proved here, given Theorem C and the standard unforgeability of the suite scheme (an assumption; for ECDSA, [GS21] Theorem 1, p. 16, proves it in the EC-GGM).**

Two points about the statement.

1. **It replaces the statement of §6.4.** §6.4 says the adversary cannot output a signature "for which honest nodes released fewer than `t − |C|` partials". The simulator knows the shares of the honest nodes of `P \ C` and of no other honest node, and `P` is fixed before the adversary chooses which honest nodes release. Proving the §6.4 form needs a guess of that subset, a loss of `binomial(n − |C|, t − 1 − |C|)`, which is not polynomial in general. Theorem D proves the form "no honest node released a partial for that message". This is the form `F_OMS` needs: an honest node releases a variant only when `Select` names it at the node's own eligible anchor (§3.7), so one honest partial already means the release was authorized. The §6.4 form is **open**; nothing else in SCHEME.md depends on it.
2. **Messages, not points.** If the owner seals the same transaction in two requests, releasing one releases a signature on the message of the other. `Auth` is defined on messages for this reason.

Claim 2 (fully corrupt committee) is the same reduction without Theorem C and without a target: `B_3` queries every variant and deals honestly, and a forgery outside the variant messages and the wallet's messages wins EUF-CMA. Status: proved here, same assumption.

If one key is used in sealed and open mode together, Theorem D still holds with EUF-CMA replaced by game TNS (suites 2, 3: `B_3` uses `PlainSign` for the non-target points) or by the game of 3.1 (suite 1: a presignature request followed at once by the signing request); the reduction `B_3` is black-box and does not rewind. Theorem E(c) does rewind, and is stated only for a key that is not used in open mode (section 8, item 4).

## 6. Authorization (claim 6; task item 4)

The authorship proof after correction C3: `c_a = Hq_auth(hd ‖ SHA-256(ct) ‖ E' ‖ T_1 ‖ T_2 ‖ z_e ‖ T_a)` and `z_a·B = T_a + c_a·Y`, with `(B, Y) = (G, X)` in open mode and `(B, Y) = (G or R_{1,1}, F_0^{(1,1)})` in sealed mode. `c_a` covers every byte of the message except `z_a`, and `z_a` is the unique solution of the verification equation.

Open-mode unforgeability (Theorems A, B') does not use claim 6: an honest node's partial on a message the adversary wrote is computed from shares the adversary supplied. Claim 6 is a separate statement about squatting, mauling and voiding.

### 6.1 Theorem E

Model of 1.1. Let `M` range over messages written by honest owners.

(a) **Open mode, suites 2 and 3.** The probability that a message with header key `X_v` passes §3.4 check 9 and is not byte-identical to a message written by the owner of `X_v` is at most `Q_H²/2^256 + ε_lock + Adv^icdh(B_C) + δ_C + Q_o·Adv^tns(A')`, with `A'` as in Theorem B'.

(b) **Open mode, suite 1.** The same event has probability at most `Q_H²/2^256 + ε_lock + Adv^icdh(B_C) + δ_C + δ_A + Q_o·(Q_auth·(U + 2)/(q − 1) + O(N²/q))`, in the EC-GGM, with `N` and `U` as in Theorem A.

(c) **Sealed mode, for a key that is used in sealed mode and by the wallet only.** The probability `ε` that a message `M' ≠ M` with the `rid` of an honest sealed message `M` passes check 9 before `M` is bound satisfies `ε' ²/Q_auth − ε'/q ≤ Adv^suf-cma_suite(B_4)` with `ε' = (ε − Adv^icdh(B_C) − δ_C − Q_H²/2^256 − Q_auth·S_msg/q)/(Q_o·S_msg)`.

(d) **No void by a third party.** A complaint against an honest owner's bound message is accepted with probability at most `Q_dleq/q` per complaint.

Proof.

*Common step.* If `M'` passes and has the same `Hq_auth` input as an honest message `M`, then (no collision in `H_hd` and SHA-256) it has the same `hdr, deal, ct, E', T_1, T_2, z_e, T_a`, hence the same `c_a` and the same `z_a`: `M' = M`. So a passing message that is not an owner's message has an `Hq_auth` input that no honest proof used, and its `(T_a, z_a)` is a valid proof at a challenge that the simulation never programmed.

(a) Run the reduction `A'` of Theorem B'. The message gives `(ctx*, T_a, z_a)` with `z_a·G = T_a + H_auth(ctx*, T_a)·X_v` and `(ctx*, T_a)` not from a `Prove` answer: a proof forgery in TNS.

(b) Lemma 5 below, applied to the reduction `B` of Theorem A: `B` answers each new `Hq_auth` query of `A` with `Chal(T_a)`, where `T_a` is the last field of the query (a uniform value if that field is not a point), and programs the points of its own simulated proofs as before. A passing non-owner message is a win in the extended game.

(c) Same `rid` in sealed mode means same `hd` (§3.2, `tie = hd`), so `M'` has the `deal` of `M` and `F_0^{(1,1)}` is the constant term of `M`'s first sealed point. Guess `v` and `M`. Run the reduction `B_3` of Theorem D with every point of `M` that carries the message `m_{1,1}` treated as a target (never queried, `R` chosen by `B_3`), until `M'` passes or `M` is bound. No honest node releases a point of `M` before `M` is bound, so `B_3` never needs a target share. Apply Lemma 4 with the `Hq_auth` answers as the values `h_i`, the signing oracle handled by cached replay and fresh queries: two accepting proofs at the same input give `s = (z_a − z'_a)/(c_a − c'_a)` with `s·B = F_0^{(1,1)}`, the signature of point `(1,1)` with the nonce `R` that `B_3` chose. The signing oracle never returned a signature with that `R` (probability `Q/q`), so `(R, s)` on `m_{1,1}` is new: an SUF-CMA forgery (an EUF-CMA forgery if no other honest point or wallet signature carries `m_{1,1}`).

(d) A complaint is accepted when `K` carries a valid `DLEQ(G, PK_i; E, K)` and the share decrypted with `K` fails its check. With `K = sk_i·E` the share of an honest dealing passes. A `K ≠ sk_i·E` has a false DLEQ statement: Lemma 3, `Q_dleq/q`. ∎

**Lemma 5 (the authorship proof next to the presignature oracle, EC-GGM).** Extend the game of [GS21] Figure 4 with an oracle `Chal(T)`: it registers `T` in the encoding table if needed (as step 3(a) of the figure does for an unknown point), draws `c ← Z_q`, records `(T, c)` and returns `c`. The adversary also wins if it outputs a recorded `(T, c)` and `z` with `z·G = T + c·D`. For an adversary with at most `N` queries, `Q_c` of them to `Chal`, and at most `U` unused presignatures at one time, the probability of this second kind of win is at most `Q_c·(U + 1)/(q − 1) + O(N²/q)`.

Proof. The proof of [GS21] Lemma 2 (Appendix B, pp. 42 to 45) shows that the lazy and the symbolic simulation proceed identically unless an event `Z` of probability `O(N²/q)` occurs. Adding `Chal` changes neither claim: the values `c` are independent of `d` and of the `r_k`, so the coefficients of the polynomials in `Domain(π)` stay independent of them. Work in the symbolic simulation of [GS21] Figure 5.

At the time of `Chal(T)` the preimage of `T` is a polynomial `P_T = a + b·D + Σ_{k∈K_T} c_k·R_k` with `c_k ≠ 0` and `K_T` a set of unused presignatures, `|K_T| ≤ U`; `c` is drawn after `P_T` is fixed. Later signing requests substitute `R_k ↦ s_k⁻¹(h_k + t_k·D)` with `s_k` uniform in `Z_q*` and independent of everything before (Figure 5, step 5(c)); `t_k ≠ 0` (step 4(d)). The final check holds in the symbolic game exactly when the polynomial `P_T` after all substitutions equals `z − c·D`. That needs every `R_k`, `k ∈ K_T`, substituted, and for the coefficient of `D`:

`b + Σ_{k∈K_T} c_k·t_k/s_k = −c`.

If `K_T` is empty this is `b = −c`, probability `1/q`. Otherwise let `k'` be the element of `K_T` substituted last. Just before that substitution every other term and `c` are fixed, and exactly one value of `s_{k'}⁻¹` satisfies the equation: probability at most `1/(q − 1)`. `k'` is not known in advance; a union over the at most `U` candidates gives `U/(q − 1)` per `Chal` query. ∎

In (b) the count is `U + 2` because the reduction of Theorem A has at most `U + 1` unused indices. Lemma 5 is stated for the game without key derivation, so (b) holds under hypothesis (H-key). With signing BIP32 siblings the substitution of [GS21] section 7.4 is `R_k ↦ s_k⁻¹(h_k + t_k·e_k + t_k·D)`; the coefficient of `D` is still `t_k/s_k`, and [GS21] p. 26 states that its Lemma 2 goes through unchanged, so the same argument gives the same bound. I have checked this substitution only; a written proof for the derived-key game is not included.

**Status.**

| Part | Status |
|---|---|
| (a) open, suites 2 and 3 | **reduced to Theorem B (proved here)**: the authorship proof is inside game TNS |
| (b) open, suite 1 | **proved here** in the EC-GGM, as an extension of the symbolic simulation of [GS21] (Figure 5, p. 23; Lemma 2, p. 22 and pp. 42 to 45). It is not a black-box corollary of Theorem 3: a rewinding extractor would ask two signatures on one presignature, which the game forbids. The extension is new and has had no outside review |
| (c) sealed | **proved here** under SUF-CMA of the suite scheme (ECDSA: up to sign), with a forking loss, for a key not used in open mode. Under EUF-CMA alone it holds when no other honest point or wallet signature carries the message of point `(1,1)`; the general EUF-CMA case is **open**. A key used in both modes is **open**: for suite 1 the rewinding meets the one-signature-per-presignature rule, as in (b) |
| (d) complaints | **proved here** |

### 6.2 What Theorem E gives for §6.7

- *Open mode: only the owner binds `rid`.* By (a), (b) every message that can bind an `rid` of `X_v` is an owner's message, byte for byte. No field can be altered, no ciphertext replaced, no proof re-randomized. A repost is the same message with the same `rid` and is ignored (§3.4). A copy on another board or chain fails §3.4 check 4, since `chain_id` and `board_id` are header fields.
- *Sealed mode.* A third party can post a sealed message of its own under `X_v` only if it knows a signature for its first point (it needs the authorship proof). Such a message has another `hd`, hence another `rid`, and honest nodes release only shares the third party dealt; the experiment of Theorem D already contains these messages, so they add no signature outside `Auth(X_v)`. By (c) the third party cannot take the `rid` of a pending sealed request.
- *Voiding.* By (d) and by (a) to (c), a third party cannot void a request by a complaint or by a bound copy with bad shares. Voiding by spending the pin needs a signature and falls under Theorems A, B', D.
- *At most one executed transaction per message* is a property of the pin and the target chain (§4), not of this document.

## 7. Status of every claim

| Claim (§) | Result here | Status | Assumptions |
|---|---|---|---|
| Share encryption (§3.2, §3.4) | Theorem C | proved here, after [GS22] Theorem 2 pp. 29 to 32; needs correction C3 | ICDH, RO, static |
| 3, sealed below `t` (§6.4) | Theorem D | proved here in the form "no honest partial"; the form "fewer than `t − |C|` partials" is open | EUF-CMA of the suite, Theorem C |
| 4, open ECDSA (§6.5) | Theorem A | reduced to [GS21] Theorem 3, p. 24 | EC-GGM, CR, RPR, ZPR, RR of the sighash, Lemma 1, Theorem C |
| 4, open ECDSA, BIP32 siblings | Corollary A' | reduced to [GS21] Theorem 4, p. 27; a tighter fixed-tweak bound is open | as above plus 4sum1, 4sum2, tweak set |
| 4, open Schnorr (§6.5) | Theorems B, B' | proved here | AOMDL with parameter `2U`, RO, Lemma 1, Theorem C |
| 4 step 1 (§6.5) | Lemma 1 | proved here | board consistency, or `b ≤ f` and post-key EUF-CMA |
| 6, authorization (§6.7) | Theorem E, Lemma 5 | (a), (b), (d) proved here; (c) proved under SUF-CMA for a key not used in open mode, otherwise open | as the mode's theorem |
| 2, sealed, fully corrupt (§6.3) | remark after Theorem D | proved here | EUF-CMA of the suite |

## 8. What remains open

1. **`reshare`.** No theorem covers a request that moves to a new committee. Needed: Lemma 1 across the freeze (board consistency), Theorem C for the old nodes as dealers (it applies as stated once the reshare dealer proof uses the construction of 2.2), and a simulation of the sub-share dealings. The last step is not Lemma 2: an honest old node outside `P` deals a sharing of a share the simulator does not know, in the exponent of a known point `Eval(·, i)`, which Lemma 2 handles, but the corrupt new nodes then hold `t' − 1` sub-shares from each of `t_old` dealers, and the joint distribution with the new commitments has to be checked. Not done.
2. **Claim 3 in the §6.4 form** (partial releases below `t − |C|`): needs a subset guess or an adaptive-security technique.
3. **A tight bound for BIP32 keys** with presignatures under one fixed tweak (3.4).
4. **Sealed claim 6 under EUF-CMA alone, and for a key used in both modes** (Theorem E(c)). For suite 1 a mixed key needs a generic-group argument in the style of Lemma 5 for a proof of knowledge of a sealed signature; not done.
5. **ICDH in the EC-GGM.** Theorem A adds an ICDH term for generic adversaries on secp256k1. No bound for it is taken from the two papers or proved here.
6. **Adaptive corruption, a UC statement, and realization of `F_OMS`**: untouched.
7. **Comparison with the published FROST and MuSig2 proofs**: blocked by the failed downloads (section 0).
8. **Lemma 5 and Theorem B have had no outside review.** LOOP item 6 schedules a cross-family review.

## 9. Corrections to SCHEME.md

Not applied here. Each row: old text, new text, reason. C1 to C9 come from the proofs; C10 to C18 from PROOF-CHECK section 6.

**C1. §2 Assumptions, share encryption.**
Old: "Gap Diffie-Hellman for the share encryption (hashed ElGamal with a public complaint that reveals one DH value)."
New: "ICDH (interactive CDH, ePrint 2022/506 p. 29) for the share encryption: hashed ElGamal with the ephemeral-key proof of 2022/506 section 4.1 and a public complaint that reveals one DH value. `HG_eph` is a random oracle into the suite group (hash to curve; for suite 3 into the prime-order subgroup). PROOFS.md Theorem C."
Reason: PROOF-CHECK section 5; Theorem C is proved under ICDH, not gap DH.

**C2. §3.1 hash table.**
Old row: "`LD1/auth` (Hq) | `hd ‖ SHA-256(ct) ‖ T_e(33) ‖ T_a(33)` | challenge of `π`".
New rows: "`LD1/eph` (hash to the suite group) | `hd ‖ SHA-256(ct) ‖ E` | second generator `g'` for the ephemeral-key proof"; "`LD1/ephpok` (Hq) | `hd ‖ SHA-256(ct) ‖ E ‖ E' ‖ T_1 ‖ T_2` | challenge of the ephemeral-key proof"; "`LD1/auth` (Hq) | `hd ‖ SHA-256(ct) ‖ E' ‖ T_1 ‖ T_2 ‖ z_e ‖ T_a` | challenge of the authorship proof". Add to the sentence before the table: "`HG_tag` is a hash-to-curve function with domain separation tag `tag`; the concrete encodings (RFC 9380 suites for secp256k1 and edwards25519) are named from memory and must be checked against the RFC before implementation."
Reason: construction 2.2; the authorship challenge must cover every other byte of the message (Theorem E, common step).

**C3. §3.2, definition of `π`.**
Old: "`π = (T_e, z_e, T_a, z_a)`, 130 bytes, two Schnorr proofs under one challenge `c = Hq_auth(hd ‖ SHA-256(ct) ‖ T_e ‖ T_a)`: knowledge of `e`: `z_e·G = T_e + c·E`; authorship. …"
New: "`π = (E', T_1, T_2, z_e, T_a, z_a)`, 196 bytes. Ephemeral-key proof: `g' = HG_eph(hd ‖ SHA-256(ct) ‖ E)`, `E' = e·g'`, `c_e = Hq_ephpok(hd ‖ SHA-256(ct) ‖ E ‖ E' ‖ T_1 ‖ T_2)`, `z_e·G = T_1 + c_e·E` and `z_e·g' = T_2 + c_e·E'`. Authorship proof: `c_a = Hq_auth(hd ‖ SHA-256(ct) ‖ E' ‖ T_1 ‖ T_2 ‖ z_e ‖ T_a)`, then as before with `c_a`: open `z_a·G = T_a + c_a·X`; sealed `z_a·B = T_a + c_a·F_0^{(1,1)}`."
Reason: with a plain Schnorr proof of `e` the encryption reduction must extract `e` from every adversarial message (PROOF-CHECK section 5). With `ad = hd` alone a copy with altered `ct` makes an honest node publish `K_i` (section 2.1). The new proof needs only soundness and simulation, and binds `ct`.

**C4. §3.4 check 9 and the last sentence of the private check.**
Old: "9. `π` verifies." and "an honest owner never causes one, and `π` stops a third party from reusing an honest `E`."
New: "9. `E'` is a valid non-identity point; the ephemeral-key proof and the authorship proof verify. A node computes `K_i` only for a message that passed this check." and "an honest owner never causes one; the ephemeral-key proof binds `E` to `hd` and to the ciphertexts, so a third party cannot reuse an honest `E` in any other message (PROOFS.md Theorem C, event `Reuse`)."
Reason: Theorem C.

**C5. §5 Transfer.**
Old: "with its own ephemeral key and proof of knowledge, using the `LD1/rs-*` labels."
New: "with its own ephemeral key and the ephemeral-key proof of §3.2 under the labels `LD1/rs-eph`, `LD1/rs-ephpok`, using the `LD1/rs-*` labels." Add `LD1/rs-eph`, `LD1/rs-ephpok` to the last row of the §3.1 table.
Reason: the same complaint oracle exists for resharing dealers.

**C6. §6.4, statement and status of claim 3.**
Old: "Status: sketched" and "the adversary cannot output a variant signature for which honest nodes released fewer than `t − |C|` partials, under unforgeability, gap DH and the random oracle model, with loss `K·L`."
New: "Status: proved in PROOFS.md Theorem D" and "the adversary cannot output a signature on a variant message for which no honest node released a partial (and which the wallet did not sign), under unforgeability of the suite scheme, ICDH and the random oracle model, with loss equal to the number of sealed points of the key. The stronger form with fewer than `t − |C|` released partials is open (the simulation would have to guess the releasing subset)."
Reason: Theorem D, point 1.

**C7. §6.5, status and last paragraph of the steps.**
Old: "Status: sketched; the single-signer games are cited, not proved here" and "ECDSA: [GS22] Theorem 3 bounds the game with a term `U·N` … Schnorr: one nonce per slot would allow a ROS-type search across outstanding slots, so the design deals two and binds `ρ` to the digest; the proof of that single-signer game is from memory."
New: "Status: ECDSA reduced to ePrint 2021/1330 Theorem 3 (PROOFS.md Theorem A; Theorem 4 for keys with signing BIP32 siblings, Corollary A'); Schnorr proved under AOMDL in the random oracle model (PROOFS.md Theorems B, B'). `reshare` not covered." and "ECDSA: Theorem 3 holds in the EC generic group model for a sighash that is collision resistant, random-preimage resistant, zero-preimage resistant and ratio resistant; the bound has a term `U·N` in the number `U` of live slots of one key and the reductions run in the adversary's time plus `O(U·N)`; raw-hash signing would break it, and every node hashes its own preimage. Schnorr: one nonce per slot would allow a ROS-type search across outstanding slots, so the design deals two and binds `ρ` to the digest; the single-signer game is stated and proved in PROOFS.md section 4."
Reason: Theorems A, B; PROOF-CHECK section 6 items 1, 2, 3.

**C8. §6.7 status; §6.3 status.**
Old: "Status: sketched" (both).
New §6.7: "Status: proved in PROOFS.md Theorem E; the sealed part needs strong unforgeability of the suite scheme." New §6.3: "Status: proved (PROOFS.md, remark after Theorem D)."
Reason: Theorem E.

**C9. §7, sizes and counts that include `π`.**
Old: "The fixed part is 654 bytes (header 524 with one output, `π` 130)."; "The `+3` is `E` and the two commitments of `π`."; "Step A, open ECDSA `G = 1`: `π` 4, DH 1, two share checks `2t`" (and the two other Step A rows).
New: "The fixed part is 720 bytes (header 524 with one output, `π` 196)."; "`+5` and one hash to curve: `E`, `E'`, `T_1`, `T_2`, `T_a`" (the three owner formulas become `… + n + 5`); Step A rows: "`π` 6 and one hash to curve" in place of "`π` 4" (each Step A count rises by 2). Every "Message" row rises by 66 bytes:

| | T1 16 | T1 64 | T1 256 | T2 16 | T2 64 | T2 256 |
|---|---|---|---|---|---|---|
| Message, sealed `K = 8`, one input | 6,400 | 22,912 | 88,960 | 7,720 | 28,456 | 111,400 |
| Message, sealed `K = 1` | 1,430 | 3,494 | 11,750 | 1,595 | 4,187 | 14,555 |
| Message, open ECDSA, `G = 1` | 2,107 | 6,235 | 22,747 | 2,437 | 7,621 | 28,357 |
| Message, open ECDSA, `G = 2` | 3,494 | 11,750 | 44,774 | 4,154 | 14,522 | 55,994 |
| Message, open Schnorr, `G = 1` | 2,817 | 9,009 | 33,777 | 3,312 | 11,088 | 42,192 |

The resharing row changes with C5: if the 98 bytes per dealer are `E` and one Schnorr proof, the formula becomes `t_old(P + 164)`, that is 5.0 KB, 63.9 KB and 960 KB for T1 at `n = 16, 64, 256`. The owner-computation table, the node-total rows and the node-download rows depend on these and must be regenerated with `costs.py`; they are not recomputed here.
Reason: C3.

**C10. §2 Assumptions, open ECDSA** (PROOF-CHECK 6.1, 6.2).
Old: "Open ECDSA: unforgeability of ECDSA with public single-use presignatures, [GS22] Theorem 3 (EC generic group model; the hash is collision resistant, random-preimage resistant and ratio resistant)."
New: "Open ECDSA: unforgeability of ECDSA with public single-use presignatures, ePrint 2021/1330 Theorem 3 (EC generic group model; the sighash is collision resistant, random-preimage resistant, zero-preimage resistant and ratio resistant; the bound has a term `U·N` and the reductions run in the adversary's time plus `O(U·N)`, `U` = live slots of one key). If the wallet also signs under BIP32 non-hardened siblings of `X`, Theorem 4 of the same paper governs, with the terms 4sum1, 4sum2 and a factor in the size of the tweak set. Also ICDH on secp256k1 for generic adversaries."
Reason: [GS21] pp. 24, 27; Theorem A, Corollary A'.

**C11. §2 Assumptions, open Schnorr** (PROOF-CHECK 6.3).
Old: "Open Schnorr: unforgeability of single-signer two-nonce Schnorr with pre-published nonces (from memory, not checked)."
New: "Open Schnorr: the algebraic one-more discrete logarithm assumption (AOMDL) with parameter twice the number of slots dealt under the key, in the random oracle model (PROOFS.md Theorem B)."
Also old: "Discrete log on the suite curve; random oracles for the labelled hashes." New: "Discrete log on the suite curve (AOMDL for open Schnorr); random oracles for the labelled hashes and, for suites 2 and 3, for the suite challenge hash."
Reason: Theorem B; discrete log alone is not what the proof uses.

**C12. §2 Assumptions, sealed mode.**
Old: "Sealed mode: standard unforgeability of ECDSA, BIP340 or Ed25519."
New: "Sealed mode: standard unforgeability of ECDSA, BIP340 or Ed25519; the statement that no third party takes the `rid` of a pending sealed request uses strong unforgeability (for ECDSA up to sign)."
Reason: Theorem E(c).

**C13. §6.5 last paragraph and §10 "Not stopped"** (PROOF-CHECK 6, internal point 1).
Old (§6.5): "`f < b < t` Byzantine nodes can certify two digests under one nonce and recover `x`." Old (§10): "can certify two digests under one nonce. The result is the key, not only a double spend."
New (§6.5): "`f < b < t` Byzantine nodes can certify several digests under one nonce. For ECDSA two digests give `x`. For two-nonce Schnorr two digests do not (ledger D7(b2)); three do." New (§10): "can certify several digests under one nonce. The result is the key (ECDSA: two digests; Schnorr: three), not only a double spend."
Reason: ledger D7; PROOF-CHECK count `2t + b < 3t`.

**C14. §6.6** (PROOF-CHECK 6, internal point 2).
Old: "For an open line two points determine the line, and the line is the key, so the open one-spend limit is policy."
New: "For an open ECDSA line two points determine the line; for the two-nonce Schnorr line three do (ledger D7(b)). The line is the key, so the open one-spend limit is policy."
Reason: ledger D7(b).

**C15. §10 "Stopped", last bullet** (PROOF-CHECK 6.4, 6.5).
Old: "**Raw-hash and ratio attacks on presignatures; ROS-type attacks on pre-published Schnorr nonces.**"
New: "**Raw-hash attacks on presignatures**, by rule: every node hashes its own preimage. **ROS-type attacks on pre-published Schnorr nonces**: two nonces bound to the digest, proved under AOMDL (PROOFS.md Theorem B)." Add under "Not stopped": "**Ratio attack on ECDSA presignatures.** No mechanism stops it; ratio resistance of the sighash is assumed (ePrint 2021/1330 p. 26 note 2)."
Reason: [GS21] p. 26; Theorem B.

**C16. §9, last paragraph** (PROOF-CHECK 6.6).
Old: "Open mode is Form A with the presignature work moved to the one party who does it for free."
New: "Open mode is Form A with the presignature work moved to the one party who does it for free, on the protocol side. On the security side it is weaker: Form A (ePrint 2022/506) uses re-randomized presignatures and rests on Theorem 6 of ePrint 2021/1330, open ECDSA uses plain presignatures and rests on Theorem 3, which needs ratio resistance and has the `U·N` term."
Reason: PROOF-CHECK section 5; [GS21] Table 1, p. 7. (The statement about 2022/506 is PROOF-CHECK's reading of its pp. 11 and 18, not mine.)

**C17. Stale status lines** (PROOF-CHECK 6.7).
- §10 "Proof status". Old: "Open Schnorr rests on a result cited from memory; open ECDSA on a theorem whose model section was not read; adaptive corruption is not covered." New: "See PROOFS.md section 7. Open: `reshare`, adaptive corruption, a UC statement, a tight bound for BIP32 keys. The Schnorr proof is not yet compared with the published FROST and MuSig2 proofs."
- §12 [GS22] entry. Old: "from memory, not checked, except these passages … Every use above is limited to the passages read." New: "ePrint 2021/1330, read in full (pp. 1 to 48), `research/sources/groth-shoup-2021-1330.pdf`." Add: "Groth, Shoup, ePrint 2022/506: section 4 read in full for PROOFS.md; other statements from REPORT.md and PROOF-CHECK.md."
- §11 item 7. Old: "Read [GS22] in full and write the reduction of claim 4; check the two-nonce Schnorr claim against the FROST and MuSig2 proofs." New: "Compare PROOFS.md Theorem B with the FROST and MuSig2 proofs once those papers are obtained (ePrint 2022/833, 2021/1375, 2020/1261, 2020/945 were blocked on 2026-11-13)."
- FINDINGS-LEDGER, "Listed, not fixed". Old: "[GS22] not read in full; the two-nonce Schnorr game is cited from memory;". New: "the two-nonce Schnorr proof (PROOFS.md Theorem B) is not compared with the published proofs;".
Reason: the paper is read; the game is proved.

**C18. §10 "Stopped", "Complaint oracle" and "Related dealing".**
Old: "**Related dealing.** Pads depend on `hd`, `π` covers everything, and an attacker cannot re-encrypt." and "**Complaint oracle.** The proof of knowledge of `e` stops reuse of an honest `E`."
New: "**Related dealing.** Pads depend on `hd`, the authorship proof covers every other byte of the message, and an attacker cannot re-encrypt (PROOFS.md Theorem E)." and "**Complaint oracle.** The ephemeral-key proof `E' = e·HG_eph(hd ‖ SHA-256(ct) ‖ E)` stops reuse of an honest `E` and lets the reduction answer every complaint without `e` (PROOFS.md Theorem C)."
Reason: C3.

Each applied correction needs a ledger row (LOOP rule). C3, C4, C5 and C9 change the wire format and the Rust prototype (`π` layout, one hash-to-curve per message, Step A check 9).
