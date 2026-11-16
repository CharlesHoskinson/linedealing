# Security proofs of line dealing

Scope: the claims of `design/SCHEME.md` section 6 that `design/PROOF-CHECK.md` left open: claim 3 (sealed points stay sealed), claim 4 (open mode, ECDSA and Schnorr), claim 6 (authorization), and the share encryption that claims 3, 4 and 6 use. Section numbers with a paragraph sign (§) refer to SCHEME.md.

The proofs change the scheme in four places and narrow five statements; section 9 lists the corrections. The changes:

1. The proof of knowledge of the ephemeral key `e` in `π` is replaced by the ephemeral-key proof of ePrint 2022/506 section 4.1, with the ciphertext hash inside the hash-to-curve input, and the authorship challenge covers the whole message (C1 to C5).
2. The ciphertext hash is the labelled hash `H_ct` (tag `LD1/ct`), not raw SHA-256 (C19).
3. In suite 3 the registered node keys, the complaint points and `E'` are checked for canonical encoding and membership in the prime-order subgroup (C20).
4. A node restored to an old state posts nothing until it has replayed the board to its earlier position, and erases again what it had erased (C22, rule 4 of §3.9). The closing rule of Theorem A needs this.

Changes 2 to 4 add no byte to any message. The narrowed statements:

1. Claim 3 holds in the form "no honest partial was released" (Theorem D).
2. The sealed part of claim 6 holds in the form "no other dealing takes the `rid` of a pending sealed request" (Theorem E(c)). A party that knows the first sealed signature can still replace the proof bytes of a pending sealed message. Byte identity holds only under added hypotheses (Theorem E(c′)).
3. In every theorem a message counts as the owner's when it carries the `(hdr, deal, ct)` of an owner message, whatever its proof bytes (section 1.1, "copy").
4. In Theorem A the number `U` of unused presignatures counts every slot that some honest node can still sign. The adversary's schedule can raise it to the number of slots ever dealt under the key (3.3 item 3).
5. Corollary A' (BIP32 siblings) holds with HMAC-SHA512 as a random oracle and for a set of signing paths fixed in advance (3.4).

Every theorem below is about the scheme with the corrections of section 9 applied.

This revision answers two blinded cross-family reviews (`design/proofs-review/review-cand-b.md`, `design/proofs-review/review-cand-c.md`) and `design/notes-2022-506.md`. `design/proofs-review/DISPOSITION.md` maps each finding to its change.

## 0. Reading record

| Source | Local path | Read for this document |
|---|---|---|
| [GS21] Groth, Shoup, *On the security of ECDSA with additive key derivation and presignatures*, ePrint 2021/1330, version of 27 April 2022 | `research/sources/groth-shoup-2021-1330.pdf` | Pages 1 to 48 in full (all sections, Theorems 1 to 9, Appendices A to D). Reference list not read |
| [GS22] Groth, Shoup, *Design and analysis of a distributed ECDSA signing service*, ePrint 2022/506, version of 16 February 2023 | `research/sources/eprint/2022-506.pdf` | Section 4 in full (4, 4.1, 4.2, 4.3, 4.4; printed pages 24 to 34). For this revision also p. 56 (Games 4 and 5 in the proof of Theorem 4) and pp. 75 to 76 (appendix A.1 to A.1.2, group membership). Every statement about this paper is limited to those pages. Section 10.1.1 (adaptive corruption of the encryption) is not read and not used |
| `design/SCHEME.md`, `design/FINDINGS-LEDGER.md`, `design/PROOF-CHECK.md`, `design/notes-2022-506.md`, the two reviews in `design/proofs-review/` | | In full |
| RFC 8032 (Ed25519 clamping, deterministic nonces), RFC 6979, BIP32, BIP340 | not local | Not read. Every statement about them is from memory and marked so |

SCHEME.md calls 2021/1330 "[GS22]". This document calls it [GS21] and keeps [GS22] for 2022/506.

**Downloads blocked.** PROOF-CHECK section 3 names five papers for the Schnorr proof. On 2026-11-13 `curl` requests to `https://eprint.iacr.org/2022/833.pdf`, `/2021/1375.pdf`, `/2020/1261.pdf` and `/2020/945.pdf` each returned HTTP 403 with a Cloudflare challenge page ("Enable JavaScript and cookies to continue"). The block was not worked around; no file was saved. The fifth paper (Bellare, Crites, Komlo, Maller, Tessaro, Zhu, CRYPTO 2022) has no ePrint number in PROOF-CHECK and was not requested. None of the five is cited below. Consequence: the Schnorr result of section 5 is proved here from first principles and is not compared with those papers. I make no statement about what they prove. The definitions of AOMDL and ICDH and the forking lemma are written out in full in section 1 so that nothing rests on an unread source.

## 1. Model, assumptions, and common lemmas

### 1.1 Execution model

- **Parties.** Honest owners with keys `X_1, …, X_{Q_o}`. One committee of `n ≥ 3f + 1` nodes per epoch, with quorum `q = ⌈(n + f + 1)/2⌉` (SCHEME §2; `q = 2f + 1` when `n = 3f + 1`). The adversary `A` is static: before the epoch keys exist it names the corrupt set `C`, with `|C| ≤ t − 1`, of which at most `f` are Byzantine (the others leak `sk_i` and shares only, §2). Corrupt nodes register any encryption key that passes the registration check of §2: a canonical encoding of an element of `𝔾` other than the identity. For suites 1 and 2 every curve point is in `𝔾`; for suite 3 the check is `[q]PK = O` (C20). No proof of possession is assumed for corrupt keys.
- **Views.** Each honest node acts on its own view of the board, a prefix of its log. A view only grows. A node restored to an old state replays the board at least to the position it had reached before, and until then it posts nothing; the replay makes it erase again every share that §3.10 made it erase (rule 4 of §3.9 with C22). A node that does not do this is Byzantine. A node is *done with* a slot of an honest message `M` when its view contains a tombstone of the `rid` of `M`, or a board height above the `exp` of `M` with no lock for the slot's generation, or a binding of that `rid` to a message that is not a copy of `M`. A node that is done with a slot holds no share of it (§3.10, §3.4) and never posts a PARTIAL for it.
- **Scheduling.** `A` chooses every honest owner's header fields (intent, window, profile), schedules the board subject to the total-order property of §2, controls the target chain's contents subject to its finality rule, and asks any owner's wallet for ordinary signatures on messages of its choice (the oracle `PlainSign`).
- **Rotation.** The theorems cover requests with `on_rotation ∈ {finish, void}`: one committee serves the request. `reshare` is not covered (section 8, item 1).
- **Messages.** For a signature suite, "message" means the byte string that the suite hashes: the sighash preimage (suite 1), the 32-byte sighash (suite 2), the transaction message (suite 3). The same word is used for an owner's protocol message `OwnerMsg` (§3.2), written `M`; the context tells which. An owner message `M'` is a *copy* of `M` if it has the `(hdr, deal, ct)` of `M`; its `π` may differ, and `M` is a copy of itself. A message is *owner-dealt for `X`* if it is a copy of a message written by the owner of `X`. `Auth(X)` is the set of messages `m` such that the wallet of `X` plain-signed `m`, or some honest node posted a PARTIAL for a slot or sealed point with message `m` that was dealt in a message owner-dealt for `X`. A PARTIAL that an honest node posts for a message under the header key `X` that is not owner-dealt puts nothing into `Auth(X)`.
- **Why a copy counts as the owner's message.** A copy has the owner's header (intent, window, profile, `E`), the owner's commitments and the owner's ciphertexts. `rid` is a function of `hdr` (and of `hd` in sealed mode), so a copy has the `rid` of the original. Every honest node decrypts the same shares from a copy as from the original, and every later step reads `hdr`, `deal` and the shares only. The one difference is `mid`. A signature released through a copy is therefore a signature the owner's dealing authorized, and the experiment must not count it as a forgery. The theorems of sections 3 to 5 do not ask who wrote the proof bytes of a copy. Theorem E states when a copy other than the original can exist: in open mode never, in sealed mode only for a party that knows the first sealed signature.
- **Forgery.** `A` wins the unforgeability experiment if it outputs `(X_v, m*, sig*)` with `X_v` an honest owner key, `sig*` valid for `m*` under the suite's verification rule, and `m* ∉ Auth(X_v)`.

What the cryptographic theorems do not state: that the messages in `Auth(X)` are the right ones. That is the state-machine property "an honest node signs only the digest it built from an eligible anchor, at most `G` times per request" (§3.6 to §3.9), checked in the Quint model and outside this document.

### 1.2 Assumptions

`𝔾` is the suite group of prime order `q` with generator `G`, written additively. `dh(aG, bG) := abG`.

- **AOMDL (algebraic one-more discrete logarithm), parameter `ℓ`.** The challenger gives `Y_0, …, Y_ℓ`, uniform in `𝔾`. The adversary may call `DL(α_0, …, α_ℓ, β)` at most `ℓ` times; the answer is `β + Σ α_i·log_G Y_i`. It wins if it outputs `log_G Y_i` for all `i = 0..ℓ`. `Adv^aomdl_ℓ(B)` is the winning probability. (In OMDL the oracle takes an arbitrary group element. AOMDL restricts the oracle to combinations the adversary declares, so it is the weaker assumption.)
- **ICDH (interactive CDH)** as in [GS22] p. 29: given uniform `U*, V* ∈ 𝔾`, compute `dh(U*, V*)`, with an oracle that decides whether `(A, V*, W)` is a DH triple for `A, W` of the adversary's choice. The paper states the restriction as "one of the first two entries in the triple must be `u`" and its proof calls the oracle only on triples `(·, v*, ·)`; the two forms are the same assumption with the roles of the two challenge points exchanged. `Adv^icdh(B)` is the winning probability.
- **Random oracles.** The labelled hashes of §3.1, including `LD1/eph`, `LD1/ephpok` (section 9, C2) and `LD1/ct` (C19), are independent random oracles. `H_ct` is the labelled hash with tag `LD1/ct` and range `{0,1}^256`. No proof step uses raw SHA-256: the bundle under review hashed `ct` with raw SHA-256, which is neither a labelled hash nor covered by any assumption of this section, and C19 removes it. `HG_eph` has range `𝔾`; `Hq_*` have range `Z_q`; `H_*` have range `{0,1}^256`. For suites 2 and 3 the suite challenge hash `H_sig` is a random oracle with range `Z_q`, independent of the labelled hashes. For suite 3 this ignores that SHA-512(`R ‖ A ‖ M`) has no tag; it is a modelling assumption.
- **Suite 1 only.** The EC generic group model of [GS21] section 2 for secp256k1 (prime order, cofactor 1, [GS21] p. 9 note 4), and four properties of the chain's sighash function `Hash`: collision resistance, random-preimage resistance, zero-preimage resistance, ratio resistance ([GS21] Definitions 3, 4, 5, 7).
- **Query counts.** For an oracle `x`, `Q_x` counts every evaluation of that oracle in the experiment: the adversary's queries and the evaluations that honest parties and the final verification make. A proof that the adversary submits without having queried its challenge is therefore counted.
- **Suite 1 only, rejection rate.** `θ_q := Pr[x(R) ≥ q]` for uniform `R ∈ 𝔾 \ {O}`. The unreduced conversion function is 2-to-1 ([GS21] p. 10), so at most `2(p − q)` of the `q − 1` points have `x ≥ q`; Hasse's bound `q − 1 = p + 2θ·p^{1/2}`, `θ ∈ [−1, 1]` (same page), gives `p − q ≤ 2·p^{1/2}`. With `p < 2^256` and `q > 2^255`: `θ_q ≤ 4·p^{1/2}/(q − 1) < 2^{−125}`. (For secp256k1 the exact value is about `2^{−126.7}`, computed from `p` and `q` quoted from memory.)
- **Suite 3 only, key distribution.** The dealt key is `x = clamp(SHA-512(seed)[0..32]) mod q` (§3.3). From memory of RFC 8032: `clamp` clears bits 0, 1, 2 and 255 and sets bit 254, so `x = 2^254 + 8u mod q` with `u ∈ [0, 2^251)`. Assumption: for a uniform secret seed the 32 bytes are uniform (SHA-512 on a secret seed as a random oracle), so `u` is uniform. The `2^251` values are distinct and nonzero mod `q`: two of them differ by `8(u − u')` with `|u − u'| < 2^251 < q`, and `2^254 + 8u` is a multiple of 8 below `2^255 < 8q`, so it is not a multiple of the odd prime `q`. The key is therefore uniform on a set `S_clamp ⊂ Z_q*` of `2^251` elements. Define `κ_3 := (q − 1)/2^251`; with `q = 2^252 + 27742317777372353535851937790883648493` (from memory) `κ_3 < 2 + 2^{−126}`. For any game with a uniform key in `Z_q*` and any adversary, the winning probability conditioned on `x ∈ S_clamp` is at most `κ_3` times the unconditioned one. `κ_1 = κ_2 := 1`.
- **Sealed mode only.** EUF-CMA of the suite signature scheme. Theorem E(c′) alone needs SUF-CMA (for ECDSA: strong unforgeability up to sign, [GS21] section 4.1.1) and a signing algorithm with fresh uniform nonces.
- **Corollary A' only.** HMAC-SHA512 is a random oracle, and the set of BIP32 derivation paths under which the wallet signs is fixed before the keys are generated (3.4).
- **Post keys.** EUF-CMA of the post-key signature scheme, used only in Lemma 1(b).

### 1.3 Lemma 1 (one digest per slot)

For a request served by one committee, all PARTIAL posts of honest nodes for `(rid, g)` use one digest `dg`, under either hypothesis:

(a) the board is a consistent total order. Then `LOCK(rid, g)` is by definition the first `q` PREVOTE posts from distinct nodes with identical `(a, B*, dg)`; it is unique, and §3.8 lets an honest node sign only the digest of that certificate.

(b) at most `f` nodes are Byzantine and post signatures are unforgeable, with no assumption on board consistency. Two certificates for `(rid, g)` with different digests have at least `2q − n ≥ f + 1` voters in common (Lean `quorum_inter_honest_q`), so one honest node's post key signed two PREVOTEs for `(rid, g)`. Rule 1 of §3.9 with the durable ledger (rules 3, 4) excludes that for an honest node, so one of the two posts is a forgery. Probability at most `n·Adv^euf_post`.

Status: **proved here** (counting; Lean `LineDealing.Quorum.quorum_inter_honest_q` and `LineDealing.Votes.one_digest_per_slot` formalize the arithmetic for every `n ≥ 3f + 1`). Limit: across a `reshare` freeze the statement needs board consistency (§5) and is not used here.

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
- **DLEQ** for the statement `log_{B_1} Y_1 = log_{B_2} Y_2`: `(T_1, T_2, z)` with `z·B_1 = T_1 + c·Y_1`, `z·B_2 = T_2 + c·Y_2`. Simulation as above. Soundness is statistical: if `Y_1 = y_1·B_1`, `Y_2 = y_2·B_2` with `y_1 ≠ y_2`, and `T_1 = t_1·B_1`, `T_2 = t_2·B_2`, a valid `z` forces `c = (t_1 − t_2)/(y_2 − y_1)`, one value. A false statement is accepted with probability at most `Q/q` over `Q` challenge queries. The count needs only that each of these challenges is a uniform value drawn after its input was fixed. It therefore holds at every input that no simulator programmed, also in an experiment where other inputs of the same oracle were programmed.
- **Group membership.** Both statements are about a group of prime order. Every point that enters a proof of this lemma is checked to be a canonical non-identity element of `𝔾` before the proof is verified: the points of a message by §3.4 check 2, `E'` by check 9, `PK_i` at registration and `K_i` in a complaint by C20. For suite 3 the verification equations are the cofactorless ones, so a commitment `T` that satisfies them with the other points in `𝔾` is in `𝔾` too.

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

The proof of Theorem 2 uses the rule in one place (p. 30 to 31): a decryption query must hit `H_G` at an input that was programmed as an adversarial query, `g' = u*·g^λ`, and not as an encryption query, `g' = g^ρ`. The input of `H_G` is `(ad, v)`. So the property needed is: **the `H_G` input of every adversarial message differs from the `H_G` input of every honest message, unless the adversarial message carries the honest ciphertexts unchanged.** Putting the ciphertext hash into the `H_G` input gives exactly that. The pads cannot take the same input (the ciphertexts depend on the pads); [GS22] p. 32 note 1 says the associated data inside `H_M` is not needed for the scheme of section 4.1. The construction below therefore uses `hd` in the pad and `(hd, H_ct(ct), E)` in `H_G`. The step "the adversarial message carries the honest ciphertexts unchanged" needs the ciphertext hash to be collision-free, so `H_ct` is a labelled hash under the random-oracle assumption of 1.2 (C19). Theorem 2 of [GS22] does not cover it as a black box, because its syntax has one `ad`; Theorem C below repeats its game sequence with the two inputs.

### 2.2 Construction (replaces the proof of knowledge of `e` in §3.2)

```
g'    = HG_eph(hd ‖ H_ct(ct) ‖ E)                  hash to the suite group, label LD1/eph
E'    = e·g'
T_1   = a·G,  T_2 = a·g'                              a random
c_e   = Hq_ephpok(hd ‖ H_ct(ct) ‖ E ‖ E' ‖ T_1 ‖ T_2)
z_e   = a + c_e·e
check: z_e·G = T_1 + c_e·E   and   z_e·g' = T_2 + c_e·E'
```

`H_ct(ct) = H_{LD1/ct}(ct)`, 32 bytes, computed and never sent. Pads are unchanged: `Hq_enc(hd, i, PK_i, K_i, slot)`, `K_i = e·PK_i = sk_i·E`. The complaint is unchanged in format: `K_i` with `DLEQ(G, PK_i; E, K_i)`; a verifier first checks that `K_i` is a canonical non-identity element of `𝔾` (C20). A node computes `K_i` for a message only after the public check of `(E', T_1, T_2, z_e)` passed (§3.4 check 9 precedes the private check).

### 2.3 Theorem C (honest pads are random)

Let `Exp` be any experiment of section 1.1 (any suite, any mode, with honest reshare dealers treated as honest dealers). Let `Exp'` be the same experiment with two changes.

(i) For every honest dealer's message `M` and every honest node `i`, each ciphertext scalar is uniform and independent of everything else, and node `i` uses its dealt share directly when it processes `M` or a copy of `M` (section 1.1).

(ii) The experiment aborts at the event `Reuse`: a message that is not a copy of an honest dealer's message, but carries an honest dealer's `E`, passes the ephemeral-key check.

Then for every adversary `A` there is an ICDH adversary `B_C`, with the running time of `A` plus one DH-oracle call per `Hq_enc` query, such that

1. `|Pr[Exp ⇒ 1] − Pr[Exp' ⇒ 1]| ≤ Adv^icdh(B_C) + δ_C`, and
2. `Pr[Reuse occurs in Exp] ≤ Adv^icdh(B_C) + δ_C`,

`δ_C = (Q_eph·Q_msg + 2·Q_ephpok + Q_dleq·Q_cmp + Q_pop·n + Q_ephpok·Q_msg + Q_msg² + Q_H·Q_msg + n + 2·Q_msg)/q + (Q_H² + Q_enc·Q_msg)/2^256`,

where `Q_msg` is the number of honest dealer messages, `Q_cmp` the number of honest complaints, `Q_eph, Q_ephpok, Q_dleq, Q_pop, Q_enc` the numbers of evaluations of those oracles (1.2, query counts), and `Q_H` the number of evaluations of `H_hd` and `H_ct`.

Proof. Games in the order of [GS22] p. 31. `U*, V*` are the ICDH challenge points.

- **Game 0** is `Exp`. Abort if two different inputs of `H_hd`, or two different inputs of `H_ct`, collide (`Q_H²/2^256`; both are random oracles by 1.2). From here `(hd, H_ct(ct))` determines `(hdr, deal, ct)`: a message is a copy of `M` exactly when it has the `(hd, H_ct(ct))` of `M`. Abort also if the adversary evaluated `H_hd` on the `(hdr, deal)` of an honest message, or `Hq_enc` on an input that starts with its `hd`, before the honest dealer wrote the message. `hdr` contains the fresh uniform point `E`, and `hd` is a fresh oracle value: at most `Q_H·Q_msg/q + Q_enc·Q_msg/2^256`.
- **Game 1** (programming, logs still known). Honest node keys are `PK_i = U* + σ_i·G` with `σ_i` uniform. A new adversarial query to `HG_eph` is answered `U* + λ·G`, `λ` uniform. An honest dealer's message uses `E = V* + τ·G`, `τ` uniform, and `HG_eph(hd ‖ H_ct(ct) ‖ E) := ρ·G`, `ρ` uniform in `Z_q*`, so `E' = ρ·E`. All values keep their distributions, except that the game aborts if some `PK_i` or some honest `E` is the identity (the scheme rejects identity points, and `ρ ≠ 0` keeps `E' ≠ O`; at most `(n + 2·Q_msg)/q`, counting the excluded value `ρ = 0`). Programming fails if the adversary queried that input before `E` existed: at most `Q_eph·Q_msg/q`.
- **Game 2.** Honest complaints use simulated DLEQ proofs, and the key-registration proofs of honest nodes (`LD1/pop`, a Schnorr proof of knowledge of `sk_i`) are simulated (Lemma 3): at most `(Q_dleq·Q_cmp + Q_pop·n)/q`. The security argument does not use the registration proofs of corrupt nodes ([GS22] p. 27 note 1 needs no proof of possession); the hop is needed only because honest nodes publish one.
- **Game 3.** For a message with an adversarial `HG_eph` input (programmed as `U* + λ·G`) that passes the ephemeral-key check, honest node `i` computes `K_i := E' + (σ_i − λ)·E`. If the DLEQ statement is true, `E' = dh(U* + λG, E) = dh(U*, E) + λE`, so `E' + (σ_i − λ)E = dh(U* + σ_i G, E) = sk_i·E`, the same value. The statement is false and accepted with probability at most `Q_ephpok/q` (Lemma 3, soundness). In this game every honest proof is still a real proof, so plain soundness is enough for this hop, as [GS22] p. 31 remarks for its own Game 3. That remark does not cover the event `Reuse` of Game 6, which comes after the simulation of Game 4 and has its own argument there.
- **Game 4.** Honest dealers' ephemeral-key proofs are simulated: at most `Q_ephpok·Q_msg/q`. The simulator programs `Hq_ephpok` at the inputs of honest messages and nowhere else, and every simulated proof is a proof of a true statement (`E' = ρ·E`).
- **Game 5.** Ciphertext scalars for corrupt recipients of an honest message are uniform. When the adversary queries `Hq_enc(hd, j, PK_j, K, slot)` for that message and corrupt `j`, with `K` an encoding of an element of `𝔾`, the game asks a DH oracle whether `(PK_j, V*, K − τ·PK_j)` is a DH triple, and if so answers `ct − share`. The triple has the form `(·, V*, ·)`, and `PK_j ∈ 𝔾` by the registration check (C20), so the oracle call is defined. Identical distribution. (The game still knows the logs and could answer the oracle itself.)
- **Game 6.** Two changes at once. Ciphertext scalars for honest recipients of an honest message are uniform and independent, and an honest node that processes an honest message or a copy of one uses its dealt share without decrypting (in Game 5 the decryption gives that share, because a copy has the same `hd`, `E` and ciphertexts and the pad does not depend on `π`; so this part changes nothing). And the game aborts on the event `Reuse` of change (ii). Games 5 and 6 proceed identically until the first of two events:
  - `Reuse`: a message with an honest `E = V* + τG` that is not a copy of an honest message passes the ephemeral-key check. Its `(hd, H_ct(ct))` differs from that of every honest message (Game 0), so its `HG_eph` input is adversarial, `g' = U* + λG`. If its DLEQ statement is true, its `E'` equals `dh(U* + λG, V* + τG)`, so `E' − τ·U* − λ·E = dh(U*, V*)`.

    *Soundness after simulation.* The statement is false and accepted with probability at most `Q_ephpok/q`, although Game 4 has replaced the honest dealers' proofs by simulated ones. [GS22] makes no such second use of soundness: its game forbids a decryption query on the associated data of an encryption query (p. 27), soundness is invoked once, in Game 3, and the paper claims only that soundness and zero knowledge suffice for that sequence (p. 31; p. 56 says the same of its protocol proof: "because we do not need to invoke the soundness property again, we do not require simulation soundness"). Here the second use is justified directly in the random oracle model. Every `Hq_ephpok` input begins with `(hd, H_ct(ct))`. The simulator programmed `Hq_ephpok` only at inputs that begin with the `(hd, H_ct(ct))` of an honest message. The `Reuse` message has another `(hd, H_ct(ct))`, so its challenge input was never programmed: its challenge is a uniform oracle value drawn after `(E, E', T_1, T_2)` were fixed. Lemma 3 (soundness at unprogrammed inputs) then gives the bound `Q_ephpok/q` over all evaluations, exactly as in Game 3. What is used is not simulation soundness of an abstract proof system but the fact that the Fiat-Shamir input contains the statement prefix `(hd, H_ct(ct), E, E')`. The same argument applies to `LD1/rs-ephpok`, whose input has the same prefix structure.
  - `Query`: the adversary queries `Hq_enc(hd, i, PK_i, K, slot)` with `K = dh(PK_i, E)` for an honest `i` and an honest message. Then `K − τ·U* − σ_i·V* − σ_i τ·G = dh(U*, V*)`.

  Why identical until then: before either event, the pad of an honest recipient in an honest message is evaluated only to build the ciphertext. An honest node computes `K_i` in three cases. (1) The message is an honest dealer's or a copy of one: no decryption, the node posts ACK and uses the share. (2) The message has an adversarial `E`: Game 3 gives `K_i`, and its pad inputs contain another `hd` and another `K_i`. (3) The message has an honest `E` and is not a copy: if it passes the check, that is `Reuse`; if not, the node computes nothing.

  `B_C` gets `U*, V*` and runs Game 6 without the logs: keys and `HG_eph` as in Game 1, `K_i` for adversarial messages as in Game 3, simulated proofs (registration, complaint, ephemeral key), backpatching with its DH oracle, uniform scalars for honest recipients. It watches for `Reuse` (it outputs `E' − τ·U* − λ·E`) and tests every `Hq_enc` query for `Query` with its oracle on `(U*, V*, K − τ·U* − σ_i·V* − σ_i τ·G)`, a triple with `V*` among its first two entries (it outputs the third entry on success). So `Pr[Reuse or Query] ≤ Adv^icdh(B_C) + Q_ephpok/q` in Game 5 and in Game 6.

Game 6 is `Exp'` (with keys generated as in Game 1, which changes no distribution; two honest messages share `E` with probability at most `Q_msg²/q`). This gives statement 1. Statement 2: the probability of `Reuse` changes by at most the loss of each hop from Game 0 to Game 5, and in Game 5 it is at most `Adv^icdh(B_C) + Q_ephpok/q`; the sum is at most `Adv^icdh(B_C) + δ_C`. ∎

**Status: proved here, following the game sequence of [GS22] Theorem 2, p. 29 to 32.** It is not a black-box use of that theorem, for the reason in 2.1. The differences from the paper's proof: two hash inputs instead of one `ad`; the `Reuse` event and its soundness argument after simulation, which the paper does not need and does not give; scalar pads; the decryption result leaves a node only as an ACK or a complaint. Limits: static corruption; ICDH and the random oracles `HG_eph`, `Hq_enc`, `Hq_ephpok`, `Hq_dleq`, `Hq_pop`, `H_hd`, `H_ct`; a group of prime order, which for suite 3 rests on the membership checks of C20 ([GS22] states Theorem 2 for a group of prime order, p. 27, and asks for the membership check of receiver keys, p. 76); no proof of possession is needed (as in [GS22] p. 27 note 1). The proof of Theorem 2 in [GS22] is a sketch without a concrete bound ("essentially equivalent" hops, p. 31); `δ_C` is derived here. A proof of delivery inside the message is still absent (§8 gap 1).

After Theorem C an outer reduction generates the honest node keys itself, decrypts normally every message that is not a copy of an honest dealer's message, and sends uniform scalars to honest nodes in honest messages. For an honest message and for each of its copies the honest nodes hold the dealt shares.

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

Symbols.

- `N_A`: the number of group-oracle queries of `A`.
- `S`: the number of open ECDSA slots dealt by honest owners. `S_msg`: the number of honest owner messages. `Q_w`: the number of wallet signatures.
- A slot of an honest message is *live* from its dealing until the first of two moments: (a) the first honest node must post a PARTIAL for it (the reduction then spends its signing request); (b) every honest node is done with it (section 1.1, "Views"). After (b) no honest node holds a share of the slot or will ever post a PARTIAL for it.
- `U`: the largest number of slots of one key that are live at one time. `U` depends on the schedule. One honest node whose view lags keeps a slot live, on a consistent board as much as on an inconsistent one, and the adversary controls the schedule. `U ≤ S` always, and the theorem holds with `U = S`.
- `N_sim`: the number of group operations that the honest parties and the final verification perform, plus `4(t − 1)` two-term multi-scalar multiplications per slot (a scalar multiplication of a point other than `G` costs at most `2·log_2 q` `add` queries).

Then

`Adv^open-ecdsa(A) ≤ ε_lock + Adv^icdh(B_C) + δ_C + δ_A + Q_o·Φ_3(N_A + N_sim + 4S + 2Q_w, U + 1)`,

`δ_A = Q_auth·S_msg/q + S·(θ_q + (2S + 4)/(q − 1))² + 8·Q_w/(q − 1) + 2S/2^256`,

with `ε_lock = 0` on a consistent board and `n·Adv^euf_post` otherwise (Lemma 1), `δ_C` from Theorem C and `θ_q < 2^{−125}` from 1.2. The hash adversaries inside `Φ_3` run in the time of `A` plus the simulation plus `O(U·N)`. The ICDH adversaries are generic-group adversaries for the same curve; their advantage is an assumption here and is not bounded by [GS21].

Proof.

- **Game 0**: the real experiment.
- **Game 1**: abort if honest nodes post PARTIALs for two digests of one `(rid, g)`. Lemma 1: `ε_lock`. From here each slot is signed by honest nodes on one message, fixed by the lock certificate.
- **Game 2**: `Exp'` of Theorem C. Honest ciphertext scalars for honest nodes are uniform, honest nodes use the dealt shares for an owner's message and for every copy of it, and no message that carries an honest `E` without being a copy passes check 9.
- **Game 3**: the authorship half of `π` in honest messages is simulated (Lemma 3): pick `z_a, c`, set `T_a = z_a·G − c·X`, program `Hq_auth`. Loss `Q_auth·S_msg/q`. The ephemeral-key part is still computed with `e`.
- **Game 4**: guess the owner `v` whose key the forgery will name. Factor `Q_o`.

**Reduction `B`** to the game of 3.1, simulating Game 4. `B` gets `(G, D)`, sets `X_v := D`, and generates all other owner keys, all honest node keys and all random oracles itself.

1. *Dealing a slot of `X_v`.* `B` requests a presignature. The honest owner resamples `k` when `r = 0`, when `x(R) ≥ q`, or when the x-coordinate of `R` repeats one in the same message (§3.4 checks 6, 7). `B` does the same: if the request returns `fail` (`r = 0`, Figure 4 step 4(e)) it requests again; if `x(R) ≥ q` or the x-coordinate repeats, it closes the index (step 5) and requests again. This reproduces the owner's rejection sampling exactly. **`B` allows one retry per slot** and aborts if a slot needs a second one. One attempt is rejected with probability at most `θ_q + 4/(q − 1) + 2S/(q − 1)` (the three causes: 1.2; [GS21] p. 10; at most `S` earlier points, two points per x-coordinate), so the abort has probability at most `S·(θ_q + (2S + 4)/(q − 1))²`. With the accepted `R`, `B` picks `w_j, μ_j` uniform for `j ∈ P` and computes by Lemma 2 in base `R`:
   `C_{w,u} = M_{u,0}·G + (Σ_j M_{u,j} w_j)·R`, `C_{μ,u} = M_{u,0}·X + (Σ_j M_{u,j} μ_j)·R`.
   These are `Com_R(p_w)`, `Com_R(p_μ)` for polynomials with `p_w(0)·R = G`, `p_μ(0)·R = X`, that is `p_w(0) = k⁻¹`, `p_μ(0) = k⁻¹x`, and the shares of `P` are distributed as in an honest dealing (Lemma 2, part 2). `B` uses only `G`, `X`, `R` and group-oracle queries.
2. *Ciphertexts and `π`.* `B` picks `e`, so it computes `K_i = e·PK_i` and the true ciphertexts for `i ∈ C`, the uniform scalars of Game 2 for honest `i`, and `E'`, `T_1`, `T_2`, `z_e` honestly. The authorship proof is the simulation of Game 3.
3. *Honest nodes.* `B` runs them as specified. For a message that is not owner-dealt they decrypt with their own keys; every value they then hold was supplied by the adversary (Game 2 has excluded a non-copy with an honest `E`). For an owner's message and for each of its copies they hold the shares of `P \ C` and nothing else; a copy is the same slot `(hd, g, ℓ)` as the original. `B` never asks whether the proof bytes of a copy are the owner's, so this theorem does not use claim 6.
4. *Partials.* When the first honest node must post a PARTIAL for slot `k` with sighash preimage `m`, `B` sends the signing request `(k, m)` and gets `s` (or `fail`, then `s := 0`; §3.8 kills the generation). With `h = Hash(m)` and `r = C̄(R)`, the polynomial `p_s = h·p_w + r·p_μ` has `p_s(0) = s` and `p_s(j) = h·w_j + r·μ_j`. By Lemma 2 part 3, honest node `i` posts `s_i = λ_0(i)·s + Σ_{j∈P} λ_j(i)(h·w_j + r·μ_j)` (directly `h·w_i + r·μ_i` if `i ∈ P`). This is the value the real node posts. By Game 1 every honest PARTIAL for slot `k` uses the same `m`, so one signing request per index suffices, as the game demands ([GS21] p. 21; PROOF-CHECK section 2 condition 2). The slot is live at this moment: a node that must post a PARTIAL is not done with the slot.
5. *Closing a slot.* `B` closes an index in two cases: a rejected presignature of step 1, at once; and a live slot at the moment every honest node is done with it (case (b) of the definition). `B` runs the honest nodes, so it sees each node's view and knows that moment. To close, `B` sends the signing request `(k, ζ)` for a fresh uniform 256-bit string `ζ` and discards the answer. The game allows any message, so this is a legal move; it removes `k` from the set of unused presignatures. `A` never sees anything that depends on `ζ`. After a close no honest node posts a PARTIAL for the slot (1.1, "Views"), so `B` is never asked for a second signing request on the index. The rule is per node on purpose: closing at the first tombstone on the board, or at height `exp` on the board, would be wrong, because a node whose view ends before that position may still see the lock and sign, and on an inconsistent board two nodes may see different logs.
6. *Wallet signatures* of `X_v` on `m`: a presignature request followed at once by the signing request `(k, m)`; `B` returns the normalized signature. Seeing `R` first only adds power to the adversary of the game. If either request returns `fail` (`r = 0` or `h + r·x = 0`; the wallet would draw a new nonce), `B` aborts: at most `8/(q − 1)` per wallet signature ([GS21] p. 10). This models a wallet with a fresh uniform nonce per signature. A wallet with deterministic nonces is modelled as one whose nonce is a uniform function of the message, and a repeated `m` is answered from a table; that the nonce derivation behaves so is an assumption about the wallet.
7. *Output.* When `A` outputs `(X_v, m*, (r*, s*))`, `B` outputs `(m*, (s*, r*))`.

*Faithfulness.* Unless `B` aborts (steps 1 and 6), the view of `A` is the view in Game 4.

*The forgery is fresh.* `B` submitted three kinds of messages to the signing oracle: the locked message of a slot in step 4, which is in `Auth(X_v)` because the slot belongs to an owner-dealt message and an honest node posts a PARTIAL for it; the message of a wallet signature in step 6, also in `Auth(X_v)`; and closing strings in step 5. There are at most `2S` closing strings (one per rejected presignature, at most `S`; one per slot closed unsigned, at most `S`), each uniform and hidden from `A`, so `m*` equals one of them with probability at most `2S/2^256`. If `m* ∉ Auth(X_v)`, then `B` wins whenever `A` does, up to that term.

*Query budget.* A slot costs at most 4 requests: one presignature and one signing or closing request, and the same again for its one allowed retry. (A request that returns `fail` allocates no index and is counted as the retry.) A wallet signature costs 2. So `B` makes at most `4S + 2Q_w` presignature and signing requests and `N_A + N_sim` group queries, with certainty, as [GS21] Theorem 3 requires of `N`. *Unused indices.* `B` works on one request at a time. The unused indices are the live slots, at most `U`, plus at most one more: a presignature of step 1 that is not yet accepted or closed, or the presignature of a wallet signature in step 6. Hence `U + 1`. Theorem 3 of [GS21] gives the bound. ∎

**Status: reduced to [GS21] Theorem 3, p. 24, with the hops proved here.** The hop to the game is black-box and uses no rewinding.

### 3.3 Conditions and limits of Theorem A

1. **EC-GGM only** ([GS21] p. 9). No standard-model or random-oracle-only statement exists for this cell of [GS21] Table 1 (p. 7).
2. **Four hash properties on the real sighash**, including zero-preimage resistance ([GS21] Definition 4; Theorem 3 lists `ZPRadv`). "Ratio resistance is essential" (p. 26 note 2): nothing in the protocol stops the ratio attack; it is assumed infeasible, with a birthday bound if the sighash is a random oracle (p. 23).
3. **The `U·N` terms.** `U·N·RPRadv` in the bound and `O(U·N)` in the running time of the hash adversaries. `U` counts live slots of one key, by step 5, and a slot stays live until every honest node is done with it. An adversary that starves one honest node of board posts keeps every slot live, and then `U = S`, the number of slots ever dealt under the key. The bound of Theorem 3 remains meaningful for `U = S`, but it is weaker than a reading with "live on the board" would suggest. Step 5 is a device of this proof; [GS21] does not mention it, and it is sound because the game of Figure 4 accepts any message in a signing request.
4. **Nodes hash their own preimage.** `B` can only submit a message, never a hash ([GS21] Figure 4 step 5(b)); a node that signed a hash supplied by another party would be outside the theorem, and p. 26 note 1 gives the forgery.
5. **One signing request per presignature** rests on Lemma 1, so on board consistency or on at most `f` Byzantine nodes with unforgeable post keys. With more than `f` Byzantine nodes in profile T2, two digests on one slot give `x` (ledger D7a).
6. **Static corruption**, `|C| ≤ t − 1`. The simulation fixes `P` before the dealing; it does not survive an adaptive choice of `C`.
7. **The base-`R` commitments add nothing.** They are group elements that `B` computes from `G`, `X`, `R` with coefficients independent of `x` and `k`, inside the game. This answers the first "the design is wrong if" item of §11 in the negative, under conditions 1 to 6.
8. **`reshare`** is not covered.
9. **Mixed model** (PROOF-CHECK section 2 condition 6). The sighash is a concrete function with the four properties of item 2; the group is generic; the labelled hashes of §3.1 are random oracles that `B` simulates and programs. `B` is an ordinary adversary of the game of Figure 4, so Theorem 3 applies to it as stated, but the statement "the labelled hashes are random oracles independent of the group encoding and of the sighash" is a modelling assumption that neither paper analyses.
10. **A node that is done with a slot stays done.** Step 5 needs the view rule of 1.1: an honest node's view only grows, and a restored node replays the board to its earlier position before it posts. SCHEME.md §2 keeps a restored node honest under rule 4 of §3.9; C22 adds the replay position and the erasure to that rule. Without it a restored node could hold again a share it had erased, and step 5 would fail.

### 3.4 BIP32-derived keys: [GS21] Theorem 4

If the wallet of `X` also signs under keys `X + δ·G` with `δ` known to the adversary (BIP32 non-hardened siblings, or the parent, with a public chain code), hypothesis (H-key) fails: `B` cannot produce those signatures from the game of 3.1. The governing game is ECDSA with additive key derivation and presignatures ([GS21] section 7.4): master key `D`, a tweak set `E ⊆ Z_q`, signing requests `(k, m_k, e_k)`, forgery on a fresh pair `(m*, e*)`.

**The tweak set must exist before `D`.** [GS21] p. 17: the set `E` of allowed tweaks "is chosen before the attack game starts", and one way to enforce this "is to obtain tweaks as the output of a hash function which is modeled as a random oracle". BIP32 tweaks are not of the first kind: the derivation hashes the compressed parent public key `⟨D + e·G⟩` ([GS21] p. 47), so the tweaks are a function of `D`. Theorem 4 applies to BIP32 only through the second route, and that needs an assumption on HMAC-SHA512. The bundle under review omitted it.

Notation of [GS21] Appendix D (pp. 46 to 47): `H_D((e, c), s) = (e + [a]_q, b)` with `(a, b) = HMAC2(c, ⟨D + e·G⟩ ‖ s)`; the tweak of the path `(s_1, …, s_ℓ)` is the first component of `H_D` iterated from `(0, IV)`, with `IV` the public chain code of `D`.

**Corollary A'.** Assume HMAC-SHA512 is a random oracle. Let `D` be the wallet's master public key for the relevant chain code. Let `𝒫` be a prefix-closed set of non-hardened derivation paths, fixed before the keys are generated, that contains the path of the dealt address key `X` and the path of every key that signs. Let `E_𝒫` be the set of their tweaks. Then Theorem A holds with `Φ_3` replaced by `E[Φ_4(E_𝒫)] + |𝒫|²/2^256 + |𝒫|·((2^256 − q)/2^256 + 1/q)`, where the expectation is over the tweaks and `Φ_4(E)` is the bound of [GS21] Theorem 4 (p. 27) for the tweak set `E`:

`Φ_4(E) = CRadv + (4+o(1))·N_psig·4sum1adv[E] + (4+o(1))·N·|E|·RPRadv + (4+o(1))·N·4sum2adv[E] + U·N·|E|·RPRadv + ZPRadv + O(N²/q)`.

Proof. *The tweaks can be drawn before `D`.* A reduction `B'` draws, for every path in `𝒫` in order of length, a uniform 64-byte value `(a, b)`; if `a ≥ q` (as an integer) it aborts. Otherwise it computes the pair `(e, c)` of that path from its parent's pair: `e = e_parent + [a]_q`, `c = b`. This uses no public key. `B'` declares `E_𝒫` as the tweak set of the game of [GS21] section 7.4 and only then receives `D`. Before it starts `A`, it programs `HMAC2(c_parent, ⟨D + e_parent·G⟩ ‖ s) := (a, b)` for every path of `𝒫` with last component `s`. The programmed inputs are distinct unless two paths of `𝒫` have the same `(e, c)` pair, probability at most `|𝒫|²/2^256` (the chain codes are independent uniform 32-byte strings); `A` has made no query yet, so no programmed point is already defined. Every other HMAC query is answered by lazy sampling. The oracle `A` sees is a random oracle, and the keys of the paths of `𝒫` are derived from `D` exactly as BIP32 derives them. *Invalid children.* BIP32 rejects a child with `a ≥ q` or with derived key `O` and moves to the next index. `B'` instead aborts in both cases: on `a ≥ q` when it draws `a`, and on `D + e·G = O` for some path of `𝒫` once it has received `D`. Given no abort, every `a` is uniform in `[0, q)` and the derived keys are exactly the BIP32 keys of the paths of `𝒫`. Per path, `Pr[a ≥ q] = (2^256 − q)/2^256` (about `2^−127.65` for secp256k1), and given `a < q` the value `e` is uniform in `Z_q` and independent of `D`, so `Pr[D + e·G = O] = 1/q`. Over `𝒫` the abort probability is at most `|𝒫|·((2^256 − q)/2^256 + 1/q)`, the last term of the bound. ([GS21] p. 47 ignores these failures; this proof charges them.)

`B'` makes `O(|𝒫|·log q)` group queries to compute the points `D + e_parent·G`; they are added to `N`. Every wallet signature under a key of `𝒫` other than `X_v` is one presignature and one signing request under its tweak, so `Q_w` counts the signatures of all keys of `𝒫`, and the presignature requests satisfy `N_psig ≤ 2S + Q_w` (one presignature per slot and one per retry, §3.2 query budget, plus one per wallet signature).

*The rest is the reduction `B` of Theorem A*, with `X_v = D + e_X·G`, slot and closing requests under the tweak `e_X`, and a signature of another key of `𝒫` as a presignature request followed by a signing request under that key's tweak. The simulation of the commitments uses `X_v` as a public point, as before. A forgery for `X_v` on `m* ∉ Auth(X_v)` is a forgery on the pair `(m*, e_X)`, which `B` never submitted. Theorem 4 holds for every fixed `E`, hence for `E_𝒫` drawn first. ∎

**Status: reduced to [GS21] Theorem 4, p. 27, under the random-oracle assumption on HMAC-SHA512. The step "the tweaks can be drawn before `D`" is proved here and has had no outside review.** [GS21] Appendix D (pp. 46 to 48) takes another route to the same end: it claims that the BIP32 derivation function is indifferentiable from a public-use random oracle when HMAC is a random oracle, with a proof outline ("From this, the claim follows", p. 48). This document does not use that claim; the programming argument above needs only a fixed path set. Limits.

(i) The bound has the terms `4sum1`, `4sum2` and the factor `|E|`, so it is weaker than `Φ_3`; with `|E|` near `q^{1/3}` the paper gives a forgery in time `q^{1/3}` (p. 28).

(ii) That attack lets the adversary choose the signing tweak after it sees `R`. In line dealing the tweak of a slot is fixed to `e_X` and sibling signatures do not publish `R` in advance, so the bound is not tight for this use. A tighter theorem for "presignatures under one fixed tweak, ordinary signatures under the others" is **open**: [GS21] does not state it and it is not proved here.

(iii) The path set is fixed in advance. An adversary that makes the wallet sign under paths it chooses adaptively is not covered. [GS21] section 7.4.2 (p. 29) gives an alternative analysis for tweaks derived by a hash function `Hash'` "without any further restrictions", with the terms `CRadv[Hash']` and `2sumadv[Hash, Hash']` and with 4sum definitions in which the adversary supplies preimages of the tweaks. Applying it to BIP32, where the derivation function depends on `D`, is **open** here.

(iv) Hardened children are not derived from `D` by a public function. Treating a hardened child key as an independent uniform key, which puts it under Theorem A, is a modelling assumption of this document.

## 4. Open Schnorr: the single-signer two-nonce game (task item 2)

### 4.1 Game TNS (two-nonce Schnorr, one signer, pre-published nonces)

Parameters: suite group `𝔾`; the suite challenge oracle `H_sig`; the sign rule `σ(R) ∈ {1, −1}` (suite 2: `−1` iff `R` has odd y; suite 3: always 1); random oracles `H_dg` (range `{0,1}^256`), `H_b` and `H_auth` (range `Z_q`); a fixed efficient function `msg(ℓ, M)` that reads message number `ℓ` out of a digest preimage `M` (in the protocol: `M` is the input of `LD1/dg` and `msg(ℓ, M) = m_ℓ`, or ⊥ if `ℓ > L'` or `M` is not a well-formed `LD1/dg` input). The function is fixed before the game; the index `ℓ` of a slot is chosen by the adversary when the slot is created, because in the protocol the adversary chooses the header fields `L` and `G` of every honest message (1.1) and with them the input index of each slot.

1. **Key.** `x ← Z_q*`, uniform, `X = x·G` (suite 2: `x` is negated if needed so that `X` has even y). The adversary gets `X`. The clamped key of suite 3 is not uniform; Theorem B' pays the factor `κ_3` of 1.2 for it.
2. **`NewSlot(ℓ)`.** `j ← j + 1`; `ℓ_j := ℓ`; `d_j, e_j ← Z_q*`; return `(D_j, E_j) = (d_j·G, e_j·G)`. At most `U` calls.
3. **`H_b(j, dg)`** returns ⊥ if slot `j` does not exist yet.
4. **`Sign(j, M)`**, at most once per `j`. If `msg(ℓ_j, M) = ⊥` return ⊥. Else `dg = H_dg(M)`, `ρ = H_b(j, dg)`, `m = msg(ℓ_j, M)`, `R = D_j + ρ·E_j`; if `R = O` return ⊥; `c = H_sig(σ(R)·R, X, m)`; return `s = σ(R)·(d_j + ρ·e_j) + c·x`. (Then `s·G = σ(R)·R + c·X`.)
5. **`PlainSign(m)`**: an ordinary suite signature on `m` with a fresh uniform nonce in `Z_q*`.
6. **`Prove(ctx)`**: `a ← Z_q`, `T = a·G`, `c = H_auth(ctx, T)`, return `(T, a + c·x)`.
7. **Winning.** The adversary outputs one of:
   - a *signature forgery* `(m*, sig*)`: `sig*` verifies for `m*` under `X` and `m*` was neither the message of a `Sign` query nor a `PlainSign` query. Verification, as an equation in the prime-order group: suite 2, `sig* = (r*, s*)`, `s*·G = lift_x(r*) + c*·X`, `c* = H_sig(r*, X, m*)`; suite 3, `sig* = (R*, s*)`, `8·s*·G = 8·R* + 8·c*·X`, `c* = H_sig(R*, X, m*)` (the cofactored equation, which every signature valid under the cofactorless equation also satisfies).
   - a *proof forgery* `(ctx*, T*, z*)`: `z*·G = T* + H_auth(ctx*, T*)·X` and `(ctx*, T*)` was not the context and commitment of a `Prove` answer.

`Adv^tns(A)` is the winning probability. The inputs of `H_sig` are encodings: for suite 2 the pair `(R, X)` enters as x-coordinates, so `R` and `−R` give the same input; `σ(R)·R` is the even-y representative.

How the protocol maps to the game: `X` is the owner key; a slot is `(hd, g, ℓ)` with `(D_j, E_j) = (D, E')` of §3.3; `H_b(j, dg)` is `Hq_bind(hd, g, ℓ, dg)`; `Sign` returns `s(0)` of the partial-signature polynomial of §3.8; `Prove` is the authorship half of `π` with `ctx` = every input of `Hq_auth` except `T_a`. `Sign(j, M)` accepts any `M`; the protocol calls it only with the digest preimage that the honest nodes built for the slot, so the game gives the adversary more than the protocol does.

### 4.2 Theorem B (TNS is hard under AOMDL)

Let `A` make at most `U` `NewSlot` calls, `Q_dg, Q_b, Q_sig, Q_auth` direct queries to those oracles, `Q_ps` `PlainSign` and `Q_pr` `Prove` queries. In this theorem the four `Q` values count the adversary's own queries only; the evaluations that `Sign` makes internally, at most `U` of `H_dg` and `U` of `H_b`, are written out as `+ U`. Let `Q := Q_sig + Q_auth + Q_b + U + 1`. There is an adversary `B` against AOMDL with parameter `2U`, running `A` twice, with

`Adv^aomdl_{2U}(B) ≥ acc²/Q − acc/q − 2(Q_b + U)²/q`, where `acc ≥ Adv^tns(A) − δ_B`,
`δ_B = ((Q_dg + U)² + (Q_dg + U)·Q_b)/2^256 + (2·(Q_b + U)·(Q_sig + Q_b + U + Q_ps) + 2·Q_ps·(Q_sig + Q_b + U + Q_ps) + Q_ps + Q_pr·(Q_auth + Q_pr) + 2U + 1)/q`.

So `Adv^tns(A) ≤ δ_B + Q/q + sqrt(Q·(Adv^aomdl_{2U}(B) + 2(Q_b + U)²/q))`.

Proof.

**Process `W`.** Input: points `Y_0, …, Y_{2U}` and the oracle `DL`. `W` sets `X := ±Y_0` (sign chosen for even y in suite 2), `D_j := Y_{2j−1}`, `E_j := Y_{2j}`, and runs `A`. If some `Y_i = O`, `W` stops with `J = 0` (`(2U + 1)/q`). The values `h_1, h_2, …` of Lemma 4 are the challenges `c` that `W` assigns as follows; everything else is `W`'s own coins.

- `H_dg(M)`: lazy uniform value. There are at most `Q_dg + U` evaluations, `U` of them inside `Sign`. Stop (`J = 0`) on a collision between two inputs (`Coll`, at most `(Q_dg + U)²/2^256`), or if the new value equals the `dg` of an earlier `H_b` query that was *unresolved* (below) (`Late`, at most `(Q_dg + U)·Q_b/2^256`; only a direct query of `A` can be unresolved).
- `H_b(j, dg)`, new input, slot `j` exists (at most `Q_b + U` evaluations, `U` of them inside `Sign`): draw `ρ` uniform (a coin). Look for `M` with `H_dg(M) = dg` in the table. If there is none, or `msg(ℓ_j, M) = ⊥`, mark `(j, dg)` unresolved and return `ρ`. Otherwise let `m = msg(ℓ_j, M)`, `R = D_j + ρ·E_j`; if `R = O` mark the pair dead and return `ρ`. Else let `R~ = σ(R)·R`. If `H_sig(R~, X, m)` is already defined, stop (`Pre`). Otherwise take the next value `h_i` and set `H_sig(R~, X, m) := h_i`; the pair `(j, dg)` is *resolved* with `(ρ, c = h_i)`. Return `ρ`.
  `Pr[Pre]`: `ρ` is uniform and independent of the earlier `H_sig` inputs, and `D_j + ρ·E_j = ±P` has at most two solutions `ρ` for each earlier point `P` (two in suite 2, where `P` and `−P` give one input; one in suite 3). The table holds at most `Q_sig + Q_b + U + Q_ps` entries, and the event can happen in each of the `Q_b + U` evaluations, those inside `Sign` included: at most `2·(Q_b + U)·(Q_sig + Q_b + U + Q_ps)/q` in total.
- `H_sig(·)` and `H_auth(·)`, new input queried by `A`: the next `h_i`.
- `PlainSign(m)`: pick `z, c` (coins), `R = z·G − c·X`. Stop if `R = O` (the game's nonce is never 0; `1/q` per query, `Q_ps/q` in total). In suite 2, if `R` has odd y, replace `(z, c)` by `(−z, −c)`, which replaces `R` by `−R` and keeps `c` uniform. Program `H_sig(R, X, m) := c` and return `(R, z)`. Stop if the input is defined: `R` is uniform, and it meets a given earlier entry with probability at most `2/q` (`R = ±P` in suite 2), so at most `2·Q_ps·(Q_sig + Q_b + U + Q_ps)/q` in total. A wallet with deterministic nonces is covered by answering a repeated `m` from a table, under the assumption that its nonce is a uniform function of the message.
- `Prove(ctx)`: pick `z, c`, `T = z·G − c·X`, program `H_auth(ctx, T) := c`. Stop if the input is defined. `H_auth` is a separate oracle with at most `Q_auth + Q_pr` entries, and `T` is uniform: at most `Q_pr·(Q_auth + Q_pr)/q` in total.
- `Sign(j, M)`: if `msg(ℓ_j, M) = ⊥` return ⊥. Query `H_dg(M)` and then `H_b(j, dg)` internally if they are new. The pair `(j, dg)` is now resolved or dead: it cannot be unresolved, because an unresolved pair whose `dg` later becomes the hash of some `M` is the event `Late`, and if `M` was in the table when `H_b(j, dg)` was first queried the pair was resolved then. Dead: return ⊥. Resolved with `(ρ, c)`: one oracle call
  `s := DL(coefficients of R~ + c·X) = σ(R)·(d_j + ρ·e_j) + c·x`,
  with coefficient `σ(R)` on `Y_{2j−1}`, `σ(R)·ρ` on `Y_{2j}`, `±c` on `Y_0`. Return `s`.
- Output of `A`. Signature forgery: `W` makes sure `H_sig` is defined at the forgery's input (one more `h_i` if not) and outputs `J` = the index of the `h` value stored there. The input is not one programmed by `PlainSign`, because `m*` was not plain-signed. Proof forgery: the same with `H_auth` and `(ctx*, T*)`, which no `Prove` answer programmed. If the forgery is invalid, `J = 0`.

Unless `W` stops, `A` sees exactly game TNS: every oracle value is uniform and assigned once; `Sign` returns the game's value; `PlainSign` and `Prove` are the perfect simulations of Lemma 3; `d_j, e_j ≠ 0` and `x ≠ 0` hold except with probability `(2U + 1)/q`. Hence `acc ≥ Adv^tns(A) − δ_B`: the terms of `δ_B` are, in order, `Coll`, `Late`, `Pre`, the `PlainSign` programming, `R = O` in `PlainSign`, the `Prove` programming, and the identity points. At most `Q` values `h_i` are delivered.

Two checks of `δ_B` against small cases. (1) `Q_b = Q_dg = Q_ps = Q_pr = Q_auth = 0`, one slot: `A` queries `H_sig` at the `Q_sig` points `D_1 + k·E_1` and then calls `Sign`; the internal `H_b` draw hits one of them with probability up to `2·Q_sig/q`, and `δ_B ≥ 2·U·(Q_sig + U)/q ≥ 2·Q_sig/q`. (2) `U = Q_b = 0`, `Q_ps = 1`, `Q_sig = K` earlier queries for one message: the simulated nonce hits one with probability up to `2K/q`, and `δ_B ≥ 2·(K + 1)/q`. The bound in the bundle under review counted neither case in full.

The step that defeats the ROS-type search is in `H_b`: the challenge `c` of a slot and a digest is fixed in the same step as `ρ`, before the adversary sees `ρ`, so `(R, c)` for the pair `(j, dg)` never changes afterwards.

**`B`** runs `Fork` on `W` (Lemma 4), caching `DL` answers: a repeated coefficient vector costs no new call. Suppose `J' = J ≥ 1` and `h_J ≠ h'_J`.

*Extraction of `x`.* The two runs are identical up to the delivery of `h_J`. The oracle input that receives value number `J` is fixed before the delivery, so it is the same in both runs: the same `(R~*, X, m*)`, or the same `(ctx*, T*)`. In the signature case both runs give a valid forgery at that input: `s*·G = R_0 + c*·X` and `s'*·G = R_0 + c'*·X` with the same prime-order point `R_0` (suite 2: `R_0 = lift_x(r*)`. Suite 3: write `R* = R_0 + T` with `T` of order dividing 8; the cofactored equation gives `8(s*·G − R_0 − c*·X) = O` in the prime-order subgroup, hence `s*·G = R_0 + c*·X`; a torsion component in a forged `R*` changes nothing, because the encoding of `R*` is part of the fixed hash input). So `x = (s* − s'*)/(c* − c'*)`. The proof case is the same with `T*` and `z*`.

*No signed pair sits at the fork.* If value `J` was assigned inside an `H_b` query for a pair `(j, dg)`, then `m* = msg(ℓ_j, M)` for that pair. Had either run signed that pair, `m*` would be the message of a `Sign` query in that run and the forgery of that run would be invalid. So in both runs every signed pair has its challenge index different from `J`.

*Slot accounting.* Fix a slot `j`. Each run signs it at most once. A signed pair costs one `DL` call and gives one equation `d_j + ρ·e_j = σ·(s − c·x)` with known `ρ, σ, s, c` once `x` is known.

| Case for slot `j` | `DL` calls on signing | What `B` knows, what it adds |
|---|---|---|
| signed in neither run | 0 | `B` calls `DL` on `D_j` and on `E_j`: 2 calls |
| signed in one run only; or in both runs on the same pair `(j, dg)` resolved before the fork (same `ρ`, same `c`, same coefficient vector, cached) | 1 | one equation; `B` calls `DL` on `E_j` and solves for `d_j`: 2 calls in all |
| signed in both runs on pairs with different `ρ`: two different pairs resolved before the fork, or one before and one after, or both after | 2 | two equations with `ρ_1 ≠ ρ_2`: solve for `d_j, e_j` |
| a dead pair (`R = O`) in a run | 0 for that run | the relation `d_j = −ρ·e_j`; treated as an equation at no cost |

A pair resolved before the fork has the same `(ρ, c)` in both runs, since both of its values precede `h_J` (its challenge index is not `J` by the previous paragraph, and `ρ` is drawn just before its challenge). Two pairs have equal `ρ` only if two independent uniform draws coincide: all draws of one run plus the post-fork draws of the other are at most `2(Q_b + U)`, so this fails with probability at most `2(Q_b + U)²/q`.

In every case `B` spends at most 2 `DL` calls per slot, `2U` in all, every call is on a declared combination of the challenge points (so the reduction is algebraic), and `B` outputs `x` (hence `log Y_0`) and all `d_j, e_j`: `2U + 1` logarithms. Lemma 4 gives the bound. ∎

**Status: proved here.** Both reviews checked Lemma 4, the extraction and the slot accounting and reported no defect in them; `δ_B` and the slot index `ℓ_j` are corrected after those reviews. The slot index changes nothing in the proof: `H_b(j, dg)` and `Sign(j, M)` exist only once slot `j` does, and `ℓ_j` is fixed at that moment, before the fork point of any value assigned for the slot. Assumption: AOMDL with parameter `2U`, where `U` is the total number of open Schnorr slots ever dealt under `X` (not the number live at one time), plus the random oracles of 4.1. The reduction forks once and loses a square root. Not compared with the unobtained papers (section 0). Covered: the BIP340 sign flip (through `σ` and the x-only hash input), the Ed25519 challenge and cofactor (above), ordinary wallet signatures under the same key, and the authorship proof under the same key.

Why two nonces: with one nonce per slot, `R = D_j` is known before the message, the `H_b` step does not exist, and `W` cannot fix `c` before the adversary chooses among messages; PROOF-CHECK section 3 records the ROS-type attack for that case from the local FROST and Sparkle+ papers.

### 4.3 Theorem B' (claim 4 for suites 2 and 3)

Suites 2 and 3, the model of 1.1. `S` is the number of open Schnorr slots dealt by honest owners under the target key, `S_msg` the number of honest messages, `Q_bind` the number of `Hq_bind` evaluations, and the other symbols are as in Theorems A and C. Then

`Adv^open-schnorr(A) ≤ ε_lock + Adv^icdh(B_C) + δ_C + δ_B' + κ·Q_o·Adv^tns(A')`,

`δ_B' = Q_bind·S_msg/2^256 + 4S²/q`,

with `κ = κ_2 = 1` for suite 2 and `κ = κ_3 < 2 + 2^{−126}` for suite 3 (1.2). `A'` makes `S` `NewSlot` calls, at most one `Sign` query per slot, `Q_w` `PlainSign` queries and one `Prove` query per honest message, and Theorem B bounds `Adv^tns(A')`.

Proof. Games 1, 2 and 4 of Theorem A (Lemma 1, Theorem C, the guess of the owner). `A'` plays TNS for `X_v` and generates everything else.

- *Key distribution.* TNS has a uniform key. Suite 2: the dealt scalar is uniform up to the sign normalization that TNS also applies. Suite 3: the dealt key is uniform on `S_clamp` (1.2, under the seed-hash assumption). For any adversary, the winning probability of TNS conditioned on `x ∈ S_clamp` is at most `κ_3` times the unconditioned one, since `Pr[x ∈ S_clamp] = 1/κ_3`. So the experiment with the clamped key is bounded by `κ_3·Adv^tns(A')`. For suite 3 the wallet's `PlainSign` is modelled with a nonce that is a uniform function of the message (RFC 8032 derives it from the other half of the seed hash; from memory), as in Theorem B.
- *Dealing.* When the owner of `X_v` writes a message with header fields `(L, G)` chosen by `A`, `A'` calls `NewSlot(ℓ)` once for each `(g, ℓ)`, `g = 1..G`, `ℓ = 1..L`. If two slot points of one message share an x-coordinate (the case in which the owner of §3.4 check 7 resamples), `A'` aborts: among the `2S` points, each pair collides with probability at most `2/(q − 1)`, in total at most `4S²/q`. `A'` picks `x_{j'}, d_{j,j'}, e_{j,j'}` uniform for `j' ∈ P` and computes `Com_G(p_x)`, `Com_G(p_d)`, `Com_G(p_e)` by Lemma 2 with `F = X`, `D_j`, `E_j` and base `G`. Each message has its own polynomial for `x`, as in §3.3.
- *Ciphertexts and `π`.* As in Theorem A step 2; the authorship proof is the answer of `Prove(ctx)` with `ctx = (hd, H_ct(ct), E', T_1, T_2, z_e)`.
- *Oracles.* `Hq_bind(hd, g, ℓ, dg)` for the `hd` of an honest message of `X_v` is `H_b(j, dg)` with `j` the slot of `(hd, g, ℓ)`; for any other `hd` it is `A'`'s own random function. The map is well defined unless two honest messages share `hd`, or `A` evaluated `H_hd` on an honest message's `(hdr, deal)` before the message existed (both inside `δ_C`, Game 0 of Theorem C), or `A` queried `Hq_bind` with an honest `hd` before the message existed (`hd` is then a fresh oracle value: `Q_bind·S_msg/2^256`). `LD1/dg` is `H_dg`, `Hq_auth` is `H_auth`, the suite hash is `H_sig`.
- *Honest nodes on messages that are not owner-dealt.* They decrypt with their own keys and compute partials from the values they hold; every such value was supplied by the adversary, and `A'` makes no `Sign` query for them. Their `Hq_bind` values come from another `hd`.
- *Honest nodes on the owner's messages and their copies.* A copy has the `hd` of the original, hence the same slots `(hd, g, ℓ)`, the same binding factors and the same shares. `A'` treats it as the original. `A'` never asks whether the proof bytes of a copy are the owner's, so the theorem does not use claim 6.
- *Partials.* When the first honest node must post a PARTIAL for slot `j` of an owner-dealt message under the locked digest with preimage `M`, `A'` calls `Sign(j, M)` and gets `s` (⊥: the generation is dead, §3.8). The partial polynomial is `p_s = σ·(p_d + ρ·p_e) + c·p_x` with `p_s(0) = s`, and honest node `i` posts `λ_0(i)·s + Σ_{j'∈P} λ_{j'}(i)·(σ·(d_{j,j'} + ρ·e_{j,j'}) + c·x_{j'})`. One `Sign` query per slot by Game 1.
- *Output.* A forgery `(X_v, m*, sig*)` with `m* ∉ Auth(X_v)` is a signature forgery in TNS: every message of a `Sign` query is the message of a slot of an owner-dealt message for which an honest node posts a PARTIAL, and every `PlainSign` message was plain-signed, so all of them are in `Auth(X_v)`. ∎

**Status: reduced to Theorem B (proved here).** Limits: static corruption; `|C| ≤ t − 1`; at most `f` Byzantine nodes or a consistent board (Lemma 1); `reshare` not covered; for suite 3 the seed-hash assumption and the factor `κ_3`. Two digests on one slot do not give `x` for this suite (ledger D7(b2)); three do.

## 5. Sealed points stay sealed below `t` (claim 3)

**Theorem D.** Any suite, sealed mode, the model of 1.1 with `|C| ≤ t − 1` and any number of Byzantine nodes among `C`. Let `Q_pt` be the number of sealed points dealt by honest owners. Then

`Adv^sealed(A) ≤ Adv^icdh(B_C) + δ_C + Q_auth·S_msg/q + Q_o·Q_pt·Adv^euf-cma_suite(B_3)`.

Recall that `A` wins with a valid signature on a message outside `Auth(X_v)`: a message for which no honest node released a partial of any sealed point of an owner-dealt message and which the wallet did not sign. The owner's sealing signatures are made by the suite's signing algorithm, the one the EUF-CMA oracle runs (§3.3: the owner "signs `m` in the ordinary way").

Proof. Game 1: `Exp'` of Theorem C. Game 2: guess the owner `v` and one sealed point `(j*, ℓ*)` of one of its messages; the guess is right if the forgery message `m*` is that point's message (if `m*` is the message of no honest sealed point, any guess works: then `B_3` below never needs the target). `B_3` gets `X_v` from the EUF-CMA challenger.

- A sealed point whose message differs from the target's message `m_t`: `B_3` asks its signing oracle, recovers `R` (suite 1: `R = s⁻¹(h·G + r·X)`, §3.3), and deals `Share_t(s)` honestly.
- A sealed point with message `m_t` (the target, and any other honest point with the same message): `B_3` does not query. It picks `R = k·G` with `k` uniform, resampling until the checks of §3.4 hold, as the owner does. If the signing algorithm is deterministic, its nonce for `m_t` is modelled as a uniform function of the message (the assumption of Theorem A step 6), and `B_3` uses one `R` for every honest point with message `m_t`. `F_0 = R + c·X` (suites 2, 3) or `h·G + r·X` (suite 1) is public. It picks `s_j` uniform for `j ∈ P` and computes the commitments by Lemma 2 with base `G` (suites 2, 3) or base `R` (suite 1) and `F = F_0`. The committed constant term is the real signature for that `R`; the distribution is that of an honest dealing.
- `π`: the ephemeral-key part is honest. The authorship proof (knowledge of `s_{1,1}`) is honest if `B_3` knows `s_{1,1}` and the simulation of Lemma 3 otherwise (`Q_auth·S_msg/q`).
- Honest nodes on a message under `X_v` that is not owner-dealt (for example one that wraps a released signature and adds points whose signatures nobody knows): they decrypt with their own keys and release what the adversary dealt them. `B_3` needs no oracle query and no target share for this, and such releases put nothing into `Auth(X_v)`.
- Honest nodes on the owner's messages and their copies: uniform ciphertext scalars (Game 1), and the same dealt shares for a copy as for the original. In sealed mode a copy with other proof bytes can exist: whoever knows `s_{1,1}` can write a new authorship proof (Theorem E(c)). `B_3` treats a copy as the original and never asks who wrote its proof bytes. A release through a copy puts the released message into `Auth(X_v)`, as a release through the original does; this is the case that the definition of section 1.1 exists for. (With `Auth` restricted to byte-identical owner messages the theorem would be false: an adversary that learns `s_{1,1}` from the wallet posts a copy with its own proof, the honest nodes release another variant through it, and that variant would count as a forgery.) A point with message `m_t` is never released by an honest node while `m_t ∉ Auth(X_v)`; if an honest node must release such a point, `m_t ∈ Auth(X_v)`, the guess was wrong, and `B_3` stops. All other points have known polynomials.
- Wallet signatures: the signing oracle.

`B_3` never queries `m_t`, so a forgery on `m* = m_t` wins EUF-CMA. ∎

**Status: proved here, given Theorem C and the standard unforgeability of the suite scheme (an assumption; for ECDSA, [GS21] Theorem 1, p. 16, proves it in the EC-GGM).**

Two points about the statement.

1. **It replaces the statement of §6.4.** §6.4 says the adversary cannot output a signature "for which honest nodes released fewer than `t − |C|` partials". The simulator knows the shares of the honest nodes of `P \ C` and of no other honest node, and `P` is fixed before the adversary chooses which honest nodes release. Proving the §6.4 form needs a guess of that subset, a loss of `binomial(n − |C|, t − 1 − |C|)`, which is not polynomial in general. Theorem D proves the form "no honest node released a partial for that message". This is the form `F_OMS` needs: an honest node releases a variant only when `Select` names it at the node's own eligible anchor (§3.7), so one honest partial already means the release was authorized. The §6.4 form is **open**; nothing else in SCHEME.md depends on it.
2. **Messages, not points.** If the owner seals the same transaction in two requests, releasing one releases a signature on the message of the other. `Auth` is defined on messages for this reason.

Claim 2 (fully corrupt committee) is the same reduction without Theorem C and without a target: `B_3` queries every variant and deals honestly, and a forgery outside the variant messages and the wallet's messages wins EUF-CMA. Status: proved here, same assumption.

If one key is used in sealed and open mode together, Theorem D still holds with EUF-CMA replaced by game TNS (suites 2, 3: `B_3` uses `PlainSign` for the non-target points) or by the game of 3.1 (suite 1: a presignature request followed at once by the signing request); the reduction `B_3` is black-box and does not rewind. Theorem E(c) is black-box too and holds for any key. Theorem E(c′) rewinds, and is stated only for a key that is not used in open mode (section 8, item 4).

## 6. Authorization (claim 6; task item 4)

The authorship proof after corrections C3 and C19: `c_a = Hq_auth(hd ‖ H_ct(ct) ‖ E' ‖ T_1 ‖ T_2 ‖ z_e ‖ T_a)` and `z_a·B = T_a + c_a·Y`, with `(B, Y) = (G, X)` in open mode and `(B, Y) = (G or R_{1,1}, F_0^{(1,1)})` in sealed mode. `c_a` covers every byte of the message except `z_a`, including all four values of the ephemeral-key proof, and `z_a` is the unique solution of the verification equation. So a message with unchanged `(hdr, deal, ct)` and any altered proof byte needs a new valid pair `(T_a, z_a)`: a new proof of knowledge of `x` (open) or of `s_{1,1}` (sealed).

Open-mode unforgeability (Theorems A, B') and Theorem D do not use claim 6: a copy of an owner's message counts as the owner's (section 1.1), and an honest node's partial on any other message is computed from shares the adversary supplied. Claim 6 is a separate statement about squatting, mauling and voiding.

### 6.1 Theorem E

Model of 1.1. Let `M` range over messages written by honest owners. `Q_rid` is the number of `H_rid` evaluations.

(a) **Open mode, suites 2 and 3: byte identity.** The probability that a message with header key `X_v` passes §3.4 check 9 and is not byte-identical to a message written by the owner of `X_v` is at most `ε_lock + Adv^icdh(B_C) + δ_C + δ_B' + κ·Q_o·Adv^tns(A')`, with `A'`, `δ_B'` and `κ` as in Theorem B'.

(b) **Open mode, suite 1: byte identity.** The same event has probability at most `ε_lock + Adv^icdh(B_C) + δ_C + δ_A + Q_o·(Q_auth·(U + 2)/(q − 1) + O((N + Q_auth)²/q))`, in the EC-GGM, with `N = N_A + N_sim + 4S + 2Q_w` and `U` as in Theorem A.

(c) **Sealed mode, any key: dealing identity.** The probability that a message passes §3.4 check 9, has the `rid` of an honest sealed message `M`, and is not a copy of `M` is at most `Adv^icdh(B_C) + δ_C + Q_rid²/2^256`.

(c′) **Sealed mode: byte identity under added hypotheses.** Hypotheses: (H1) the key is used in sealed mode and by the wallet, and not in open mode; (H2) the suite's signing algorithm draws a fresh uniform nonce for every signature, and the owner's sealing signatures and the wallet's signatures are made by it; (H3) the suite scheme is SUF-CMA (ECDSA: up to sign). Let `ε` be the probability that a message `M' ≠ M` with the `rid` of an honest sealed message `M` passes checks 1 to 9. Let `Q_s` be the number of signatures the signing algorithm produces in the experiment and

`ε' = (ε − Adv^icdh(B_C) − δ_C − Q_rid²/2^256 − Q_auth·S_msg/q − S_msg·(Q_auth/2^256 + Q_H/(q − 1)))/(Q_o·S_msg)`.

Then `ε'²/Q_auth − ε'/q − 4·Q_s/(q − 1) ≤ Adv^suf-cma_suite(B_4)`.

Without (H2) the statement is false; see the counterexample after the proof.

(d) **No void by a third party.** In the whole experiment, the probability that some complaint against an owner-dealt message (an honest owner's message or a copy) is accepted is at most `Q_dleq/q`.

Proof.

*Common step.* If `M'` passes and has the same `Hq_auth` input as an honest message `M`, then (no collision in `H_hd` and `H_ct`, inside `δ_C`) it has the same `hdr, deal, ct, E', T_1, T_2, z_e, T_a`, hence the same `c_a` and the same `z_a`: `M' = M`. So a passing message that is not byte-identical to an owner's message has an `Hq_auth` input that no honest proof used, and its `(T_a, z_a)` is a valid proof at a challenge that the simulation never programmed.

(a) Run the reduction `A'` of Theorem B' and stop at the first message under `X_v` that passes check 9 and is not byte-identical to an owner's message. The message gives `(ctx*, T_a, z_a)` with `z_a·G = T_a + H_auth(ctx*, T_a)·X_v` and `(ctx*, T_a)` not from a `Prove` answer: a proof forgery in TNS. This covers a copy with altered proof bytes as well as a message with another dealing.

(b) Lemma 5 below, applied to the reduction `B` of Theorem A: `B` answers each new `Hq_auth` query of `A` with `Chal(T_a)`, where `T_a` is the last field of the query (a uniform value if that field is not a point), and programs the points of its own simulated proofs as before. A passing message that is not byte-identical to an owner's message is a win in the extended game. The `Q_auth` calls to `Chal` are queries of the extended game: each can register a new point in the encoding table, so the collision term of Lemma 5 is `O((N + Q_auth)²/q)` with `N` the query count of Theorem A, which does not include them.

(c) Sealed mode has `tie = hd`, and the input of `H_rid` is a concatenation of fixed-width fields (§3.1). If no two inputs of `H_rid` collide (`Q_rid²/2^256`; a random oracle by 1.2), a message `M'` with the `rid` of `M` has the `hd` of `M`. If no two inputs of `H_hd` collide (inside `δ_C`), `M'` has the `hdr` and the `deal` of `M`, in particular the `E` of `M`, since `E` is a header field. If `M'` is not a copy of `M`, its `ct` differs. Its `hd` differs from that of every other honest message, so it is a copy of no honest message, and it carries the honest `E` and passes the ephemeral-key check (part of check 9): that is the event `Reuse`. Theorem C, statement 2, bounds it by `Adv^icdh(B_C) + δ_C`. No assumption on the signature scheme is used, and nothing is rewound. ∎ for (c)

(c′) By (c), up to its bound, `M'` is a copy of `M`: it has the `deal` of `M`, and `F_0^{(1,1)}` is the constant term of `M`'s first sealed point. Guess `v` and `M` (factor `Q_o·S_msg`). `B_4` runs the reduction `B_3` of Theorem D against a SUF-CMA challenger with one change of targets: the only target is point `(1,1)` of `M`, for which `B_4` picks `R = k·G` with `k` uniform itself (by (H2) this is the real distribution) and simulates the commitments by Lemma 2; every other sealed point, including points of other messages that carry the message `m_{1,1}`, and every wallet signature, comes from the signing oracle, which SUF-CMA allows also for `m_{1,1}`. The authorship proof of `M` is simulated (`Q_auth·S_msg/q`). `B_4` runs until `M'` passes checks 1 to 9. Check 5 says `rid` is not yet bound, so no honest node has yet released a point of `M`, and `B_4` never needs a share of the target outside `P`. The `Hq_auth` input of `M'` contains the `hd` of `M`. It was first evaluated after `M` was written, except with probability `S_msg·(Q_auth/2^256 + Q_H/(q − 1))` (`hd` is a fresh oracle value unless `H_hd` was evaluated on `(hdr, deal)` before the owner drew the nonce points in `deal`), and by the common step it is not the input that the simulation programmed.

Apply Lemma 4 with the `Hq_auth` answers as the values `h_i` (at most `Q_auth`) and `J` the index of the answer at the input of `M'`; the signing oracle is handled by cached replay and fresh queries. The fork point lies after the writing of `M`, so both runs have the same `M`, the same `R` and the same `F_0^{(1,1)}`. Two accepting proofs at the same input with different challenges give `s = (z_a − z'_a)/(c_a − c'_a)` with `s·B = F_0^{(1,1)}`: the signature on `m_{1,1}` with the nonce `R` that `B_4` chose. It is a SUF-CMA forgery unless the signing oracle returned a signature on `m_{1,1}` equal to it, for ECDSA equal up to sign. That needs an oracle nonce equal to `±k`. The oracle's nonces are uniform and independent of `k` (H2), there are at most `2·Q_s` oracle signatures over the two runs, and each has a nonce in `{k, −k}` with probability at most `2/(q − 1)`: at most `4·Q_s/(q − 1)`. Lemma 4 gives `ε'²/Q_auth − ε'/q` for the fork, and the forgery term is subtracted. ∎ for (c′)

*Counterexample without (H2)* (review cand-c, finding 2). Let the wallet be deterministic (RFC 8032, or RFC 6979 for ECDSA; from memory) and let the owner seal with it. `A` chooses the intent, computes `m_{1,1}`, asks `PlainSign(m_{1,1})` and receives the very `(R_{1,1}, s_{1,1})` that the owner seals. `A` takes the owner's `M` from the wire before it is bound, writes a new authorship proof `(T'_a, z'_a)` with its knowledge of `s_{1,1}`, and posts the copy first. The copy passes with probability 1, and no SUF-CMA forgery arises, because `s_{1,1}` is an oracle answer. The same holds for any party that the owner showed the first signature to. This is why byte identity is not claimed in general, and why (c) is the statement that §6.7 uses.

(d) A complaint is accepted when `K` passes the membership check of C20, carries a valid `DLEQ(G, PK_i; E, K)`, and the share decrypted with `K` fails its check. `G`, `PK_i` (registration check), `E` (§3.4 check 2) and `K` are elements of the prime-order group `𝔾`, so the statement `log_G PK_i = log_E K` is well defined and Lemma 3 applies. With `K = sk_i·E` the share of an owner-dealt message passes: a copy has the owner's `E`, commitments and ciphertexts, and the pad does not depend on `π`. A `K ≠ sk_i·E` makes the DLEQ statement false. In the real experiment no `Hq_dleq` input is programmed, and `Q_dleq` counts every evaluation, including those of the verifiers, so the probability that any false statement is accepted is at most `Q_dleq/q` in total (Lemma 3). ∎

*Why (d) needs C20* (review cand-c, finding 10). Without the membership check, in suite 3 a corrupt node can register `PK_j = sk_j·G + T` with `T` of order 2. For an odd `e` the owner's pad uses `K_j = e·PK_j = e·sk_j·G + T`, while the node complains with `K'_j = sk_j·E`, a different point, and the cofactorless DLEQ equations hold for it whenever the challenge is even. The honest owner's request is voided with constant probability. With C20 the key `PK_j` is rejected at registration.

**Lemma 5 (the authorship proof next to the presignature oracle, EC-GGM).** Extend the game of [GS21] Figure 4 with an oracle `Chal(T)`: it registers `T` in the encoding table if needed (as step 3(a) of the figure does for an unknown point), draws `c ← Z_q`, records `(T, c)` and returns `c`. The adversary also wins if it outputs a recorded `(T, c)` and `z` with `z·G = T + c·D`. For an adversary with at most `N` queries in all, `Q_c` of them to `Chal`, and at most `U` unused presignatures at one time, the probability of this second kind of win is at most `Q_c·(U + 1)/(q − 1) + O(N²/q)`.

Proof. The proof of [GS21] Lemma 2 (Appendix B, pp. 42 to 45) shows that the lazy and the symbolic simulation proceed identically unless an event `Z` of probability `O(N²/q)` occurs. Adding `Chal` changes neither claim: the values `c` are independent of `d` and of the `r_k`, so the coefficients of the polynomials in `Domain(π)` stay independent of them; a `Chal` query adds at most two entries to the table, as an `add` query does, which is why `N` counts the `Chal` queries. Work in the symbolic simulation of [GS21] Figure 5.

At the time of `Chal(T)` the preimage of `T` is a polynomial `P_T = a + b·D + Σ_{k∈K_T} c_k·R_k` with `c_k ≠ 0` and `K_T` a set of unused presignatures, `|K_T| ≤ U`; `c` is drawn after `P_T` is fixed. Later signing requests substitute `R_k ↦ s_k⁻¹(h_k + t_k·D)` with `s_k` uniform in `Z_q*` and independent of everything before (Figure 5, step 5(c)); `t_k ≠ 0` (step 4(d)). The final check holds in the symbolic game exactly when the polynomial `P_T` after all substitutions equals `z − c·D`. That needs every `R_k`, `k ∈ K_T`, substituted, and for the coefficient of `D`:

`b + Σ_{k∈K_T} c_k·t_k/s_k = −c`.

If `K_T` is empty this is `b = −c`, probability `1/q`. Otherwise let `k'` be the element of `K_T` substituted last. Just before that substitution every other term and `c` are fixed, and exactly one value of `s_{k'}⁻¹` satisfies the equation: probability at most `1/(q − 1)`. `k'` is not known in advance; a union over the at most `U` candidates gives `U/(q − 1)` per `Chal` query. ∎

In (b) the count is `U + 2` because the reduction of Theorem A has at most `U + 1` unused indices, and the total query count of the extended game is `N + Q_auth`. Lemma 5 is stated for the game without key derivation, so (b) holds under hypothesis (H-key). With signing BIP32 siblings the substitution of [GS21] section 7.4 is `R_k ↦ s_k⁻¹(h_k + t_k·e_k + t_k·D)`; the coefficient of `D` is still `t_k/s_k`, and [GS21] p. 26 states that its Lemma 2 goes through unchanged, so the same argument gives the same bound. I have checked this substitution only; a written proof for the derived-key game is not included.

**Status.**

| Part | Status |
|---|---|
| (a) open, suites 2 and 3 | **reduced to Theorem B (proved here)**: the authorship proof is inside game TNS |
| (b) open, suite 1 | **proved here** in the EC-GGM, as an extension of the symbolic simulation of [GS21] (Figure 5, p. 23; Lemma 2, p. 22 and pp. 42 to 45). It is not a black-box corollary of Theorem 3: a rewinding extractor would ask two signatures on one presignature, which the game forbids. Both reviews checked Lemma 5 and found it correct as stated; the query count in (b) is corrected after review cand-c, finding 5 |
| (c) sealed, dealing identity | **reduced to Theorem C (proved here)**, plus collision-freedom of `H_rid`. No unforgeability assumption, any key, any wallet |
| (c′) sealed, byte identity | **proved here** under (H1) to (H3), with a forking loss. False without (H2). The bound is rewritten after both reviews and this form has had no outside review. A key used in both modes is **open**: for suite 1 the rewinding meets the one-signature-per-presignature rule, as in (b) |
| (d) complaints | **proved here**, with the membership checks of C20 |

### 6.2 What Theorem E gives for §6.7

- *Open mode: only the owner binds `rid`.* By (a), (b) every message that can bind an `rid` of `X_v` is an owner's message, byte for byte. No field can be altered, no ciphertext replaced, no proof re-randomized. A repost is the same message with the same `rid` and is ignored (§3.4). A copy on another board or chain fails §3.4 check 4, since `chain_id` and `board_id` are header fields.
- *Sealed mode: only the owner's dealing binds the `rid` of the owner's request.* By (c) a message that takes the `rid` of a pending sealed request carries the owner's header, commitments and ciphertexts. What a third party can change is the proof: someone who knows `s_{1,1}` (the wallet signed `m_{1,1}` on request with a deterministic nonce, or the owner disclosed the signature) can post a copy with its own authorship proof before the owner's message is bound. The copy has another `mid` and nothing else: the same intent, the same `rid`, the same shares at every honest node, the same variants, and no complaint against it succeeds (d). It delays nothing and authorizes nothing new. A third party can also post a sealed message of its own under `X_v` if it knows a signature for its first point. Such a message has another `hd`, hence another `rid`, and honest nodes release only shares the third party dealt; the experiment of Theorem D already contains these messages, so they add no signature outside `Auth(X_v)`.
- *Voiding.* By (d) and by (a) to (c), a third party cannot void a request by a complaint or by a bound message with bad shares: in open mode it cannot bind at all, and in sealed mode whatever it binds under the owner's `rid` carries the owner's ciphertexts. Voiding by spending the pin needs a signature and falls under Theorems A, B', D.
- *At most one executed transaction per message* is a property of the pin and the target chain (§4), not of this document.

## 7. Status of every claim

| Claim (§) | Result here | Status | Assumptions |
|---|---|---|---|
| Share encryption (§3.2, §3.4) | Theorem C | proved here, after [GS22] Theorem 2 pp. 29 to 32; needs corrections C3, C19, C20; the `Reuse` step has its own soundness argument | ICDH, RO (incl. `H_ct`), prime-order group (C20 for suite 3), static |
| 3, sealed below `t` (§6.4) | Theorem D | proved here in the form "no honest partial"; the form "fewer than `t − |C|` partials" is open | EUF-CMA of the suite, Theorem C; `Auth` counts copies |
| 4, open ECDSA (§6.5) | Theorem A | reduced to [GS21] Theorem 3, p. 24 | EC-GGM, CR, RPR, ZPR, RR of the sighash, Lemma 1, Theorem C, the view rule of 1.1; `U` is schedule-dependent, at most `S` |
| 4, open ECDSA, BIP32 siblings | Corollary A' | reduced to [GS21] Theorem 4, p. 27, for a path set fixed in advance; the step that draws the tweaks before `D`, with the invalid-child abort, is proved here and passed the fix check; a tighter fixed-tweak bound and adaptive paths are open | as above plus 4sum1, 4sum2, HMAC-SHA512 as a random oracle |
| 4, open Schnorr (§6.5) | Theorems B, B' | proved here | AOMDL with parameter `2U`, RO, Lemma 1, Theorem C; suite 3: seed-hash assumption, factor `κ_3` |
| 4 step 1 (§6.5) | Lemma 1 | proved here | board consistency, or `b ≤ f` and post-key EUF-CMA |
| 6, authorization (§6.7) | Theorem E, Lemma 5 | (a), (b), (c), (d) proved here; (c) is dealing identity, not byte identity; (c′) byte identity only for fresh-nonce wallets under SUF-CMA | as the mode's theorem; (c): Theorem C and `H_rid` only |
| 2, sealed, fully corrupt (§6.3) | remark after Theorem D | proved here | EUF-CMA of the suite |

## 8. What remains open

1. **`reshare`.** No theorem covers a request that moves to a new committee. Needed: Lemma 1 across the freeze (board consistency), Theorem C for the old nodes as dealers (it applies as stated once the reshare dealer proof uses the construction of 2.2 with the `LD1/rs-*` labels, `LD1/rs-ct` included), and a simulation of the sub-share dealings. The last step is not Lemma 2: an honest old node outside `P` deals a sharing of a share the simulator does not know, in the exponent of a known point `Eval(·, i)`, which Lemma 2 handles, but the corrupt new nodes then hold `t' − 1` sub-shares from each of `t_old` dealers, and the joint distribution with the new commitments has to be checked. Not done.
2. **Claim 3 in the §6.4 form** (partial releases below `t − |C|`): needs a subset guess or an adaptive-security technique.
3. **BIP32.** A tight bound with presignatures under one fixed tweak; paths chosen adaptively by the adversary; an application of [GS21] section 7.4.2 to a derivation function that depends on `D` (3.4).
4. **Byte identity of a pending sealed message.** Not claimed in general and false for a deterministic wallet that signs `m_{1,1}` on request (6.1, counterexample). Lost relative to the bundle under review: "a third party cannot re-randomize the proof of a sealed message". Kept: Theorem E(c), dealing identity. Theorem E(c′) gives byte identity for fresh-nonce wallets under SUF-CMA; a key used in both modes is open there, and for suite 1 it needs a generic-group argument in the style of Lemma 5 for a proof of knowledge of a sealed signature.
5. **ICDH in the EC-GGM.** Theorem A adds an ICDH term for generic adversaries on secp256k1. No bound for it is taken from the two papers or proved here.
6. **Adaptive corruption, a UC statement, and realization of `F_OMS`**: untouched.
7. **Comparison with the published FROST and MuSig2 proofs**: blocked by the failed downloads (section 0).
8. **Review state.** Two blinded cross-family reviews read the bundle of 2026-11-13. They found no defect in Lemma 4, in the extraction and slot accounting of Theorem B, or in Lemma 5. Everything this revision changed has had no outside review: `δ_B`, `δ_A` with the retry cap, the per-node closing rule, the `Reuse` soundness argument, Corollary A' with the tweak-programming step, Theorem E(c) and (c′), the factor `κ_3`.
9. **`U` is schedule-dependent.** Theorem A's `U` counts slots that some honest node may still sign. A bound in the number of slots live on the board would need a rule that lets a lagging node drop a slot without reading the board, or a proof that closes an index while one honest node can still sign it. Neither exists.
10. **Modelling assumptions without analysis**: deterministic wallet nonces as a uniform function of the message (Theorems A, B, D); SHA-512 of the Ed25519 seed as a random oracle (1.2); HMAC-SHA512 as a random oracle (Corollary A'); the labelled hashes as random oracles next to a concrete sighash built from the same SHA-256 (3.3 item 9; [GS22] is said by `design/notes-2022-506.md` to discuss this for its own protocol in an appendix that this document has not read).
11. **The restore rule.** The view rule of 1.1 is a hypothesis of Theorem A. C22 writes it into rule 4 of §3.9 (it is a new rule, added because the closing rule needs it), including how a node whose storage was rolled back learns a board position at or beyond its earlier one. The mechanism works only on a consistent board; on an inconsistent board a node that lost the record of its position counts as Byzantine (C22), so the inconsistent-board branch of Theorem A assumes that restored honest nodes keep that record. The mechanism is not proved here, and the Lean model behind ledger row R1 covers votes, not erasure.
12. **Constants from memory**: the Ed25519 group order and clamp, the secp256k1 `p` and `q` used for the numeric value of `θ_q` (the bound `θ_q < 2^{−125}` uses only `p < 2^256 < 2q`). To be checked against the standards before the numbers are quoted elsewhere.

## 9. Corrections to SCHEME.md

Each row: old text, new text, reason. C1 to C9 come from the proofs; C10 to C18 from PROOF-CHECK section 6; C19 to C23 from the two cross-family reviews and `design/notes-2022-506.md`. All are applied to SCHEME.md (2026-11-13) and have rows in FINDINGS-LEDGER.md. C1 to C18 are kept below as first written; where their "New" text says `SHA-256(ct)`, C19 replaces it by `H_ct(ct)`, C12 and the first half of C8 are superseded by C21, and C22 supersedes the words "`U` = live slots of one key" in C7 and C10.

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

**C19. §3.1, §3.2, §10: labelled ciphertext hash** (review cand-b finding 3, review cand-c finding 9).
Old: `SHA-256(ct)` in the inputs of `LD1/eph`, `LD1/ephpok`, `LD1/auth` and in §3.2, §10.
New: `H_ct(ct)`, with a new table row "`LD1/ct` | `ct` | ciphertext digest", and `LD1/rs-ct` in the resharing row.
Reason: raw SHA-256 is neither a labelled hash nor under any assumption of 1.2, and the binding of the ciphertexts (Theorem C Game 0, Theorem E common step) needs it collision-free. Cost: 0 bytes on the wire (the digest is computed, never sent); one more SHA-256 compression call per evaluation, for the 64-byte tag prefix.

**C20. §2 Setup, §3.4 check 9 and complaint verification, §10: group membership** (review cand-c finding 10; notes-2022-506 item 4).
Old: check 2 of §3.4 applied to the points of a `MSG` post only.
New: a key registration is accepted only if `PK_i` passes check 2 (canonical, not the identity, suite 3 `[ℓ]PK_i = O`); check 9 says `E'` passes check 2; a complaint is verified only if `K_i` passes check 2.
Reason: Theorem C and Theorem E(d) are statements about a group of prime order; with cofactor 8 a corrupt node can otherwise void an honest request (6.1). Cost: 0 bytes. Suite 3: one multiplication by `ℓ` per registered key and epoch, one per complaint, one per message for `E'`. Suites 1 and 2: an on-curve test.

**C21. §2 Assumptions (sealed mode), §3.2, §6.7, §10: sealed authorization is dealing identity** (review cand-b findings 2 and 6, review cand-c findings 1 and 2).
Old: "the statement that no third party takes the `rid` of a pending sealed request uses strong unforgeability"; §6.7 "the sealed part needs strong unforgeability"; §3.2 "only the owner can write a message that carries unreleased signatures".
New: no other dealing takes the `rid`, under ICDH and the random oracles (Theorem E(c)); a party that knows `s_{1,1}` can replace the proof bytes of a pending sealed message, which changes `mid` only; byte identity holds for fresh-nonce wallets under strong unforgeability (Theorem E(c′)).
Reason: the old statement is false for a deterministic wallet that signs `m_{1,1}` on request. Cost: 0 bytes, no protocol change. No change to `LD1/auth` was needed: since C2 its input covers `E', T_1, T_2, z_e`, so an altered ephemeral-key proof already needs a new authorship proof.

**C22. §3.9 rule 4; §2 Assumptions (open ECDSA): views and `U`** (review cand-c finding 6).
Old: rule 4 ended at "its ledger has no entry"; "`U` = live slots of one key".
New: a restored node posts nothing until its replay has reached its earlier board position and erases again what §3.10 made it erase; a node that lost the record of that position recovers one from `q` answers on a consistent board and counts as Byzantine otherwise; "`U` = the slots of one key that some honest node can still sign".
Reason: Theorem A step 5 closes a presignature index only when every honest node is done with the slot, and a node that is done must stay done. Cost: 0 bytes; a restored node waits for its replay.

**C23. §2 Assumptions, §6.5 status: assumptions that the proofs use and §2 did not name** (review cand-c findings 8 and 12; review cand-b finding 4).
New: HMAC-SHA512 as a random oracle and a fixed set of signing paths for BIP32 keys (Corollary A'); SHA-512 of the Ed25519 seed as a random oracle, with a factor of about 2 for the clamped key (Theorem B'); wallet nonces fresh and uniform, or deterministic and modelled as a uniform function of the message.
Reason: 1.2, 3.4, 4.3. Cost: none.

Each applied correction has a ledger row (LOOP rule). C3, C4, C5 and C9 change the wire format and the Rust prototype (`π` layout, one hash-to-curve per message, Step A check 9). C19 to C23 change no wire format. C19 and C20 change the Rust prototype (`impl/src/message.rs`, `impl/src/ed25519.rs`: the `LD1/ct` hash inside the three challenge inputs; the membership checks at registration and on complaints) and `experiments/line-dealing/checks.py` (check T15 still hashes the old `LD1/auth` input). The prototype and `checks.py` now implement C3 to C5, C9, C19, C20 and C22 (merge efa3160: 91 tests pass; `checks.py` 37 of 37).
