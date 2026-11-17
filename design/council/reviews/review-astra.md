## cand-3c91

VERDICT: changes_requested

### Blocking findings

1. **§3.2: the encryption formula reuses a mask across the two ECDSA polynomials in a slot, enabling public key recovery.**

   The mask is `H_enc(hd, i, PK_i, K_i, slot id)`. Both `w_i` and `μ_i` belong to the same signing slot; no polynomial-component identifier distinguishes their masks. As written, anyone can subtract their ciphertexts:
   \[
   ct_{\mu,i}-ct_{w,i}=\mu_i-w_i.
   \]
   Interpolating these publicly available differences yields
   \[
   \delta=\mu-w=(x-1)/k.
   \]
   After one legitimate signature \(s=hw+r\mu\) is released,
   \[
   w=\frac{s-r\delta}{h+r},\qquad x=1+\frac{\delta}{w},
   \]
   except in the negligible exceptional case \(h+r=0\).

   **No corrupted committee member is needed.** I reproduced this recovery using secp256k1 arithmetic and verified the legitimate signature.

   **Required fix:** domain-separate every encrypted polynomial component, including mode, variant, generation, input, and component labels such as `ecdsa-w` and `ecdsa-mu`. Specify an injective encoding. If “slot id” was intended to identify individual polynomials, state that explicitly: its current usage identifies a signing slot containing multiple polynomials.

2. **§§2, 6.5 and 10: open mode does not meet the brief’s unrestricted below-reconstruction-threshold security criterion.**

   The document candidly limits active security to \(f\), while advertising reconstruction at \(t=2f+1\). These are materially different guarantees.

   For \(n=16,f=5,t=11\), six Byzantine nodes—below \(t\)—can support two conflicting 11-vote certificates, each containing those six nodes and a different group of five honest nodes. Once the committee-run board exceeds its fault bound, the groups can receive different anchors and sign different digests using the same ECDSA slot. No honest node votes twice. The two signatures expose the nonce and key:
   \[
   k=(h_0-h_1)/(s_0-s_1),\qquad x=(s_0k-h_0)/r.
   \]

   **Required fix:** either provide signing security against every coalition of fewer than \(t\) active adversaries, or explicitly mark this acceptance criterion unmet for open mode. The mixed model of \(f\) active plus \(f\) passive corruptions cannot substitute for that requirement. Sealed mode avoids this particular key-extraction problem.

3. **§§3.3–4: the first anchor can permanently prevent an otherwise feasible spend.**

   `B*` is the first block collecting \(f+1\) observations. Suppose its fee statistic exceeds every sealed variant’s fee. `Select` says to wait for a later block, but subsequent executions still evaluate `state(B*)`; no transition replaces that anchor. Fees can subsequently fall below the ceiling without the request progressing.

   The same omission affects open requests whose first anchored state lacks sufficient funds but which are intended to include later deposits.

   **Required fix:** define anchor replacement before signing, with explicit eligibility checks and generation rules. Once any nonce has been used, a replacement digest must receive fresh nonce material. State liveness conditional on funding, fee feasibility, and sufficient time before expiry.

### Non-blocking findings

- **The core signing algebra is sound independently of the encryption flaw.** The equations
  \[
  wR=G,\quad \mu R=X,\quad sR=hG+rX
  \]
  and their share-level versions hold. I checked them numerically on secp256k1. The Schnorr interpolation equation also holds; BIP340 requires the stated nonce-parity adjustment and x-only challenge encoding.

- **Existing-key support is credible at the scalar/signature level.** Normalizing the Taproot output secret and reducing the expanded Ed25519 scalar modulo the subgroup order preserve the intended public key. Sealed ECDSA’s recovery of \(R=s^{-1}(hG+rX)\) is valid, including when the wallet supplied a low-\(s\) signature. These facts still need the proposed independent-verifier and transaction tests.

- **Gap 1 remains only partly closed.** Public commitments establish what correctly delivered shares must represent; they do not prove that the ciphertexts contain those shares. ACKs and complaints are an interactive delivery check. The document acknowledges this accurately. Sealed mode also distributes signatures rather than importing the address key, and offers selection rather than unrestricted committee-side construction.

- **The principal payload arithmetic checks out.** Using the document’s approximate 430-byte fixed envelope:

  | Bytes | \(n=16\) | \(n=64\) | \(n=256\) |
  |---|---:|---:|---:|
  | One polynomial, \(33(t-1)+32n\) | 842 | 3,434 | 13,802 |
  | Open ECDSA, one slot | 2,147 | 7,331 | 28,067 |
  | Sealed, eight one-input variants | 7,430 | 28,166 | 111,110 |

  These are payload estimates, not complete network costs. The final accounting should include proof verification, authenticated board traffic, BFT dissemination, complaint handling, and resharing. The 50-µs multiplication assumption is appropriately identified as unmeasured.

- **Reference labeling is candid.** The candidate distinguishes passages actually consulted from papers not read in full. My passage check of the local Groth–Shoup §7.3 confirms the ratio-resistance assumption and outstanding-presignature-dependent bound. It does not validate the entire composition. The exact two-nonce Schnorr reduction remains unfinished; invoking MuSig2/FROST by analogy does not establish it.

- **The formal functionality needs reconciliation with its exceptions.** In particular, the “nothing for a void request” rule must accommodate the explicitly permitted retention and later release of sealed signatures by a qualified coalition. Also resolve whether `G` counts total generations or additional bump generations.

### Strongest idea worth keeping

Dealing the coefficients of the ECDSA signing equation in base \(R\) is the strongest contribution. It makes address binding and partial-signature verification simple, and eliminates committee-side secret multiplication when the owner knows both the key and nonce. The sealed variant is also useful: distributing ordinary signatures on transactions that all consume the same pin gives a meaningful restriction even against a fully corrupt committee. Preserve the distinction between that guarantee and open mode’s policy enforcement.

## cand-a7e2

VERDICT: changes_requested

### Blocking findings

1. **§3.4, ECDSA Round B: the stated combination leaks the key and does not produce ECDSA signatures.**

   The document specifies public combination values
   \[
   \widetilde w=k\gamma,\qquad
   \widetilde u=\gamma(km+rkx).
   \]
   Consequently,
   \[
   s'=\widetilde u/\widetilde w=m+rx,
   \]
   whereas the nonce point \(\Gamma=\gamma G\) requires
   \[
   s=\gamma^{-1}(m+rx).
   \]
   Worse, anyone obtaining those advertised combination values recovers
   \[
   x=(s'-m)/r.
   \]
   Aborting after failed signature verification does not retract the broadcast transcript. I checked that the stated result fails secp256k1 ECDSA verification while the correctly divided result passes.

   There are additional inconsistent equations: `U_i := k_i C_S + m K_i` encodes \(k_i x+mk_i\), not the claimed \(k_i(m+rx)\). Shifting \(\Gamma\) without updating its corresponding secret/ciphertext representation also breaks consistency.

   The local [Trout++ paper](/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2026-1455.pdf), Protocols 4–5, uses different masked products, commitments, and coordinated nonce randomization.

   **Required fix:** replace this section with a faithful specification of the actual protocol, including its ciphertext updates, proof relations, and combination formula. Verify both correctness and transcript privacy before claiming the ECDSA bridge works.

2. **§§3.2–3.4: hashing the authorization signature into `req_id` permits replay through ECDSA malleability.**

   The identifier hashes the entire owner message, including `sigma_auth`. No low-\(s\) requirement is specified for that authorization signature. Under ordinary ECDSA verification, both \((r,s)\) and \((r,q-s)\) verify on the same body, but produce different request identifiers.

   An attacker can submit both encodings. With dynamic Ethereum nonce selection, the committee can execute the first request at nonce \(N\), then the second at nonce \(N+1\). The owner authorized one request; the committee pays twice. The same problem applies to dynamic UTXO selection when enough funds remain. ECDSA’s sign-flip malleability is explicitly described in [EIP-2](https://eips.ethereum.org/EIPS/eip-2).

   **Required fix:** derive a stable authorization nullifier from canonical authenticated content, independent of the signature encoding. Require canonical authorization signatures as an additional check. Test replay after the first spend becomes final.

3. **§8, gap 3: single-spend protection below \(t\) contradicts the protocol’s own fault model.**

   The security section only guarantees single spend for at most \(f\) Byzantine nodes. The ideal functionality deliberately stops setting `Spent` when \(f<|\mathcal K|<t\). Nevertheless, gap 3 claims that every coalition below \(t\) cannot cause a second transaction.

   For 11-of-16, ten corrupt nodes can obtain one certificate/signature with honest node A and another with honest node B. Both transactions can satisfy `BuildTx` individually on successive finalized states, using different account nonces. The corrupt nodes supply inconsistent host-chain histories; neither honest signer needs to authorize a transaction outside the per-transaction predicate.

   **Required fix:** distinguish intent-conforming signatures from single-use authorization. Limit the latter claim to the actual consensus fault bound, or introduce an enforceable common spending pin/external serialization mechanism. Correct the functionality, gap table, and comparison table together.

4. **§3.4 and Claim 4: the described ROAST scheduling cannot provide the claimed liveness.**

   The design requires “disjoint active \(t\)-subsets.” Two such subsets already require \(2t\) nodes. In the primary configurations, \(2t>n\): even two disjoint signing sets are impossible.

   With only one active set, one silent signer can stall it indefinitely in an asynchronous network. Moreover, overlapping retries cannot reuse the same honest signer’s nonce slot. The document binds a slot to a request, but does not specify a complete allocation rule for multiple attempts and signing subsets.

   **Required fix:** specify the actual ROAST scheduler, including overlapping sessions, fresh per-attempt nonce allocation, coordinator behavior, and durable consumption state. Separate the optimistic one-round path from robustness bounds. The local Trout++ §6.4 supports applying ROAST to the actual IA protocol; it does not establish this altered scheduler.

5. **§3.2 and Claim 2: the modified PoCS sampling does not justify the claimed statistical simulation.**

   Let \(D=\widetilde s\,2^\lambda\) be the witness-range bound. The candidate samples
   \[
   r\in[0,D],\quad k_r\in[0,2^\lambda D],\quad
   z_r=k_r+cr,\quad c<2^\lambda.
   \]
   The witness-dependent shift \(cr\) can therefore be comparable to the entire masking interval. The usual shifted-uniform argument gives potentially constant statistical distance, not the claimed \(2^{-\lambda}\).

   The local [cgVSS proof](/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2023-451.pdf), Figure 1, includes an additional statistical-hiding factor in the proof-randomness range. The candidate also changes its batching/challenge construction, so the original theorem cannot simply be inherited.

   **Required fix:** restore proven sampling bounds and specify the exact instantiated proof, or prove the modified construction. Recalculate response sizes afterward. This finding invalidates the supplied proof argument; it is not, by itself, a demonstrated practical key-extraction attack.

6. **§4.2: the deterministic builder can exceed the owner’s fee ceiling.**

   The dust branch calculates change using a two-output fee but checks the cap using a one-output fee. Using the candidate’s own weights and a rate of 1,000 sat/kw:

   - One input plus two P2WPKH outputs: fee 562 sat.
   - One input plus one output: fee 438 sat.
   - Input value 10,762 sat; payment 10,000 sat; calculated change 200 sat.
   - Fee ceiling 700 sat.

   The change is below the stated 294-sat dust threshold. The proposed check accepts \(438+200=638\le700\). But emitting only the payment actually pays \(10{,}762-10{,}000=762\) sat—above the ceiling.

   Sweep mode similarly computes `fee_eff` but subsequently subtracts the uncapped `fee(w)`.

   **Required fix:** enforce the ceiling against the final transaction’s actual input-minus-output fee. Resolve output selection first, recompute the fee consistently, and reject infeasible constructions.

7. **§§1 and 3.1: Ed25519 address binding is incorrectly generalized across chains.**

   The test `X_eff == addr_32` fits Solana’s ordinary public-key address model. It does not establish ownership of all the claimed Sui, Aptos, and NEAR accounts.

   Sui derives an address by hashing the signature-scheme flag and public key. Aptos derives an authentication key and permits key rotation while preserving the account address. Thus an ordinary valid existing account is a counterexample to the proposed equality check. See [Sui’s address derivation](https://www.docs.sui.io/develop/transactions/transaction-auth/auth-overview) and [Aptos account authentication](https://aptos.dev/network/blockchain/accounts).

   **Required fix:** narrow the supported chains or provide chain-specific address binding, transaction serialization, and authorization-state checks. Also distinguish compressed versus uncompressed legacy P2PKH keys, and explicitly separate already-tweaked Taproot secrets from internal secrets.

8. **§7: several cost derivations and primary-source attributions are incorrect.**

   The tables mostly evaluate their own formulas correctly:

   | Candidate formula | \(n=16\) | \(n=64\) | \(n=256\) |
   |---|---:|---:|---:|
   | Owner bytes | 5,240 | 17,096 | 64,520 |
   | Owner CPU, ms | 54.73 | 194.89 | 755.53 |
   | ECDSA IA online CPU, ms | 758.665 | 2,003.145 | 6,981.065 |

   The problem is the underlying evidence:

   - Local cgVSS reports **0.62 seconds dealer time and 1.9 seconds receiver time** at 200 nodes, not the asserted 0.25-second verification benchmark.
   - Local Trout++ Table 2 reports **450 bytes** and **54 ms** for signing without identifiable aborts, not 487 bytes.
   - Trout++’s benchmark machine is an **Apple M2 Pro**, not the claimed AMD EPYC.
   - The response-size calculation \(\lceil(914+257)/8\rceil+15\) equals **162**, not 261.
   - The cited Trout++ “Theorem 8” is absent from the local paper.

   The sub-second projections also rely on proposed batching and protocol changes that were not measured.

   **Required fix:** rebuild the estimates from the corrected protocol and actual source tables. Distinguish measured values, extrapolations, proposed optimizations, and logical broadcast payloads from physical network traffic.

### Non-blocking findings

- **Several underlying equations are worth preserving.** The Shamir commitments, honest-execution PoCS verification identities, and FROST aggregation equation are algebraically consistent. Ed25519 scalar normalization is correct. The BIP340 nonce-parity handling is substantially correct. Taproot tweaking should reject an out-of-range tweak rather than silently reduce it, as specified by [BIP341](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341.mediawiki).

- **Committee handover needs a precise replacement rule.** Lagrange weights depend on the complete selected old committee subset. If a selected dealer disappears, replacing it changes the other weights too; previously weighted dealings cannot simply be retained. Also remove the suggestion that \(f+1<t\) old shares suffice to reconstruct a degree-\((t-1)\) sharing.

- **The adaptive committee-sizing argument is inapplicable as stated.** Binomial sampling bounds apply to a fixed compromised population, not an adversary free to target committee members after selection. Even under independent sampling, for \(n=900,\beta=0.25,f=299\), I calculate
  \[
  \Pr[X>f]\approx1.34\times10^{-8}\approx2^{-26.2},
  \]
  not below \(2^{-40}\). This does not undermine a properly restricted static model, but the adaptive sizing claim should be withdrawn.

- **Post-spend erasure alone does not give the claimed forward secrecy.** Public dealing ciphertexts remain decryptable with retained epoch keys. Likewise, an EIP-1559 “sweep” reserving the maximum gas charge generally leaves the difference between maximum and actual charges behind.

- **Submission authentication does not close spam abuse.** An attacker can sign expensive malformed requests under its own keys. Gate 0 rejects unauthenticated garbage; admission control still needs a specified fee or resource rule.

- **Citation honesty cannot be inferred from labels alone.** The candidate marks many papers “read in full,” but the demonstrable misquotations and nonexistent theorem make those labels unreliable evidence of source grounding. I cannot determine its reading history. My paper comparisons above are checks of the cited local passages, not claims that I independently read every paper in full.

### Strongest idea worth keeping

The useful architecture is an address-bound publicly verifiable dealing that delivers ordinary Shamir shares, followed by deterministic transaction construction and an existing threshold-signing implementation. Binding \(A_0\) to the effective address key and authenticating the intent alongside the dealing are sensible choices. Keep that architecture, but use the published cryptographic components faithfully and treat transaction construction, replay state, and committee handover as separate obligations requiring their own checks.

## Head-to-head

**cand-3c91 is the better base after correction.** Its ciphertext-mask flaw is critical, but localized, and its principal ECDSA equations survive independent checking. Its sealed mode provides a clear restriction against a fully corrupt committee, while the document generally distinguishes policy, cryptographic guarantees, and unfinished proof work honestly.

cand-a7e2 has a useful composition strategy, especially public verification of share delivery. However, its stated ECDSA path can disclose the key, its replay identifier is unsafe without additional canonicalization, its builder violates fee authorization, and its robustness and benchmark claims depart from the cited sources.

Neither candidate is approvable as written.