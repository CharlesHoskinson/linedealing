Evidence labels: [local] = checked against the local paper text (pdftotext of the named PDF, or the named .txt/.md); [calc] = recomputed by me; [memory] = BIP340/341, RFC 8032, EIP-1559, ECDSA facts from memory, not checked against a local copy.

## cand-a7e2
VERDICT: changes_requested

### Blocking findings

1. **§3.4 Case 2 step 3, ECDSA combine equation is wrong and, as written, publishes the key.**
   - Claim: nonce point Γ = γG, r_x = x(Γ), w̃ = kγ, ũ = γ(km + r_x·k·x), s' = ũ·w̃⁻¹.
   - Flaw: that gives s' = m + r_x·x. A valid signature for nonce γ needs s = γ⁻¹(m + r_x·x). Step 2 of the same section states u_i = k_i(m + r_x·x), which would be correct, so steps 2 and 3 contradict each other.
   - Check [calc]: toy prime-order curve (q = 967), 300 random trials. Step-2 reading verified 299/300; step-3 formula verified 0/300; x = (s' − m)/r_x recovered the key 300/300. Anyone who sees the failed s' (or the opened ũ, w̃) learns x_eff.
   - Fix: restate signing from Trout++ Protocol 5 exactly, and prove the opened values are u·k and u·(H(m)·r⁻¹ + x) with u a committed mask.

2. **§3.3/§3.4 ECDSA path is not the protocol it cites as "verbatim Trout++".** [local: 2026-1455.pdf, Protocols 2, 4, 5, Functionality 6, Theorem 7]
   - Trout++ round 1 sends R'_i = k'_i·E, K'_i = Enc(α_i, k'_i), U_i = OptCom(β_i, u_i) with two proofs (R_CL-EC, R_ComKwlg). The candidate describes (Γ_i, K_i, G'_i = βG_q + γ_i·H), i.e. two encryptions and no OptCom.
   - Trout++ nonce is R = ρ·R' + μ·E with ρ = H_ρ(m, X, transcript), μ = H_μ(sid, ρ). The candidate's "Γ ← Γ + τG" is additive only; the cited security argument (constant loss from [1]) is for the ρ, μ form.
   - "Π_Log*", "Π_Aff", "Π_Lin", "Theorem 8", "Fig. 6" do not appear in the Trout++ text or in Trout (2025-1666).
   - Consequence: Claims 2, 3 and 4 for ECDSA rest on Theorem 7 of a protocol that is not the one specified. Theorem 7 also covers Protocol 2+3 (a DKG key), not an owner-dealt key; that composition is unproven, though the paper says any Shamir-shared key is intended to work.
   - Fix: adopt Protocol 5 unchanged, including ρ/μ randomization and OptCom, and state the dealt-key composition as a proof obligation.

3. **§3.2 req_id replay through a malleable σ_auth (no corruption needed).**
   - req_id = H_req(Msg_O) covers σ_auth. For scheme 0x01, σ_auth is compact ECDSA with no low-s rule (low-s is imposed only on the spend signature).
   - Attack: any observer replaces (r, s) by (r, q − s) [memory; confirmed in the toy check, 299/299]. The body is unchanged, Gate 0 and Gate 1 pass, req_id is new, Spent[req_id'] is false, and a second AnchorCert and spend follow.
   - Effect: in exact-amount mode with guard 0x00 (dynamic UTXOs) or 0x02 (EVM nonce floor) the recipient is paid `amount` twice plus a second fee. Blocked only by sweep mode (nothing left), a pinned outpoint, or an exact pinned nonce. The attacker profits when it is the recipient.
   - Same exposure for Ed25519 if s < ℓ is not enforced [memory]. BIP340 is not affected.
   - Violates "one owner message gives at most the spends it names".
   - Fix: derive req_id from (chain_id, X_eff, nonce_salt) or from the body without σ_auth, and enforce canonical signatures.

4. **§3.4 Round A / F_OBTS step 2: one Byzantine leader can burn the owner's only message.**
   - Spent[req_id] := true is set when AnchorCert commits; BuildTx runs afterwards (step 3), and ⊥ means "refuse to sign". F_OBTS also sets Spent before BuildTx and then outputs ABORT.
   - §4.1 voting rule checks only finality depth and the fee rate. It does not require BuildTx ≠ ⊥, nor that the anchor is recent.
   - Attack: with |K| ≤ f, a leader proposes a finalized anchor at which the build fails (before the funding output matures under min_confs, a fee window above max_fee, an old anchor). Honest validators vote, the request is spent, nothing is signed, and the owner is offline. This contradicts Claim 4.
   - Fix: validators vote only if BuildTx succeeds at the anchor and the anchor is within a bounded age of their own finalized tip; set Spent only together with a successful build.

5. **§7 verification costs use a number the cited paper does not contain.** [local: 2023-451.pdf §7.4, §8]
   - The paper reports dealer 0.62 s and receiver 1.9 s at n = 200. The candidate cites "0.25 s public verification" and fits 1.25 ms per party. "0.25" does not appear in the paper.
   - With the paper's figure the slope is about 9.5 ms per party: DealRx ≈ 0.15 s, 0.6 s, 2.4 s for n = 16, 64, 256, not 25, 85, 327 ms. The Schnorr compute row and both ECDSA online rows inherit the error.
   - At n = 256 this exceeds the candidate's own falsifier 2 (Gate 1 > 1.0 s). The paper's 1.9 s may include work the candidate would not do, but no source supports 0.25 s.
   - Fix: re-derive from the 1.9 s figure or measure.

### Non-blocking findings

- **PoCS mask has no statistical slack** (Algorithm 1 step 7): k_r ∈ [0, s̃·2^{2λ}], while c·r ranges up to 2^λ · s̃·2^λ = s̃·2^{2λ}. The "within 2^-λ" simulation step in Claim 2 fails as parameterised; z_r leaks information about r. cgVSS Figure 1 uses a mask of q·|D_q|·2^{λst} [local]. Fix: k_r ∈ [0, s̃·2^{3λ}] and widen the range check. The size derivation "⌈(914+257)/8⌉ + 15 = 261" is also wrong arithmetic (it is 162); the 261-byte slot happens to be large enough for the corrected mask.
- **PoCS and signing equations otherwise hold** [calc]: the three PoCS checks, X_agg = Σβ_j·A_j, the BIP340 nonce-negation rule, the Ed25519 challenge, Lagrange coefficients and the reshare identity ΣW_i = X_eff are all correct. Normalization for Taproot and Ed25519 is correct [memory].
- **Gap 3 is overclaimed.** §8 says fewer than t corrupt nodes "cannot sign a second tx"; Claim 3.3 proves single spend only for |K| ≤ f. With f+1 corruptions (n = 3f+1, t = 2f+1) two conflicting AnchorCerts each get 2f+1 votes and 2f+1 signers from K plus disjoint honest groups, giving two Intent-compliant spends. The "≈2n/3" figure covers only unforgeability of non-BuildTx messages.
- **Gate 0 does not close request-channel abuse.** σ_auth proves knowledge of some key; an attacker generates throwaway keys and forces Gate 1 class-group work on every node.
- **Nonce/presignature rollback** is handled only by RAM zeroization. A node restored from a snapshot can reuse a slot; durable consumption records are needed.
- **Burned-but-valid transactions.** A signed Bitcoin transaction that misses its fee window stays valid forever; an owner who re-issues can pay twice. Solana blockhash lifetime (150 slots) can expire under the f+1 ROAST worst case.
- **EIP-1559 sweep leaves a remainder** (value = bal − 21000·maxFeePerGas, actual fee is lower), so "zero balance left" is false there.
- **ROAST session bound** is n − t + 1 [local: roast.txt Theorem 4.3]. That equals f+1 only for t = n − f; for the fast-quorum t = f+1 it is 2f+1. The cited "ROAST Theorem 4.1" was not found in the local text.
- **Class-group facts**: s is about √|Δ_K|, not √|Δ_K|/q; cgVSS reports 1752-bit elements (219 B), not 225 B [local].
- **Cost arithmetic**: every table entry follows from its stated formula for n = 16, 64, 256 [calc]. The inputs are the problem (finding 5, and below). Binomial tails in §2.3 are conservative: Pr[|K| ≥ 171] at β = 0.25 is about 2^-146 [calc].
- **Citations marked "read in full" contain details absent from the sources** [local]:
  - Trout++ benchmarks ran on a Mac mini M2 Pro, not "AMD EPYC 9B14 at 2.6 GHz".
  - Sign without IA is 450 B, not 487 B; "720 B Setup" is not in the paper.
  - Table 3 columns are "34-of-*" and "67-of-*", not "34-of-50" and "67-of-100".
  - Constant-time figures are 3,044 ms and 9,025 ms (13,271 ms total at 34), not 3.5 s, 8.5 s, 15.2 s.
  - "ESORICS 2026" is not in the PDF.
  - cgVSS ran in Rust on a 2.8 GHz Xeon GCP instance with BLS12-381 commitments, not "C++/PARI on a 2.4 GHz E5-2680 v4". PoCS is Figure 1 and Theorem 3 / Appendix D, not "Fig. 3" and "Theorem 1 / App. C".

### Strongest idea worth keeping
Key-independent presigning on both paths, with the ECDSA Setup message riding on the anchor decision. Trout++ does state that its first round is key-, signing-set- and message-independent and that Setup can run in parallel with it (Remark 1) [local], so a committee can stock nonces before any owner message exists and rotation discards nothing. Combined with decoupled thresholds (t = n − f for secrecy, f for liveness, which ROAST supports) and the single t-term MSM for the Feldman check, this is the right performance shape, provided the ECDSA section is rewritten to the actual protocol.

## cand-5d08
VERDICT: approved

Approved for its declared scope (existing Taproot key-path addresses). I found no attack, counterexample or failing equation.

### Blocking findings
None.

### Non-blocking findings

- **ECDSA is not covered; Ed25519 is a sketch.** The first line and the coverage table say so. Against the brief's primary target this is the main shortfall: existing Bitcoin/Ethereum ECDSA addresses get the import but no signing backend, proof or costs, and no account-chain builder exists. The Taproot claim is real: normalization, A_0 = X, and the script check are correct [memory].
- **Equations hold** [calc]. The PoCS matches cgVSS Figure 1 term for term (γ powers, W, X, Y, z_r over Z, z_s mod q) [local]; all three verification equations check; the mask q·2^2048·2^128 has the required slack and fits 384 bytes. FROST with ν parity gives zG = R + cX; share verification and the reshare identity Σλ_i·Y_i = X are correct.
- **Cost arithmetic is correct** for all three n [calc]: packet sizes 11,399 / 36,503 / 136,919 B, all operation counts, all traffic rows and migration payloads follow from the stated formulas.
- **Costs are conservative and unitless.** The profile uses 512-byte elements on a ~3072-bit discriminant; cgVSS reports 1752-bit elements at 128-bit security [local], so the packet is roughly 2.3 times larger than needed. Computation is given as operation counts with no time estimates; the brief asks for computation per node.
- **Circular hash definition.** The envelope contains dealing_hash = H(D), D contains π, and π's Fiat–Shamir context "includes the envelope's authorization context". Define the context as the envelope without dealing_hash, owner_seal and padding.
- **State after a builder failure is unspecified.** If B returns failure at the chosen checkpoint, the document does not say whether rid moves to REJECTED_OR_EXPIRED (burning the owner's message, as in a7e2 finding 4) or stays UNSEEN until admit_until. Specify the latter.
- **Safety should not depend on synchrony.** The network is declared synchronous. If the log's agreement depends on Δ, a delay yields two LOCK records and two transactions. With n = 3f+1 a log that is safe under asynchrony is available; require it and keep synchrony for liveness only.
- **t = f+1** gives secrecy only against fewer than n/3; the a7e2 threshold decoupling would raise this at no protocol cost.
- **Two log decisions plus two FROST rounds per attempt** (8 message delays), with fresh nonces generated after LOCK. Safe, slower than preprocessed nonces.
- **Locked T can become unusable** (fee change, reorg, external spend) and the request then stalls permanently; stated honestly in §10.
- **Retained decryption keys**: public ciphertexts stay decryptable by later compromise of epoch keys; acknowledged, no erasure rule given.
- **Citations are honest.** cgVSS §§3.3, 5.2, Figures 1 and 4, Appendix E and the 23-page length all match the local PDF [local]. BIP340/341 and RFC 8032 are disclosed as checked online, not local reads; the brief's rule wants those labelled "from memory, not checked" or read locally.

### Strongest idea worth keeping
The request identity and lock discipline. rid = H(chain, board, X, owner_nonce) excludes ciphertext randomness, proof and seal bytes, so re-encoding, signature malleation and migration cannot mint a second allowance. The log records LOCKED(rid, packet_hash, checkpoint, T) before any share is released, T never changes, retries re-sign only T, and migration carries the lock, reservations, tombstones and consumed nonce identifiers together with the reshared key. This directly prevents the replay that breaks cand-a7e2, and it treats nonce consumption as durable state.

## Head-to-head
cand-5d08 is the better base. Its equations are correct, its proof parameters are sound, its replay and lock model survives malleation, retries and rotation, and it states its limits without overclaiming. Its weakness is scope: Taproot only, synchronous, t = f+1, slow signing path, oversized parameters.

cand-a7e2 has the wider ambition and the better performance ideas, but it fails on soundness and evidence: an ECDSA combine formula that leaks the key, an ECDSA protocol that is not the cited one, a replay through req_id, a liveness burn by one leader, a mask without slack, and benchmark inputs that are not in the papers.

Recommended merge: keep 5d08's identity, lock, nonce-durability and migration state machine; add a7e2's decoupled thresholds t = n − f, key-independent FROST nonce pools with ROAST, the 1827-bit class-group profile, and its account-chain builders. Add ECDSA only by implementing Trout++ Protocol 5 exactly as published, with the dealt-key composition treated as an open proof obligation.
