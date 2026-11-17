# Verification of SCHEME.md (line dealing) against the local papers

Scope: `/home/hoskinson/Projects/mpcexperiments/design/SCHEME.md` sections 2, 3, 6, 9, 10, 12 and `/home/hoskinson/Projects/mpcexperiments/design/FINDINGS-LEDGER.md`, checked against local copies. Paper text was treated as data. Page numbers are the printed page numbers of each PDF. Items marked "reviewer's" are my own reasoning and are not in any paper.

## 0. Reading record

| Source | Local path | What was read |
|---|---|---|
| Groth, Shoup, *On the security of ECDSA with additive key derivation and presignatures*, ePrint 2021/1330, version of 27 April 2022, 51 pages. SCHEME.md calls it [GS22]; the signing-service paper cites it as [GS21] | `/home/hoskinson/Projects/mpcexperiments/research/sources/groth-shoup-2021-1330.pdf` and `.txt` | Pages 1 to 48 in full: EC-GGM (section 2), all game definitions, Theorems 1 to 9 with proofs, Appendices A to D. Reference list not read |
| Komlo, Goldberg, FROST, ePrint 2020/852, version of 22 December 2020, 35 pages | `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2020-852.pdf` | In full, including Appendix A and the changelog |
| Crites, Komlo, Maller, *Fully Adaptive Schnorr Threshold Signatures*, ePrint 2023/445, 53 pages | `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2023-445.pdf` | Read in part. Abstract, sections 1, 2, 3, 4.1, 5, 6, 7, and Appendix A from p. 32 to the simulator analysis on p. 40. Not read: a few lines on pp. 9 to 10, the end of section 4.2, the forking analysis that ends Appendix A, Appendices B and C (pp. 41 to 53) |
| Groth, Shoup, *Design and analysis of a distributed ECDSA signing service*, ePrint 2022/506, version of 16 February 2023, 99 pages. Byte-identical to `/home/hoskinson/Projects/mpcexperiments/research/sources/shoup-tecdsa.pdf` | `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2022-506.pdf` | Read in part. Abstract, section 1 up to 1.1, section 1.2 up to "Communication costs", section 2 (all), section 4 from the decryption-algorithm definition (p. 25) to the end of 4.4, section 8.9.4. Not read: 1.1, 1.3, 3, 5 to 7, 8.1 to 8.9.3, 9, 10, appendices. Every statement below about this paper is limited to the parts read |

## 1. Verdicts

| SCHEME.md claim | Paper-dependent step | Verdict |
|---|---|---|
| 6.1 `F_OMS` | none | A definition. SCHEME.md states that no proof of realization exists; nothing to check against the papers |
| 6.2 Claim 1, address binding | none (direct calculation; Feldman 1987 is not local) | No theorem cited or needed. The algebra matches the ECDSA equation `hG + tD = sR` of 2021/1330 p. 2 |
| 6.3 Claim 2, sealed, fully corrupt committee | standard unforgeability of the suite scheme | No cited theorem. The reduction as sketched needs only the plain signing oracle |
| 6.4 Claim 3, sealed below `t` | share encryption with a public complaint | GAP in the encryption step (section 5). The signature step needs only plain unforgeability (reviewer's check, section 5) |
| 6.5 Claim 4 step 1, one digest per slot | none | No cited theorem; quorum counting |
| 6.5 Claim 4, open ECDSA | 2021/1330 Theorem 3 (p. 24) | The Theorem 3 step is CONFIRMED WITH CONDITIONS (section 2). The claim as a whole also inherits the encryption GAP of section 5, so open ECDSA is not cleared |
| 6.5 Claim 4, open Schnorr | "single-signer two-nonce Schnorr" | GAP (section 3), plus the encryption GAP |
| 6.5, one nonce per slot allows a ROS-type attack | 2020/852 section 2.5; 2023/445 section 1 | CONFIRMED (section 3) |
| 6.5, raw-hash signing breaks presignatures and ratio resistance is needed | 2021/1330 section 7.3 | CONFIRMED: Definition 7 (p. 23), notes 1 and 2 (p. 26) |
| 6.6 Claim 5, impossibility | none | No cited theorem; one wording error for Schnorr (section 6) |
| 6.7 Claim 6, authorization | soundness of `π` next to the signing oracles | No cited theorem covers it (section 5) |
| 6.8 Claim 7, liveness | none | No cited theorem |
| 6.9 acceptance table | as claims 3 and 4 | The "met" entries for Open T1 ("nothing about the key", "no signature") rest on the Schnorr GAP, the ECDSA conditions and the encryption GAP. The sealed entry "no signature for unreleased variants" rests on the encryption GAP |
| Multiplicative re-randomization (cand-3c91 line 241; not in SCHEME.md) | 2021/1330 Theorem 5 (p. 31) | GAP; no section 6 claim depends on it (section 4) |

No claim was found WRONG in the sense of a written counterexample. One sentence of 6.5 is not supported for Schnorr (section 6).

## 2. Question 1: does Theorem 3 cover owner-dealt public presignatures with base-`R` commitments?

**Verdict: CONFIRMED WITH CONDITIONS.** Theorem 3 does not cover the protocol directly. Its game (Figure 4, p. 22) gives the adversary `G`, `D`, the points `R_k`, and one signature `(s_k, t_k)` per presignature on a message the challenger hashes. The base-`R` commitments, the exposed shares and the honest partials are outside that game. They are covered through the reduction of claim 4 steps 2 and 3, and that reduction is sound for these reasons:

- With `t − 1` exposed shares `w_j`, `μ_j` (padded with random values when fewer are exposed), every coefficient commitment of `p_w` is a known linear combination of `G` and `R`, and every one of `p_μ` a known linear combination of `X` and `R`. The scalars are independent of `x` and `k`. In the symbolic game of section 7.2 (p. 22) these points have preimages `a + cR_k` and `bD + cR_k`, the form the proof already handles. An adversary in the Theorem 3 game can compute them itself with group-oracle queries.
- Each honest partial `s_i = m·w_i + r·μ_i` is an interpolation of the oracle's `s` and the exposed shares.

The base-`R` commitments therefore give no forgery path beyond Theorem 3. This answers the first "the design is wrong if" item of SCHEME.md section 11 in the negative, under the conditions below.

Conditions:

1. **The reduction is written out.** It is a sketch in 6.5. The paper supports the method only in general terms: "the security of an ECDSA threshold signing protocol can be reduced to the security of an appropriate variant of non-threshold ECDSA" (2022/506 p. 10).
2. **One signature per presignature.** The game forbids two signing requests on one index (2021/1330 p. 21). In the protocol this rests on the lock quorum with at most `f` Byzantine nodes and on unforgeable post keys, and across a freeze on board consistency. 2022/506 states the same rule for its quadruples: use at most once, "breaking this rule would reveal the signing key" (p. 13).
3. **Hash assumptions on the real sighash.** Theorem 3 needs collision resistance, random-preimage resistance, ratio resistance and zero-preimage resistance (p. 24). SCHEME.md section 2 lists three and omits zero-preimage resistance. The reductions run in the adversary's time plus `O(U·N)`.
4. **EC-GGM only.** The model covers prime-order curves with cofactor 1 (p. 9, note 4). secp256k1 qualifies. The paper has no standard-model or random-oracle-only statement.
5. **`X` is not an additively derived key, or the row changes.** Theorem 3 is the "no derivation × presigs" cell of Table 1 (p. 7). If `X` is a BIP32 non-hardened child and the adversary knows the chain code, a signature under `X` is also a candidate forgery under a sibling key, and the governing result is Theorem 4 (p. 27), with the terms `N_psig·4sum1` and `N·4sum2` and a factor `|E|`. The paper's `q^{1/3}` attack (pp. 4, 28 to 29) lets the adversary choose the signing tweak from `E`. Line dealing signs under one dealt key, so the signing tweak is fixed. Reviewer's estimate: with a fixed signing tweak the search loses its fourth list and costs about the birthday bound. No theorem in the paper states that case. SCHEME.md targets "an existing address", which is usually a BIP32 child, so the section 2 assumption line should name Theorem 4 for such keys.
6. **Layers outside the theorem.** The share encryption with complaints and the proof `π` (a Schnorr proof under the ECDSA key `x`) are simulated in the random oracle model next to a generic-group argument. Neither paper analyses that combination. The encryption layer is a GAP on its own (section 5).
7. **The meaning of `U`.** `U` is the largest number of unused presignatures at one time (p. 24). Unused slots never leave the game by themselves. Reviewer's device: the reduction can close an expired slot with a signing query on a random message the adversary never sees, which makes `U` the number of slots live at one time for `X`. The paper does not state this.

Two further matches. "Nodes hash their own preimage" is the right rule: the challenger computes `h_k = Hash(m_k)` (Figure 4, step 5b), and note 1 (p. 26) gives the forgery when the caller supplies `h`. Theorem 3 also gives strong unforgeability up to sign (note 4, p. 26; section 4.1.1, p. 11), which fits the low-`s` rule of SCHEME.md 3.7.

## 3. Question 2: is the two-nonce Schnorr covered by FROST's proof or by 2023/445?

**Verdict: GAP.** Neither local paper proves it.

- **FROST, 2020/852.** Theorem 6.1 (p. 17) and Theorem A.2 (p. 29) are for FROST-Interactive. There the binding value comes from a one-time VRF with committed keys and proofs of knowledge, the preprocessing runs serially so that the simulator can extract by rewinding (p. 29), and signing has an extra round. The reduction is to discrete log by forking. For the hash-derived `ρ` of plain FROST the paper says "We now heuristically demonstrate" (p. 18); footnote 7 calls it "the main heuristic step" and says necessity is not proved. `ρ = Hq_bind(hd, g, ℓ, dg)` is a hash-derived binding value, so it falls under the heuristic part.
- **2023/445.** It proves Sparkle+ (Theorems 1 to 3, pp. 23 to 26), a commit-reveal scheme. Round 1 publishes `cm_i = H_cm(i, R_i)`, and the nonce is revealed only in round 2 with the message (Figure 8, p. 21). The static simulator fixes each honest `R_k` after it has chosen the challenge (Appendix A, p. 38, case 2). That is impossible when `D` and `E'` are public before the message exists. Its Figure 1 (p. 4) lists FROST, FROST2 and FROST3 with the static assumption AOMDL and no adaptive proof. Page 6 attributes the static AOMDL proof to its reference [10]; [35], [16], [62] and [29] are cited there for the variants. None of these is local.

What "one party generated all nonces and the key" changes relative to FROST's setting:

- The corrupt nodes contribute no nonce. `R = D + ρE'` is fixed by the owner's points and `ρ`. The attack path through adversarial commitments is absent. The path through adaptive message choice remains.
- The corrupt nodes hold Shamir shares of `d` and `e'`. FROST signers hold no shares of each other's nonces. The reduction must simulate nonce shares by interpolation, as claim 4 step 2 does. No local proof contains that step.
- Sparkle+ models centralized key generation (pp. 15, 20), for a different signing protocol. Neither paper models a dealer for the nonces.
- There is one `ρ` per slot. FROST uses one `ρ_i` per signer (Figure 3, p. 15). With one logical signer the two coincide.

The statement "one nonce per slot would allow a ROS-type search" is CONFIRMED. 2020/852 p. 6 says the Drijvers attack applies when the adversary controls "choosing the message m to be signed", and pp. 6 to 7 say the scheme of Gennaro et al. with preprocessed nonces "is likewise affected". 2023/445 says pre-processing beyond its commitment round "would make the scheme susceptible to ROS attacks" (pp. 3 to 4).

Assumption mismatch: SCHEME.md section 2 lists discrete log and random oracles. 2020/852 claims discrete log for FROST-Interactive only, and 2023/445 lists AOMDL for the FROST family. If the proof follows that line, section 2 must add AOMDL or OMDL.

To close: obtain and read [10] Bellare, Crites, Komlo, Maller, Tessaro, Zhu (CRYPTO 2022); [16] Bellare, Tessaro, Zhu, ePrint 2022/833; [35] Crites, Komlo, Maller, ePrint 2021/1375; [58] Nick, Ruffing, Seurin, MuSig2; and Benhamouda et al. on ROS, ePrint 2020/945. Then state the single-signer game exactly: public `X`; slots `(D_j, E'_j)` published in advance; one query `(j, m)` per slot that returns `σ(d_j + ρe'_j) + c·x`, with the BIP340 sign flip and the Ed25519 challenge. Check whether one of those theorems covers it at one signer. I make no statement about what they prove.

## 4. Question 3: multiplicative re-randomization

**Verdict: GAP. It blocks no claim of SCHEME.md**, which does not use re-randomization. The question comes from `/home/hoskinson/Projects/mpcexperiments/design/council/proposals/cand-3c91.md` line 241.

- Theorem 5 (p. 31) is for `R = R' + δG` only. Its proof uses the additive term: equation (8) (p. 32) has `− c_ℓ δ_ℓ` on the left, so the left side vanishes with probability `1/q` and the ratio case disappears. With `R = δR'` the substitution is `R_k ↦ δ_k⁻¹ s_k⁻¹(h_k + t_k D)`. Then `δ_k` merges with `s_k`, and the left side of (8) has no `δ` term. The proof does not transfer line by line.
- The requirement on `δ`: it is chosen after the signing request is fixed and is unpredictable (2021/1330 p. 30; note 2, p. 33). 2022/506 p. 11: "It is essential that δ is chosen after the adversary has made his signing request"; p. 14 note 4: the beacon seed is generated after the request is paired with a quadruple. SCHEME.md has no such source. A `δ` hashed from the request is discussed and not analysed (2021/1330 p. 6; p. 30 note 2).
- Reviewer's unreviewed sketch, not a verification result: with `δ` unpredictable when the message is fixed, `t_ℓ = C̄(δ_ℓ R'_ℓ)` is a fresh value drawn after `h_ℓ`, `A_{ℓ−1}`, `B_{ℓ−1}` and `t*` are fixed. The left side of the analogue of (8) then vanishes with probability `O(1/q)`, except when `R*` is a known multiple of `R'_ℓ`; that case reduces to random-preimage resistance by placing the challenge in `t_ℓ`. This suggests a Theorem 5 style bound with no ratio-resistance term. It needs a full proof, including the analogue of Lemma 3.
- A second way: 2022/506 gets a linear additive `δ` by sharing `λ`, `κλ` and `αλ` and opening `μ + δλ` (pp. 13 to 14, notes 1 and 3). The "not linear" objection therefore holds only for dealt `k⁻¹`. An owner could deal `λ`, `kλ`, `xλ`. That is a redesign: three polynomials per slot, and the constant terms are no longer the public points `G` and `X`. I did not check it.

## 5. Other section 6 claims and the section 3 rules they use

- **Share encryption and complaints (claims 3, 4 step 2, 6; rules 3.2, 3.4).** GAP. 2022/506 proves its multi-recipient scheme under ICDH in the random oracle model (Theorem 2, p. 29). That scheme reveals `w = v^α` in a decryption proof, as a complaint reveals `K_i`. The proof depends on a specific ephemeral-key proof: `v' = g'^β` with `g' = H_G(ad, v)`, plus a proof that `v` and `v'` have the same exponent (p. 28). With it the reduction answers a decryption-proof query as `w = v'·v^{σ−λ}` and needs only soundness and zero knowledge (p. 31). SCHEME.md uses a plain Schnorr proof of `e`. A reduction must then extract `e` from every adversarial message to answer its complaints, which Theorem 2 does not do. The simplified scheme of section 4.3 (p. 32) does not apply: it assumes a decryption proof is produced only after another honest party decrypted successfully. To close: adopt the ephemeral-key proof of section 4.1, and check the choice of associated data against the rule that decryption queries use only associated data not used in an encryption query (p. 27); or prove extraction for the Schnorr proof in the algebraic or generic group model. SCHEME.md says "gap Diffie-Hellman"; the paper's assumption is ICDH (p. 29).
- **Claim 3, signature step.** Reviewer's check: the reduction can choose the `R` of the target point itself and never query its message, so plain unforgeability suffices. The public `R` of an unreleased sealed point does not need the presignature model, because its message is fixed before `R` exists.
- **Claim 6.** The statement that only a holder of `x` binds `rid` needs soundness of a Schnorr proof under a key that also answers ECDSA presignature queries or two-nonce Schnorr queries. No local theorem covers that joint use.
- **Form A comparison (section 9).** "Committee rounds after the request is fixed: 1" agrees with 2022/506 p. 2 item 7 and p. 7. The table omits that the protocol of 2022/506 uses re-randomized presignatures with a beacon and BIP32 derivation and rests on Theorem 6 of 2021/1330 (2022/506 pp. 11, 18). Open ECDSA rests on Theorem 3, a weaker cell of Table 1 (2021/1330 p. 7). "Open mode is Form A with the presignature work moved" is not exact on the security side.

## 6. Statements to correct

Contradicted or qualified by the papers:

1. Section 2, open ECDSA assumption: add zero-preimage resistance and the `O(U·N)` running-time term (2021/1330 p. 24).
2. Section 2, open ECDSA: name Theorem 4 for BIP32-derived keys (p. 27; Table 1, p. 7).
3. Section 2, open Schnorr: discrete log plus random oracles is not what the local sources support for a hash-derived binding value (2020/852 pp. 18 to 19; 2023/445 p. 4).
4. Section 10, "Stopped: raw-hash and ratio attacks": no mechanism stops the ratio attack. It is assumed infeasible, and "ratio resistance is essential" (2021/1330 p. 26, note 2). Only raw-hash signing is stopped by rule.
5. Section 10, "Stopped: ROS-type attacks on pre-published Schnorr nonces": supported by a heuristic argument only (2020/852 p. 18, footnote 7) until section 3 is closed.
6. Section 9: the Form A point of section 5.
7. Stale status lines. Section 10 "Proof status" ("open ECDSA on a theorem whose model section was not read"), section 12 [GS22] entry ("Not read: the EC generic group model of section 2, Theorem 1 and its proof, section 8 onward"), and the ledger line "[GS22] not read in full": the paper is now read. Section 11 item 7 keeps its second half (the Schnorr check) only.

Internal points, not from the papers:

1. Sections 6.5 and 10 say `f < b < t` Byzantine nodes "can certify two digests under one nonce and recover `x`". This holds for ECDSA (ledger D7a). For two-nonce Schnorr it is not supported. D7(b2) shows that two signatures on one slot do not fix `x`. Reviewer's count for the coalition: the three polynomials `d`, `e'`, `x` have `3t` unknown coefficients; `b` corrupt nodes give `3b` equations; two partial-signature polynomials add at most `2(t − b)`; the total `2t + b` is below `3t` for every `b < t`. Three digests on one slot would be needed.
2. Section 6.6 says "two points determine the line". For the two-nonce Schnorr line, D7(b) needs three.

## 7. Section 12 references that can be upgraded

Upgrade to "read in full":

- [GS22] Groth, Shoup, ePrint 2021/1330: `/home/hoskinson/Projects/mpcexperiments/research/sources/groth-shoup-2021-1330.pdf` (pages 1 to 48; reference list excepted).
- Komlo, Goldberg, FROST, ePrint 2020/852: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2020-852.pdf`.

Local now, read in part in this pass, not "in full":

- Internet Computer signing service, ePrint 2022/506: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2022-506.pdf` (parts listed in section 0). SCHEME.md takes its statements from REPORT.md.
- Crites, Komlo, Maller, ePrint 2023/445: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2023-445.pdf` (not cited in section 12; parts listed in section 0).

Local now, not read in this pass; statements still come from REPORT.md or from memory:

- cgVSS: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2023-451.pdf`
- Groth NI-DKG: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2021-339.pdf`
- Ika: `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2024-253.pdf` and `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/2025-297.pdf`
- RFC 9591: `/home/hoskinson/Projects/mpcexperiments/research/sources/lifecycle/rfc9591.txt`

Still not local, still "from memory": Feldman VSS (1987); Bellare et al. on non-interactive threshold Schnorr; MuSig2; Benhamouda et al. on ROS; Abdalla, Bellare, Rogaway; BIP125, BIP143, BIP340, BIP341; RFC 8032; EIP-2, EIP-1559, EIP-2718; Solana durable nonces. None of them appears in `/home/hoskinson/Projects/mpcexperiments/research/sources/eprint/SOURCES.tsv`.

## 8. What closes each gap

1. Open ECDSA: write the reduction of section 2; fix the section 2 assumption line (zero-preimage resistance, Theorem 4 for derived keys).
2. Open Schnorr: obtain the five papers of section 3, state the single-signer game, and either cite a covering theorem or prove it. Add AOMDL or OMDL if the proof needs it.
3. Share encryption: adopt the ephemeral-key proof of 2022/506 section 4.1 and check its associated-data rule (p. 27), or prove extraction in the algebraic group model.
4. Re-randomization: optional. Prove the multiplicative variant with a `δ` source that is unpredictable after the lock, or leave it out.
5. Correct the two Schnorr sentences of section 6 and the stale status lines.

Working draft of this report (temporary): `/tmp/claude-1000/-home-hoskinson/bee643b4-08f5-4340-b29d-1a5130e7b1e5/scratchpad/verification-draft.txt`
