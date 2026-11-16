# Disposition of the proofs review

Subject: `design/PROOFS.md`, reviewed blind by two cross-family reviewers on the frozen bundle `design/proofs-review/bundle/` (2026-11-13). Both verdicts: changes_requested. This table also covers the gap raised in `design/notes-2022-506.md` item 3.

Result: 16 blocking findings, all VALID, all fixed in PROOFS.md; none was dismissed. 4 non-blocking findings: 2 ask for changes (applied), 2 confirm parts of the document (no change). Five corrections went into SCHEME.md (C19 to C23, rows in `design/FINDINGS-LEDGER.md`). None changes a byte on the wire.

Section numbers are those of the revised PROOFS.md; "§" is SCHEME.md. Where a reviewer's constant was wrong but the finding stands, the row gives the corrected value.

## Findings

| Finding | Severity | Verdict | What changed | Where |
|---|---|---|---|---|
| cand-b 1: `δ_B` omits the `H_b` draws inside `Sign` and the factor 2 of the BIP340 x-only input | blocking | VALID | `δ_B` recomputed over all evaluations: `Q_b + U` and `Q_dg + U`, factor 2 on every nonce collision, `R = O` in `PlainSign`, `Prove` charged against `H_auth` only. Both reviewers' small cases are worked in the text and are dominated by the new bound. Propagates to Theorem B' and E(a) through `Adv^tns` | PROOFS 4.2 (statement, process `W`, the paragraph "Two checks") |
| cand-b 2: a copy with unchanged ciphertexts and altered proof is treated as adversarial by the outer reductions | blocking | VALID | New definition: a *copy* of `M` has the `(hdr, deal, ct)` of `M`; a message is *owner-dealt* if it is a copy of an owner's message. `Auth`, `Exp'` of Theorem C and the reductions of A, B', D treat a copy as the original (same shares, same slots). This changes the experiment and is listed as a narrowed statement. No protocol change was needed: since C2 the `LD1/auth` input covers `E', T_1, T_2, z_e`, so the only free bytes are `(T_a, z_a)`. Theorem D needs no stronger assumption | PROOFS intro, 1.1, 2.3 (i) and case (1), 3.2 step 3, 4.3, 5; SCHEME §3.2, §6.7 (C21) |
| cand-b 3: `SHA-256(ct)` has no assumption | blocking | VALID | Protocol change C19: the labelled hash `H_ct` (`LD1/ct`) replaces raw SHA-256 in `LD1/eph`, `LD1/ephpok`, `LD1/auth`; it is a random oracle under 1.2, so the birthday term is justified. 0 wire bytes, one more compression call | PROOFS 1.2, 2.1, 2.2, 2.3 Game 0, 9 C19; SCHEME §3.1, §3.2, §10 |
| cand-b 4: uniform TNS key against the clamped Ed25519 key | blocking | VALID | 1.2 states the seed-hash assumption, shows that the `2^251` clamped scalars are distinct and nonzero mod `q`, and defines `κ_3 = (q − 1)/2^251 < 2 + 2^{−126}`. Theorem B' multiplies `Adv^tns` by `κ_3` for suite 3. RFC 8032 is quoted from memory and marked so | PROOFS 1.2, 4.1 item 1, 4.3; SCHEME §2 (C23) |
| cand-b 5: retries exceed the query budget of Theorem A | blocking | VALID | One retry per slot, then abort. Budget `4S + 2Q_w`, held with certainty. `δ_A` gets `S·(θ_q + (2S + 4)/(q − 1))²` with `θ_q = Pr[x(R) ≥ q] < 2^{−125}`, derived from 2021/1330 p. 10 (2-to-1 conversion, Hasse). Closing strings recounted: at most `2S`, term `2S/2^256`. `U + 1` rechecked | PROOFS 1.2, 3.2 (statement, steps 1, 5, 6, final paragraphs) |
| cand-b 6: E(c) omits the nonce-collision loss | blocking | VALID | E(c) is replaced. New (c): dealing identity, from Theorem C and `H_rid` collisions alone, no forking. The byte-identity form is kept as (c′) under explicit hypotheses, with the term `4·Q_s/(q − 1)` for an oracle nonce in `{k, −k}` over both runs, and the `H_rid` term | PROOFS 6.1 (c), (c′); SCHEME §2, §6.7 (C21) |
| cand-b 7: Lemma 4, the extraction of Theorem B and Lemma 5 survive | non-blocking | no change asked | Kept. The status lines record that both reviews checked these parts | PROOFS 4.2 status, 6.1 status table, 8 item 8 |
| cand-b 8: citations and the associated-data construction are accurate | non-blocking | no change asked | Kept. The citation "[GS22] p. 24" for "no proof of possession" now points to p. 27 note 1, the passage reread for this revision | PROOFS 2.3 |
| cand-c 1: authorship-proof mauling on unchanged `(hd, ct)` breaks A, B', D | blocking | VALID | Same fix as cand-b 2, by the reviewer's option (a). The reviewer's counterexample to Theorem D is quoted in section 5 as the reason for the definition | PROOFS 1.1, 2.3, 3.2, 4.3, 5 |
| cand-c 2: E(c) is false for deterministic wallets; missing `R`-collision and `H_rid` terms | blocking | VALID | Same fix as cand-b 6. The counterexample is in the text. Byte identity for a pending sealed message is no longer claimed in general; what is lost is in section 8 item 4. The reviewer's `4Q/(q − 1)` for the 4-to-1 conversion function is not needed: two ECDSA signatures on one message are equal up to sign only if the nonces are `±k`, so the term is `2/(q − 1)` per oracle signature, `4·Q_s/(q − 1)` over two runs | PROOFS 6.1 (c), (c′), counterexample; 6.2; 8 item 4; SCHEME §2, §3.2, §6.7 (C21) |
| cand-c 3: `δ_B` omits internal queries; `R = O` and `2/q` in `PlainSign` | blocking | VALID | Same fix as cand-b 1; the new `δ_B` equals the reviewer's formula | PROOFS 4.2 |
| cand-c 4: `msg(j, M)` cannot be fixed in advance; `Hq_bind` pre-query and x-collision terms | blocking | VALID | `NewSlot(ℓ)`: the adversary gives the input index when the slot is created; `msg(ℓ, M)` is a fixed function. Theorem B' gets `δ_B' = Q_bind·S_msg/2^256 + 4S²/q`; the `H_hd` pre-query is charged in `δ_C` | PROOFS 4.1, 4.2 (status), 4.3 |
| cand-c 5: E(b) uses Theorem A's `N`, which omits the `Chal` queries | blocking | VALID | `O((N + Q_auth)²/q)` in E(b); Lemma 5 says that `N` counts the `Chal` queries and why | PROOFS 6.1 (b), Lemma 5 |
| cand-c 6: the closing rule of Theorem A fails on an inconsistent board and under board lag | blocking | VALID | A slot is live until the first honest PARTIAL or until every honest node is done with it in its own view. `U` is schedule-dependent, at most `S`; this weakening is stated in 3.3 item 3 and section 8 item 9. The fix needs a node that is done to stay done, also after a restore: new model item "Views" and SCHEME rule 4 (C22). The rollback mechanism is a rule, not a proved property (section 8 item 11) | PROOFS 1.1, 3.2 (symbols, steps 4, 5), 3.3 items 3, 10; SCHEME §3.9 rule 4, §2 |
| cand-c 7: `x(R) ≥ q` retries exceed `3S + 2Q_w` | blocking | VALID | Same fix as cand-b 5. The reviewer's `2^{−127.6}` is replaced by the derived bound `θ_q < 2^{−125}` (numerically about `2^{−126.7}`, the factor 2 of the 2-to-1 conversion included). Wallet failures add `8·Q_w/(q − 1)` | PROOFS 1.2, 3.2 |
| cand-c 8: Theorem 4 needs the tweak set before `D`; BIP32 tweaks depend on `D` | blocking | VALID | Corollary A' restated: HMAC-SHA512 is a random oracle, the path set `𝒫` is fixed in advance, bound `E[Φ_4(E_𝒫)] + |𝒫|²/2^256`. The step that draws the tweaks before `D` and programs HMAC is proved in the text and marked "no outside review". The indifferentiability claim of 2021/1330 Appendix D is not used. Adaptive paths and section 7.4.2 are open. The reviewer's references to 2022/506 pp. 10 and 90 are not used (not read) | PROOFS 1.2, 3.4, 7, 8 item 3; SCHEME §2, §6.5 (C23) |
| cand-c 9: raw `SHA-256(ct)` | blocking | VALID | Same fix as cand-b 3 (the reviewer's first option) | PROOFS 1.2, 2.3; SCHEME C19 |
| cand-c 10: no subgroup check on `PK_i` and `K_i` in suite 3 | blocking | VALID | Protocol change C20: registered `PK_i`, complaint `K_i` and `E'` must pass check 2 (canonical, not the identity, `[ℓ]P = O`). Model 1.1 says corrupt nodes register any key that passes the check. Theorem C Game 5 and Theorem E(d) cite it; the 2-torsion attack is recorded after the proof of E(d). 0 wire bytes; one multiplication by `ℓ` per key and epoch, per complaint, per message | PROOFS 1.1, 1.5, 2.2, 2.3 Game 5, 6.1 (d); SCHEME §2 Setup, §3.4, §10 |
| cand-c 11: query counts should include honest evaluations; identity points and `Hq_enc` pre-queries in `δ_C` | non-blocking | VALID, applied | 1.2 defines `Q_x` as all evaluations. `δ_C` gets `(n + 2·Q_msg)/q`, `Q_enc·Q_msg/2^256` and `Q_H·Q_msg/q`; `ρ` is drawn from `Z_q*`. E(d) is now a bound over the whole experiment | PROOFS 1.2, 2.3, 6.1 (d) |
| cand-c 12: typo "Theorem 6(c)"; wallet retries; clamping factor | non-blocking | VALID, applied | Typo fixed. `Q_w/2^256` removed and `8·Q_w/(q − 1)` added to `δ_A`. Clamping: as cand-b 4. The reviewer's density 0.488 and factor 2.05 are wrong: the density is `2^251/(q − 1)`, just below 1/2, and the factor is `κ_3 < 2 + 2^{−126}` | PROOFS 1.2, 3.2, 4.3 |
| notes-2022-506 item 3: the `Reuse` step uses soundness after Game 4 simulated the honest proofs; 2022/506 pp. 31 and 56 claim soundness and ZK only | gap | VALID | Argument added inside the `Reuse` bullet: every `Hq_ephpok` input starts with `(hd, H_ct(ct))`, the simulator programs only inputs of honest messages, a `Reuse` message has another prefix, so its challenge is an unprogrammed uniform value and the statistical soundness bound of Lemma 3 applies. Lemma 3 states soundness at unprogrammed inputs. The Game 3 remark no longer reads as covering `Reuse`. Theorem C also gets statement 2, a bound on `Pr[Reuse]` in `Exp`, which E(c) uses | PROOFS 1.5, 2.3 (Games 3, 4, 6; statement 2) |

## Protocol changes and their cost

| Id | Change | Wire bytes | Computation |
|---|---|---|---|
| C19 | `H_ct(ct)` (label `LD1/ct`, and `LD1/rs-ct`) replaces `SHA-256(ct)` inside `LD1/eph`, `LD1/ephpok`, `LD1/auth` | 0 | one more SHA-256 compression call per evaluation |
| C20 | Suite 3: registered `PK_i`, complaint `K_i` and `E'` must be canonical, non-identity and satisfy `[ℓ]P = O`; same for resharing dealings (§5) | 0 | one multiplication by `ℓ` per key and epoch, per complaint, per message |
| C21 | Sealed claim 6 restated as dealing identity; text only | 0 | none |
| C22 | Rule 4 of §3.9, a new rule that the closing-rule fix needs: a restored node replays to its earlier board position before it posts and erases again; without a record of that position it recovers one on a consistent board and counts as Byzantine on an inconsistent one. `U` redefined | 0 | a restored node waits for its replay |
| C23 | Three assumption lines in §2 (HMAC-SHA512 for BIP32, SHA-512 of the Ed25519 seed, wallet nonces) | 0 | none |

The Rust prototype (`impl/src/message.rs`, `impl/src/ed25519.rs`) and `experiments/line-dealing/checks.py` (check T15) still use the old challenge inputs. They were not changed and no check was rerun for this revision.

## Still open after this revision

1. Everything the revision changed has had no outside review: `δ_B`, `δ_A` and the retry cap, the per-node closing rule, the `Reuse` soundness argument, Corollary A' with the tweak-programming step, Theorem E(c) and (c′), the factor `κ_3`.
2. Byte identity of a pending sealed message is not claimed in general (false for deterministic wallets). Theorem E(c′) covers fresh-nonce wallets; a key used in both modes is open there.
3. Theorem A's `U` is the number of slots some honest node can still sign, up to all slots ever dealt; a bound in board-live slots is open.
4. The restore rule of C22 is a hypothesis of Theorem A. The way a rolled-back node learns its earlier board position works on a consistent board only, is written as a rule, and is not proved or modelled in Lean.
5. BIP32: adaptive path choice, a tight fixed-tweak bound, and the route through 2021/1330 section 7.4.2.
6. Constants quoted from memory (Ed25519 order and clamp, secp256k1 `p`, `q` for the numeric `θ_q`) and RFC 8032, RFC 6979, BIP32, which are not in the repository.
7. Unchanged from before: `reshare`, claim 3 in the "fewer than `t − |C|` partials" form, ICDH in the EC-GGM, adaptive corruption and UC, comparison with the published FROST and MuSig2 proofs.

## Fix check (2026-11-13)

Both original reviewers checked their own findings against the revised text (frozen bundle `fixcheck/`, hashes in `FIXCHECK.sha256`).

| Reviewer | Verdict | Original blocking findings | New blocking findings |
|---|---|---|---|
| cand-b | changes_requested | 6 of 6 RESOLVED | 1: Corollary A' omits the BIP32 invalid-child loss (`a ≥ q`, derived key `O`) |
| cand-c | approved | 10 of 10 RESOLVED | none |

| Finding | Disposition | Fix |
|---|---|---|
| fixcheck cand-b, new 1 | VALID | Corollary A': `B'` aborts on `a ≥ q` and on a derived key `O`; the bound gains `|𝒫|·((2^256 − q)/2^256 + 1/q)`, derived per path in the proof. Verified by reading the revised passage: the abort events are exactly the BIP32 rejection events, and conditioned on no abort the derived keys are the BIP32 keys. |
