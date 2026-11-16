# Triage of the blinded review: paper-split

Bundle manifest hash: `35cd9a5c01aa2cd2b9608cfbbeea39d84944d4db7bd4add701326eb901450751` (see `BUNDLE.md`).
Verdicts: Astra `changes_requested`, 10 findings, all marked BLOCKING. Carbon `changes_requested`, 15 findings, 10 marked BLOCKING.

Each finding was checked against the bundle before a fix. "Fixed" means the change is in the paper and the check named in the last column passed.

## Astra (GPT-6 Astra)

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| A1 | Profile proposition claims more than `Profiles.lean`: the Lean `charter` maps P0 and P1 to the single-user charter only. | Admissible, blocking. Confirmed in `Profiles.lean` lines 21 to 25. | Proposition now states the model (P0, P1 = `user`; P2 = `user ∨ G`). New paragraph: other charters get the profile-free combination from Prop. access and Prop. keysplit(f); the user need not sign them; deployed P0 signs by line dealing, outside the model. | Every sentence of the proposition matches a D19 theorem statement. |
| A2 | Blindness stated without its exceptions: non-TEE nodes see `tw` at birth; ECDSA slot ids name the account; enumeration breaks ticket hiding. | Admissible, blocking. Confirmed in the paper's own view table and DESIGN C10. | Setting: `tw` seen by enclaves in TEE mode and by nodes at birth in non-TEE mode. Blindness: "blindness until release" now conditioned on non-enumeration on Schnorr and states ECDSA account identification. C10 row states both exceptions. | Statements agree with Table views and DESIGN C10. |
| A3 | Release procedure omits the per-release revocation check and the P2 hold window. | Admissible, blocking. Confirmed in DESIGN §5.4. | Added to "Select, witness, release, combine": ledger check before each release at a finalized height at least as new as the anchor reports, P2 `Δ_hold` (launch 2 blocks) before generation 1, revocation voids or stops later generations. | Text matches DESIGN §5.4 paragraph by paragraph. |
| A4 | C6 constrains every node, but a corrupt non-TEE node can emit its own partial. | Admissible, blocking. DESIGN argument covers honest nodes and completed release. | C6 now: no honest node releases, so no release completes, because a release needs `t` nodes. | Matches DESIGN C6 argument. |
| A5 | Recovery called unconditional, but ECDSA exit without anchored slots needs a refill with every session party online. | Admissible, blocking. Confirmed in DESIGN C15. | C15 row, §Exit and §Profiles: "without policy checks" replaces "always"/"unconditional"; ECDSA refill condition stated. | No "unconditional" or "P1 always" remains (grep). |
| A6 | Without the Taproot tweak term the signature verifies under neither key, not under `P`. | Admissible, blocking. The challenge hashes `x(Q)`, so `c_P ≠ g_Q c_Q` in general. | Sentence now: the signature fails under `Q`. | Algebra re-derived; the Lean theorem used (`C4_tweak_twice_fails`) is unaffected. |
| A7 | Intro says the ECDSA functionalities "are instantiated"; the construction says O1, O2 are open. | Admissible, blocking. | Intro: "have candidate instantiations ... whose adaptation at our threshold is open". | Consistent with §ECDSA slots and O1, O2, O19. |
| A8 | Latency omits the two batched bind rounds of the TEE release. | Admissible, blocking. Confirmed in DESIGN §7.7 carriage paragraph. DESIGN §11.2 has the same omission. | TEE: `max(F_M, C+h) + C + 4h`, board-first `2C + 5h`; estimates F_M + 1.2 s / F_M + 0.7 s, 2.25 s / 1.25 s; non-TEE saves `3h`; O36 dependence and P2 hold wait stated; O36 added to the open table. | Round count matches DESIGN §7.7; values recomputed with h = 50 ms. |
| A9 | CPU totals do not equal the sum of their rows. | Admissible, blocking. DESIGN §11.3 has the same error. | Totals 3.0 to 6.3 ms and 4.4 to 10.5 ms; rates 160 to 330 and 95 to 230 per second and core. | 1.8 + 1.2 = 3.0, 2.7 + 3.6 = 6.3, 2.4 + 2.0 = 4.4, 3.3 + 7.2 = 10.5; 1000/3.0 = 333, 1000/6.3 = 159, 1000/4.4 = 227, 1000/10.5 = 95. |
| A10 | "One envelope deals one secret and every key is a PRF output" contradicts random capsule keys and P0's retained line dealings. | Admissible, blocking. Confirmed in DESIGN §4.6. | Abstract and intro scoped to the outer dealing and the committee-derived keys; §Envelope states capsule keys are the initiator's random keys and P0 carries line dealing's own dealings. | Consistent with DESIGN §4.6. |

Build after the fixes: latexmk clean, no undefined or multiply defined references, no overfull boxes, 29 pages. Commit 27855cc.

## Carbon (Gemini 4 Carbon, high)

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| G1 | Profile proposition exceeds `Profiles.lean`; §Profiles and the abstract repeat the unscoped claim; P0 is mismodeled. | Same as A1, plus the setting and abstract sentences. | Fixed with A1. §Profiles: P1 and P2 share one combination rule; P0 shares the envelope and ordering path and signs by line dealing. Abstract: profile independence is stated for the single-user and guardian charters, and the profiles share one envelope and one ordering path. | Every profile sentence matches a D19 statement or names the model's limit. |
| G2 | Prop. keysplit(b): `Eval` undefined and the degree bound missing; false for families longer than `t`. | Admissible, blocking. `D21_reconstruct_point` uses `feldmanEval t`. | Defined `Eval_t(C, i) = Σ_{j<t} i^j C_j`; `Q` is a set of distinct indices in Z/q. | Matches the Lean statement. |
| G3 | Rogue-key sentence subtracts `tw G`, but `tw` hashes `X_r`. | Admissible, blocking. DESIGN §3.1 gives `X_r = zG − X_f − Σ X_a`. | §Birth now uses the DESIGN form: the key is `z + tw`, known once the actor holds the seed. Prop. keysplit(d) states the Lean theorem with an explicit fixed `tw`. | Matches `C2_rogue_key_without_pop` and DESIGN §3.1. |
| G4 | Precedence definition omits "not burned"; C13 says "earlier live request". | Admissible, blocking. `BoardPrec` requires `¬ Burned`. | Precedence = first request in board order that names the slot, while live; after it ends the slot is burned and nobody has precedence. C13: "an earlier request". | Matches `BoardPrec` and Prop. precedence (a) to (c). |
| G5 | Unauthorized envelopes can burn an account's ECDSA slots; a P2 user can burn the guardians' slots and stay offline. | Admissible as a design finding. DESIGN §4.1 decides precedence before the authorization and accepts burn spam for committee pools only by pool cost (O34); for per-address ECDSA slots the same rule is a denial of service. The paper cannot change the protocol alone. | Limits §ECDSA states the exposure under the paper's burn rule (named slots burn when their request ends), the SLOT_TAKEN voiding that holds under either DESIGN burn rule, the P2 seizure delay, and the rule that would close it, which the protocol does not have. No O-number exists; reported to the lead for a DESIGN rule and an obligation. | Statement agrees with DESIGN §4.1, §5.3 item 4 and §5.8. |
| G6 | Session parties include OR escrow holders; `T_0` size and zero inputs missing. | Admissible, blocking. DESIGN §3.6. | Escrow holders excluded; `T_0` of `k_γ` members; members outside `T_0` enter zero. | Matches DESIGN §3.6 lines on session parties. |
| G7 | Board-first omits the unused-nullifier check, the root-age bound and the certificate gate on the ledger. | Admissible, blocking. DESIGN §5.3 steps 1 to 5. | Board-first paragraph now has all five steps. | Matches DESIGN §5.3. |
| G8 | Blindness overstated in both modes; table omits board leaks. | Admissible, blocking; overlaps A2. | TEE operator sentence lists the public board fields; "or chain" removed and the suite leak stated; table rows for P2 escrow at birth, board-first call at post, and selected index at anchor; receive-key link in Limits; C21 TEE clause. | Matches DESIGN §6.1 table and §6.4 items 3, 9, 13, 15, 16. |
| G9 | Limits says an admitted set needs `t` nodes; in non-TEE mode without anchors fewer suffice. | Admissible, blocking. | Limits and §Slots state the Schnorr fork count `3(t − |C|) ≤ n − |C|`: 6 at n = 9, 10 at n = 17. Limits also states the ECDSA count with an admitted set, `2(t − |C|) ≤ n − |C|`: 5 and 7, where two signatures on one nonce give `x`. | 3(7 − 6) = 3 ≤ 3; 3(7 − 5) = 6 > 4. 3(12 − 10) = 6 ≤ 7; 3(12 − 9) = 9 > 8. 2(7 − 5) = 4 ≤ 4; 2(7 − 4) = 6 > 5. 2(12 − 7) = 10 ≤ 10; 2(12 − 6) = 12 > 11. |
| G10 | Intro "are instantiated" ECDSA claim. | Same as A7. | Fixed with A7. | As A7. |
| G11 | `59 or more` for K = L = 1 disagrees with DESIGN §11.1 `more than 60`. | Not a paper error. `sizes.py` gives a minimum of 59 (Solana, n = 17, TEE); DESIGN is wrong. | No paper change. | Reviewer reran `sizes.py` with the same result. |
| G12 | CPU totals and latency rounds. | Same as A8 and A9. The reviewer also counts a witness round as a round trip (6h). | Fixed with A8 and A9. The paper keeps DESIGN's convention of one `h` per batched round; a round-trip count is a modelling choice for item 11's measurements. | As A8 and A9. |
| G13 | `auth_ref` filling for envelopes without an authorization is not stated. | Admissible, non-blocking. DESIGN §4.6 says 32 random bytes; §4.6 contribution-frame line says zero. | §Envelope states 32 random bytes. | Matches DESIGN lines 417 and 432. |
| G14 | Langford notation clash; uncited FR95 entry. | Admissible, non-blocking. | Langford sentence names the coefficients `k^{-1}` and `k^{-1}x` in our notation; FR95 removed from the bibliography. | bibtex: 0 warnings. |
| G15 | `\cref` prints "Theorem" for propositions and the open statement; intro says 58 theorems. | Admissible, non-blocking. Confirmed in the PDF text. | `\label[proposition]`, `\label[statement]` and `\crefname`; intro says 57 theorems and one equivalence. | PDF text: every reference reads Proposition 1 to 7 or Open statement 8. |

Build after the fixes: latexmk clean, no undefined or multiply defined references, no overfull boxes, 30 pages.

## Findings for the design specification

These are DESIGN.md errors that the review exposed. The paper is fixed; the specification is outside this lane.

- §11.2 latency table omits the two bind rounds of §7.7 (A8).
- §11.3 totals and rates do not equal the sum of the rows (A9).
- §4.1 precedence is decided before the authorization is in force, so unauthorized envelopes block, and under §4.1's burn rule burn, per-address ECDSA slots, including P2 guardian slots (G5). Needs a rule and an obligation number.
- §4.1 burns every named slot when its request ends or lapses; §4.5 item 4 burns only reserved slots. The two rules disagree.
- §11.6 quotes 160 to 400 requests per second; the corrected §11.3 totals give 160 to 330 at n = 9 (A9).
- §4.6 contribution frames carry `auth_ref` zero, against the 32 random bytes of the same section (G13).
- §11.1 gives "more than 60" for K = L = 1; `sizes.py` gives 59 at n = 17 in TEE mode (G11).
- §5.11 leaf-set row still says that two leaf sets leak "the committee's halves x"; §3.6 and the paper carry the corrected statement.

## Sync with the design after the review

Main moved during the review (batched ledger writes, pending-floor checkpoint fields, pool-key roots, O37). The paper was brought in line after merging main: four pool fields per checkpoint and the restart burn from the pending floor to `h + B`; settlement leaves under the checkpoint's settlement root, with the carried VOID leaf on reissue; board-first calls under a board-first root with no per-call ledger write; pool-key roots; the ledger-write table split into user writes and committee writes with the checkpoint sizes of DESIGN §11.6; O29 restated and O37 added. The rate-derived leaf count of §11.6 was left out, because it used the uncorrected rate. These changes postdate the blinded bundle and were not reviewed by either lane.
