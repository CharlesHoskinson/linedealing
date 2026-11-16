# Review 3 triage

Bundle: commit 1166333 (BUNDLE.md). Reviewer A: `astra-raw.md`. Reviewer B: `carbon-raw.md`. Lead findings: section L. Each row: verdict, one-line reason, and where it is fixed. Decisions 42 to 46 of DECISIONS.md record the changes.

## Reviewer A

| Id | Severity | Verdict | Reason | Fix |
|---|---|---|---|---|
| A-F1 | blocking | admissible | Correct: slot uniqueness and the anchor are board facts, safe for `|C| ≤ f`, while C5, C9, C12, C20 claimed `|C| < t`. Three forked histories give `x_f`. Present before item 27 too. | §4.1 "Agreement on a slot's ticket", C5, C9, C12, C20, R2, §9.3, O27, new O32 (`slot_anchor`); DECISIONS 42 |
| A-F2 | blocking | admissible | Correct: §3.6 step 7 let one ECDSA slot serve every subset; two subsets give two evaluations of one half line. Also across the branches of an OR gate. | §3.6 step 7 leaf-set binding, §3.8, §4.4, §4.5, §5.11, C12, O33; DECISIONS 43; vector `check.py` (d) |
| A-F3 | major | admissible | Correct for the vector: the challenge omitted `Y_i`; the design did not specify the transcript. Cheap. | §4.6 transcript; `check.py` `dleq_ch` and forged-partial case; DECISIONS 46(1) |
| A-F4 | major | admissible | Correct: `y` cannot be pseudorandom given `P = y·G`. Statement restated; no plaintext attack claimed. | §9.3 Theorem D restated, O26; DECISIONS 46(2) |
| A-F5 | blocking | admissible | Correct: §7.11 kept slots unclaimed at the checkpoint, which may have signed in the lost tail. | §7.11 item 2 burns the reservation window, C16; DECISIONS 46(3) |
| A-F6 | blocking | admissible | Correct: actors had no `R_0` or salt; the combiner also lacked `R_0` and the initiator's term point. | §4.2 step 2 and actor rule 1, §4.6 capsule and TEE header, sizes; `sizes.py`; DECISIONS 46(4) |
| A-F7 | blocking | admissible | Correct: `hd` covers the ciphertext that is keyed by `hd`. | §4.6 sealed contribution keyed by `dd`, §4.7 `dd` uniqueness, §5.11; DECISIONS 45 |
| A-F8 | major | admissible | Correct: a vote for a proposal without a QC fixes an `open` digest that peers then refuse to change. Cheap rule. | §7.7 provisional `open` entries, O28; DECISIONS 46(5) |
| A-F9 | blocking | admissible as major | The attack is correct, but it is an overclaim of C10, not a break of a mechanism; non-TEE B1, B2 were already PARTIAL. Fixed by narrowing the claim. | §4.2 "What the ticket hides", §6.4 item 12, C10; DECISIONS 46(6) |
| A-F10 | major | admissible | Correct: `t` broken enclaves or `t` non-TEE nodes reconstruct `κ_0` before ordering; C12 cannot survive all `n`. | §9.2, C10, C21, §6.4 item 14; DECISIONS 46(7) |
| A-F11 | major | admissible | Correct: broadcast is not inclusion; the mempool sees the transaction. | §10 B6 PARTIAL; DECISIONS 46(8) |
| A-F12 | major | admissible | Correct: an offline holder cannot sign `pop` for `X_u`. Fixed with `pop_U` at registration and a proof of `δ`; the non-TEE linkage is stated. | §3.1 steps 1 and 3, §6.4 item 13; DECISIONS 46(9) |
| A status audit | — | admissible in part | C15, C16 now name O5, O10, O17. C4 already says it inherits C17's open status. The C6 remark (an honest node's release vs a completed release) changes no claim: C6 is stated for honest nodes and a release needs `t`. | C15, C16 |

Reviewer A: 12 findings, 6 blocking (F1, F2, F5, F6, F7, F9), 6 major. All admissible; F9 downgraded to major.

## Reviewer B

| Id | Severity | Verdict | Reason | Fix |
|---|---|---|---|---|
| B-F1 | blocking | admissible (duplicate of A-F7) | Same hash cycle; same fix (`dd` as context). | as A-F7 |
| B-F2 | blocking | admissible | Correct: `auth_ref` was outside `hd` and `π`; a rewritten copy passed the public checks. | §4.6 `eid = H(hd ‖ auth_ref)` bound in `π`, random unused `auth_ref`; DECISIONS 49 |
| B-F3 | blocking | admissible | Correct: without `ic` and `r_tkc` no node can check `auth` against `hd` and `tkc`. | §4.6 header carries `ic`, `r_tkc`; sizes; DECISIONS 49 |
| B-F4 | blocking | admissible | Correct: the Ethereum hash has no sender, and the ticket did not tie a slot to the record. | §5.3 item 4 slot roots per source, §5.4 item 4 TEE check; DECISIONS 48 |
| B-F5 | blocking | admissible | Correct: the owner could burn guardian slots, and `G_g = 4 < K·L = 6`. | `slr_G` per source, `G_g = 2·K·L_max`; DECISIONS 48 |
| B-F6 | blocking | admissible | Correct: `k_hdr` encrypted two messages. | `k_fin`, one message per key; DECISIONS 49 |
| B-F7 | blocking | admissible (duplicate of A-F12) | Same gap. The zero-knowledge birth fix is O8 already; the cheap relation is taken and the non-TEE link is stated. | as A-F12 |
| B-F8 | major | admissible | Correct: one honest combiner could not reach `f + 1` VOID posts; escrow commitments for ECDSA checks were missing. Nested ECDSA gates stay without a vector (O18). | §5.6 verified VOID, §4.4 escrow commitments by leaf id; DECISIONS 50(1) |
| B-F9 | major | admissible | Correct: members of one group shared `slot_a`, so they shared `ρ_a`; `cm_addr` did not bind chain or root. | §4.2 leaf ids, §3.1 `cm_addr`; DECISIONS 50(2) |
| B-F10 | minor | admissible | Correct: ECDSA actor table bytes were not counted. The header weight is dropped instead, since it follows from the set. | `sizes.py`, §4.6; DECISIONS 50(3) |
| B-F11 | blocking | admissible (extends A-F5) | Same window, and also cold-start path 1 and recovery. Not taken: dropping the `E` backup of ECDSA slots, because the burn rule already closes the window and the backup still serves a verified record. | §7.11 items 1 and 2, §5.8; DECISIONS 46(3) |
| B-F12 | blocking | admissible (same root as L1) | Correct. Precedence by board order closes it without delaying the header open. Point 5, honest collisions in a public pool, is open item O34. | §4.1 precedence; DECISIONS 44; O34 |
| B-F13 | major | admissible | Correct: the slot witness key lacked suite, epoch and ECDSA scope. | §7.7 table; DECISIONS 50(4) |
| B-F14 | blocking | admissible | Correct: a released request could settle to unspent and keep a live signature. | §5.6 Finality, RELEASED settlement, complaints after ADMIT; DECISIONS 47 |
| B-F15 | blocking | admissible as major | Correct, and inside O29, which keeps C6 and C11 open for board-first. The cheap rules are taken; the proof stays O29. | §5.3 steps 2 and 3; DECISIONS 50(5) |
| B-F16 | major | admissible | Correct: STALLED depended on a node's local table. | §5.9 step 6; DECISIONS 50(6) |
| B-F17 | major | admissible | Correct: host and Midnight heights were compared, and generation 1 outran `revoke`. | §5.5 Midnight heights, `Δ_hold`; DECISIONS 50(7) |
| B-F18 | major | admissible | Correct: zero `auth_ref`, public BIRTH_OK and vote kinds showed the request class. | §4.6, §3.1, §6.4 item 15, C10, C21, B5; DECISIONS 49, 50(8) |
| B-F19 | major | admissible | Correct: the ECDSA session and escrow dealings run in the clear. Stated in both modes; encryption is O35. | §6.1, §6.4 item 3, B1; DECISIONS 50(9) |
| B-F20 | blocking | admissible | Correct: the TEE claims ignored the rollback bound of §7.7, and a per-charter anchor cannot protect the shared `x_f`. | §1, C5, C6, C12, O32; DECISIONS 50(10) |
| B-F21 | major | admissible (extends A-F10) | Adds C1 and C2: `q` broken enclaves sign a birth certificate. | §9.2; DECISIONS 50(11) |
| B-F22 | major | admissible | Correct: the fixed complaint window needs synchrony. C14 stays open. | O5; DECISIONS 50(12) |
| B-F23 | major | admissible in part | Missing obligations on C2, C5, C6, C7 and the §9.3 "none" rows are fixed. Not taken: downgrading R2, multi-actor R1 and B3 to PARTIAL. Each of those cells already names its open proof (O6, O20, O26), and §10 grades the design against §9's statuses; a grade change would hide which proof is missing. | C2, C5, C6, C7, §9.3; DECISIONS 50(13) |

Reviewer B: 23 findings as labeled in the review: 12 blocking (F1 to F7, F11, F12, F14, F15, F20), 10 major, 1 minor; its own summary line says 11 blocking and 11 major. Three are duplicates of A findings (F1, F7, F11 in part). All admissible except the grade-downgrade part of F23; F15 downgraded to major.

## Lead findings

| Id | Severity | Verdict | Reason | Fix |
|---|---|---|---|---|
| L1 | major | admissible (also B-F12) | Reservation by the first request in force lets a node that read a header after ordering copy its slots into a request that comes into force first and void it, against C13. A-F1 does not cover it (it holds at `|C| ≤ f`). | §4.1 precedence by board order, §4.7 item 3, §5.4, VOID reason SLOT_TAKEN, C13, O27; DECISIONS 44 |
| L2 | minor | admissible | A dishonest dealer can reuse one outer dealing under two sets of bodies; both share every PRF key. Within C18's honest-initiator hypothesis, but cheap to close. | §4.7 `dd` uniqueness; DECISIONS 45 |
| L3 | — | inadmissible here | A board-first `authorize` relayed to Midnight after release and then rejected leaves the record behind the host chain. Already open item O29; no new text. | none |
