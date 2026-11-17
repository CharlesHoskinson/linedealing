# Midnight writes audit: Sherlock (Moriarty)

Date: 2026-11-14. Read-only audit. Nothing in Moriarty was edited except the llm-wiki entries named at the end.

Owner ruling (2026-11-14): no design may write to Midnight per event. A design commits per checkpoint, epoch or batch (one Merkle root or a few fixed-size fields), keeps item data off chain and checks it against the root.

## Design of record and how it was found

- `llm-wiki/wiki/overview.md` and `llm-wiki/wiki/syntheses/WorkstreamStatus.md` point to the live loop `research/sherlock-tested-design-20261113/LOOP.md` (main `7d6c4bd13`) and to the architecture `research/sherlock-final-design-20261111/ARCHITECTURE.md`.
- The newest integrated design tree is branch `t10q` at `f8fd268e3` (T10m merged, T10q fixes running). The contract `tools/sherlock-sdk/sherlock-ledger.compact` exists on `t10q` and not on `main`. Every citation below of the form `t10q:path:line` is read at `f8fd268e3` with `git show`. No worktree was opened.
- Also read: `research/sherlock-processor-final-20261111/FINAL-DESIGN.md`, the OpenSpec specs `sherlock-modular-leaf-20261111/specs/sherlock-ledger-contract/spec.md` and `sherlock-processor-final-20261111/specs/{sherlock-midnight-side,sherlock-anchor-chunks}/spec.md`, the T9 and T10 RESULTS, the Mycroft a3 lane report (branch `mycroft` at `9249f5789`), and the legacy contracts in `tools/sherlock-sdk/`.

## Measured and stated sizes used below

| Item | Value | Label and source |
|---|---|---|
| `acceptRun` transaction | 6,783 bytes | MEASURED on the local devnet, block 22,728 (`~/.cache/t10mm/devnet/t10a-state.json`, key `calls/accept/txBytes`; a run state file, not a committed receipt) |
| `SherlockLedger` deploy transaction | 5,388 bytes (Preview), 5,390 bytes (devnet) | MEASURED (`~/.cache/t17/preview/t10a-state.json`, `~/.cache/t10mm/devnet/t10a-state.json`; run state files) |
| Wrap proof | 2,912 bytes | MEASURED (`t10q:research/sherlock-t9-contract-20261113/RESULTS.md:182`) |
| Wrap verifier key | 1,325 bytes, 1,353 bytes framed; one copy per entry, three entries | MEASURED (LOOP T10m row; `t10q:research/sherlock-t10-bound-20261114/RESULTS.md:22`) |
| `runs` entry | one `Field` key and one `Field` value | `t10q:tools/sherlock-sdk/sherlock-ledger.compact:25` |
| `openClaim` and `acceptCollection` transaction sizes | unstated | no measurement found |
| Warm call time, one wrap proof per ledger call | 175.5 s on huginn | DERIVED from MEASURED stages (LOOP.md:64, lead decision O3) |

**Throughput.** The design states no throughput. ARCHITECTURE says "No throughput figure is quoted (R-10)" (`t10q:research/sherlock-final-design-20261111/ARCHITECTURE.md:2526`), and throughput gates stay in SRC-011 and SRC-015, which are latency and memory caps, not rates. The only rate this audit can give is a per-prover ceiling: one ledger call needs one wrap proof, so one prover issues at most 86,400 / 175.5 = about 492 ledger calls per day (DERIVED from LOOP.md:64). The elastic design adds provers, so the network-wide rate is that ceiling times the number of provers, and it is unbounded by the design.

## Discriminator

Each row is classified by one question: does the write count grow with user transactions, or with runs, claims, chunks or provers?

- **OK**: one write per checkpoint, epoch, batch, deployment or rarer, or exactly one call per user transaction that the user pays for anyway (a Compact call that Sherlock proves in place of the native proof).
- **PER-EVENT**: the count grows with internal events (runs settled by an operator, claims, chunks) and should be batched.
- **UNCLEAR**: the design leaves the trigger or the rate open.

## Findings table

| # | Site | What is written | Trigger | Writes per event | Rate | Class | Proposed batch |
|---|---|---|---|---|---|---|---|
| 1 | `acceptRun`, Compact entry path: `t10q:tools/sherlock-sdk/sherlock-ledger.compact:41-46`; ARCHITECTURE.md:3089 | one wrap proof verified (2,912 B), one `runs` insert `claim_pub -> outcome_pub`; tx 6,783 B MEASURED | a user's Compact call, proved by Sherlock in place of the native proof | 1 call per user call | equal to the user call rate; at most about 492 per prover per day (DERIVED) | OK | none needed: it replaces the native call one for one. The `runs` entry is new state that a native call would not write; see row 2 |
| 2 | `acceptRun`, general run path: same lines; ARCHITECTURE.md section 1.8 "A general run is a Sherlock program whose effect words write its run statement" | as row 1, plus one permanent `runs` entry per run | each proved run (co-processor job) | 1 tx, 1 proof verify, 1 map insert per run | per run; unstated rate; ceiling about 492 per prover per day (DERIVED); `runs` grows by one entry per run forever | PER-EVENT when an operator or service settles each job; OK only when the run's own user submits and pays | settle jobs through `acceptCollection` (row 3) once per epoch: one `set_pub` per epoch, claims held off chain in the collection's SET tree, consumers check membership against the root (in their own proof via GP-2, or row 4 in the batched form). Make `acceptRun` the path for a single user-submitted run only, and say so in the LEDGER CONTRACT kit |
| 3 | `acceptCollection`: `t10q:tools/sherlock-sdk/sherlock-ledger.compact:48-53`; ARCHITECTURE.md:3090 ("It makes no per-claim write") | one wrap proof verified, one `verified_roots` insert of `set_pub` | one collection (a JOIN tree of many runs) | 1 per collection | per collection; unstated | OK (this is the batched form) | none. Note: `L` over a SET root is still open (LOOP T8b row: "open: L over SET (after T10)"), so only the per-run path (rows 1 and 2) is tested end to end today |
| 4 | `openClaim`: `t10q:tools/sherlock-sdk/sherlock-ledger.compact:55-61`; ARCHITECTURE.md:3091; FP-3 fact 3 (ARCHITECTURE.md:446) | one opening proof verified (one full wrap proof per claim), one `runs` insert | each claim a consumer wants settled from a verified collection | 1 tx, 1 wrap proof, 1 map insert per claim | per claim; a collection of N claims costs 1 + N transactions and N wrap proofs (N x 175.5 s proving, DERIVED) if every claim is opened | PER-EVENT: it undoes the batching of row 3 | do not settle claims one by one. Consumers that are Sherlock runs discharge claims in circuit from the verified `set_root` (GP-2 DESCEND and DL-STEP, no ledger write). For a consumer contract that must see a claim on chain: have the collection statement carry a second, Fr-native root over the `claim_pub` values (a Compact-checkable Merkle root, built in `L` or the wrap), and let the consumer contract check a Merkle path against `verified_roots` inside its own call, with its own nullifier if the claim is single-use. Item data (the member list and paths) stays off chain with the prover or a data-availability store. Added dependency: claim data availability, and a consumer waits for the collection's epoch to close |
| 5 | `foreign: Map<fclaim_d, ()>` and the `FOREIGN` opening: ARCHITECTURE.md:3086, :3091; LDG-001, LDG-005 | one map insert per foreign claim opened | each foreign claim opened from a collection | 1 tx and 1 proof per foreign claim | per foreign claim; unstated | PER-EVENT (design text only; not in the compiled contract) | same as row 4: foreign claims stay members of the collection root and are checked by path |
| 6 | Chunked calls: ARCHITECTURE.md:3208, :3214 to :3216, :3231; FINAL-DESIGN.md:170-175; `sherlock-anchor-chunks/spec.md` ANC-002, ANC-004 | `k` contract calls in one transaction, each with its own wrap proof and one anchor overwrite (`ins anchor := a_out`) | one logical call whose transcript exceeds `L_TX` = 1,024 words | `k` calls, `k` proofs, `k` anchor overwrites per logical call; `k` = 5 to 30 at code defaults, "about `k` times the fee of one call" (ARCHITECTURE.md:3231) | per oversized call; proving `k` x 175.5 s (Mycroft a3 REPORT.md:20, ESTIMATE); no suite entry needs it today (largest `L_e` 699 of 1,015 words, Mycroft a3 REPORT) | PER-EVENT (one call per chunk, an internal cut), inside one user transaction | the effect words themselves are the user's ledger writes and must stay in the transcript, so the batch target is the overhead: `k - 1` extra proofs and `k` anchor writes. Size `L_TX` so one call covers every measured entry (the ledger takes up to 65,536 public inputs per call, ARCHITECTURE.md section 1.10; the cost is wrap rows per public word under the k = 21 cap, which E5 measures). Keep chunking as a fallback with a plan-time cap and a printed fee, as Mycroft a3 question 5 already recommends. No net state growth: the last chunk writes `C_P` back |
| 7 | OpenSpec text still specifies `descend`: `t10q:openspec/changes/sherlock-modular-leaf-20261111/specs/sherlock-ledger-contract/spec.md:24-29` (LDG-004), :18 (LDG-003 with `shape_d`), :31-32 (LDG-005); FINAL-DESIGN.md:102 lists `descend` | one `descend` call per `K_open` levels, each inserting a sub-root into `verified_roots`, then one `openClaim` | each claim deeper than `K_open` levels | `ceil(depth / K_open)` calls plus 1 per claim | per level per claim | PER-EVENT (stale spec; ARCHITECTURE.md:446 and :3091 say "`descend` is removed") | update the spec to the ARCHITECTURE form (depth inside the proof), and then to the row 4 batched form. If built as written it is worse than row 4 |
| 8 | Deployment per program: N-11 AFK pick, `t10q:research/sherlock-t10-bound-20261114/RESULTS.md:15`; constructor `sherlock-ledger.compact:29-34` | one contract: anchor `C_P`, `reg_root`, three copies of the wrap key (1,353 B framed each); deploy tx 5,388 B MEASURED | each new program | 1 deploy per program | per program; rare | OK | none needed for the rate. The per-program contract is the SRC-007 owner item (one universal ledger for all programs needs a program registry root) |
| 9 | `reg_root`: `sherlock-ledger.compact:27` (sealed, set once by the constructor); ARCHITECTURE.md:3088 "history and revocation rule of N-8 (open)" | today nothing after deploy | registry change | today 0; after N-8 unstated | unstated | UNCLEAR (N-8 open) | when N-8 is decided, update the registry by one new root per registry epoch, never one write per registered key, with the entry list off chain and membership proved in circuit (the GP-3 hook already proves membership against `reg_root`) |
| 10 | T19 validium demo: LOOP.md:41 | one stored state root per accepted batch | one batch, or one GP-4 fold of several batches | 1 per batch or fold | per batch; unstated | OK (the owner's batched shape: root on chain, data off chain) | submit one call per fold, not per batch, where latency allows |

## No Midnight writes (negative findings)

- Leaves, nodes (N1, N2, N3), `L`, `L_Fr` and the wrap write nothing to Midnight; only the final wrap proof is submitted (FINAL-DESIGN.md:38-43; ARCHITECTURE.md section 1.10).
- Continuations, checkpoints, suspension and resume write nothing on chain: the mode 1 checkpoint record is a host artifact in the HOST CHECKPOINT STORE kit (ARCHITECTURE.md kit CONTINUATION, "Mode 1 checkpoint record (host artifact, persisted)"; FINAL-DESIGN.md:241).
- GP-2 DESCEND, DL-STEP and SEAL-WITH-DEPS are node modes in the proof tree, not contract calls.
- The elastic schedule (T16), the prover daemon (T14b) and the GPU work (T14) have no ledger side.
- A search of ARCHITECTURE.md, FINAL-DESIGN.md, LOOP.md and the two live OpenSpec changes for prover registration, stake, slashing, payment, bounty, marketplace and attestation found none.

## Legacy and superseded contracts (appendix)

These sit in `tools/sherlock-sdk/` on `t10q` but are not the design of record. They are listed so no one revives them unchanged.

| Site | Writes | Class | Note |
|---|---|---|---|
| `t10q:tools/sherlock-sdk/sherlock-anchor.compact:78-80` (`acceptValidity`) and `:85-127` (`settleValidity`) | two transactions per settlement; `validity_ok` and `settled` sets grow by one statement each; `root`, `height`, `batch_no` overwritten | PER-EVENT: one settlement advances exactly two machine steps (`:2-4`, `:107`) | stagenet A9 milestone; superseded by `SherlockLedger` |
| `t10q:tools/sherlock-sdk/rollup-anchor.compact` | same two-call accept and settle pattern per rollup batch | OK per batch, but two transactions where one would do | stagenet B4 milestone |
| `t10q:tools/sherlock-sdk/sherlock-run.compact:40-46` | `runs.insert(stmt)`, overwrite of `steps` and `result` per run | as row 2 | C6 per-program milestone contract, "kept until N-11 is answered" (ARCHITECTURE.md kit LEDGER CONTRACT, code skeleton) |
| `t10q:docs/sherlock/design/suspension-and-finance.md` (2026-10-25) | settles every batch, including each `Waiting` checkpoint, as a new root through the A9 pattern | UNCLEAR (superseded) | pre-C6 design note |

## Summary of PER-EVENT items

1. `acceptRun` used for every job of the co-processor (row 2): one transaction and one permanent `runs` entry per run.
2. `openClaim` (row 4) and the `foreign` opening (row 5): one transaction, one wrap proof and one map insert per claim, which cancels the gain of `acceptCollection`.
3. Chunked calls (row 6): `k` proofs and `k` anchor writes for one logical call, `k` = 5 to 30.
4. The stale OpenSpec `descend` (row 7): one call per `K_open` levels per claim.

The batched form already exists in the design: `acceptCollection` writes one `set_pub` per collection and no claim. The changes this audit proposes (proposals, not rulings) are: route operator-settled runs through one collection per epoch; replace per-claim `openClaim` with membership checks against the collection root inside the consumer's own proof or call, with the claim list held off chain; size `L_TX` so chunking is a rare fallback; fix the stale OpenSpec text; and decide N-8 as one root update per registry epoch. The cost is latency (a claim is usable once its epoch's collection lands) and a data-availability dependency on whoever holds the claim list and paths.
