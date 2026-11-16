# Conformance of impl/ to linedealing.qnt

This file maps the Quint model `formal/quint/linedealing.qnt` to the Rust prototype in `impl/`, lists what each side has that the other lacks, and records the result of model-based conformance testing: Quint traces replayed step by step on the Rust code.

## 1. How the test works

- **Wrapper.** `conformance/linedealing_mbt.qnt` imports `linedealing_protocol` and adds one variable, `proj`. Each wrapped step runs the original step and sets `proj'` to the projection of the pre-state. State `k + 1` of a trace therefore carries the projection of state `k`. The projection holds what the model derives from the board and what the Rust board stores: binding, status, ACK quorum, ROTATE, HANDOVER, the reshare set Q, and per generation the active epoch, the freeze decision, lock or release, the lock digest and attempt, and the anchor height and failure of attempts 1 and 2 of each epoch. The wrapper adds no protocol behaviour; it also re-exports the five invariants and the witness negations so that `--invariants` and `--invariant` work on it. Instances: `mbt_n4`, `mbt_n7`, `mbt_broken_prevote`, `mbt_broken_rule4`.
- **Traces.** `conformance/gen_traces.sh conformance/jobs.txt <dir>` runs every job line through `heavy-run`, with `quint run --mbt --out-itf`, and strips the per-step nondet picks. Rows without an invariant check the five safety invariants and write `N_TRACES` sampled traces; rows with an invariant write that invariant's counterexample (a witness negation for directed deep traces, or `cNoNonceReuse` for the mutants).
- **Driver.** `impl/tests/quint_conformance.rs` with the loader `impl/tests/itf/mod.rs` (serde_json, already in Cargo.lock through criterion). For every step it derives the transition from the state diff (one new post, one new chain block, one board-height tick, or one node record change; `mbt::actionTaken` is used only as a label) and drives the Rust code:
  - honest PREVOTE and PARTIAL only through `NodeState::prevote` / `NodeState::partial`, then `Board::apply`;
  - every other honest post after `NodeState::ensure_can_post`;
  - Byzantine posts straight to `Board::apply`;
  - a disk rollback as `NodeState::restart(.., PersistedNodeState::default(), Some(position))`, a clean restart with `snapshot()`;
  - after every step every honest node runs `NodeState::replay` with a recording erase callback.
  Evidence flags come from trace ground truth (`badNodes` of the bound MSG, the first deal of a dealer, chain contents) or from the Rust board's own state (the freeze set for deal validity), never from the projection.
- **Checks after every step.** Board projection against `proj`; each honest node's slot ledger (`NodeState::slot_digest`, a read-only accessor added for the test), abstentions and erasures against the model's node record; the five invariants on the Rust state (honest partial values per generation, `PinLedger` executions, tombstone causes, no honest old-committee partial for a transferred generation, lock present at every honest open PARTIAL); and negative probes (a node whose slot holds another digest, or that abstains, must not be able to sign the locked digest).
- **Mutants.** A trace of a broken instance must be refused by the Rust signer policy at an honest PREVOTE or PARTIAL at or before the state where the model violates `NoNonceReuse`, with `AlreadyVoted` or `Digest` (rule 1) or `ReplayAbstention` (rule 4).
- **Regressions.** Each finding that was fixed has a trace in `tests/quint-regressions/` (repository root) that the same driver replays in `cargo test`; see section 6.

Run: `cargo test --offline --release --test quint_conformance -- --nocapture` (from `impl/`). The committed corpus is `conformance/traces/`; `QUINT_TRACES=<dir>` replays another corpus with the same layout.

## 2. State variables

| Quint | Rust | Notes |
|---|---|---|
| `board: List[Post]` | `Board` (`board.rs`): `apply` reduces the log into `Request` | The model keeps the log and recomputes; Rust reduces at arrival. Rust `position` also counts ticks, so positions are never compared. |
| `boardHeight` | `Board::height`, advanced by `apply(h, Event::Tick)` | A model tick has no post; Rust records a `Tick` event. |
| `chainBlocks` | none in the board; `PinLedger` for the pin; `builder.rs` for fees | Chain state is an adapter input (`LocalBuild`, evidence flags). |
| `byz1`, `byz2` | none | The driver routes honest posts through `NodeState` and Byzantine posts directly. |
| `nodes_e[i].ledger` | `PersistedNodeState::slots` (`(rid, g) -> {digest, voted}`) | Compared in open mode. Rust also writes a slot for a sealed PARTIAL; the model does not. |
| `nodes_e[i].abstained` | `NodeState::abstain` (`abstains`) | Compared every step. |
| `nodes_e[i].erased` | erase callback of `NodeState::replay` | Rust erasure must cover every model erasure, except the model's per-partial erasure, which Rust does not model. |
| `nodes_e[i].chainTip`, `builderImpl` | caller's chain adapter and builder | Not in the board. |

## 3. Actions

| Quint action | Rust | Notes |
|---|---|---|
| `postOwnerMsg` | `Event::Bind`, `Board::bind` | Step A public checks map to `bind`'s parameter checks (`nb <= exp`, height `<= exp`, reshare needs `t = f + 1`); first valid MSG binds, later ones get `Bound`. |
| `honestStepA` (ACK / COMPLAINT) | `Event::Ack`, `Event::Complaint{valid}`; `transition` | ACK quorum `q` arms; a valid complaint is a VOID tombstone. |
| `honestObs` | `Event::Obs`; `transition`, `check_generation` | First `q` distinct reports, entry `f + 1` descending. `Anchor::cut` and `previous` are the board cut. |
| `honestNack` | `Event::Nack` | `f + 1` NACKs fail the attempt; attempt `a + 1` must follow a failed `a`. |
| `honestPrevote` | `NodeState::prevote` (durable slot first, rule 1, rule 5 via the window) then `Event::Prevote` | Lock = first candidate with `q` voters (`LockCertificate`). |
| `honestOpenPartial` | `NodeState::partial` (own digest, lock, rules 2 and 3) then `Event::Partial` | Rust allows a byte-identical resend; the model posts once and erases. |
| `honestSealedPartial` | `NodeState::partial` with `variant`, `Event::Partial` | The first valid sealed partial sets `Release`. |
| `rollbackNode`, `rollbackNodeWithRule4` | `NodeState::restart` with an empty or older ledger, then `replay` (rule 4) | `replay` abstains on own PREVOTE/PARTIAL posts with no slot. |
| `restartKeepLedger` | `NodeState::restart` with `snapshot()` | |
| `postRotate` | `Event::Rotate`, `Board::rotate` | Finish: no change. Void: VOID. Reshare: `Freeze` with `in_flight` = generations with lock or release. |
| `honestReshareDeal` | `Event::Dealer{valid}` | Dealers in board order. |
| `honestReshareComplaint` | `Event::DealerComplaint{valid}` | |
| `honestReady` | `Event::Ready{dealers}` | Q = first `t_old` non-complained dealers; HANDOVER = first Q with `q'` READY. Rust marks the old attempts of transferred generations FAILED, so the new committee's attempt numbers continue after them (the driver maps model attempt `a` of epoch 2 to `a + offset`). |
| `honestPostFinal`, `honestPostVoid` | `Event::Final`, `Event::ForeignSpend` | `f + 1` posts of one epoch. |
| `tickBoardHeight` | `Event::Tick`; expiry in `apply` | Expiry when height `> exp` and no generation is in flight. |
| `advanceChainReqSpend`, `advanceChainForeignSpend` | `PinLedger::execute` | The driver also checks that the Rust board holds the lock (release) for the executed value and an honest partial for it. |
| `advanceChainEmpty`, `syncNodeChainTip` | none | Chain adapter. |
| `byzPost`, `byzEchoPrevote` | `Board::apply` with the post as an event | |

Invariants: `NoNonceReuse`, `LockBeforeShare` (rules 1 to 4 in `NodeState`, lock check in `transition`), `AtMostOneExecution` (`PinLedger`), `NoTransientTombstone` (only `Final`, `Void`, `Expired` tombstones exist in `Tombstone`), `FreezeSafety` (`check_generation` rejects non-in-flight old-committee posts after the freeze; `Ready` moves only non-in-flight generations).

## 4. Model behaviour that the Rust code does not implement

- **Eligibility and the builder.** The board never evaluates `Eligible`. `trigger(S)` exists nowhere in `impl/`. `Build` (`build_utxo`, `build_eip1559`) enforces the `Δ` rule, but sealed `select_utxo` does not, and its doc comment says the board enforces it, which the board does not. NACK decisions, OBS heights and `LocalBuild` are caller inputs. The model's `buildOpenTxFee` and `selectSealedVariant` are not checked against the Rust builders by this test.
- **Sealed `j_{g-1}`.** The model takes `j_{g-1}` as Select at the anchor of `g - 1`; Rust's board check uses the released variant of `g - 1` and 0 when `g - 1` was not released. Honest variants come from the builder, so this only weakens Rust's sanity check.
- **Reconstruction.** `canReconstructOpen/Sealed` credit Byzantine shares; Rust's `Request::signed` counts posted partials only.
- **Erasure after a node's own PARTIAL.** The model erases generation `g` at the node's PARTIAL; Rust allows a deterministic resend and has no such erasure.

## 5. Rust behaviour that the model does not cover

- Persistence: file ledger, fsync and rename order, orphan temporary file, storage poisoning, `recover_position` from `2f+1` answers, `replay_target` blocking all posts until the replay reaches the retained position. The driver always restarts with the current position.
- A sealed PARTIAL writes a slot and is replayed under rule 4 in Rust; the model's rollback ignores sealed partials (and never rolls back a sealed node, because its ledger is empty).
- Erasure on every VOID tombstone (valid complaint, VOID from Byzantine-completed quorum, VOID rotation for epoch-2 nodes) and on FINAL reached by any post; the model erases only when an honest FINAL/VOID completes the quorum or at a VOID rotation for epoch 1.
- Model posts by an epoch before its ROTATE (see M2): the board cannot authenticate them. More than two generations, attempts and variants, several requests, repeated rotations (a second ROTATE with an unfinished handover voids the request), committee sizes other than the two instances, the `n = 9` instance (no wrapper instance), evidence flags (`valid`) on Bind, Partial, Final and ForeignSpend, and the cryptography.

## 6. Findings

Every finding was checked on the code; the verdicts and the inputs are in `tests/quint-regressions/COUNTEREXAMPLES.md`.

- **M1 (model bug, fixed).** The model let an honest old-committee node post RS_DEAL after HANDOVER. SCHEME section 5 says that old nodes erase the transferred shares when HANDOVER is on the board, so such a deal would deal shares the node no longer holds. The replay found it: the Rust board refused the honest model step (`Handover`). Fix: the `holdsShares` guard in `honestReshareDeal`. The Quint test `dealAfterHandoverTest` fails on the pre-fix model (`runs/v3/m1_prefix_test.log`) and passes after (`runs/v3/unit_tests.log`). The pre-fix trace is the regression `tests/quint-regressions/deal-after-handover.itf.json`. Verdict on the code: GUARD HOLDS.
- **G1 (open design, closed by DECISIONS 55).** The poster validates its evidence before it posts FINAL or VOID, and the board counts authenticated posts of members at their board positions, whatever the evaluator's chain view. Rust now follows the model's rule.
- **G2 (open design, closed by DECISIONS 56).** Each epoch that served the request (the binding epoch, and a successor from its ROTATE position) counts its own FINAL and VOID posts against its own `f + 1`, before or after HANDOVER. Epochs never add. VOID counts members whatever foreign txid they report.
- **M2 (model artifact).** `firstFinalQuorumIdx` and `firstVoidQuorumIdx` accept a post by an epoch before the ROTATE that registers its committee. The board refuses such a post (`Epoch`): no key of that epoch exists yet. Verdict on the code: GUARD HOLDS. The model should require the epoch's ROTATE before its posts count.
- **E1 (doc defect, fixed).** The doc comment of `builder::select_utxo` said that the board enforces generation eligibility. It does not; each node checks eligibility before it posts OBS, as the model's `honestObs` does. The comment is corrected.

How the replay treats M2: the replay has no tolerance for G1 or G2. It marks a FINAL or VOID post that the model counts and the board refuses because its epoch is not registered at that position. It accepts a later divergence as M2 only when the model's first tombstone quorum depends on a marked post, no authenticated quorum exists without the marked posts, and the divergence is a status or a share the model erased and Rust kept. The replay continues to the last step of the trace and checks every other field. Any other divergence fails the test.

## 7. Results

Model file: SHA-256 in `runs/v3/MODEL.sha256`. `quint typecheck` passes on `linedealing.qnt` and on `conformance/linedealing_mbt.qnt` (`runs/v3/typecheck.log`); the 7 Quint unit tests pass (`runs/v3/unit_tests.log`). The invariant runs of `runs/v3/run_all.sh` (the rows of REPORT.md, rerun on the fixed model) give the same verdict as `runs/v2` on every row (`runs/v3/SUMMARY.txt`); the reshare witness rate is 941 of 2,000 traces in `s_n4_adv_reshare` (v2: 920) and 87 of 400 in `s_n7_adv_reshare` (v2: 79), so the new guard does not block honest resharing.

Corpus: `conformance/jobs.txt`, generated with `gen_traces.sh` (logs in `conformance/traces/logs/`), plus the scripted trace `conformance/traces/n4/scripted_failedAttemptScenarioN4.itf.json`. Every mutant row ended with `[violation]` of `cNoNonceReuse`. `gen_traces.sh` now exits non-zero when a row has no verdict or a mutant row did not violate, and reports a directed row that missed its target.

Replay (`cargo test --release --test quint_conformance -- --nocapture`):

| Instance | Traces (seeds) | Steps replayed and projections compared | Negative probes | Outcome |
|---|---|---|---|---|
| `n4` (N = 4, F = 1) | 299: 280 sampled (seeds 1001 to 1062, 20 each), 18 from directed rows (seeds 3001 to 3018) and 1 scripted (`scripted_failedAttemptScenarioN4`) | 8,832 | 618 | 298 conform exactly; 1 (`cInitArmedOpenReshare_cStepAdversarial_s1022_1`) conforms to the last step with an M2 status and erasure divergence from step 30 |
| `n7` (N = 7, F = 2) | 110: 105 sampled (seeds 2001 to 2041, 15 each) and 5 from directed rows (seeds 2051 to 2055) | 4,103 | 320 | all 110 conform exactly |
| `broken_prevote` | 4 (seeds 201, 203, 211, 212) | 83 | 6 | all 4 refused by Rust (`Digest` on an honest PREVOTE) before the model violates `NoNonceReuse` |
| `broken_rule4` | 6 (seeds 202, 204, 207, 209, 213, 214) | 143 | 25 | all 6 refused by Rust (`ReplayAbstention` on an honest PREVOTE in 5, on an honest open PARTIAL in 1) before the violation |

In total 419 traces and 13,161 steps; no mismatch. A directed row checks a witness negation; 7 of them ended `[ok]` because the sampler did not reach the target, and their trace is an ordinary sample: `cNoFailedAttempt` (seeds 3011, 3012, 3013, 2053) and `cNoAttempt2Anchor` (seeds 3014, 3015, 3016). No sampled trace reaches a failed attempt, because an honest NACK needs an anchor that is not eligible while every honest reporter was eligible at its own tip. The scripted trace closes that gap: the Quint run `failedAttemptScenario` in `conformance/linedealing_mbt.qnt` (exported with `quint test --main=mbt_n4 --match=failedAttemptScenarioN4 --out-itf=...`) has Byzantine node 4 report a height whose block fails the trigger between two honest reports, so the anchor is not eligible; two honest NACKs fail attempt 1, and attempt 2 anchors, locks and gets a PARTIAL. The test requires an `n4` trace that reaches a failed attempt and an attempt-2 anchor.

Other phases reached (counts are printed by the test): lock certificates, honest open and sealed partials, spends, generation 2, freeze with an in-flight generation, HANDOVER, epoch-2 partials, disk rollback after an own PREVOTE or PARTIAL, FINAL, VOID and EXPIRED. Reached rarely: honest resharing complaints (3 steps), generation-2 spends (3 traces), freeze with an in-flight generation (6 traces), a failed attempt and attempt 2 (the scripted trace only; none in `n7`). The board ignored 29 honest posts that are redundant in the model too (READY or resharing complaint after HANDOVER, PREVOTE after a lock), and the projection shows that ignoring them changed nothing. Rust erases shares on every VOID tombstone, which the model does not (section 5).

The regression trace `tests/quint-regressions/deal-after-handover.itf.json` replays in `quint_regressions_replay` and `regression_m1_old_node_cannot_deal_after_handover`. The regression tests of G1 and G2 are `g1_final_counted_without_evaluator_chain_view` and `g2_old_committee_final_counts_after_handover` in `impl/src/board.rs`; the counterexample test of E1 is `counterexample_e1_*` there.

## 8. Not covered

Section 4 lists the model behaviour that Rust leaves to the caller (eligibility, builders, reconstruction) and section 5 the Rust behaviour the model does not reach (persistence and position recovery, more than two generations, attempts and variants, several requests, repeated rotations, the `n = 9` instance, evidence flags, the cryptography). The replay never feeds Rust an input outside the model's reachable states, so these are covered only by the unit and integration tests of `impl/`. Within the model, failed attempts, honest NACKs and attempt 2 are replayed on one scripted `n = 4` trace only, and never at `n = 7`.
