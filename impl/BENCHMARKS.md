# Measurements

This file gives the measurements of the prototype at commit 78df8aa. Every CPU figure was taken in an **exclusive heavy slot, on a pinned core with the `performance` governor, at a delivered clock of about 4.0 GHz** (2026-11-16, unit `item33-pinned2`). The open/sealed line-dealing tables and the committee simulation cover the earlier protocol, which the crate still contains. The seald Sessions tables measure the Veritee seald daemon. [benchmarks.html](benchmarks.html) shows the same numbers with charts.

## Conditions

- **Machine.** NVIDIA RTX Spark N1X laptop on AC: aarch64, 10 Cortex-X925 cores (4.0 GHz) and 10 Cortex-A725 cores (2.8 GHz). Every single-thread row is pinned to CPU 19, an X925 core (`taskset -c 19`).
- **Toolchain.** rustc and Cargo 1.99.1, k256 0.13.4, curve25519-dalek 4.1.3, ed25519-dalek 2.2.0, criterion 0.5.1.
- **Time measure.** Every CPU row is **thread CPU time** (`CLOCK_THREAD_CPUTIME_ID`, `benches/support/cputime.rs`): the time that the benchmark thread runs on its core. Criterion uses it through a custom measurement, and `tests/bench9.rs` and `tests/split_latency.rs` use it directly. The committee simulation is the only wall-clock table of the split-line prototype; the seald tables give thread CPU time and wall time.
- **Admission.** The run held `heavy-slot --exclusive` (unit `item33-pinned2`, script `~/.cache/loop-verify/item33/quiet-rerun.sh inner`, 2026-11-16 13:45 to 14:07 MST). The lock admits no other heavy-slot job.
- **Host load.** Interactive sessions and jobs outside heavy-slot kept running. At the step boundaries the 1-minute load average on 20 cores was 1.84 to 5.85 during the criterion, bench9 and latency rows (13:45 to 14:01), 2.87 to 3.84 during the committee simulation and 2.87 to 4.84 during the seald rows. [bench-results/steps.log](bench-results/steps.log) gives the load at the start and end of every step.
- **Power and clock.** The governor was `performance` and the laptop was on AC at the start, middle and end snapshots. ACPI zones read 51 to 64 °C. [bench-results/env.log](bench-results/env.log) has the snapshots. CPPC feedback counters over a 2 s pinned busy loop give delivered performance 152.5 on CPU 19 and 152.9 on CPU 5 (nominal 154 = 4,004 MHz), that is 3,966 and 3,976 MHz ([bench-results/clock.txt](bench-results/clock.txt), read after the run).

## Commands

From `impl/`, with `CARGO_TARGET_DIR=target`, inside `heavy-slot --exclusive` (script `~/.cache/loop-verify/item33/quiet-rerun.sh`):

```sh
LD_BENCH_N=9  taskset -c 19 cargo bench --offline --bench protocol -- --noplot
LD_BENCH_N=17 taskset -c 19 cargo bench --offline --bench protocol -- --noplot
for n in 5 9 17 33; do SPLIT_BENCH_N=$n taskset -c 19 cargo bench --offline --bench split -- --noplot; done
taskset -c 19 cargo test --offline --release --test bench9 -- --ignored --nocapture
SPLIT_LATENCY_RUNS=40 taskset -c 19 cargo test --offline --release --test split_latency -- --ignored --nocapture
./target/release/split_sizes
cargo test --offline --release --test split_envelope reference_and_real_serialization_budgets_cover_every_grid_and_committee -- --nocapture
LD_SKIP_BUILD=1 taskset -c 5-9,15-19 bash run-simulation-matrix.sh
python3 -I benches/criterion_table.py target/criterion
python3 -I benches/bench_report.py target/criterion bench-results
```

From `server/seald` in the Veritee repository, branch `committee-sessions-seald` at f5aadbd:

```sh
SEALD_BENCH_ITERS=50 SEALD_BENCH_DAEMON_ITERS=20 taskset -c 19 cargo test --offline --locked --release --test sessions_bench -- --ignored --nocapture --test-threads=1
```

Raw outputs are in [bench-results/](bench-results/): `criterion-protocol-n{9,17}.txt`, `criterion-split-n{5,9,17,33}.txt`, `split-medians.md`, `split-latency.txt`, `split-sizes.txt`, `split-budgets.txt` (bytes only), `derived.json` and `seald-bench.txt`. [bench9-output.txt](bench9-output.txt), [simulation-results.txt](simulation-results.txt) and [simulation-results.csv](simulation-results.csv) are in this directory. `cargo clippy --release --all-targets -- -D warnings` is clean and `cargo test --offline --release` passes on this tree (383 passed, 0 failed, 12 ignored).

## Split-line committee

Committee sizes use `f = ⌊(n − 1)/3⌋`, `t = n − f` and `q = ⌈(n + f + 1)/2⌉`: n = 5 has t = 4, q = 4; n = 9 has t = 7, q = 6; n = 17 has t = 12, q = 12; n = 33 has t = 23, q = 22. The request is a Bitcoin P2TR spend with `K = 8`, `L = 2`, `G_max = 2` (30 halves, 15 bodies, 4 committee slots), single user unless a row names actors. Ed25519 rows use `K = L = 1`, ECDSA rows `K = 3`, `L = 2` over the ideal slot session.

### Serialized sizes

All values are bytes from serialized prototype objects (`split_sizes`); frame capacity is 16,384 bytes. Layout, header, bodies and capsules include AEAD tags.

| n | Suite | Grid | Frame used | Outer + proof | Layout | Header | Bodies | Capsules | First other actor | Next other actor | CONTRIB frame used | Embedded actor |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | BIP340 | K=8, L=2 | 11195 | 521 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 2591 | 1711 |
| 5 | ECDSA (embedded actors) | K=3, L=2 | 2660 | 521 | 64 | 446 | 336 | 1197 | 594 | 495 | 1235 | 355 |
| 5 | Ed25519 | K=1, L=1 | 1426 | 521 | 64 | 379 | 80 | 286 | 492 | 459 | 977 | 97 |
| 9 | BIP340 | K=8, L=2 | 11422 | 748 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 2818 | 1711 |
| 9 | ECDSA (embedded actors) | K=3, L=2 | 2887 | 748 | 64 | 446 | 336 | 1197 | 594 | 495 | 1462 | 355 |
| 9 | Ed25519 | K=1, L=1 | 1653 | 748 | 64 | 379 | 80 | 286 | 492 | 459 | 1204 | 97 |
| 17 | BIP340 | K=8, L=2 | 11843 | 1169 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 3239 | 1711 |
| 17 | ECDSA (embedded actors) | K=3, L=2 | 3308 | 1169 | 64 | 446 | 336 | 1197 | 594 | 495 | 1883 | 355 |
| 17 | Ed25519 | K=1, L=1 | 2074 | 1169 | 64 | 379 | 80 | 286 | 492 | 459 | 1625 | 97 |
| 33 | BIP340 | K=8, L=2 | 12718 | 2044 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 4114 | 1711 |
| 33 | ECDSA (embedded actors) | K=3, L=2 | 4183 | 2044 | 64 | 446 | 336 | 1197 | 594 | 495 | 2758 | 355 |
| 33 | Ed25519 | K=1, L=1 | 2949 | 2044 | 64 | 379 | 80 | 286 | 492 | 459 | 2500 | 97 |

| n | t | One Schnorr slot on the board | Four Schnorr slots |
|---:|---:|---:|---:|
| 5 | 4 | 2,924 | 10,028 |
| 9 | 7 | 8,351 | 30,317 |
| 17 | 12 | 24,612 | 92,580 |
| 33 | 23 | 88,159 | 339,181 |

**TEE actor bytes.** `tests/split_envelope.rs` builds and serializes requests with and without the TEE header fields and checks that one more actor overflows the frame. At `K = 8`, `L = 2` an other actor adds 790 bytes, and 943 bytes in TEE mode (the weighted point, 33 B, and 30 four-byte pair ids), at n = 9 and n = 17 alike; the TEE header adds 377 bytes once. The largest signing sets per frame, non-TEE / TEE, are:

| Grid | n = 9 | n = 17 |
|---|---|---|
| BIP340 `K = 8`, `L = 2` | 6 / 5 | 6 / 4 |
| BIP340 `K = 8`, `L = 1` | 11 / 10 | 11 / 9 |
| BIP340 `K = 5`, `L = 2` | 14 / 12 | 13 / 11 |
| ECDSA `K = 3`, `L = 2` | 26 / 24 | 25 / 23 |
| ECDSA `K = 1`, `L = 1` | 33 / 31 | 32 / 30 |
| BIP340 `K = 1`, `L = 1` | 32 / 30 | 31 / 29 |

**Actor pool post.** The encoded points of one pool of `N_pool = 64` pairs `(D, E)` are 4,224 bytes (64 × 2 × 33). The POOL record framing (pool id, pool key and its signature) has no encoder in the prototype (O23), so the full post size stays an estimate.

### Scale table

CPU columns are thread CPU time from the criterion medians in [CPU cost](#cpu-cost). The derived columns follow DESIGN §11.3: the request path is `pi_check` + `outer_share_check` + header key (`header_partial` + `header_combine_open`) + `release_ticket_checks` + `own_signature_partials` + variant partial (`header_partial`) + selected body (`open_body_reconstruct_combine_bip340_actors0`); the high end adds one block's vote checks. Slot replenishment per request is `(t/n)·slot_deal_message + (t − t/n)·slot_batch_verify` for 4 slots. Requests per second and core is `1000 / (path + slots)`. Bytes are encoder output (`split_sizes`).

| n | t | q | Request path (ms) | Slot work (ms) | Slot share | Total CPU per request (ms) | Total, × n = 9 | Requests/s per core | Frame bytes used / sent | Slot bytes per request (4 slots, all t dealers) | Board bytes per request, frame + slots |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 4 | 4 | 1.61 to 1.72 | 2.58 | 62% | 4.19 to 4.29 | 0.57 | 232.8 to 238.8 | 11,195 / 16,384 | 10,028 | 26,412 |
| 9 | 7 | 6 | 1.79 to 1.95 | 5.56 | 76% | 7.34 to 7.51 | 1.00 | 133.2 to 136.2 | 11,422 / 16,384 | 30,317 | 46,701 |
| 17 | 12 | 12 | 2.09 to 2.42 | 11.92 | 85% | 14.01 to 14.34 | 1.91 | 69.8 to 71.4 | 11,843 / 16,384 | 92,580 | 108,964 |
| 33 | 23 | 22 | 2.83 to 3.43 | 33.99 | 92% | 36.82 to 37.42 | 5.01 | 26.7 to 27.2 | 12,718 / 16,384 | 339,181 | 355,565 |

Every size runs. The request path grows slowly with n; slot dealing and its checks grow with `t·n` per message and take most of a node's CPU from n = 9 on. Board votes have no encoder in the prototype, so the board-byte column leaves them out (DESIGN §11.1 estimates under 1 KB per request at n = 9 and under 2 KB at n = 17).

Other derived figures, same method:

| Figure | n = 5 | n = 9 | n = 17 | n = 33 |
|---|---:|---:|---:|---:|
| Header key (ms) | 0.212 | 0.298 | 0.442 | 0.775 |
| Failure-path extra (ms), `combine_failure_path` − selected body | 0.662 | 1.012 | 1.690 | 3.647 |
| Combiner per request (ms), selected body | 0.758 | 0.848 | 1.006 | 1.393 |

### Midnight transactions

The committee writes **one checkpoint transaction per 60 s interval, whatever the number of requests in it** (DESIGN §11.6). One checkpoint carries any number of settlement leaves and board-first calls in its fixed-size roots. User `authorize` transactions grow with the requests: one per Midnight-first request, none per board-first request. The checkpoint payload uses the DESIGN §11.6 field list at P = 2 pools (`88 + 52·P + 64 + 8n + 8 + 32n + 64q` bytes); the prototype has no checkpoint encoder.

| n | Requests per checkpoint (one core per node) | Checkpoint payload (B) | N = 10³: committee tx / user tx (Midnight-first) / user tx (board-first) | N = 10⁵ | N = 10⁷ |
|---:|---:|---:|---|---|---|
| 5 | 13,970 | 720 | 1 / 1,000 / 0 | 8 / 100,000 / 0 | 716 / 10,000,000 / 0 |
| 9 | 7,994 | 1,008 | 1 / 1,000 / 0 | 13 / 100,000 / 0 | 1,251 / 10,000,000 / 0 |
| 17 | 4,185 | 1,712 | 1 / 1,000 / 0 | 24 / 100,000 / 0 | 2,390 / 10,000,000 / 0 |
| 33 | 1,604 | 2,992 | 1 / 1,000 / 0 | 63 / 100,000 / 0 | 6,236 / 10,000,000 / 0 |

Committee counts are ⌈N / (60·R)⌉ at the one-core rate R of the scale table (low end). A node with more cores serves the same N in fewer intervals and needs fewer checkpoint transactions.

### Latency, simulated

`tests/split_latency.rs` measures 40 real BIP340 requests per committee size (K = 8, L = 2) and places the measured per-node work on a discrete-event schedule. The model:

- Each node's work is measured in thread CPU time on the real code: the `π` check, outer share and header partial (order step); the header opening; the release (ticket checks, body partial, signature partials); the selected-body combination; and one QC check (`q` strict Ed25519 verifications) after each board commit. Nodes run in parallel, one core each.
- **Board, fixed C** (the DESIGN §11.2 model): a post or vote is committed C after it is submitted. **Board, random-phase blocks**: blocks start every C at a uniform random phase; a submission waits for the next block start and commits C later. Each measured request is replayed at 32 phases.
- **Peer round h**: the messages of a round arrive h after they are sent. The header-partial exchange, the release witness, the two slot-bind rounds and the release are one round each. Witness and bind carry no cryptographic work in the prototype, so they are pure delay.
- A node opens the header with its own partial and the first `t − 1` others. The first node that holds `t` release partials combines and broadcasts.
- Midnight-first: the authorization is in force at `F_M` = 10 s, later than every header opening, and the table gives the time after `F_M`. Board-first: in force at once. The board-first proof check is not in the prototype and is not counted.
- Non-TEE mode has no witness and no bind rounds.

Post to broadcast, n = 9 (n = 17 adds 0.3 to 0.6 ms to every fixed-C row):

| Mode | Authorization | C ms | h ms | DESIGN formula | Simulated, fixed C | Simulated, random-phase blocks, p50 / p99 |
|---|---|---:|---:|---:|---:|---:|
| TEE | Midnight-first | 1000 | 50 | F_M + 1,200 ms | F_M + 1,201.4 ms | F_M + 1,700.5 / 2,192.0 ms |
| TEE | Midnight-first | 500 | 50 | F_M + 700 ms | F_M + 701.4 ms | F_M + 950.9 / 1,196.7 ms |
| TEE | board-first | 1000 | 50 | 2,250 ms | 2,252.3 ms | 3,700.5 / 4,192.0 ms |
| TEE | board-first | 500 | 50 | 1,250 ms | 1,252.3 ms | 1,950.9 / 2,196.7 ms |
| non-TEE | Midnight-first | 1000 | 50 | F_M + 1,050 ms | F_M + 1,051.4 ms | F_M + 1,550.5 / 2,042.0 ms |
| non-TEE | Midnight-first | 500 | 50 | F_M + 550 ms | F_M + 551.4 ms | F_M + 800.9 / 1,046.7 ms |
| non-TEE | board-first | 1000 | 50 | 2,100 ms | 2,102.3 ms | 3,550.5 / 4,042.0 ms |
| non-TEE | board-first | 500 | 50 | 1,100 ms | 1,102.3 ms | 1,800.9 / 2,046.7 ms |

Under the fixed-C model the CPU on the critical path adds 1.4 to 2.3 ms at n = 9 and 1.7 to 2.9 ms at n = 17 to the DESIGN formula; the commits and peer rounds set the latency. The random-phase model adds the wait for a block start, up to C per commit. A Midnight-first request waits about C/2 at the median for its one commit after `F_M`. A board-first request waits for two block starts, and the second wait is nearly a full block, because its ADMIT votes follow the order commit by only h plus CPU. The full table, with h = 25 and h = 0 rows and n = 17, is in [bench-results/split-latency.txt](bench-results/split-latency.txt).

## CPU cost

Exclusive heavy slot, pinned core (CPU 19), `performance` governor, delivered clock about 4.0 GHz. The 95% intervals of the split-line rows are within ±0.5% of the median, and the widest protocol row is ±0.8% (`ed25519_open_n17_t12/combine`).

### Criterion medians, thread CPU time

50 samples, 1 s warm-up and 5 s measurement per row.

| Row | n = 5 | n = 9 | n = 17 | n = 33 |
|---|---:|---:|---:|---:|
| `pi_check` | 213.9 µs | 210.7 µs | 212.8 µs | 218.4 µs |
| `outer_share_check` | 270.3 µs | 272.8 µs | 277.7 µs | 287.7 µs |
| `header_partial` | 72.3 µs | 72.3 µs | 72.1 µs | 72.3 µs |
| `header_combine_open` | 139.7 µs | 225.5 µs | 369.9 µs | 702.5 µs |
| `release_ticket_checks` | 83.5 µs | 83.5 µs | 83.4 µs | 83.6 µs |
| `own_signature_partials` | 197 ns | 197 ns | 197 ns | 197 ns |
| `variant_key` | 200.4 µs | 286.3 µs | 430.2 µs | 764.0 µs |
| `open_body_reconstruct_combine_bip340_actors0` | 758.3 µs | 848.4 µs | 1.006 ms | 1.393 ms |
| `open_body_reconstruct_combine_bip340_actors2` | 1.194 ms | 1.285 ms | 1.441 ms | 1.829 ms |
| `open_body_reconstruct_combine_ed25519_actors0` | 638.6 µs | 733.2 µs | 894.0 µs | 1.300 ms |
| `open_body_reconstruct_combine_ed25519_actors2` | 1.190 ms | 1.287 ms | 1.447 ms | 1.850 ms |
| `combine_bip340_actors0` | 396.6 µs | 398.8 µs | 411.3 µs | 467.3 µs |
| `combine_bip340_actors2` | 626.2 µs | 628.7 µs | 640.4 µs | 698.0 µs |
| `combine_ecdsa_actors0` | 414.9 µs | 565.3 µs | 824.0 µs | 1.427 ms |
| `combine_ecdsa_actors2` | 565.4 µs | 715.1 µs | 974.0 µs | 1.576 ms |
| `combine_ed25519_actors0` | 259.6 µs | 266.7 µs | 286.4 µs | 358.2 µs |
| `combine_ed25519_actors2` | 499.6 µs | 507.4 µs | 529.6 µs | 598.9 µs |
| `combine_failure_path` | 1.421 ms | 1.861 ms | 2.696 ms | 5.040 ms |
| `vote_batch_verify_q_single_verify_strict` | 107.5 µs | 161.7 µs | 323.8 µs | 598.1 µs |
| `slot_deal_message` | 1.128 ms | 1.967 ms | 3.437 ms | 6.786 ms |
| `slot_batch_verify` | 523.2 µs | 647.4 µs | 840.5 µs | 1.312 ms |
| `slot_fallback_verify` | 318.7 µs | 437.9 µs | 640.7 µs | 1.083 ms |
| `slot_lazy_eval` | 3.5 µs | 6.1 µs | 10.4 µs | 19.9 µs |
| `contribution_seal` | 771.9 µs | 771.7 µs | 773.9 µs | 771.8 µs |
| `contrib_frame_open` | 821.7 µs | 911.5 µs | 1.063 ms | 1.416 ms |
| `actor_contribution_work` | 10.848 ms | 10.857 ms | 10.828 ms | 10.875 ms |
| `wallet_build_request` | 7.693 ms | 7.813 ms | 8.217 ms | 9.023 ms |

The 95% intervals are in [bench-results/split-medians.md](bench-results/split-medians.md).

### Line-dealing protocol (open and sealed)

#### Microbenchmarks, thread CPU time

Criterion medians in microseconds, one thread, 10 samples, 100 ms warm-up, 1 s target, with `f = ⌊(n − 1)/3⌋` and `t = f + 1` or `t = n − f`.

| Suite | Mode | n | t | Owner deal+encrypt | Step A | Decrypt | Partial | Verify partial | Combine |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ecdsa | open | 9 | 3 | 818.5 | 342.0 | 108.5 | 85.2 | 85.2 | 101.9 |
| ecdsa | sealed-k8 | 9 | 3 | 3,060.2 | 895.0 | 285.2 | 56.5 | 56.5 | 100.2 |
| bip340 | open | 9 | 3 | 854.9 | 383.8 | 102.5 | 102.1 | 99.3 | 97.3 |
| bip340 | sealed-k8 | 9 | 3 | 1,989.0 | 790.4 | 190.8 | 44.8 | 42.0 | 97.3 |
| ed25519 | open | 9 | 3 | 2,586.5 | 1,149.3 | 61.3 | 76.9 | 76.5 | 114.7 |
| ed25519 | sealed-k8 | 9 | 3 | 6,385.6 | 2,213.7 | 103.5 | 30.0 | 29.9 | 114.8 |
| ecdsa | open | 9 | 7 | 1,051.1 | 415.3 | 112.4 | 88.2 | 88.1 | 143.6 |
| ecdsa | sealed-k8 | 9 | 7 | 3,986.8 | 1,187.1 | 300.9 | 58.0 | 57.9 | 143.6 |
| bip340 | open | 9 | 7 | 1,029.9 | 494.0 | 108.2 | 106.7 | 104.0 | 140.6 |
| bip340 | sealed-k8 | 9 | 7 | 2,455.0 | 1,082.6 | 206.2 | 46.3 | 43.5 | 140.6 |
| ed25519 | open | 9 | 7 | 3,291.5 | 1,792.0 | 66.3 | 80.0 | 79.7 | 155.8 |
| ed25519 | sealed-k8 | 9 | 7 | 8,259.0 | 3,925.8 | 117.4 | 31.1 | 31.0 | 156.0 |
| ecdsa | open | 17 | 6 | 1,302.3 | 401.5 | 108.7 | 87.5 | 87.3 | 132.7 |
| ecdsa | sealed-k8 | 17 | 6 | 4,327.9 | 1,122.3 | 294.4 | 57.6 | 57.5 | 132.6 |
| bip340 | open | 17 | 6 | 1,342.4 | 471.9 | 96.8 | 102.9 | 102.7 | 129.6 |
| bip340 | sealed-k8 | 17 | 6 | 2,917.4 | 1,017.3 | 180.2 | 43.2 | 43.1 | 129.5 |
| ed25519 | open | 17 | 6 | 4,592.4 | 1,835.4 | 65.5 | 79.2 | 78.9 | 145.3 |
| ed25519 | sealed-k8 | 17 | 6 | 11,454.1 | 3,715.4 | 115.4 | 30.9 | 30.7 | 145.3 |
| ecdsa | open | 17 | 12 | 1,654.5 | 510.8 | 114.8 | 91.9 | 91.9 | 200.5 |
| ecdsa | sealed-k8 | 17 | 12 | 5,735.6 | 1,560.9 | 317.8 | 59.9 | 59.8 | 200.3 |
| bip340 | open | 17 | 12 | 1,610.1 | 636.5 | 105.6 | 109.7 | 109.6 | 197.4 |
| bip340 | sealed-k8 | 17 | 12 | 3,630.8 | 1,455.7 | 203.4 | 45.5 | 45.3 | 197.5 |
| ed25519 | open | 17 | 12 | 5,665.2 | 2,805.7 | 73.2 | 84.1 | 83.8 | 217.0 |
| ed25519 | sealed-k8 | 17 | 12 | 14,356.9 | 6,300.0 | 135.9 | 32.7 | 32.4 | 216.3 |

The owner measurement excludes preparation of transaction fixtures and sealed wallet signatures. Step A includes public validation. Bitcoin sealed validation reconstructs the variants and sighashes. Decryption includes share checks. Partial creation includes its local verification. Combination combines optimistically, names bad partials and verifies the final signature.

#### Per-request CPU (bench9), open ECDSA, one slot

`tests/bench9.rs`, release build, one thread, thread CPU time, a timed loop per step after one warm-up call. Per-node CPU per request = Step A + decrypt + lock digest + partial + one signature check per board post (3q quorum posts + t partials); the combiner's work is added once.

| Committee | t | Owner message (bytes) | Post checks | Per-node CPU (µs) | Combiner (µs) | Requests/s per core |
|---|---:|---:|---:|---:|---:|---:|
| n=7, f=2 | 3 | 1,333 | 18 | 1,432.9 | 100.4 | 652 |
| n=7, f=2 | 5 | 1,465 | 20 | 1,575.5 | 121.9 | 589 |
| n=9, f=2 | 3 | 1,461 | 21 | 1,587.1 | 100.4 | 593 |
| n=9, f=2 | 7 | 1,725 | 25 | 1,874.1 | 144.0 | 496 |
| n=10, f=3 | 4 | 1,591 | 25 | 1,812.2 | 111.2 | 520 |
| n=10, f=3 | 7 | 1,789 | 28 | 2,026.4 | 143.8 | 461 |

One board post check is 51.1 µs, so post checks are 68% of the per-node CPU at n = 9, t = 3. The message sizes equal the SCHEME §7 and `costs.py` figures for the same parameters.

#### Committee simulation, wall clock

`run-simulation-matrix.sh` runs the release `committee-sim` binary over every combination of: n = 9, f = 2, q = 6; t = 3, 7; ECDSA, BIP340, Ed25519; open and sealed with K = 8; 16 concurrent requests after preparation; one-way link delay 0, 25, 50 ms; batch size 1, 16; board service interval 1 ms; seed 42. All 72 runs complete all 16 requests: 1,152 reconstructed and verified signatures.

The simulator runs nine worker threads and measures wall-clock latency, so the host load enters these numbers directly. The script ran on the ten Cortex-X925 cores (`taskset -c 5-9,15-19`) at a 1-minute load average of 2.87 to 3.84. In every suite, mode, threshold and batch size, p50 grows with the link delay. Read the table for completion and relative order; the requests/s column is a lower bound on what nine dedicated cores would give.

| t | Link ms | Batch size | p50 ms | p99 ms | Requests/s |
|---:|---:|---:|---:|---:|---:|
| 3 | 0 | 1 | 606.5 | 725.5 | 22.0 |
| 3 | 0 | 16 | 88.0 | 95.3 | 162.4 |
| 3 | 25 | 1 | 657.7 | 776.4 | 20.6 |
| 3 | 25 | 16 | 274.4 | 280.7 | 56.2 |
| 3 | 50 | 1 | 706.8 | 825.2 | 19.4 |
| 3 | 50 | 16 | 471.1 | 478.4 | 33.2 |
| 7 | 0 | 1 | 617.7 | 741.0 | 21.6 |
| 7 | 0 | 16 | 101.4 | 110.1 | 140.3 |
| 7 | 25 | 1 | 667.7 | 791.3 | 20.2 |
| 7 | 25 | 16 | 288.1 | 297.5 | 53.1 |
| 7 | 50 | 1 | 717.0 | 840.5 | 19.0 |
| 7 | 50 | 16 | 492.6 | 501.4 | 31.7 |

All suites at zero injected latency, batch size 16:

| Suite | Mode | t | p50 ms | p99 ms | Requests/s |
|---|---|---:|---:|---:|---:|
| ECDSA | open | 3 | 88.0 | 95.3 | 162.4 |
| ECDSA | open | 7 | 101.4 | 110.1 | 140.3 |
| ECDSA | sealed-k8 | 3 | 110.8 | 139.5 | 112.4 |
| ECDSA | sealed-k8 | 7 | 134.9 | 170.4 | 92.0 |
| BIP340 | open | 3 | 90.0 | 98.4 | 157.1 |
| BIP340 | open | 7 | 109.8 | 118.2 | 130.7 |
| BIP340 | sealed-k8 | 3 | 93.6 | 116.2 | 134.7 |
| BIP340 | sealed-k8 | 7 | 122.0 | 148.3 | 105.5 |
| Ed25519 | open | 3 | 128.6 | 152.0 | 103.0 |
| Ed25519 | open | 7 | 169.5 | 200.8 | 78.1 |
| Ed25519 | sealed-k8 | 3 | 182.1 | 246.1 | 64.3 |
| Ed25519 | sealed-k8 | 7 | 274.5 | 366.4 | 43.3 |

Latency includes owner preparation, queueing, board exchanges, cryptographic work and verified reconstruction. It excludes target-chain execution. Every worker processes the owner message and decrypts its own shares; the sequencer verifies each signed post and each partial individually. Batching groups transport messages and board commits; it does not aggregate cryptographic verification. The sequencer replaces BFT consensus. Chain finality, disk fsync costs and physical share erasure are absent. Per-request clocks start before serial owner preparation, and throughput starts before all preparation and ends at the last verified signature.

The honest workload emits 36 posts per open request and 27 per sealed request. For one-way delay L, network transit alone needs at least 8L in open mode and 6L in sealed mode. At a 1 ms board interval, single-post batches bound the service rate at 27.8 open or 37.0 sealed requests/s, and full batches of 16 at 444.4 or 592.6; these are derived bounds, not measurements.

## seald Sessions

`server/seald/tests/sessions_bench.rs` in the Veritee repository (branch `committee-sessions-seald`, f5aadbd) runs the Sessions service and daemon on one host, pinned to CPU 19. A committee of n seats has `f = ⌊(n − 1)/3⌋`, threshold t and w witnesses. The service rows run seat 0 in process with a sequential pool and window B = 10, 50 samples after 10 warm-up calls. The daemon rows run every seat (Node, Runtime, `FileSessionsBoard` and peer RPC) with 20 samples per operation (16 and 28 per-seat samples for the whole-committee restart), once over an in-process transport and once over the attested peer transport on a Unix socket. Thread CPU is `CLOCK_THREAD_CPUTIME_ID` of the calling thread; wall is `CLOCK_MONOTONIC`. Each board append, checkpoint publish and service checkpoint calls fsync, so their wall times include the disk. All values are in microseconds.

### Service operations, seat 0

| n | f | t | w | operation | samples | thread CPU median (us) | thread CPU p90 (us) | wall median (us) | wall p90 (us) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 3 | 2 | create (first session_open) | 50 | 12.8 | 13.6 | 13.1 | 14.0 |
| 4 | 1 | 3 | 2 | session_put (1 entry, overwrite) | 50 | 19.8 | 20.2 | 20.0 | 20.5 |
| 4 | 1 | 3 | 2 | session_get (1 entry) | 50 | 8.1 | 8.2 | 8.3 | 8.5 |
| 4 | 1 | 3 | 2 | slot_get (one share) | 50 | 8.8 | 8.9 | 9.0 | 9.2 |
| 4 | 1 | 3 | 2 | session_checkpoint (seal, fsync, w acks) | 50 | 2672.5 | 2963.0 | 12069.0 | 13717.4 |
| 4 | 1 | 3 | 2 | restore after reboot of seat 0 (new Service + open) | 50 | 3659.7 | 4063.6 | 16383.6 | 18019.6 |
| 4 | 1 | 3 | 2 | restore after whole-committee restart, burn [1,10] | 50 | 3634.6 | 3997.9 | 15820.3 | 18449.0 |
| 7 | 2 | 5 | 4 | create (first session_open) | 50 | 13.7 | 14.3 | 14.0 | 14.6 |
| 7 | 2 | 5 | 4 | session_put (1 entry, overwrite) | 50 | 20.9 | 22.1 | 21.1 | 22.5 |
| 7 | 2 | 5 | 4 | session_get (1 entry) | 50 | 9.4 | 9.5 | 9.6 | 9.8 |
| 7 | 2 | 5 | 4 | slot_get (one share) | 50 | 10.0 | 10.1 | 10.2 | 10.4 |
| 7 | 2 | 5 | 4 | session_checkpoint (seal, fsync, w acks) | 50 | 3631.2 | 3919.6 | 12244.6 | 13857.2 |
| 7 | 2 | 5 | 4 | restore after reboot of seat 0 (new Service + open) | 50 | 4764.2 | 5261.5 | 17353.8 | 19012.2 |
| 7 | 2 | 5 | 4 | restore after whole-committee restart, burn [1,10] | 50 | 4745.7 | 5107.9 | 17292.3 | 21109.9 |

### Threshold PRF key derivation, one record header

| n | f | t | w | operation | samples | thread CPU median (us) | thread CPU p90 (us) | wall median (us) | wall p90 (us) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 3 | 2 | prove_partial (one peer, DLEQ proof) | 50 | 114.5 | 115.9 | 114.7 | 116.2 |
| 4 | 1 | 3 | 2 | session_key: verify t proofs + combine t | 50 | 450.5 | 456.0 | 450.8 | 456.3 |
| 4 | 1 | 3 | 2 | derive_key: t proofs + verify + combine, one thread | 50 | 796.2 | 800.2 | 796.5 | 800.5 |
| 7 | 2 | 5 | 4 | prove_partial (one peer, DLEQ proof) | 50 | 114.4 | 117.4 | 114.7 | 117.7 |
| 7 | 2 | 5 | 4 | session_key: verify t proofs + combine t | 50 | 749.3 | 751.3 | 749.6 | 751.6 |
| 7 | 2 | 5 | 4 | derive_key: t proofs + verify + combine, one thread | 50 | 1324.2 | 1328.1 | 1324.5 | 1328.4 |

### Daemon operations, in-process transport

| n | f | t | w | operation | samples | thread CPU median (us) | thread CPU p90 (us) | wall median (us) | wall p90 (us) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 3 | 2 | create (session_open, new account-pool session) | 20 | 77.9 | 89.3 | 78.2 | 89.7 |
| 4 | 1 | 3 | 2 | session_put (1 entry, overwrite) | 20 | 85.5 | 86.9 | 85.8 | 87.2 |
| 4 | 1 | 3 | 2 | session_get (1 entry) | 20 | 73.2 | 73.6 | 73.5 | 74.1 |
| 4 | 1 | 3 | 2 | slot_get (one share) | 20 | 73.9 | 74.4 | 74.3 | 74.7 |
| 4 | 1 | 3 | 2 | session_checkpoint (t partials + w witnesses over peer RPC) | 20 | 12801.9 | 13490.7 | 97738.0 | 108981.4 |
| 4 | 1 | 3 | 2 | committee_checkpoint (1 Midnight write each, asserted) | 20 | 2557.7 | 2766.2 | 27257.4 | 33486.9 |
| 4 | 1 | 3 | 2 | restore after reboot of seat 0 (session_open) | 20 | 16332.4 | 17068.5 | 101500.8 | 108187.8 |
| 4 | 1 | 3 | 2 | restore after whole-committee restart, burn [1,10] (per seat) | 16 | 15329.8 | 16571.6 | 105451.7 | 125984.2 |
| 7 | 2 | 5 | 4 | create (session_open, new account-pool session) | 20 | 86.8 | 101.2 | 87.1 | 101.6 |
| 7 | 2 | 5 | 4 | session_put (1 entry, overwrite) | 20 | 94.4 | 98.1 | 94.7 | 98.4 |
| 7 | 2 | 5 | 4 | session_get (1 entry) | 20 | 81.8 | 82.2 | 82.1 | 82.5 |
| 7 | 2 | 5 | 4 | slot_get (one share) | 20 | 82.5 | 83.1 | 82.9 | 83.4 |
| 7 | 2 | 5 | 4 | session_checkpoint (t partials + w witnesses over peer RPC) | 20 | 25406.8 | 26490.4 | 189975.2 | 199388.2 |
| 7 | 2 | 5 | 4 | committee_checkpoint (1 Midnight write each, asserted) | 20 | 4679.3 | 5053.7 | 48412.6 | 53230.7 |
| 7 | 2 | 5 | 4 | restore after reboot of seat 0 (session_open) | 20 | 30870.0 | 32750.0 | 205696.6 | 225873.4 |
| 7 | 2 | 5 | 4 | restore after whole-committee restart, burn [1,10] (per seat) | 28 | 28754.4 | 31058.3 | 211281.2 | 230520.2 |

### Daemon operations, attested peer transport over a Unix socket

| n | f | t | w | operation | samples | thread CPU median (us) | thread CPU p90 (us) | wall median (us) | wall p90 (us) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 3 | 2 | create (session_open, new account-pool session) | 20 | 75.3 | 89.6 | 75.6 | 90.0 |
| 4 | 1 | 3 | 2 | session_put (1 entry, overwrite) | 20 | 85.4 | 87.2 | 85.7 | 87.5 |
| 4 | 1 | 3 | 2 | session_get (1 entry) | 20 | 72.7 | 72.9 | 73.0 | 73.2 |
| 4 | 1 | 3 | 2 | slot_get (one share) | 20 | 73.6 | 73.9 | 73.8 | 74.2 |
| 4 | 1 | 3 | 2 | session_checkpoint (t partials + w witnesses over peer RPC) | 20 | 4371.0 | 4647.7 | 101492.5 | 116063.2 |
| 4 | 1 | 3 | 2 | committee_checkpoint (1 Midnight write each, asserted) | 20 | 2271.7 | 2440.6 | 26417.9 | 31082.9 |
| 4 | 1 | 3 | 2 | restore after reboot of seat 0 (session_open) | 20 | 7208.4 | 7701.6 | 107822.1 | 113690.7 |
| 4 | 1 | 3 | 2 | restore after whole-committee restart, burn [1,10] (per seat) | 16 | 5688.0 | 5905.7 | 108035.9 | 121170.9 |
| 7 | 2 | 5 | 4 | create (session_open, new account-pool session) | 20 | 87.3 | 110.1 | 87.6 | 110.5 |
| 7 | 2 | 5 | 4 | session_put (1 entry, overwrite) | 20 | 95.4 | 96.3 | 95.7 | 96.6 |
| 7 | 2 | 5 | 4 | session_get (1 entry) | 20 | 82.6 | 82.7 | 82.8 | 83.0 |
| 7 | 2 | 5 | 4 | slot_get (one share) | 20 | 83.2 | 84.2 | 83.5 | 84.5 |
| 7 | 2 | 5 | 4 | session_checkpoint (t partials + w witnesses over peer RPC) | 20 | 7318.6 | 7572.1 | 198718.1 | 214566.5 |
| 7 | 2 | 5 | 4 | committee_checkpoint (1 Midnight write each, asserted) | 20 | 4311.6 | 4694.3 | 51849.0 | 56151.7 |
| 7 | 2 | 5 | 4 | restore after reboot of seat 0 (session_open) | 20 | 11013.1 | 11628.5 | 222413.3 | 234049.9 |
| 7 | 2 | 5 | 4 | restore after whole-committee restart, burn [1,10] (per seat) | 28 | 9398.1 | 10031.9 | 210493.1 | 231071.5 |

Thread CPU counts only the calling thread; wall time covers the whole operation, including its peer RPC rounds.

### Midnight writes

`FileSessionsBoard` with `LedgerCheckpointSink` over `MockLedger`. A checkpoint covers every put since the previous one.

| n | puts per checkpoint | checkpoints | Midnight writes during puts | Midnight writes per checkpoint | append CPU median (us) | append CPU p90 (us) | append wall median (us) | append wall p90 (us) | publish CPU median (us) | publish CPU p90 (us) | publish wall median (us) | publish wall p90 (us) | covered entries at end |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | 1 | 50 | 0 | 1 | 637.2 | 763.1 | 7887.2 | 10480.6 | 2193.0 | 2603.1 | 28968.1 | 34270.2 | 50 |
| 4 | 10 | 50 | 0 | 1 | 1701.5 | 2603.8 | 10297.5 | 12432.2 | 3436.8 | 4346.1 | 31239.0 | 34629.8 | 500 |
| 4 | 100 | 10 | 0 | 1 | 2596.9 | 3540.5 | 11857.8 | 14534.5 | 4105.1 | 4609.5 | 33129.4 | 35840.9 | 1000 |
| 4 | 1000 | 3 | 0 | 1 | 4892.1 | 7117.2 | 16423.2 | 20988.5 | 7720.2 | 10519.1 | 39145.1 | 44521.1 | 3000 |
| 7 | 1 | 50 | 0 | 1 | 624.5 | 770.4 | 8109.0 | 10379.2 | 3442.9 | 4062.8 | 50463.2 | 57556.6 | 50 |
| 7 | 10 | 50 | 0 | 1 | 1713.8 | 2539.3 | 10353.1 | 13250.0 | 4995.4 | 5884.8 | 52633.7 | 60545.6 | 500 |
| 7 | 100 | 10 | 0 | 1 | 2603.7 | 3655.9 | 12181.7 | 15056.0 | 5698.7 | 6510.0 | 57210.3 | 60913.1 | 1000 |
| 7 | 1000 | 3 | 0 | 1 | 4897.8 | 7027.8 | 16566.2 | 20484.6 | 8639.8 | 11722.3 | 57140.6 | 57501.5 | 3000 |

The committee writes **one Midnight transaction per checkpoint, whatever the number of puts in it**, and none during the puts. The service path (`session_checkpoint`) writes no Midnight transaction and appends no board statement:

| n | session_checkpoint calls | Midnight writes (MockLedger records) | board statements appended |
|---|---|---|---|
| 4 | 60 | 0 | 0 |
| 7 | 60 | 0 | 0 |

Midnight transactions at scale for `ops` operations with P puts per checkpoint, `tx = ⌈ops / P⌉ × W` with the measured W = 1 (derived, not measured):

| ops | P = 1 | P = 10 | P = 100 | P = 1000 | one write per op (removed design) |
|---|---|---|---|---|---|
| 1000 | 1000 | 100 | 10 | 1 | 1000 |
| 100000 | 100000 | 10000 | 1000 | 100 | 100000 |
| 10000000 | 10000000 | 1000000 | 100000 | 10000 | 10000000 |
